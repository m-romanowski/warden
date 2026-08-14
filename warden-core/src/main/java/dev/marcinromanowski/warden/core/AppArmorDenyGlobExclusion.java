package dev.marcinromanowski.warden.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

// AppArmor resolves overlapping allow/deny rules by pure set-subtraction
// (effective-allow = union(allow) - union(deny)), confirmed empirically on a real kernel to be
// unconditional and symmetric with respect to specificity: a narrow "deny" carved out of a broad
// "allow" works (the credential-blacklist mechanism this whole project protects depends on this
// direction), but the *reverse* - a narrow, higher-priority "allow" meant to carve an exception
// out of a broader, lower-priority "deny" glob - does not, regardless of emission order or which
// rule is more specific. This is a real, practically-relevant gap: a caller's own default-deny
// credential-glob policy commonly wants to allow-list one specific, safe-looking exception file
// (e.g. a `.env.example` template committed alongside a deny-all `.env*` glob) - exactly the
// shape this class exists to support.
//
// This class computes a *replacement* set of deny clauses that together match "the original deny
// glob, minus one specific literal path" - restoring the intended precedence without relying on
// any AppArmor priority mechanism that doesn't exist. Scoped deliberately narrow, not a general
// glob-difference solver: the deny pattern's directory portion (everything up to and including
// the last "/") must be either the recursive-anywhere prefix "/**/", or a literal (no-wildcard)
// directory that matches the excluded path's own directory exactly. Its filename portion (after
// that "/") must be a *single*-wildcard pattern ("prefix*" or "*suffix") or no wildcard at all.
// Any other shape (a wildcard elsewhere in the directory portion, multiple wildcards in the
// filename, "**" inside the filename itself, unsafe characters in the excluded suffix) falls back
// to Optional.empty() - the caller then leaves the original deny clause untouched, which is still
// correct and secure, just not able to express this specific carve-out (the pre-existing,
// already-accepted behavior).
//
// For the recursive-anywhere case specifically, this excludes by *filename* rather than by the
// excluded path's exact directory: the resulting deny-clause set matches "any file with this
// exact name, at any depth" minus the one excluded literal, rather than "at this glob, except this
// one exact absolute path elsewhere in the tree". A named, deliberate simplification (not an
// oversight) - matches how a git-style convention treats a filename like ".env.example" as
// inherently a safe pattern wherever it appears (that's exactly why it's excluded from the
// credential blacklist to begin with), and avoids a second, independent layer of directory-scoped
// glob-difference this project does not currently need.
final class AppArmorDenyGlobExclusion {

  // AppArmorGlobTranslator now always prepends a leading "/" to a relative-looking pattern, so a
  // "match anywhere" deny glob arrives here as "/**/<filenameGlob>", not "**/<filenameGlob>".
  private static final String RECURSIVE_DIRECTORY = "/**/";
  private static final String SAFE_SUFFIX_CHARACTERS =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";

  private AppArmorDenyGlobExclusion() {
  }

  // denyPattern and excludedLiteralPath are both already-AppArmor-compatible absolute patterns
  // (AppArmorGlobTranslator.toAppArmorPattern already applied by the caller).
  static Optional<List<String>> excludeLiteralPath(String denyPattern, String excludedLiteralPath) {
    int lastSlash = denyPattern.lastIndexOf('/');
    if (lastSlash < 0) {
      return Optional.empty();
    }
    String directoryPrefix = denyPattern.substring(0, lastSlash + 1);
    String filenameGlob = denyPattern.substring(lastSlash + 1);
    String excludedDirectory = excludedLiteralPath.substring(0, excludedLiteralPath.lastIndexOf('/') + 1);
    if (!directoryPrefix.equals(RECURSIVE_DIRECTORY) && !directoryPrefix.equals(excludedDirectory)) {
      return Optional.empty();
    }
    String excludedName = excludedLiteralPath.substring(excludedLiteralPath.lastIndexOf('/') + 1);
    if (!hasOnlySafeCharacters(excludedName)) {
      return Optional.empty();
    }
    Optional<List<String>> filenameBranches = excludeFromFilenameGlob(filenameGlob, excludedName);
    return filenameBranches.map(branches -> withDirectoryPrefix(branches, directoryPrefix));
  }

  private static List<String> withDirectoryPrefix(List<String> branches, String directoryPrefix) {
    return branches.stream()
        .map(branch -> directoryPrefix + branch)
        .toList();
  }

  private static Optional<List<String>> excludeFromFilenameGlob(String filenameGlob, String excludedName) {
    int wildcardCount = countWildcards(filenameGlob);
    if (wildcardCount == 0) {
      return filenameGlob.equals(excludedName) ? Optional.of(List.of()) : Optional.empty();
    }
    if (wildcardCount != 1) {
      return Optional.empty();
    }
    if (filenameGlob.endsWith("*")) {
      return excludeFromTrailingStarGlob(filenameGlob, excludedName);
    }
    if (filenameGlob.startsWith("*")) {
      return excludeFromLeadingStarGlob(filenameGlob, excludedName);
    }
    return Optional.empty();
  }

  private static Optional<List<String>> excludeFromTrailingStarGlob(String filenameGlob, String excludedName) {
    String literalPrefix = filenameGlob.substring(0, filenameGlob.length() - 1);
    if (!excludedName.startsWith(literalPrefix)) {
      return Optional.empty();
    }
    String excludedRest = excludedName.substring(literalPrefix.length());
    return Optional.of(divergenceBranches(literalPrefix, excludedRest));
  }

  private static Optional<List<String>> excludeFromLeadingStarGlob(String filenameGlob, String excludedName) {
    String literalSuffix = filenameGlob.substring(1);
    if (!excludedName.endsWith(literalSuffix)) {
      return Optional.empty();
    }
    String excludedPrefix = excludedName.substring(0, excludedName.length() - literalSuffix.length());
    List<String> branches = divergenceBranches("", excludedPrefix)
        .stream()
        .map(branch -> branch + literalSuffix)
        .toList();
    return Optional.of(branches);
  }

  private static int countWildcards(String pattern) {
    return (int) pattern.chars()
        .filter(character -> character == '*')
        .count();
  }

  private static boolean hasOnlySafeCharacters(String value) {
    for (int index = 0; index < value.length(); index++) {
      if (SAFE_SUFFIX_CHARACTERS.indexOf(value.charAt(index)) < 0) {
        return false;
      }
    }
    return !value.isEmpty();
  }

  // Enumerates every string starting with fixedPrefix except exactly (fixedPrefix + excludedRest),
  // as a set of AppArmor pattern branches - the "divergence trie" construction: for each position
  // in excludedRest, one branch stopping exactly there and one branch diverging with a different
  // character there, plus one branch for anything strictly longer than the fully-excluded string.
  private static List<String> divergenceBranches(String fixedPrefix, String excludedRest) {
    List<String> branches = new ArrayList<>();
    for (int position = 0; position < excludedRest.length(); position++) {
      String matchedSoFar = excludedRest.substring(0, position);
      char divergingChar = excludedRest.charAt(position);
      branches.add(fixedPrefix + matchedSoFar);
      branches.add(fixedPrefix + matchedSoFar + "[^" + divergingChar + "]*");
    }
    branches.add(fixedPrefix + excludedRest + "?*");
    return branches;
  }
}
