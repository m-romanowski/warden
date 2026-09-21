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
// glob, minus one specific literal path" - restoring the intended precedence by rewriting the
// pattern rather than by ranking the rules. apparmor.d(5) documents a "priority=" rule qualifier,
// present in the parser from 4.1 onward, and this project does not use it anywhere - not for a
// caller's rules and not for warden's own reserved paths, which are emitted bare. It would express
// this carve-out in one clause, and it is hard-refused by every parser below 4.1, which includes
// Ubuntu 24.04 LTS. The pattern grammar the rewrite below uses instead - "**", "*", "?" and a
// negated character class - compiles on 2.13.3, 3.0.4, 4.0.1, 4.1.0~beta5 and 5.0.2, so there is
// nothing for a version gate to choose between. One piece of it has a narrower warrant: the octal
// byte escape this class puts inside the negated class has been measured on 5.0.2 only, and a
// parser that read it as four literal characters would produce a class that excludes the wrong
// bytes rather than one that fails to load.
//
// The rewrite is a trie over the excluded path. Every path the deny covers other than the excluded
// one relates to it in exactly one of three ways: it diverges at some position, it stops short of
// it, or it runs past it. One clause per case, unioned, is the original deny with a path-exact hole
// in it. Measured on apparmor_parser 5.0.2 / kernel 7.0.0-31 over ten deny-and-exception shapes,
// reads and writes alike, including a generated profile loaded whole: no probe path was decided
// differently from "exempt exactly this one path and nothing else".
//
// Two flavours of divergence, and mixing them is exactly what the previous version of this class got
// wrong. A negated character class matches "/" - measured, "deny /zz/c[^e]cert.pem r," denies
// /zz/c/cert.pem, because "[^e]" bound the separator - while "*" and "?" do not. So a branch meant
// to reach into subdirectories spells its remainder with "**" and a class that does not exclude "/",
// and a branch that must stay inside one directory spells it with "*" and a class that does
// ("[^/e]", measured to leave /zz/c/cert.pem alone). The old construction emitted "[^c]*" for both,
// so a directory component could bind the excluded filename and the class then swallowed the slash,
// re-denying paths the exception was written to reach and leaving same-named files elsewhere
// reachable. Its header claimed the recursive-anywhere case excluded "by filename at any depth",
// which described neither what it emitted nor anything that loads: what it did depended on how the
// surrounding directories happened to be spelled.
//
// Which trie a deny gets depends on where its wildcards are. A recursive-anywhere deny whose
// filename glob ends in a literal ("/**/*.pem", "/**/.env") is one trie over the excluded path with
// that literal factored off the end and re-appended to every branch. The literal has to come off
// first: run the same trie over the whole path and its "stops short" branch at the position where
// the literal begins re-appends that literal and spells the excluded path itself, which denies the
// one path the whole rewrite exists to give back. Checked over every single-character edit of a
// worked path - 508 of them - the whole-path trie deviates on exactly that one path and the stem
// trie on none. A recursive-anywhere deny whose
// filename glob ends in a wildcard ("/**/.env*") has no such literal, and gets two tries instead:
// one over the excluded path's directory, whose branches keep the deny's own filename glob and cover
// every other directory, and one over the excluded filename inside that directory. A deny whose
// directory portion is literal is that second trie alone.
//
// The first shape denies slightly more than the pattern it replaces: "/**/*.pem" does not match a
// file sitting directly at the filesystem root and the trie does. That is the same reading
// AppArmorGlobTranslator.zeroSegmentForms already emits as a separate deny clause for the same
// pattern, so it widens the profile by nothing it did not already say.
//
// Still deliberately narrow, not a general glob-difference solver. The deny's directory portion must
// be either "/**/" or a literal directory equal to the excluded path's own, and its filename portion
// must carry at most one "*", at its start or its end, and no "?". Anything else falls back to
// Optional.empty() and the caller leaves the original deny clause untouched - still correct and
// secure, just unable to express this particular carve-out.
//
// Cost: two clauses per byte of the path the trie enumerates, per exception, per deny clause the
// caller wrote - a read deny and a write deny over the same glob each pay in full. The clause count
// is asserted in AppArmorDenyGlobExclusionTest. What it costs at load time was measured on parser
// 5.0.2 / kernel 7.0.0-31, ten exceptions in one profile, best of three loads:
//
//   excluded path length      22       50       74      101
//   clauses                  742     1862     2822     3902
//   profile bytes          21 KB    79 KB   153 KB   263 KB
//   apparmor_parser        0.02s    0.05s    0.32s    1.17s
//
// At the shape a caller actually writes there is nothing to manage: two exceptions over ordinary
// paths is 177 clauses and 6.7 KB, and the profile loads in the same 0.04s it takes with the deny
// globs left whole. It stops being free when the excluded paths are both long and numerous, because
// the parser's cost grows faster than the clause count does - ten exceptions under a
// hundred-character directory adds a second to every sandbox launch. A caller in that position gets
// more from naming shorter exception paths than from anything this class could emit.
final class AppArmorDenyGlobExclusion {

  private static final String RECURSIVE_DIRECTORY = "/**/";
  private static final String SEPARATOR = "/";
  private static final String DOUBLE_SEPARATOR = "//";
  private static final char WILDCARD = '*';
  private static final char SINGLE_CHARACTER_WILDCARD = '?';

  private AppArmorDenyGlobExclusion() {
  }

  static Optional<List<String>> excludeLiteralPath(String denyPattern, String excludedLiteralPath) {
    int denySlash = denyPattern.lastIndexOf('/');
    Optional<List<AppArmorPathByte>> excludedPath = AppArmorPathEscaping.splitIntoBytes(excludedLiteralPath);
    if (denySlash < 0 || excludedPath.isEmpty() || excludedLiteralPath.contains(DOUBLE_SEPARATOR)) {
      return Optional.empty();
    }
    return excludeFromDeny(
        denyPattern.substring(0, denySlash + 1),
        denyPattern.substring(denySlash + 1),
        excludedPath.get()
    );
  }

  private static Optional<List<String>> excludeFromDeny(
      String denyDirectory,
      String filenameGlob,
      List<AppArmorPathByte> excludedPath
  ) {
    int lastSlash = lastSeparator(excludedPath);
    if (lastSlash < 0 || lastSlash == excludedPath.size() - 1 || !isSupportedFilenameGlob(filenameGlob)) {
      return Optional.empty();
    }
    if (RECURSIVE_DIRECTORY.equals(denyDirectory)) {
      return excludeUnderAnyDirectory(filenameGlob, excludedPath, lastSlash);
    }
    String excludedDirectory = spell(excludedPath.subList(0, lastSlash + 1));
    if (hasWildcard(denyDirectory) || !denyDirectory.equals(excludedDirectory)) {
      return Optional.empty();
    }
    return excludeWithinOneDirectory(
        filenameGlob,
        excludedDirectory,
        excludedPath.subList(lastSlash + 1, excludedPath.size())
    );
  }

  private static Optional<List<String>> excludeUnderAnyDirectory(
      String filenameGlob,
      List<AppArmorPathByte> excludedPath,
      int lastSlash
  ) {
    List<AppArmorPathByte> excludedName = excludedPath.subList(lastSlash + 1, excludedPath.size());
    List<AppArmorPathByte> excludedDirectory = excludedPath.subList(0, lastSlash);
    String trailingLiteral = trailingLiteralOf(filenameGlob);
    if (!trailingLiteral.isEmpty() && !trailingLiteral.equals(filenameGlob)) {
      return withoutSuffix(excludedPath, trailingLiteral)
          .filter(stem -> !stem.isEmpty())
          .map(stem -> anyDirectoryBranches(stem, trailingLiteral));
    }
    if (excludedDirectory.isEmpty()) {
      return Optional.empty();
    }
    String name = spell(excludedName);
    if (!trailingLiteral.isEmpty()) {
      return name.equals(trailingLiteral)
          ? Optional.of(anyDirectoryBranches(excludedDirectory, SEPARATOR + trailingLiteral))
          : Optional.empty();
    }
    String literalPrefix = filenameGlob.substring(0, filenameGlob.length() - 1);
    String excludedDirectorySpelling = spell(excludedPath.subList(0, lastSlash + 1));
    return withoutPrefix(excludedName, literalPrefix)
        .map(rest -> bothTries(excludedDirectory, excludedDirectorySpelling, filenameGlob, literalPrefix, rest));
  }

  private static List<String> bothTries(
      List<AppArmorPathByte> excludedDirectory,
      String excludedDirectorySpelling,
      String filenameGlob,
      String literalPrefix,
      List<AppArmorPathByte> rest
  ) {
    List<String> branches = new ArrayList<>(anyDirectoryBranches(excludedDirectory, SEPARATOR + filenameGlob));
    branches.addAll(oneDirectoryBranches(excludedDirectorySpelling, literalPrefix, rest, ""));
    return branches;
  }

  private static Optional<List<String>> excludeWithinOneDirectory(
      String filenameGlob,
      String excludedDirectory,
      List<AppArmorPathByte> excludedName
  ) {
    String trailingLiteral = trailingLiteralOf(filenameGlob);
    if (trailingLiteral.equals(filenameGlob)) {
      String name = spell(excludedName);
      return name.equals(trailingLiteral) ? Optional.of(List.of()) : Optional.empty();
    }
    if (!trailingLiteral.isEmpty()) {
      return withoutSuffix(excludedName, trailingLiteral)
          .map(head -> oneDirectoryBranches(excludedDirectory, "", head, trailingLiteral));
    }
    String literalPrefix = filenameGlob.substring(0, filenameGlob.length() - 1);
    return withoutPrefix(excludedName, literalPrefix)
        .map(rest -> oneDirectoryBranches(excludedDirectory, literalPrefix, rest, ""));
  }

  private static List<String> anyDirectoryBranches(List<AppArmorPathByte> stem, String tail) {
    List<String> branches = new ArrayList<>();
    for (int position = 1; position < stem.size(); position++) {
      AppArmorPathByte diverging = stem.get(position);
      addBranch(branches, spell(stem.subList(0, position)) + "[^" + diverging.classMember() + "]**" + tail);
    }
    for (int position = 1; position < stem.size(); position++) {
      addBranch(branches, spell(stem.subList(0, position)) + tail);
    }
    addBranch(branches, spell(stem) + "?**" + tail);
    addBranch(branches, spell(stem) + "/**" + tail);
    return branches;
  }

  private static void addBranch(List<String> branches, String branch) {
    if (!branch.contains(DOUBLE_SEPARATOR)) {
      branches.add(branch);
    }
  }

  private static List<String> oneDirectoryBranches(
      String directory,
      String literalPrefix,
      List<AppArmorPathByte> variable,
      String tail
  ) {
    String base = directory + literalPrefix;
    List<String> branches = new ArrayList<>();
    for (int position = 0; position < variable.size(); position++) {
      AppArmorPathByte diverging = variable.get(position);
      branches.add(base + spell(variable.subList(0, position)) + "[^/" + diverging.classMember() + "]*" + tail);
    }
    for (int position = 0; position < variable.size(); position++) {
      branches.add(base + spell(variable.subList(0, position)) + tail);
    }
    branches.add(base + spell(variable) + "?*" + tail);
    return branches;
  }

  private static String trailingLiteralOf(String filenameGlob) {
    if (filenameGlob.indexOf(WILDCARD) < 0) {
      return filenameGlob;
    }
    return filenameGlob.charAt(0) == WILDCARD && filenameGlob.length() > 1
        ? filenameGlob.substring(1)
        : "";
  }

  private static boolean isSupportedFilenameGlob(String filenameGlob) {
    if (filenameGlob.isEmpty() || filenameGlob.indexOf(SINGLE_CHARACTER_WILDCARD) >= 0) {
      return false;
    }
    int first = filenameGlob.indexOf(WILDCARD);
    int last = filenameGlob.lastIndexOf(WILDCARD);
    return first < 0 || (first == last && (first == 0 || first == filenameGlob.length() - 1));
  }

  private static boolean hasWildcard(String pattern) {
    return pattern.indexOf(WILDCARD) >= 0 || pattern.indexOf(SINGLE_CHARACTER_WILDCARD) >= 0;
  }

  private static Optional<List<AppArmorPathByte>> withoutSuffix(List<AppArmorPathByte> bytes, String suffix) {
    int length = escapedByteCount(suffix);
    if (length <= 0 || length > bytes.size()) {
      return Optional.empty();
    }
    String carried = spell(bytes.subList(bytes.size() - length, bytes.size()));
    return suffix.equals(carried)
        ? Optional.of(bytes.subList(0, bytes.size() - length))
        : Optional.empty();
  }

  private static Optional<List<AppArmorPathByte>> withoutPrefix(List<AppArmorPathByte> bytes, String prefix) {
    int length = escapedByteCount(prefix);
    if (length < 0 || length > bytes.size()) {
      return Optional.empty();
    }
    String carried = spell(bytes.subList(0, length));
    return prefix.equals(carried)
        ? Optional.of(bytes.subList(length, bytes.size()))
        : Optional.empty();
  }

  private static int escapedByteCount(String escapedLiteral) {
    return AppArmorPathEscaping.splitIntoBytes(escapedLiteral)
        .map(List::size)
        .orElse(-1);
  }

  private static int lastSeparator(List<AppArmorPathByte> bytes) {
    for (int position = bytes.size() - 1; position >= 0; position--) {
      AppArmorPathByte candidate = bytes.get(position);
      if (SEPARATOR.equals(candidate.spelling())) {
        return position;
      }
    }
    return -1;
  }

  private static String spell(List<AppArmorPathByte> bytes) {
    StringBuilder spelled = new StringBuilder();
    for (AppArmorPathByte pathByte : bytes) {
      spelled.append(pathByte.spelling());
    }
    return spelled.toString();
  }
}
