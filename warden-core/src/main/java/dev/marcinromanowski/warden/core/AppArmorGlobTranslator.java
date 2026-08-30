package dev.marcinromanowski.warden.core;

import java.util.ArrayList;
import java.util.List;

// AppArmor's own path-pattern grammar already understands the glob subset FilesystemRule
// patterns use (**, *, literal segments, ${user.home}) natively - unlike Seatbelt's SBPL, which
// only accepts a full regex, AppArmor needs no translation at all for these shapes. Empirically
// confirmed on a real kernel: '.' and '(' ')' are literal characters here (a `*.env` pattern does
// not match `secretXenv`), not regex metacharacters - so nothing needs escaping for those.
// Bracket/brace character classes ([...], {...}) are rejected rather than passed through, since
// AppArmor gives them real (different) meaning and no bundled or operator rule in this codebase
// uses them - a wrong assumption about that meaning would be a silent security bug. ',' and a
// line break are rejected because AppArmor rule syntax is unquoted and comma/newline-terminated
// (`<pattern> <access-mode>,`, `# comment` to end of line) - an unescaped occurrence in an
// untrusted pattern could inject new rule syntax or comment out the rest of a line.
//
// '\' is rejected for a third reason, and SeatbeltGlobTranslator already rejects it, so accepting
// it here made one rule set mean two different things. '\' is a legal character in a Linux
// filename and callers interpolate real paths into patterns, but AppArmor reads it as an escape:
// measured on a real kernel, a rule set scoped to a directory literally named "work\space" is
// parsed as naming "workspace" instead, so every clause built from that root - the tree-wide allow
// and the denies carved out of it alike - lands on a different real directory. The confined
// process was granted read-write on that other directory, which no rule named, and refused every
// write inside the workspace the sandbox was built for. A component ending in '\' is worse still:
// apparmor_parser rejects the whole profile ("syntax error, unexpected TOK_END_OF_RULE"), which
// reaches the caller as a failed launch rather than a rejected rule, and the same pattern makes
// java.nio.file's own glob compiler throw PatternSyntaxException ("No character to escape").
final class AppArmorGlobTranslator {

  private static final String USER_HOME_TOKEN = "${user.home}";
  private static final String UNSUPPORTED_PATTERN_CHARACTERS = "[]{},\\";
  private static final String RECURSIVE_ANYWHERE_PREFIX = "/**/";

  private AppArmorGlobTranslator() {
  }

  static String toAppArmorPattern(String globPattern) {
    String expanded = expandUserHome(Preconditions.nonBlank(globPattern, "globPattern"));
    rejectUnsupportedSyntax(expanded);
    return absolute(expanded);
  }

  // FilesystemRule callers commonly express "this filename anywhere in the tree" as a
  // leading-"**"-without-a-slash pattern (e.g. "**/.env") - valid, meaningful glob syntax against
  // an already-absolute candidate path under java.nio.file's own PathMatcher semantics (which is
  // what these patterns are authored against), but AppArmor's own grammar requires every pattern
  // to be a genuinely absolute path starting with "/". Passing a pattern like "**/.env" straight
  // through produces a real AppArmor parser error ("Lexer found unexpected character: '*'"),
  // confirmed the first time this generator was exercised end to end with a real, non-empty rule
  // list - no earlier test here ever used a relative-looking pattern.
  //
  // The leading "/" does not preserve "anywhere" all the way up to the filesystem root. E.g., "/**/.env"
  // does not match "/.env", because AppArmor's "**" does not match the empty string between two
  // slashes. The same holds for a trailing "**" - "/x/**" does not match "/x/". So a caller's "match
  // this name anywhere" pattern covers every depth except a file sitting directly at "/".
  //
  // zeroSegmentForm below names that missing case, and AppArmorProfileGenerator emits it for DENY
  // clauses only. Under the java.nio.file PathMatcher semantics this file itself names two paragraphs
  // up, "**/config.json" does match "/config.json", so a caller writing that pattern did write the
  // root-level case, and SeatbeltProfileGenerator's own translation of it already grants exactly that
  // on macOS.
  //
  // The real reason is risk asymmetry, not authorship. Getting the zero-segment reading wrong on a
  // deny costs one more path the confined process cannot reach. Getting it wrong on an allow hands
  // out read or write at the filesystem root, where every wrong emission this generator could make
  // is maximally expensive. Deny is emitted because the cost of being wrong is bounded, and that
  // leaves an allow-side "/**/<name>" pattern granting the root-level case on macOS and not on
  // Linux - a real, deliberate divergence, recorded here because it is not otherwise visible.
  private static String absolute(String pattern) {
    return pattern.startsWith("/") ? pattern : "/" + pattern;
  }

  // The zero-segment readings of a leading "/**/" pattern - "/**/.env" also meaning "/.env" - which
  // AppArmor's own "**" does not cover, measured above.
  //
  // Every leading "/**/" is stripped, not just the first, so "/**/**/.env" yields both "/**/.env"
  // (depth one, which neither the original nor a single strip covers, since both "**" have to be
  // non-empty) and "/.env" (depth zero).
  //
  // Only the leading form is handled: it is the one this class itself manufactures out of a
  // caller's "match anywhere" pattern. An interior "**" ("/a/**/b") has the same gap, a workspace-scoped
  // "<root>/**/<name>" deny is a shape callers write, and does not cover "<root>/<name>". It is
  // left uncovered here deliberately: covering it means a clause per subset of the "**"
  // occurrences, and a caller who means the zero-depth case can name it in a rule of its own, which
  // is what the callers writing that shape already do. The leading form gets this treatment instead
  // because a caller cannot name it at all - "**/<name>" is the only spelling there is for it, and
  // it is this class that turns it into a pattern AppArmor reads as depth-one-or-more.
  //
  // A form that reduces to bare "/" is refused: "**/" as written by a caller means "any directory
  // anywhere", and turning that into a clause naming the filesystem root itself is a reach beyond
  // restating the caller's own pattern at zero depth.
  static List<String> zeroSegmentForms(String appArmorPattern) {
    List<String> forms = new ArrayList<>();
    String remaining = appArmorPattern;
    while (remaining.startsWith(RECURSIVE_ANYWHERE_PREFIX)) {
      remaining = "/" + remaining.substring(RECURSIVE_ANYWHERE_PREFIX.length());
      if (!remaining.equals("/")) {
        forms.add(remaining);
      }
    }
    return List.copyOf(forms);
  }

  private static void rejectUnsupportedSyntax(String pattern) {
    for (int index = 0; index < pattern.length(); index++) {
      char current = pattern.charAt(index);
      if (UNSUPPORTED_PATTERN_CHARACTERS.indexOf(current) >= 0 || current == '\n' || current == '\r') {
        String message = "Unsupported character in sandbox rule pattern (bracket/brace classes are"
            + " not translated, ',' and line breaks are rejected as an AppArmor rule-syntax"
            + " injection risk, and '\\' is rejected because AppArmor reads it as an escape and"
            + " would scope the rule to a different path than the one written): " + pattern;
        throw new IllegalArgumentException(message);
      }
    }
  }

  private static String expandUserHome(String pattern) {
    if (!pattern.contains(USER_HOME_TOKEN)) {
      return pattern;
    }
    String userHome = Preconditions.nonBlank(System.getProperty("user.home"), "user.home");
    return pattern.replace(USER_HOME_TOKEN, userHome);
  }
}
