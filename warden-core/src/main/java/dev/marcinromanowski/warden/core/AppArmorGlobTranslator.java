package dev.marcinromanowski.warden.core;

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
final class AppArmorGlobTranslator {

  private static final String USER_HOME_TOKEN = "${user.home}";
  private static final String UNSUPPORTED_PATTERN_CHARACTERS = "[]{},";

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
  // list - no earlier test here ever used a relative-looking pattern. Empirically confirmed a
  // leading "/" preserves the intended "anywhere, including at the filesystem root" meaning
  // exactly (AppArmor's own "**" matches zero segments too, unlike a regex translation's own
  // zero-width-match edge cases).
  private static String absolute(String pattern) {
    return pattern.startsWith("/") ? pattern : "/" + pattern;
  }

  private static void rejectUnsupportedSyntax(String pattern) {
    for (int index = 0; index < pattern.length(); index++) {
      char current = pattern.charAt(index);
      if (UNSUPPORTED_PATTERN_CHARACTERS.indexOf(current) >= 0 || current == '\n' || current == '\r') {
        String message = "Unsupported character in sandbox rule pattern (bracket/brace classes are"
            + " not translated; ',' and line breaks are rejected as an AppArmor rule-syntax"
            + " injection risk): " + pattern;
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
