package dev.marcinromanowski.warden.core;

// Translates the glob subset FilesystemRule patterns use (**, *, literal segments,
// ${user.home}) into an SBPL (regex #"...") body. Bracket/brace character classes are rejected
// rather than silently mistranslated, since a wrong translation would be a silent security bug.
// '"' and '\' are rejected for a second, sharper reason: the emitted regex is embedded in an
// SBPL string literal (#"..."), so an unescaped '"' would close that literal early and let
// whatever follows be parsed as live SBPL syntax rather than regex content. Rejecting outright,
// not attempting to escape, since this generator has no way to prove escaping is correctly
// interpreted by libsandbox's own regex-literal grammar.
final class SeatbeltGlobTranslator {

  private static final String USER_HOME_TOKEN = "${user.home}";
  private static final String UNSUPPORTED_GLOB_CHARACTERS = "[]{}\"\\";
  private static final String REGEX_METACHARACTERS = "^$.|+()[]{}";
  private static final char GLOB_WILDCARD = '*';
  private static final char GLOB_SINGLE_CHARACTER = '?';

  private SeatbeltGlobTranslator() {
  }

  static String toRegex(String globPattern) {
    String expanded = expandUserHome(Preconditions.nonBlank(globPattern, "globPattern"));
    rejectUnsupportedSyntax(expanded);
    StringBuilder regex = new StringBuilder("^");
    int index = 0;
    while (index < expanded.length()) {
      char current = expanded.charAt(index);
      boolean isDoubleWildcard = current == GLOB_WILDCARD
          && index + 1 < expanded.length()
          && expanded.charAt(index + 1) == GLOB_WILDCARD;
      if (isDoubleWildcard) {
        regex.append(".*");
        index += 2;
      } else if (current == GLOB_WILDCARD) {
        regex.append("[^/]*");
        index += 1;
      } else if (current == GLOB_SINGLE_CHARACTER) {
        regex.append("[^/]");
        index += 1;
      } else if (REGEX_METACHARACTERS.indexOf(current) >= 0) {
        regex.append('\\')
            .append(current);
        index += 1;
      } else {
        regex.append(current);
        index += 1;
      }
    }
    return regex.append('$')
        .toString();
  }

  private static void rejectUnsupportedSyntax(String pattern) {
    for (int index = 0; index < pattern.length(); index++) {
      if (UNSUPPORTED_GLOB_CHARACTERS.indexOf(pattern.charAt(index)) >= 0) {
        String message = "Unsupported character in sandbox rule pattern (bracket/brace classes are"
            + " not translated; '\"' and '\\' are rejected as an SBPL string-literal injection risk): "
            + pattern;
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
