package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.RulePath;

// Translates a RulePath into an SBPL regex literal body, #"...".
//
// Every character a real path can hold is carried by escaping it as a regex metacharacter where the
// regex engine would otherwise read it as syntax. Measured through the real sandbox-exec for each of
// them, against the named path and two decoy directories: a space, tab, line break, "#", ",", "!",
// "[", "]", "{", "}", "\", a single quote and non-ASCII all reach exactly the path they name. A
// backslash needs the escaped spelling specifically - written raw it collapses and the rule lands on
// a different directory, measured, which is the same failure AppArmor has with it.
//
// "*" and "?" are escaped here too, and that is not a detail. They are the pattern language, so a
// caller's wildcard never arrives as a character at all - it arrives as a wildcard token from
// GlobPattern, and a "*" that does arrive as a character is one a real directory name holds.
// Measured: a workspace named "My*Project" spelled with the wildcard live granted three sibling
// directories the rule never named, on both platforms.
//
// A double quote is the one character that cannot be carried, and GlobPattern refuses it. The
// #"..." literal is a raw passthrough terminated by the first quote in it: \" ends the literal
// early and leaves the rest of the clause to be read as live profile syntax, \x22 is not
// interpreted, and a character class around it matches something else entirely. All three measured.
// The plain-string spelling of the same filter, (regex "..."), does accept an escaped quote - and is
// not used, because its string literal eats one level of backslash before the regex sees it:
// measured, an escaped "." there became "any character" and granted a decoy directory the rule never
// named. A form that turns a missed escape into a silent over-grant is the wrong place to gain one
// character.
final class SeatbeltGlobTranslator {

  private static final String REGEX_METACHARACTERS = "^$.|+*?()[]{}\\";

  private SeatbeltGlobTranslator() {
  }

  static String toRegex(RulePath target) {
    StringBuilder regex = new StringBuilder("^");
    RulePath required = Preconditions.nonNull(target, "target");
    for (GlobToken token : GlobPattern.parse(required.pattern())) {
      switch (token) {
        case GlobLiteral literal -> appendLiteral(regex, literal.codePoint());
        case GlobWildcard.ANY_PATH -> regex.append(".*");
        case GlobWildcard.ANY_SEGMENT -> regex.append("[^/]*");
        case GlobWildcard.SINGLE_CHARACTER -> regex.append("[^/]");
      }
    }
    return regex.append('$')
        .toString();
  }

  private static void appendLiteral(StringBuilder regex, int codePoint) {
    if (REGEX_METACHARACTERS.indexOf(codePoint) >= 0) {
      regex.append('\\');
    }
    regex.appendCodePoint(codePoint);
  }
}
