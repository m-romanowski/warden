package dev.marcinromanowski.warden.core;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

// Renders the literal characters of a path into the byte alphabet an AppArmor rule clause can
// carry, and back.
//
// A clause is "<pattern> <access-mode>," on one unquoted line, and a path interpolated verbatim is
// a path that can end its own clause. Character by character: a bare space makes the parser read
// the rest of the path as an access mode, a line break ends the clause mid-path, and "!" and an
// unbalanced "[", "]", "{" or "}" are outright syntax errors. A bare "\" is worse than any of
// those, because the profile still loads: it is read as an escape, and the rule lands on a different
// directory than the one written. None of these characters is unusual in a directory a person
// actually works in.
//
// "," and "#" are this grammar's rule terminator and comment introducer, and in a path position
// both measured as ordinary literal characters that reach exactly the path they name. They are
// escaped all the same. What a byte means where is then not a question this class has to keep
// answering correctly for a rule to be the rule that was written.
//
// AppArmor's own answer is a fixed-width octal byte escape, "\NNN", accepted unquoted anywhere in a
// pattern. Measured against the parser and then against the kernel for every byte this class
// escapes: the confined process reaches the path that was named and neither of two decoy
// directories - one with the character dropped, one with it replaced. It stays unambiguous when
// the next character is itself a digit, which is why the fixed width matters and why a
// variable-length spelling is not used.
//
// Escaping is per byte of the UTF-8 encoding rather than per character, because a path is a byte
// string to the kernel and to the parser alike, and a multi-byte character escaped as one unit
// would name a path no filesystem holds.
//
// Only the bytes that need it are escaped. AppArmor reads a backslash before an ordinary letter as
// its own escape sequence - "\n" is a line break and not the letter n, measured, along with \t \r
// \a \f \e and the octal digits - so escaping everything would rename most paths rather than
// protect them. What is left unescaped is the set measured to be inert in a pattern: ASCII letters
// and digits, "/", ".", "_" and "-".
//
// "*" and "?" are escaped here like everything else. A wildcard a caller wrote never reaches this
// class: AppArmorGlobTranslator renders those from the parsed pattern's own wildcard tokens, and
// hands this class only the characters a path really holds.
//
// A body carrying these escapes still contains no brace, which is the invariant the privileged
// policy helper's bound rests on (see scripts/install-apparmor-policy.sh): "{" reaches the parser
// as "\173", four bytes none of which is a brace.
final class AppArmorPathEscaping {

  private static final String UNESCAPED_PUNCTUATION = "/._-";
  private static final String JAVA_GLOB_METACHARACTERS = "\\*?[]{}";
  private static final char ESCAPE = '\\';
  private static final int OCTAL_DIGITS = 3;
  private static final int OCTAL_RADIX = 8;
  private static final int BYTE_MASK = 0xFF;
  private static final int ASCII_LIMIT = 128;

  private AppArmorPathEscaping() {
  }

  static String escapeLiteralPath(String path) {
    StringBuilder escaped = new StringBuilder(path.length());
    path.codePoints()
        .forEach(codePoint -> appendLiteral(escaped, codePoint));
    return escaped.toString();
  }

  static void appendLiteral(StringBuilder escaped, int codePoint) {
    for (byte encoded : Character.toString(codePoint)
        .getBytes(StandardCharsets.UTF_8)) {
      int octet = encoded & BYTE_MASK;
      if (isInert(octet)) {
        escaped.append((char) octet);
        continue;
      }
      escaped.append(ESCAPE)
          .append(octalDigits(octet));
    }
  }

  static String unescape(String escapedPattern) {
    StringBuilder unescaped = new StringBuilder(escapedPattern.length());
    int index = 0;
    while (index < escapedPattern.length()) {
      char current = escapedPattern.charAt(index);
      if (current != ESCAPE) {
        unescaped.append(current);
        index++;
        continue;
      }
      AppArmorEscapedRun decoded = decodeRun(escapedPattern, index);
      unescaped.append(decoded.text());
      index = decoded.nextIndex();
    }
    return unescaped.toString();
  }

  static String toJavaGlobPattern(String escapedPattern) {
    StringBuilder glob = new StringBuilder(escapedPattern.length());
    int index = 0;
    while (index < escapedPattern.length()) {
      char current = escapedPattern.charAt(index);
      if (current != ESCAPE) {
        glob.append(current);
        index++;
        continue;
      }
      AppArmorEscapedRun decoded = decodeRun(escapedPattern, index);
      decoded.text()
          .codePoints()
          .forEach(codePoint -> appendGlobLiteral(glob, codePoint));
      index = decoded.nextIndex();
    }
    return glob.toString();
  }

  private static void appendGlobLiteral(StringBuilder glob, int codePoint) {
    if (codePoint < ASCII_LIMIT && JAVA_GLOB_METACHARACTERS.indexOf(codePoint) >= 0) {
      glob.append(ESCAPE);
    }
    glob.appendCodePoint(codePoint);
  }

  private static String octalDigits(int octet) {
    String digits = Integer.toOctalString(octet);
    return "0".repeat(OCTAL_DIGITS - digits.length()) + digits;
  }

  private static boolean isInert(int octet) {
    if (octet >= ASCII_LIMIT) {
      return false;
    }
    char character = (char) octet;
    boolean alphanumeric = (character >= 'a' && character <= 'z')
        || (character >= 'A' && character <= 'Z')
        || (character >= '0' && character <= '9');
    return alphanumeric || UNESCAPED_PUNCTUATION.indexOf(character) >= 0;
  }

  private static AppArmorEscapedRun decodeRun(String escapedPattern, int start) {
    ByteArrayOutputStream octets = new ByteArrayOutputStream();
    int index = start;
    while (index < escapedPattern.length() && escapedPattern.charAt(index) == ESCAPE) {
      String digits = escapedPattern.substring(index + 1, index + 1 + OCTAL_DIGITS);
      octets.write(Integer.parseInt(digits, OCTAL_RADIX));
      index += 1 + OCTAL_DIGITS;
    }
    return new AppArmorEscapedRun(octets.toString(StandardCharsets.UTF_8), index);
  }
}
