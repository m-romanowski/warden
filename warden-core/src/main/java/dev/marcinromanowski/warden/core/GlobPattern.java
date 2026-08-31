package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.RulePath;
import dev.marcinromanowski.warden.api.SandboxRuleRejectedException;
import java.util.ArrayList;
import java.util.List;

// Reads a RulePath's glob into the tokens both platform translators render, so that the two cannot
// disagree about what a pattern says. Each has its own alphabet - AppArmor takes the same glob
// vocabulary natively, SBPL takes a regex - and neither has anything to decide about the pattern's
// meaning once it is tokenised.
//
// The supported vocabulary is "**", "*", "?", and "\" escaping whatever follows it. Every other
// java.nio.file glob construct is refused here. A character class or an alternation has no
// equivalent in either policy language, and translating one as text produces a rule that matches a
// filename spelled "{pem,key}" - measured on both platforms, a deny written that way leaves exactly
// the files it names readable and is bit-for-bit indistinguishable from writing no rule at all. A
// refusal reaches the caller as a failed launch naming the pattern, which is the only outcome of the
// three that a person can act on.
//
// A double quote is refused wherever it appears, escaped or not. SBPL takes a pattern as a regex
// inside a #"..." literal, and that literal has no escape for its own terminator - measured, \" ends
// it early and the rest of the clause is then read as live profile syntax, \x22 is not interpreted,
// and a character class around it matches the wrong thing. AppArmor could carry one, and refusing it
// here too is what keeps one rule list from being two different policies.
//
// A NUL byte is refused for a plainer reason: no filesystem path can hold one, so a pattern
// containing one names nothing and is a caller mistake rather than a path to support.
final class GlobPattern {

  private static final String USER_HOME_TOKEN = "${user.home}";
  private static final char ESCAPE = '\\';
  private static final char UNSUPPORTED_QUOTE = '"';
  private static final char UNSUPPORTED_NUL = '\0';
  private static final String REFUSED_CONSTRUCTS = "[]{}";
  private static final char WILDCARD = '*';
  private static final char SINGLE_CHARACTER_WILDCARD = '?';

  private GlobPattern() {
  }

  static List<GlobToken> parse(String globPattern) {
    String expanded = expandUserHome(Preconditions.nonBlank(globPattern, "globPattern"));
    List<GlobToken> tokens = new ArrayList<>();
    int index = 0;
    while (index < expanded.length()) {
      int codePoint = expanded.codePointAt(index);
      int width = Character.charCount(codePoint);
      requireCarryable(codePoint, expanded);
      if (codePoint == ESCAPE) {
        index = appendEscaped(tokens, expanded, index + width);
        continue;
      }
      if (REFUSED_CONSTRUCTS.indexOf(codePoint) >= 0) {
        throw refusedConstruct((char) codePoint, expanded);
      }
      if (codePoint == SINGLE_CHARACTER_WILDCARD) {
        tokens.add(GlobWildcard.SINGLE_CHARACTER);
        index += width;
        continue;
      }
      if (codePoint == WILDCARD) {
        boolean recursive = index + width < expanded.length() && expanded.charAt(index + width) == WILDCARD;
        tokens.add(recursive ? GlobWildcard.ANY_PATH : GlobWildcard.ANY_SEGMENT);
        index += recursive ? width + 1 : width;
        continue;
      }
      tokens.add(new GlobLiteral(codePoint));
      index += width;
    }
    return List.copyOf(tokens);
  }

  private static int appendEscaped(List<GlobToken> tokens, String pattern, int index) {
    if (index >= pattern.length()) {
      String message = "Unsupported sandbox rule pattern: it ends in a backslash with nothing to"
          + " escape. A backslash makes the next character literal, so a trailing one names no path."
          + " Write \"\\\\\" for a path whose real name ends in a backslash. Pattern: " + pattern;
      throw new SandboxRuleRejectedException(message, pattern);
    }
    int codePoint = pattern.codePointAt(index);
    requireCarryable(codePoint, pattern);
    tokens.add(new GlobLiteral(codePoint));
    return index + Character.charCount(codePoint);
  }

  private static void requireCarryable(int codePoint, String pattern) {
    if (codePoint == UNSUPPORTED_QUOTE) {
      String message = "Unsupported character in sandbox rule pattern: a double quote ('\"')."
          + " macOS Seatbelt takes a rule pattern as a regex inside a #\"...\" literal, whose only"
          + " terminator is that same character and which has no escape for it, so a pattern"
          + " containing one cannot be expressed there at all. Refused on Linux as well, where it"
          + " could be expressed, so that one rule list does not mean two different policies."
          + " Pattern: " + pattern;
      throw new SandboxRuleRejectedException(message, pattern);
    }
    if (codePoint == UNSUPPORTED_NUL) {
      String message = "Unsupported character in sandbox rule pattern: a NUL byte. No filesystem"
          + " path can contain one, so this pattern names nothing. Pattern: " + pattern;
      throw new SandboxRuleRejectedException(message, pattern);
    }
  }

  private static SandboxRuleRejectedException refusedConstruct(char construct, String pattern) {
    return new SandboxRuleRejectedException(
        "Unsupported construct in sandbox rule pattern: '" + construct + "'. Neither AppArmor nor"
            + " Seatbelt has a character class or an alternation, and emitting one as text produces"
            + " a rule that matches a filename spelled that way and nothing else - a deny written"
            + " like that enforces nothing. Write one rule per alternative, or escape the character"
            + " as \"\\" + construct + "\" if a real path holds it. Pattern: " + pattern,
        pattern
    );
  }

  private static String expandUserHome(String pattern) {
    if (!pattern.contains(USER_HOME_TOKEN)) {
      return pattern;
    }
    String userHome = Preconditions.nonBlank(System.getProperty("user.home"), "user.home");
    return pattern.replace(USER_HOME_TOKEN, RulePath.quote(userHome));
  }
}
