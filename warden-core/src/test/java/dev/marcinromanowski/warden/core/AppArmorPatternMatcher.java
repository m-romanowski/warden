package dev.marcinromanowski.warden.core;

import java.util.regex.Pattern;

final class AppArmorPatternMatcher {

  private static final int OCTAL_DIGITS = 3;
  private static final int OCTAL_RADIX = 8;

  private AppArmorPatternMatcher() {
  }

  static boolean matches(String appArmorPattern, String path) {
    return Pattern.compile(toRegularExpression(appArmorPattern))
        .matcher(path)
        .matches();
  }

  private static String toRegularExpression(String appArmorPattern) {
    StringBuilder expression = new StringBuilder();
    int index = 0;
    while (index < appArmorPattern.length()) {
      char current = appArmorPattern.charAt(index);
      if (current == '*') {
        boolean recursive = appArmorPattern.startsWith("**", index);
        expression.append(recursive ? ".*" : "[^/]*");
        index += recursive ? 2 : 1;
        continue;
      }
      if (current == '?') {
        expression.append("[^/]");
        index++;
        continue;
      }
      if (current == '[') {
        int close = appArmorPattern.indexOf(']', index);
        expression.append("[^")
            .append(classMembers(appArmorPattern.substring(index + 2, close)))
            .append(']');
        index = close + 1;
        continue;
      }
      if (current == '\\') {
        expression.append(Pattern.quote(String.valueOf(decode(appArmorPattern, index))));
        index += 1 + OCTAL_DIGITS;
        continue;
      }
      expression.append(Pattern.quote(String.valueOf(current)));
      index++;
    }
    return expression.toString();
  }

  private static String classMembers(String body) {
    StringBuilder members = new StringBuilder();
    int index = 0;
    while (index < body.length()) {
      if (body.charAt(index) == '\\') {
        members.append("\\x{")
            .append(Integer.toHexString(decode(body, index)))
            .append('}');
        index += 1 + OCTAL_DIGITS;
        continue;
      }
      members.append("\\x{")
          .append(Integer.toHexString(body.charAt(index)))
          .append('}');
      index++;
    }
    return members.toString();
  }

  private static char decode(String escaped, int index) {
    return (char) Integer.parseInt(escaped.substring(index + 1, index + 1 + OCTAL_DIGITS), OCTAL_RADIX);
  }
}
