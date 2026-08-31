package dev.marcinromanowski.warden.core;

import java.util.List;

final class AwkwardPathNames {

  static final List<String> ALL = List.of(
      "a b", "a,b", "a#b", "a{b}c", "a[b]c", "a!b", "a\tb", "a\nb", "a'b", "a\\b", "a:b", "a$b",
      "a`b", "a;b", "a&b", "a|b", "a<b", "a*b", "a?b", "praća", "日本", "a 0b"
  );

  private AwkwardPathNames() {
  }

  static String decoyOf(String name) {
    StringBuilder decoy = new StringBuilder(name.length());
    name.codePoints()
        .filter(codePoint -> codePoint < 128 && Character.isLetterOrDigit(codePoint))
        .forEach(decoy::appendCodePoint);
    return decoy.isEmpty() ? "decoy" : decoy.toString();
  }
}
