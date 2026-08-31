package dev.marcinromanowski.warden.core;

sealed interface GlobToken {

  record Literal(int codePoint) implements GlobToken {
  }

  enum Wildcard implements GlobToken {
    // "**" - spans path separators.
    ANY_PATH,
    // "*" - spans one path segment.
    ANY_SEGMENT,
    // "?" - one character within a segment.
    SINGLE_CHARACTER
  }
}
