package dev.marcinromanowski.warden.core;

enum GlobWildcard implements GlobToken {
  // "**" - spans path separators.
  ANY_PATH,
  // "*" - spans one path segment.
  ANY_SEGMENT,
  // "?" - one character within a segment.
  SINGLE_CHARACTER
}
