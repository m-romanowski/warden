package dev.marcinromanowski.warden.core;

final class Preconditions {

  private Preconditions() {
  }

  static <T> T nonNull(T value, String field) {
    if (value == null) {
      throw new NullPointerException(field + " must not be null");
    }
    return value;
  }

  static String nonBlank(String value, String field) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(field + " must not be blank");
    }
    return value;
  }

  static int positiveOrZero(int value, String field) {
    if (value < 0) {
      throw new IllegalArgumentException(field + " must not be negative");
    }
    return value;
  }
}
