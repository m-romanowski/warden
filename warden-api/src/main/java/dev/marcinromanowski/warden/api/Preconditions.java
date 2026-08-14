package dev.marcinromanowski.warden.api;

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

  static int validPort(int port, String field) {
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException(field + " must be between 1 and 65535");
    }
    return port;
  }
}
