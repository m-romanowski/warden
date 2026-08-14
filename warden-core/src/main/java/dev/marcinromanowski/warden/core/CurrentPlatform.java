package dev.marcinromanowski.warden.core;

import java.util.Locale;

final class CurrentPlatform {

  private static final String ARM64_ARCHITECTURE = "arm64";
  private static final String X64_ARCHITECTURE = "x64";

  private CurrentPlatform() {
  }

  static String current() {
    String operatingSystem = normalizedSystemProperty("os.name");
    String architecture = normalizedSystemProperty("os.arch");
    if (operatingSystem.contains("mac")) {
      return "darwin-" + architecture;
    }
    if (operatingSystem.contains("linux")) {
      return "linux-" + architecture;
    }
    if (operatingSystem.contains("windows")) {
      return "windows-" + architecture;
    }
    return operatingSystem + "-" + architecture;
  }

  private static String normalizedSystemProperty(String key) {
    String value = Preconditions.nonBlank(System.getProperty(key), key)
        .trim();
    return switch (value.toLowerCase(Locale.ROOT)) {
      case "aarch64" -> ARM64_ARCHITECTURE;
      case "amd64", "x86_64" -> X64_ARCHITECTURE;
      default -> value.toLowerCase(Locale.ROOT);
    };
  }
}
