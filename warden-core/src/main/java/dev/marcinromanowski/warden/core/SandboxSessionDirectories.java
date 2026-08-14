package dev.marcinromanowski.warden.core;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;

final class SandboxSessionDirectories {

  private SandboxSessionDirectories() {
  }

  static void deleteQuietly(Path sessionDirectory) {
    if (!Files.exists(sessionDirectory)) {
      return;
    }
    try (var paths = Files.walk(sessionDirectory)) {
      paths.sorted(Comparator.reverseOrder())
          .forEach(SandboxSessionDirectories::deleteFileQuietly);
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to walk sandbox session directory " + sessionDirectory, e);
    }
  }

  private static void deleteFileQuietly(Path path) {
    try {
      Files.deleteIfExists(path);
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to delete sandbox session file " + path, e);
    }
  }
}
