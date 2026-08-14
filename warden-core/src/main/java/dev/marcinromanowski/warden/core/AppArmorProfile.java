package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.FilesystemRule;
import dev.marcinromanowski.warden.api.SandboxEstablishmentException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

// A loaded, per-session AppArmor filesystem profile. Ties the kernel-visible profile name to the
// exact file apparmor_parser needs to unload it again - both -r (load) and -R (remove) take the
// same file-path argument, not the profile's own declared name (empirically confirmed - passing
// the bare name to -R fails silently rather than removing anything).
final class AppArmorProfile implements AutoCloseable {

  private static final String PROFILE_NAME_PREFIX = "warden-sandbox-";
  private static final String PROFILE_FILE_SUFFIX = ".profile";

  private final String name;
  private final Path profilePath;
  private boolean closed;

  private AppArmorProfile(String name, Path profilePath) {
    this.name = name;
    this.profilePath = profilePath;
  }

  static AppArmorProfile load(List<FilesystemRule> filesystemRules, Path bwrapSessionDirectory) {
    String name = PROFILE_NAME_PREFIX + UUID.randomUUID()
        .toString()
        .replace("-", "");
    String profileText = AppArmorProfileGenerator.generate(name, filesystemRules, Optional.of(bwrapSessionDirectory));
    Path profilePath = writeProfileFile(name, profileText);
    PrivilegedProcesses.run(List.of("apparmor_parser", "-r", profilePath.toString()));
    return new AppArmorProfile(name, profilePath);
  }

  String name() {
    return name;
  }

  @Override
  public void close() {
    if (closed) {
      return;
    }
    closed = true;
    try {
      PrivilegedProcesses.run(List.of("apparmor_parser", "-R", profilePath.toString()));
    } finally {
      deleteQuietly();
    }
  }

  private static Path writeProfileFile(String name, String profileText) {
    try {
      Path profilePath = SecureTempFiles.createOwnerOnlyTempFile(name, PROFILE_FILE_SUFFIX);
      Files.writeString(profilePath, profileText);
      return profilePath;
    } catch (IOException e) {
      throw new SandboxEstablishmentException("Failed to write AppArmor profile file", e);
    }
  }

  private void deleteQuietly() {
    try {
      Files.deleteIfExists(profilePath);
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to delete AppArmor profile file " + profilePath, e);
    }
  }
}
