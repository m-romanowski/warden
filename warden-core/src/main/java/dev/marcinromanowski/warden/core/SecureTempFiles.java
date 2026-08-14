package dev.marcinromanowski.warden.core;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;

final class SecureTempFiles {

  private SecureTempFiles() {
  }

  static Path createOwnerOnlyTempFile(String prefix, String suffix) throws IOException {
    return Files.createTempFile(
        Preconditions.nonBlank(prefix, "prefix"),
        Preconditions.nonBlank(suffix, "suffix"),
        ownerOnlyFileAttributes()
    );
  }

  static Path createOwnerOnlyTempDirectory(String prefix) throws IOException {
    return Files.createTempDirectory(Preconditions.nonBlank(prefix, "prefix"), ownerOnlyDirectoryAttributes());
  }

  private static FileAttribute<?>[] ownerOnlyFileAttributes() {
    if (doesNotSupportPosixPermissions()) {
      return new FileAttribute<?>[0];
    }
    return new FileAttribute<?>[] {
        PosixFilePermissions.asFileAttribute(
            EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
        )
    };
  }

  private static FileAttribute<?>[] ownerOnlyDirectoryAttributes() {
    if (doesNotSupportPosixPermissions()) {
      return new FileAttribute<?>[0];
    }
    return new FileAttribute<?>[] {
        PosixFilePermissions.asFileAttribute(
            EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)
        )
    };
  }

  private static boolean doesNotSupportPosixPermissions() {
    return !FileSystems.getDefault()
        .supportedFileAttributeViews()
        .contains("posix");
  }
}
