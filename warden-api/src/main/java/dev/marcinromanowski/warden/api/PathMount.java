package dev.marcinromanowski.warden.api;

import java.nio.file.Path;

/**
 * A host path declared reachable inside the sandbox, alongside the sandbox root. A persistent
 * profile, cache or state directory living outside the sandbox root needs one of these - on Linux
 * the sandbox starts from an empty filesystem, so a path that was never mounted does not exist
 * inside it and a {@link FilesystemRule} covering it has nothing to govern.
 *
 * <p>Reachability is not access. A mount only makes the path addressable, what may then be read
 * or written under it stays entirely a matter of the {@link FilesystemRule} list, enforced by the
 * generated platform profile.
 *
 * <p>The path is mounted at the same absolute path inside the sandbox, which is why there is a
 * single path component rather than a host path and an in-sandbox path. Filesystem rules are
 * written as host paths and the enforcement profile is generated from them, so a mount remapped
 * to a different in-sandbox path would leave the mount plan and the profile governing it
 * describing different paths.
 *
 * <p>Only Linux has a mount namespace to populate. On macOS every host path is already reachable
 * and the generated Seatbelt profile alone decides access, so a mount is a no-op there.
 *
 * @param path the host path to make reachable, made absolute and normalized
 * @param access whether the sandboxed process may write through the mount
 */
public record PathMount(Path path, MountAccess access) {

  /** Validates and normalizes the components above. */
  public PathMount {
    path = Preconditions.nonNull(path, "path")
        .toAbsolutePath()
        .normalize();
    access = Preconditions.nonNull(access, "access");
  }

  /** A mount the sandboxed process cannot write through. */
  public static PathMount readOnly(Path path) {
    return new PathMount(path, MountAccess.READ_ONLY);
  }

  /** A mount the sandboxed process can write through. */
  public static PathMount readWrite(Path path) {
    return new PathMount(path, MountAccess.READ_WRITE);
  }
}
