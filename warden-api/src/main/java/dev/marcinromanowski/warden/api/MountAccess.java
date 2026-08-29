package dev.marcinromanowski.warden.api;

/** How the sandboxed process may use a {@link PathMount} - the mount itself is always readable. */
public enum MountAccess {
  /** The mounted path cannot be written through the mount. */
  READ_ONLY,
  /** The mounted path can be written through the mount. */
  READ_WRITE
}
