package dev.marcinromanowski.warden.api;

/** The kinds of filesystem access a {@link FilesystemRule} allows or denies. */
public enum AccessKind {
  /** Read access to file content. */
  READ,
  /** Write access to file content. */
  WRITE,
  /**
   * Whether a directory outside the sandbox root is addressable at all - a coarser concept than
   * {@link #READ}/{@link #WRITE}, with no distinct equivalent on every platform.
   */
  EXTERNAL_DIRECTORY
}
