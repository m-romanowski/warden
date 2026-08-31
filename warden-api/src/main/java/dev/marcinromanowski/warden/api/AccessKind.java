package dev.marcinromanowski.warden.api;

/** The kinds of filesystem access a {@link FilesystemRule} allows or denies. */
public enum AccessKind {
  /** Read access to file content. */
  READ,
  /** Write access to file content. */
  WRITE,
  /**
   * Permission to resolve through a directory outside the sandbox root and to stat what it holds,
   * without permission to list its own entries. Grant it for the directories a confined process has
   * to walk on the way to somewhere it is allowed, and {@link #READ} for the ones whose contents it
   * is meant to enumerate - a rule naming both grants the listing.
   */
  EXTERNAL_DIRECTORY,
  /**
   * Permission to run the matched path as a program. Distinct from {@link #READ}: a
   * readable-but-not-executable path fails to start on both platforms, and a native binary runs
   * from a path with no read grant at all on both, since neither kernel mediates its own image load
   * as a file read. A script needs {@link #READ} as well, because its interpreter has to open it.
   *
   * <p>On a {@link Decision#DENY} rule it means the opposite - the matched path may not be run even
   * where a broader grant would otherwise allow it - and it refuses the execution alone, leaving
   * whatever read access the rule set grants untouched.
   *
   * <p>The child stays under the same confinement rather than transitioning to another profile or
   * dropping out of one.
   */
  EXECUTE,
  /**
   * Permission to take a file lock ({@code flock}, POSIX record locks) on the matched path.
   * Distinct from {@link #WRITE} on Linux: a writable-but-not-lockable path fails locking with
   * {@code EPERM}, which SQLite and other embedded stores surface as a corrupt-or-busy database
   * rather than as a permission problem. Grant it for the trees a confined process keeps its own
   * lock-taking state in, not for every writable tree - holding a lock on a file an unconfined
   * process also opens is a capability of its own.
   */
  LOCK
}
