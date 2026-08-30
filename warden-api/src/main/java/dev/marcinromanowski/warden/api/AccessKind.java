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
  EXTERNAL_DIRECTORY,
  /**
   * Permission to run the matched path as a program. Distinct from {@link #READ} on Linux, where a
   * readable-but-not-executable path fails {@code execve} with {@code EACCES} - a sandboxed process
   * cannot start a binary the embedder placed outside the standard system locations without it. The
   * child stays under the same confinement rather than transitioning to another profile or dropping
   * out of one.
   *
   * <p>On a {@link Decision#DENY} rule it means the opposite - the matched path may not be run even
   * where a broader grant would otherwise allow it - but it is <strong>Linux-only</strong>, and a
   * rule set containing one is refused when a macOS profile is generated from it. Seatbelt has no
   * per-path execute operation, so the only clause it could emit is a read deny, which was measured
   * to make the whole matched tree unreadable rather than merely unrunnable. Refusing is deliberate:
   * a rule that quietly means something much broader on one of the two platforms it is authored for
   * is worse than one that says it cannot be expressed there.
   *
   * <p>For a script, add {@link #READ} to the deny: the interpreter has to
   * read the file, so denying the read stops it running on both platforms. For a native binary
   * there is no macOS equivalent - denying its read does not stop it running, because the kernel's
   * own image load is not mediated as a file read - so such a rule belongs in the Linux rule set
   * only.
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
