package dev.marcinromanowski.warden.api;

import java.net.URI;
import java.time.Duration;
import java.util.Optional;

/**
 * A launched, sandboxed process. Deliberately does not expose the raw {@code java.lang.Process}
 * it wraps - calling {@code Process.destroy()} directly would bypass the sandbox-specific
 * teardown {@link #close()} is responsible for.
 */
public interface SandboxedProcess extends AutoCloseable {

  /** Whether the process is still running. */
  boolean isAlive();

  /** The process's own operating-system process id. */
  long pid();

  /** The process's exit code, if it has already terminated. */
  Optional<Integer> exitCode();

  /** Requests termination, allowing the process (and any descendants) a chance to shut down cleanly. */
  void destroy();

  /** Forcibly terminates the process and any descendants. */
  void destroyForcibly();

  /** Blocks until the process terminates or the given timeout elapses, whichever comes first. */
  boolean waitFor(Duration timeout);

  /**
   * The URI a caller should use to reach this process's own control-plane endpoint, if the launch
   * request supplied a {@code controlPlaneHint}. May differ from that hint - see the launch
   * request builder for why.
   */
  Optional<URI> controlPlaneUri();

  /** Tears down the sandbox (proxy, generated profile, and any bridging processes) and the process itself. */
  @Override
  void close();

}
