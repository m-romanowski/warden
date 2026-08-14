package dev.marcinromanowski.warden.api;

import java.io.Serial;

/**
 * Thrown when warden cannot establish an OS-level sandbox for a requested launch - a missing
 * privileged install step, an unsupported platform, or a failure in the underlying sandboxing
 * mechanism itself. warden never falls back to running a process unsandboxed, this exception is
 * the fail-closed signal instead.
 */
public final class SandboxEstablishmentException extends RuntimeException {

  @Serial
  private static final long serialVersionUID = 1L;

  /** Creates the exception with the given message and no cause. */
  public SandboxEstablishmentException(String message) {
    super(message);
  }

  /** Creates the exception with the given message and cause. */
  public SandboxEstablishmentException(String message, Throwable cause) {
    super(message, cause);
  }

}
