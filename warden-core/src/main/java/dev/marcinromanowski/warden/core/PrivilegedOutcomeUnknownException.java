package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.SandboxEstablishmentException;

import java.io.Serial;

final class PrivilegedOutcomeUnknownException extends SandboxEstablishmentException {

  @Serial
  private static final long serialVersionUID = 1L;

  PrivilegedOutcomeUnknownException(String message) {
    super(message);
  }

  PrivilegedOutcomeUnknownException(String message, Throwable cause) {
    super(message, cause);
  }
}
