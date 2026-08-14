package dev.marcinromanowski.warden.api;

/** Launches a process inside an OS-level sandbox. See {@code OsSandboxedProcessLauncher} for the real implementation. */
@FunctionalInterface
public interface SandboxedProcessLauncher {

  /**
   * Launches the requested command inside a sandbox.
   *
   * @throws SandboxEstablishmentException if the sandbox cannot be established - never falls
   *     back to running the command unsandboxed
   */
  SandboxedProcess launch(SandboxLaunchRequest request) throws SandboxEstablishmentException;

}
