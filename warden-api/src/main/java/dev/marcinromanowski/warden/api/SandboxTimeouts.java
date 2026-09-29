package dev.marcinromanowski.warden.api;

import java.time.Duration;

/**
 * How long the sandbox waits at each point where it can wait forever. Defaults suit the
 * launches warden was measured against, and a caller whose payload or machine differs overrides
 * the one that does not fit rather than the whole set.
 *
 * @param privilegedCommand how long a root helper invocation may take before it is killed and the
 *     launch fails. Loading a policy is the slow one, and its cost is the deny pattern set against
 *     the allow tree rather than anything about the machine, so a large contributed rule set can
 *     need more than the default
 * @param privilegedOutputDrain how long to keep collecting a killed helper's output after it has
 *     exited, so a failure still carries what the helper said
 * @param gracefulShutdown how long a sandboxed process is given to exit on its own before it is
 *     killed
 * @param controlPlaneRelayDrain how long the control-plane relay waits for its other pump to
 *     finish once a response is complete
 */
public record SandboxTimeouts(
    Duration privilegedCommand,
    Duration privilegedOutputDrain,
    Duration gracefulShutdown,
    Duration controlPlaneRelayDrain
) {

  /**
   * The privileged-command timeout used unless overridden. Three minutes rather than something
   * tighter because the slow privileged call is an AppArmor policy load, and that is measured at
   * 44.5-46.2 s for warden's own 214-entry reference rule set on Ubuntu 26.04 aarch64. Its cost is
   * the deny pattern set against the allow tree, which no count predicts and which a contributed
   * rule set can multiply several times over, so the headroom is deliberate. A hang is unbounded
   * either way, so waiting longer to declare one costs far less than killing a launch that would
   * have succeeded.
   */
  public static final Duration DEFAULT_PRIVILEGED_COMMAND = Duration.ofMinutes(3);
  /** The privileged-output drain timeout used unless overridden. */
  public static final Duration DEFAULT_PRIVILEGED_OUTPUT_DRAIN = Duration.ofSeconds(5);
  /** The graceful-shutdown timeout used unless overridden. */
  public static final Duration DEFAULT_GRACEFUL_SHUTDOWN = Duration.ofSeconds(5);
  /** The control-plane relay drain timeout used unless overridden. */
  public static final Duration DEFAULT_CONTROL_PLANE_RELAY_DRAIN = Duration.ofSeconds(5);

  /** Validates that every timeout is present and positive. */
  public SandboxTimeouts {
    privilegedCommand = positive(privilegedCommand, "privilegedCommand");
    privilegedOutputDrain = positive(privilegedOutputDrain, "privilegedOutputDrain");
    gracefulShutdown = positive(gracefulShutdown, "gracefulShutdown");
    controlPlaneRelayDrain = positive(controlPlaneRelayDrain, "controlPlaneRelayDrain");
  }

  /** The defaults every launch uses unless the caller overrides them. */
  public static SandboxTimeouts defaults() {
    return new SandboxTimeouts(
        DEFAULT_PRIVILEGED_COMMAND,
        DEFAULT_PRIVILEGED_OUTPUT_DRAIN,
        DEFAULT_GRACEFUL_SHUTDOWN,
        DEFAULT_CONTROL_PLANE_RELAY_DRAIN
    );
  }

  /** Returns a copy with the privileged-command timeout replaced. */
  public SandboxTimeouts withPrivilegedCommand(Duration timeout) {
    return new SandboxTimeouts(timeout, privilegedOutputDrain, gracefulShutdown, controlPlaneRelayDrain);
  }

  /** Returns a copy with the privileged-output drain timeout replaced. */
  public SandboxTimeouts withPrivilegedOutputDrain(Duration timeout) {
    return new SandboxTimeouts(privilegedCommand, timeout, gracefulShutdown, controlPlaneRelayDrain);
  }

  /** Returns a copy with the graceful-shutdown timeout replaced. */
  public SandboxTimeouts withGracefulShutdown(Duration timeout) {
    return new SandboxTimeouts(privilegedCommand, privilegedOutputDrain, timeout, controlPlaneRelayDrain);
  }

  /** Returns a copy with the control-plane relay drain timeout replaced. */
  public SandboxTimeouts withControlPlaneRelayDrain(Duration timeout) {
    return new SandboxTimeouts(privilegedCommand, privilegedOutputDrain, gracefulShutdown, timeout);
  }

  private static Duration positive(Duration timeout, String name) {
    Duration required = Preconditions.nonNull(timeout, name);
    if (required.isZero() || required.isNegative()) {
      throw new IllegalArgumentException(name + " must be positive");
    }
    return required;
  }
}
