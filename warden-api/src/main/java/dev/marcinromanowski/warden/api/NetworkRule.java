package dev.marcinromanowski.warden.api;

import java.util.Optional;

/**
 * An allow/deny rule for network egress, matched against a host pattern and an optional port.
 *
 * @param hostPattern a host pattern (e.g. an exact hostname or {@code "*"})
 * @param port the specific port this rule is scoped to, or empty for any port
 * @param decision whether a matching connection attempt is allowed or denied
 * @param reason a short, human-readable reason
 */
public record NetworkRule(
    String hostPattern,
    Optional<Integer> port,
    Decision decision,
    String reason
) {

  /** Validates the components above. */
  public NetworkRule {
    hostPattern = Preconditions.nonBlank(hostPattern, "hostPattern");
    port = Preconditions.nonNull(port, "port");
    port.ifPresent(value -> Preconditions.validPort(value, "port"));
    decision = Preconditions.nonNull(decision, "decision");
    reason = Preconditions.nonBlank(reason, "reason");
  }

  /** An {@code ALLOW} rule for the given host, any port. */
  public static NetworkRule allowHost(String hostPattern, String reason) {
    return new NetworkRule(hostPattern, Optional.empty(), Decision.ALLOW, reason);
  }

  /** An {@code ALLOW} rule for the given host and port. */
  public static NetworkRule allowHost(String hostPattern, int port, String reason) {
    return new NetworkRule(hostPattern, Optional.of(port), Decision.ALLOW, reason);
  }

  /** A {@code DENY} rule matching every host and port. */
  public static NetworkRule denyAll(String reason) {
    return new NetworkRule("*", Optional.empty(), Decision.DENY, reason);
  }
}
