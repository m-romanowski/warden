package dev.marcinromanowski.warden.core;

import java.time.Duration;
import java.util.Map;

/**
 * How long the sandbox proxy waits for a live ask decision on an unmatched network-egress
 * request before timing out and denying (see {@code NetworkDecisions}). A JVM system property
 * with an environment-variable fallback, no persisted file, no settings UI - a property of the
 * sandbox proxy mechanism itself.
 *
 * @param timeout how long to wait before timing out and denying, at least 1 second
 */
public record SandboxNetworkAskTimeoutConfiguration(Duration timeout) {

  /** The JVM system property this configuration reads first. */
  public static final String TIMEOUT_SECONDS_PROPERTY = "warden.sandbox.networkAskTimeoutSeconds";
  /** The environment variable fallback if {@link #TIMEOUT_SECONDS_PROPERTY} is unset. */
  public static final String TIMEOUT_SECONDS_ENVIRONMENT_VARIABLE = "WARDEN_SANDBOX_NETWORK_ASK_TIMEOUT_SECONDS";
  /** The timeout used when neither the property nor the environment variable is set. */
  public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(120L);

  private static final long MIN_TIMEOUT_SECONDS = 1L;

  /** Validates the timeout above. */
  public SandboxNetworkAskTimeoutConfiguration {
    if (timeout == null) {
      throw new IllegalArgumentException("timeout must not be null");
    }
    if (timeout.toSeconds() < MIN_TIMEOUT_SECONDS) {
      throw new IllegalArgumentException("network ask timeout must be at least 1 second");
    }
  }

  static SandboxNetworkAskTimeoutConfiguration load() {
    return load(System.getProperties(), System.getenv());
  }

  static SandboxNetworkAskTimeoutConfiguration load(Map<?, ?> properties, Map<String, String> environment) {
    String configuredValue = configuredValue(properties, environment);
    if (configuredValue == null) {
      return new SandboxNetworkAskTimeoutConfiguration(DEFAULT_TIMEOUT);
    }
    return new SandboxNetworkAskTimeoutConfiguration(Duration.ofSeconds(parseSeconds(configuredValue)));
  }

  private static String configuredValue(Map<?, ?> properties, Map<String, String> environment) {
    Object propertyValue = properties.get(TIMEOUT_SECONDS_PROPERTY);
    if (propertyValue instanceof String value && !value.isBlank()) {
      return value.trim();
    }
    String environmentValue = environment.get(TIMEOUT_SECONDS_ENVIRONMENT_VARIABLE);
    if (environmentValue == null || environmentValue.isBlank()) {
      return null;
    }
    return environmentValue.trim();
  }

  private static long parseSeconds(String value) {
    try {
      return Long.parseLong(value);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("network ask timeout must be a whole number of seconds", e);
    }
  }
}
