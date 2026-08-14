package dev.marcinromanowski.warden.core;

import java.util.Locale;

// Host-pattern grammar: an exact hostname, or a "*.example.com" leading-wildcard subdomain
// pattern. Deliberately not a full glob engine like SeatbeltGlobTranslator - hostnames have no
// directory-boundary concept and a leading-wildcard suffix match is the only pattern shape any
// real allowlist entry needs.
final class NetworkHostMatcher {

  private static final String WILDCARD_PREFIX = "*.";

  private NetworkHostMatcher() {
  }

  static boolean matches(String hostPattern, String candidateHost) {
    String normalizedPattern = Preconditions.nonBlank(hostPattern, "hostPattern")
        .toLowerCase(Locale.ROOT);
    String normalizedCandidate = Preconditions.nonBlank(candidateHost, "candidateHost")
        .toLowerCase(Locale.ROOT);
    if (normalizedPattern.startsWith(WILDCARD_PREFIX)) {
      String suffix = normalizedPattern.substring(1);
      return normalizedCandidate.length() > suffix.length() && normalizedCandidate.endsWith(suffix);
    }
    return normalizedCandidate.equals(normalizedPattern);
  }
}
