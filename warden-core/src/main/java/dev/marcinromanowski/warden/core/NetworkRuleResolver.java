package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.Decision;
import dev.marcinromanowski.warden.api.NetworkRule;
import java.util.List;

// First-match-wins resolution over an already priority-ordered rule list. An unmatched host
// resolves to ASK, not DENY - a genuinely synchronous ask channel exists at the proxy boundary
// (unlike SeatbeltProfileGenerator's filesystem case), so this resolver only classifies. The
// fail-closed fallback (no ask handler wired, ask timeout) is decided by NetworkDecisions.
final class NetworkRuleResolver {

  private NetworkRuleResolver() {
  }

  static Decision resolve(List<NetworkRule> rules, String host, int port) {
    Preconditions.nonBlank(host, "host");
    for (NetworkRule rule : Preconditions.nonNull(rules, "rules")) {
      if (matches(rule, host, port)) {
        return rule.decision();
      }
    }
    return Decision.ASK;
  }

  static boolean isAllowed(List<NetworkRule> rules, String host, int port) {
    return resolve(rules, host, port) == Decision.ALLOW;
  }

  private static boolean matches(NetworkRule rule, String host, int port) {
    if (!NetworkHostMatcher.matches(rule.hostPattern(), host)) {
      return false;
    }
    return rule.port()
        .map(rulePort -> rulePort == port)
        .orElse(true);
  }
}
