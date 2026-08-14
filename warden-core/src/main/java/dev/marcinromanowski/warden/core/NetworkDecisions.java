package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.Decision;
import dev.marcinromanowski.warden.api.NetworkAskHandler;
import dev.marcinromanowski.warden.api.NetworkAskRequest;
import dev.marcinromanowski.warden.api.NetworkRule;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

// Shared by SandboxConnectHandler and SandboxForwardProxyHandler so there is one CONNECT/plain-HTTP
// decision path, not two independently-maintained ones. A rule match (ALLOW/DENY) resolves
// immediately. An unmatched host, or an explicit ASK-decision rule match, becomes a live ask when
// a handler is wired - always folding to DENY on timeout, handler failure, or when no handler is
// wired at all. This is the last layer. Timeout never falls back to ALLOW.
final class NetworkDecisions {

  private NetworkDecisions() {
  }

  static CompletableFuture<Decision> resolve(
      List<NetworkRule> rules,
      Optional<NetworkAskHandler> askHandler,
      String attributionHint,
      String host,
      int port,
      Executor executor
  ) {
    Decision ruleDecision = NetworkRuleResolver.resolve(rules, host, port);
    if (ruleDecision == Decision.ALLOW) {
      return CompletableFuture.completedFuture(Decision.ALLOW);
    }
    if (ruleDecision == Decision.DENY || askHandler.isEmpty()) {
      return CompletableFuture.completedFuture(Decision.DENY);
    }
    NetworkAskRequest request = new NetworkAskRequest(host, port, attributionHint);
    NetworkAskHandler requiredHandler = askHandler.get();
    Duration timeout = SandboxNetworkAskTimeoutConfiguration.load()
        .timeout();
    return CompletableFuture.supplyAsync(() -> requiredHandler.ask(request), executor)
        .thenCompose(Function.identity())
        .orTimeout(timeout.toSeconds(), TimeUnit.SECONDS)
        .exceptionally(throwable -> Decision.DENY);
  }
}
