package dev.marcinromanowski.warden.api;

import java.util.concurrent.CompletableFuture;

/**
 * Resolves an unmatched network-egress request live, e.g. by asking an operator. Once-only: the
 * returned future answers exactly this one connection attempt. warden never caches a decision
 * across requests, a caller wanting that wraps this interface itself.
 */
@FunctionalInterface
public interface NetworkAskHandler {

  /** Asks for a decision on the given request. */
  CompletableFuture<Decision> ask(NetworkAskRequest request);

}
