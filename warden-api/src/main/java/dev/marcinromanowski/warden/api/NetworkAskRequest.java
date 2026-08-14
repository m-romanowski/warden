package dev.marcinromanowski.warden.api;

/**
 * A single unmatched network-egress connection attempt, passed to a {@link NetworkAskHandler}
 * for a live decision.
 *
 * @param host the destination host
 * @param port the destination port
 * @param attributionHint opaque to warden itself - never parsed or interpreted, just threaded
 *     through to {@link NetworkAskHandler} for the caller's own routing
 */
public record NetworkAskRequest(
    String host,
    int port,
    String attributionHint
) {

  /** Validates the components above. */
  public NetworkAskRequest {
    host = Preconditions.nonBlank(host, "host");
    port = Preconditions.validPort(port, "port");
    attributionHint = Preconditions.nonNull(attributionHint, "attributionHint");
  }
}
