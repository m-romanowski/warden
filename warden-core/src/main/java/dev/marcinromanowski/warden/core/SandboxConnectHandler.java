package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.Decision;
import dev.marcinromanowski.warden.api.NetworkAskHandler;
import dev.marcinromanowski.warden.api.NetworkRule;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.handler.ConnectHandler;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.HostPort;

// Gates HTTP CONNECT tunnels (the path a sandboxed process's HTTPS calls take) against the
// resolved NetworkRule list. Jetty 12's ConnectHandler lives in jetty-server, not jetty-proxy -
// the CONNECT tunnel mechanism and forward-proxying of plain HTTP requests
// (SandboxForwardProxyHandler, the delegate handler passed to this class) are separate artifacts
// in this Jetty version.
//
// handleConnect (not handle) is the override point: ConnectHandler.handle already does the
// CONNECT-method/tunnelSupport dispatch checks before calling handleConnect, so overriding here
// reuses that logic for free. The decision itself (NetworkDecisions.resolve) is asynchronous - an
// unmatched host may become a live ask - so this class cannot simply override
// validateDestination(host, port), whose boolean return has no way to represent "pending". Once a
// decision is known, ALLOW re-invokes super.handleConnect(...) rather than hand-rolling
// connectToServer's success path: ConnectHandler's actual tunnel setup (SelectorManager wiring)
// lives behind a private field with no subclass accessor, so reusing Jetty's own handleConnect is
// the only way to reach it. validateDestination is primed via a thread-confined flag immediately
// before that re-entrant call (synchronous within the same call stack, cleared in a finally
// block) so Jetty's own internal validateDestination call sees the already-resolved answer.
//
// Authorization is gated in validateDestination(host, port), not handleAuthentication - the real
// connect target is computed once, via a single HostPort parse of serverAddress (default port
// 80), and that exact (host, port) pair is what must be used for the decision, avoiding a
// mismatch class of bug where
// a second, differently-defaulted port parse could authorize the wrong port. Denying with a clean
// 403 (Forbidden) rather than 407 (Proxy Authentication Required) is deliberate too - real HTTP
// clients interpret 407 as "retry with credentials" rather than "blocked by policy".
final class SandboxConnectHandler extends ConnectHandler {

  private final List<NetworkRule> networkRules;
  private final Optional<NetworkAskHandler> askHandler;
  private final String attributionHint;
  private final Consumer<String> diagnostics;
  private final ThreadLocal<Boolean> preResolvedDecision = new ThreadLocal<>();

  SandboxConnectHandler(
      Handler handler,
      List<NetworkRule> networkRules,
      Optional<NetworkAskHandler> askHandler,
      String attributionHint,
      Consumer<String> diagnostics
  ) {
    super(handler);
    this.networkRules = List.copyOf(Preconditions.nonNull(networkRules, "networkRules"));
    this.askHandler = Preconditions.nonNull(askHandler, "askHandler");
    this.attributionHint = Preconditions.nonNull(attributionHint, "attributionHint");
    this.diagnostics = Preconditions.nonNull(diagnostics, "diagnostics");
  }

  @Override
  protected void handleConnect(Request request, Response response, Callback callback, String serverAddress) {
    String host;
    int port;
    try {
      HostPort hostPort = new HostPort(serverAddress);
      host = hostPort.getHost();
      port = hostPort.getPort(80);
    } catch (IllegalArgumentException e) {
      onConnectFailure(request, response, callback, e);
      return;
    }
    String resolvedHost = host;
    int resolvedPort = port;
    CompletableFuture<Decision> pendingDecision =
        NetworkDecisions.resolve(networkRules, askHandler, attributionHint, resolvedHost, resolvedPort, getExecutor());
    pendingDecision.whenCompleteAsync(
        (decision, throwable) ->
        completeConnect(
            request, response, callback, serverAddress, resolvedHost, resolvedPort,
            throwable != null ? Decision.DENY : decision
        ),
        getExecutor()
    );
  }

  private void completeConnect(
      Request request,
      Response response,
      Callback callback,
      String serverAddress,
      String host,
      int port,
      Decision decision
  ) {
    diagnostics.accept("CONNECT " + host + ":" + port + " decision=" + decision);
    if (decision != Decision.ALLOW) {
      Response.writeError(
          request, response, callback, HttpStatus.FORBIDDEN_403,
          "host not allowed by sandbox network policy"
      );
      return;
    }
    preResolvedDecision.set(Boolean.TRUE);
    try {
      super.handleConnect(request, response, callback, serverAddress);
    } finally {
      preResolvedDecision.remove();
    }
  }

  @Override
  public boolean validateDestination(String host, int port) {
    Boolean preResolved = preResolvedDecision.get();
    if (preResolved != null) {
      return preResolved;
    }
    boolean allowed = NetworkRuleResolver.isAllowed(networkRules, host, port);
    diagnostics.accept("CONNECT " + host + ":" + port + " decision=" + (allowed ? "ALLOW" : "DENY"));
    return allowed;
  }

  @Override
  protected InetSocketAddress newConnectAddress(String host, int port) {
    InetAddress resolved = SandboxDnsResolution.resolveAndValidate(host);
    return new InetSocketAddress(resolved, port);
  }
}
