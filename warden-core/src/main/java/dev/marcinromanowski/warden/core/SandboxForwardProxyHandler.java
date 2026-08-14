package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.Decision;
import dev.marcinromanowski.warden.api.NetworkAskHandler;
import dev.marcinromanowski.warden.api.NetworkRule;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.Consumer;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.http.HttpURI;
import org.eclipse.jetty.proxy.ProxyHandler;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.util.Callback;

// Gates plain (non-CONNECT) HTTP forward-proxy requests - the SandboxConnectHandler wrapping this
// class only authorizes CONNECT tunnels, so a plain "GET http://host/path HTTP/1.1" absolute-URI
// request reaching this delegate handler needs its own authorization check before
// ProxyHandler.Forward's superclass behavior dispatches it upstream. Unlike SandboxConnectHandler,
// no Jetty-internal tunnel machinery needs to be re-entered here - super.handle(...) is called
// directly once ALLOW is known.
final class SandboxForwardProxyHandler extends ProxyHandler.Forward {

  private static final String HTTPS_SCHEME = "https";
  private static final int HTTPS_DEFAULT_PORT = 443;
  private static final int HTTP_DEFAULT_PORT = 80;

  private final List<NetworkRule> networkRules;
  private final Optional<NetworkAskHandler> askHandler;
  private final String attributionHint;
  private final Executor executor;
  private final Consumer<String> diagnostics;

  SandboxForwardProxyHandler(
      List<NetworkRule> networkRules,
      Optional<NetworkAskHandler> askHandler,
      String attributionHint,
      Executor executor,
      Consumer<String> diagnostics
  ) {
    this.networkRules = List.copyOf(Preconditions.nonNull(networkRules, "networkRules"));
    this.askHandler = Preconditions.nonNull(askHandler, "askHandler");
    this.attributionHint = Preconditions.nonNull(attributionHint, "attributionHint");
    this.executor = Preconditions.nonNull(executor, "executor");
    this.diagnostics = Preconditions.nonNull(diagnostics, "diagnostics");
  }

  // configureHttpClient is where ProxyHandler.Forward's own outbound connections get resolved -
  // without overriding this, the forward path has no DNS-rebinding protection at all, unlike the
  // CONNECT-tunnel path's newConnectAddress override (SandboxConnectHandler).
  @Override
  protected void configureHttpClient(HttpClient httpClient) {
    super.configureHttpClient(httpClient);
    httpClient.setSocketAddressResolver(new SandboxSocketAddressResolver());
  }

  @Override
  public boolean handle(Request request, Response response, Callback callback) {
    HttpURI httpUri = request.getHttpURI();
    String host = httpUri.getHost();
    if (host == null) {
      diagnostics.accept("HTTP " + request.getMethod() + " " + requestTarget(httpUri) + " decision=DENY");
      Response.writeError(
          request, response, callback, HttpStatus.FORBIDDEN_403,
          "host not allowed by sandbox network policy"
      );
      return true;
    }
    CompletableFuture<Decision> pendingDecision =
        NetworkDecisions.resolve(networkRules, askHandler, attributionHint, host, resolvedPort(httpUri), executor);
    pendingDecision.whenCompleteAsync(
        (decision, throwable) ->
        completeForward(
            request, response, callback, httpUri,
            throwable != null ? Decision.DENY : decision
        ),
        executor
    );
    return true;
  }

  private void completeForward(Request request, Response response, Callback callback, HttpURI httpUri, Decision decision) {
    diagnostics.accept("HTTP " + request.getMethod() + " " + requestTarget(httpUri) + " decision=" + decision);
    if (decision != Decision.ALLOW) {
      Response.writeError(
          request, response, callback, HttpStatus.FORBIDDEN_403,
          "host not allowed by sandbox network policy"
      );
      return;
    }
    super.handle(request, response, callback);
  }

  private static int resolvedPort(HttpURI httpUri) {
    if (httpUri.getPort() > 0) {
      return httpUri.getPort();
    }
    return HTTPS_SCHEME.equalsIgnoreCase(httpUri.getScheme()) ? HTTPS_DEFAULT_PORT : HTTP_DEFAULT_PORT;
  }

  // Scheme + authority + path only, deliberately excluding the query string - some providers pass
  // API keys as query parameters, and a diagnostics log is exactly the wrong place for those to
  // land in a component whose whole purpose is credential/network containment.
  private static String requestTarget(HttpURI httpUri) {
    return httpUri.getScheme() + "://" + httpUri.getAuthority() + httpUri.getPath();
  }
}
