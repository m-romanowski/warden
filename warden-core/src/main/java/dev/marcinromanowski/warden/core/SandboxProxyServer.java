package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.NetworkAskHandler;
import dev.marcinromanowski.warden.api.NetworkRule;
import dev.marcinromanowski.warden.api.SandboxEstablishmentException;
import java.net.InetAddress;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.unixdomain.server.UnixDomainServerConnector;

// Local, loopback-only forward proxy the sandboxed process's HTTP_PROXY/HTTPS_PROXY environment
// variables point at. Two Jetty handlers do the real work: SandboxConnectHandler authorizes and
// tunnels HTTP CONNECT (the path HTTPS calls take), delegating anything else to
// SandboxForwardProxyHandler for plain-HTTP forward proxying - both consult the exact same
// NetworkRule list, so there is one allow/deny decision per host, not two independently
// maintained ones.
final class SandboxProxyServer implements AutoCloseable {

  private static final int EPHEMERAL_PORT = 0;
  // Jetty's own default idle timeout (30s, both on the connector and inside ConnectHandler's
  // tunnel-side endpoint) is too short for this proxy's primary intended traffic - a non-streaming
  // LLM completion can easily sit quiet for longer than that between the request and the first
  // byte of response, which would otherwise tear down an in-flight tunnel mid-request.
  private static final long IDLE_TIMEOUT_MILLIS = 300_000L;

  private final Server server;
  private final int boundPort;
  private final Consumer<String> diagnostics;

  private SandboxProxyServer(Server server, int boundPort, Consumer<String> diagnostics) {
    this.server = server;
    this.boundPort = boundPort;
    this.diagnostics = diagnostics;
  }

  static SandboxProxyServer start(
      List<NetworkRule> networkRules,
      Optional<NetworkAskHandler> askHandler,
      String attributionHint,
      Consumer<String> diagnostics
  ) {
    return start(networkRules, askHandler, attributionHint, diagnostics, Optional.empty());
  }

  // unixDomainSocketPath is Linux-only, additive: when present, the SAME server (same
  // connectHandler, same enforcement decisions) also binds a UnixDomainServerConnector at that
  // path, reachable from inside a bwrap --unshare-net sandbox via a bind-mounted socket file,
  // since loopback TCP does not cross network-namespace boundaries.
  //
  // suppression-reason: both connectors are owned by server (added via server.addConnector()) and
  // are stopped as part of server.stop() in close() below - neither is an independently-managed
  // resource.
  @SuppressWarnings("PMD.CloseResource")
  static SandboxProxyServer start(
      List<NetworkRule> networkRules,
      Optional<NetworkAskHandler> askHandler,
      String attributionHint,
      Consumer<String> diagnostics,
      Optional<Path> unixDomainSocketPath
  ) {
    Server server = new Server();
    ServerConnector connector = new ServerConnector(server);
    connector.setHost(
        InetAddress.getLoopbackAddress()
            .getHostAddress()
    );
    connector.setPort(EPHEMERAL_PORT);
    connector.setIdleTimeout(IDLE_TIMEOUT_MILLIS);
    server.addConnector(connector);
    Optional<Path> requiredSocketPath = Preconditions.nonNull(unixDomainSocketPath, "unixDomainSocketPath");
    requiredSocketPath.ifPresent(socketPath -> addUnixDomainConnector(server, socketPath));
    List<NetworkRule> requiredRules = List.copyOf(Preconditions.nonNull(networkRules, "networkRules"));
    Optional<NetworkAskHandler> requiredAskHandler = Preconditions.nonNull(askHandler, "askHandler");
    String requiredAttributionHint = Preconditions.nonNull(attributionHint, "attributionHint");
    Consumer<String> requiredDiagnostics = Preconditions.nonNull(diagnostics, "diagnostics");
    SandboxForwardProxyHandler forwardHandler = new SandboxForwardProxyHandler(
        requiredRules, requiredAskHandler, requiredAttributionHint, server.getThreadPool(), requiredDiagnostics
    );
    SandboxConnectHandler connectHandler = new SandboxConnectHandler(
        forwardHandler, requiredRules, requiredAskHandler, requiredAttributionHint, requiredDiagnostics
    );
    connectHandler.setIdleTimeout(IDLE_TIMEOUT_MILLIS);
    server.setHandler(connectHandler);
    startServer(server);
    SandboxProxyServer proxyServer = new SandboxProxyServer(server, connector.getLocalPort(), requiredDiagnostics);
    requiredDiagnostics.accept(
        "proxy started port=" + proxyServer.port() + requiredSocketPath.map(path -> " unixDomainSocket=" + path)
            .orElse("")
    );
    return proxyServer;
  }

  private static void addUnixDomainConnector(Server server, Path socketPath) {
    UnixDomainServerConnector unixDomainConnector = new UnixDomainServerConnector(server, new HttpConnectionFactory());
    unixDomainConnector.setUnixDomainPath(socketPath);
    unixDomainConnector.setIdleTimeout(IDLE_TIMEOUT_MILLIS);
    server.addConnector(unixDomainConnector);
  }

  int port() {
    return boundPort;
  }

  @Override
  public void close() {
    stopServer(server);
    diagnostics.accept("proxy stopped port=" + boundPort);
  }

  // suppression-reason: Jetty's LifeCycle.start() declares "throws Exception" - there is no
  // narrower checked type to catch, and this must translate to warden's unchecked-failure
  // convention.
  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private static void startServer(Server server) {
    try {
      server.start();
    } catch (Exception e) {
      throw new SandboxEstablishmentException("Failed to start sandbox proxy server", e);
    }
  }

  // suppression-reason: Jetty's LifeCycle.stop() declares "throws Exception" - there is no
  // narrower checked type to catch, and this must translate to warden's unchecked-failure
  // convention.
  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private static void stopServer(Server server) {
    try {
      server.stop();
    } catch (Exception e) {
      throw new IllegalStateException("Failed to stop sandbox proxy server", e);
    }
  }
}
