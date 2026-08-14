package dev.marcinromanowski.warden.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;
import java.time.Duration;
import java.util.function.Consumer;

// Bridges a normal loopback TCP port (what a caller's own control-plane HTTP client already
// expects to connect to) to a bind-mounted Unix domain socket exposing a sandboxed process's real
// control-plane port from inside a bwrap --unshare-net namespace - the mirror image of
// SandboxProxyServer's own UDS connector (that one bridges egress FROM the sandbox OUT, this one
// bridges control-plane traffic FROM the host IN).
//
// Deliberately does not track or force-close individual in-flight relayed connections on its own
// close() - this relay's connections are short-lived HTTP request/response cycles from the
// caller's own HTTP client. Closing the listening socket (refusing new connections) combined with
// the sandboxed process's own teardown (which breaks the UDS side of any in-flight relay,
// terminating its pump threads via IOException on their own read/write) is sufficient.
final class ControlPlaneRelay implements AutoCloseable {

  private static final int EPHEMERAL_PORT = 0;
  private static final int ACCEPT_BACKLOG = 50;

  private final ServerSocket serverSocket;
  private final Path unixDomainSocketPath;
  private final Consumer<String> diagnostics;
  private final Thread acceptThread;
  private volatile boolean closing;

  private ControlPlaneRelay(ServerSocket serverSocket, Path unixDomainSocketPath, Consumer<String> diagnostics) {
    this.serverSocket = serverSocket;
    this.unixDomainSocketPath = unixDomainSocketPath;
    this.diagnostics = diagnostics;
    this.acceptThread = SandboxThreads.namedDaemonThread("warden-sandbox-control-plane-relay-accept", this::acceptLoop);
  }

  // suppression-reason: ownership of the returned ServerSocket transfers to the ControlPlaneRelay
  // instance constructed from it just below, which closes it in close() - not an unmanaged
  // resource, PMD just cannot see the transfer-of-ownership pattern here.
  @SuppressWarnings("PMD.CloseResource")
  static ControlPlaneRelay start(Path unixDomainSocketPath, Consumer<String> diagnostics) {
    Path requiredSocketPath = Preconditions.nonNull(unixDomainSocketPath, "unixDomainSocketPath");
    Consumer<String> requiredDiagnostics = Preconditions.nonNull(diagnostics, "diagnostics");
    ServerSocket serverSocket = bind();
    ControlPlaneRelay relay = new ControlPlaneRelay(serverSocket, requiredSocketPath, requiredDiagnostics);
    relay.acceptThread.start();
    requiredDiagnostics.accept(
        "control-plane relay started port=" + relay.port() + " unixDomainSocket=" + requiredSocketPath
    );
    return relay;
  }

  int port() {
    return serverSocket.getLocalPort();
  }

  @Override
  public void close() {
    closing = true;
    try {
      serverSocket.close();
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to close control-plane relay listener", e);
    }
    diagnostics.accept("control-plane relay stopped port=" + port());
  }

  private static ServerSocket bind() {
    try {
      return new ServerSocket(EPHEMERAL_PORT, ACCEPT_BACKLOG, InetAddress.getLoopbackAddress());
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to bind control-plane relay listener", e);
    }
  }

  // suppression-reason: ownership of tcpConnection transfers to the spawned relay thread, which
  // closes it via relay()'s own try-with-resources - not an unmanaged resource, PMD just cannot
  // see the transfer across the thread boundary.
  @SuppressWarnings("PMD.CloseResource")
  private void acceptLoop() {
    while (!closing) {
      Socket tcpConnection;
      try {
        tcpConnection = serverSocket.accept();
      } catch (SocketException _) {
        // Expected on close(): closing the listening socket unblocks accept() with exactly this
        // exception - not a real failure once closing is already true.
        return;
      } catch (IOException e) {
        if (!closing) {
          diagnostics.accept("control-plane relay accept failed: " + e);
        }
        continue;
      }
      SandboxThreads.namedDaemonThread("warden-sandbox-control-plane-relay-connection", () -> relay(tcpConnection))
          .start();
    }
  }

  // suppression-reason: tcpIn/tcpOut/udsIn/udsOut are lightweight views over
  // closableTcpConnection/udsChannel, both already covered by this method's own
  // try-with-resources - closing the underlying Socket/SocketChannel is sufficient.
  @SuppressWarnings("PMD.CloseResource")
  private void relay(Socket tcpConnection) {
    try (
        Socket closableTcpConnection = tcpConnection;
        SocketChannel udsChannel = SocketChannel.open(UnixDomainSocketAddress.of(unixDomainSocketPath))
    ) {
      InputStream tcpIn = closableTcpConnection.getInputStream();
      OutputStream tcpOut = closableTcpConnection.getOutputStream();
      InputStream udsIn = Channels.newInputStream(udsChannel);
      OutputStream udsOut = Channels.newOutputStream(udsChannel);

      Thread toSandbox = SandboxThreads.namedDaemonThread(
          "warden-sandbox-control-plane-relay-pump-out", () -> pump(tcpIn, udsOut)
      );
      toSandbox.start();
      // The reverse direction runs on this same thread rather than a third one - once it returns
      // (the sandboxed process's own response is complete and its side of the connection closed),
      // this method's try-with-resources closes both ends, which unblocks the other pump thread's
      // own blocked read via IOException.
      pump(udsIn, tcpOut);
      toSandbox.join(
          Duration.ofSeconds(5)
              .toMillis()
      );
    } catch (IOException e) {
      diagnostics.accept("control-plane relay connection failed: " + e);
    } catch (InterruptedException _) {
      Thread.currentThread()
          .interrupt();
    }
  }

  private static void pump(InputStream source, OutputStream destination) {
    try {
      source.transferTo(destination);
    } catch (IOException _) {
      // Expected once the other side of either connection closes mid-relay - not logged as a
      // failure, that is the normal way a request/response cycle over this bridge ends.
    }
  }
}
