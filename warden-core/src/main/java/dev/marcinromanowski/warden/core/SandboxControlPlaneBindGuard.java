package dev.marcinromanowski.warden.core;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

// SBPL's own network-bind/network-inbound "(local tcp 'localhost:<port>')" filter cannot express
// "loopback interface only" - confirmed empirically against a real sandbox-exec: the grammar
// accepts only the symbolic tokens "localhost" or "*" (a literal IP address is rejected outright
// as invalid syntax), and a process under a profile using the "localhost" token can still
// successfully bind 0.0.0.0 and accept a real inbound TCP connection from a LAN-routable address
// on the same machine.
//
// This guard closes the gap independently of SBPL: it polls the real bound socket address for the
// control-plane port via lsof (there is no portable JDK API to inspect another process's own
// sockets) and destroys the process immediately, unconditionally, the moment it is ever found
// bound to anything other than loopback - fail-closed, no grace period, no retry, no way for the
// sandboxed process itself to influence or evade this check.
final class SandboxControlPlaneBindGuard implements AutoCloseable {

  private static final long POLL_INTERVAL_MILLIS = 500L;
  private static final String LSOF_PATH = "/usr/sbin/lsof";
  private static final String NAME_FIELD_PREFIX = "n";
  private static final String WILDCARD_ADDRESS = "*";

  private final ScheduledExecutorService executor;

  private SandboxControlPlaneBindGuard(ScheduledExecutorService executor) {
    this.executor = executor;
  }

  // suppression-reason: executor ownership is transferred to the returned
  // SandboxControlPlaneBindGuard, which is closed by OsSandboxedProcess.close() - it is not an
  // unmanaged resource, PMD just cannot see the transfer-of-ownership pattern here.
  @SuppressWarnings("PMD.CloseResource")
  static SandboxControlPlaneBindGuard start(
      Process process,
      int expectedPort,
      Runnable onViolation,
      Consumer<String> diagnostics
  ) {
    Preconditions.nonNull(process, "process");
    Preconditions.nonNull(onViolation, "onViolation");
    Preconditions.nonNull(diagnostics, "diagnostics");
    ScheduledExecutorService executor = SandboxThreads.singleScheduledExecutor(
        "warden-sandbox-control-plane-bind-guard"
    );
    SandboxControlPlaneBindGuard guard = new SandboxControlPlaneBindGuard(executor);
    executor.scheduleWithFixedDelay(
        () -> guard.poll(process, expectedPort, onViolation, diagnostics),
        POLL_INTERVAL_MILLIS,
        POLL_INTERVAL_MILLIS,
        TimeUnit.MILLISECONDS
    );
    return guard;
  }

  @Override
  public void close() {
    executor.shutdownNow();
  }

  private void poll(Process process, int expectedPort, Runnable onViolation, Consumer<String> diagnostics) {
    if (!process.isAlive()) {
      close();
      return;
    }
    Optional<BoundAddressCheck> check = queryBoundAddress(process.pid(), expectedPort);
    if (check.isEmpty()) {
      return;
    }
    if (check.get()
        .safe()) {
      return;
    }
    diagnostics.accept(
        "control-plane port " + expectedPort + " for pid=" + process.pid()
            + " is bound to a non-loopback address (" + check.get()
                .description()
            + ") - destroying the process. SBPL cannot restrict a bind/inbound grant to the"
            + " loopback interface by itself, so this is enforced independently."
    );
    onViolation.run();
    close();
  }

  // Empty means "not currently bound at this port" (process hasn't started listening yet, or has
  // already stopped) - not a violation, just keep polling.
  private static Optional<BoundAddressCheck> queryBoundAddress(long pid, int port) {
    List<String> command = List.of(
        LSOF_PATH, "-a", "-p", Long.toString(pid), "-iTCP:" + port, "-sTCP:LISTEN", "-n", "-P", "-Fn"
    );
    try {
      Process lsof = new ProcessBuilder(command)
          .start();
      boolean finished = lsof.waitFor(POLL_INTERVAL_MILLIS, TimeUnit.MILLISECONDS);
      if (!finished) {
        lsof.destroyForcibly();
        return Optional.empty();
      }
      String output = new String(
          lsof.getInputStream()
              .readAllBytes(), StandardCharsets.UTF_8
      );
      return parseBoundAddressCheck(output);
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to query control-plane bind address via lsof", e);
    } catch (InterruptedException _) {
      Thread.currentThread()
          .interrupt();
      return Optional.empty();
    }
  }

  private static Optional<BoundAddressCheck> parseBoundAddressCheck(String lsofOutput) {
    return lsofOutput.lines()
        .filter(line -> line.startsWith(NAME_FIELD_PREFIX))
        .findFirst()
        .map(line -> line.substring(NAME_FIELD_PREFIX.length())
            .trim()
        )
        .map(SandboxControlPlaneBindGuard::addressWithoutPort)
        .map(SandboxControlPlaneBindGuard::evaluate);
  }

  private static String addressWithoutPort(String addressAndPort) {
    int lastColon = addressAndPort.lastIndexOf(':');
    String address = lastColon < 0 ? addressAndPort : addressAndPort.substring(0, lastColon);
    if (address.startsWith("[") && address.endsWith("]")) {
      return address.substring(1, address.length() - 1);
    }
    return address;
  }

  // Parse failure or the explicit wildcard token are both treated as a violation, not silently
  // skipped: this check exists specifically because the process is not trusted, so an address this
  // guard cannot positively confirm as loopback must fail closed, not fail open.
  private static BoundAddressCheck evaluate(String address) {
    if (WILDCARD_ADDRESS.equals(address.trim())) {
      return new BoundAddressCheck(false, "wildcard address \"*\"");
    }
    try {
      InetAddress resolved = InetAddress.getByName(address);
      return new BoundAddressCheck(resolved.isLoopbackAddress(), resolved.getHostAddress());
    } catch (UnknownHostException _) {
      return new BoundAddressCheck(false, "unparseable address \"" + address + "\"");
    }
  }

}
