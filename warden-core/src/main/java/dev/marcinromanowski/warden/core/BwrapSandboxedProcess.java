package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.SandboxedProcess;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

// Linux counterpart to OsSandboxedProcess: wraps the bwrap-launched Process plus every resource a
// Linux launch establishes alongside it - the AppArmor policy, SandboxProxyServer (bound over a
// Unix domain socket here, not loopback TCP, since loopback does not cross network-namespace
// boundaries), the optional ControlPlaneRelay, and the per-session directories. close() tears all
// of these down together, in the reverse order they were established.
//
// Process-tree-aware teardown, same reasoning as OsSandboxedProcess documents for its own close().
// The tree is deeper here than on macOS: bwrap runs the payload as pid 2 of a fresh pid namespace,
// beside an init of bwrap's own at pid 1, so the process this class holds is never the payload.
final class BwrapSandboxedProcess implements SandboxedProcess {

  private static final Duration GRACEFUL_SHUTDOWN_TIMEOUT = Duration.ofSeconds(5);

  private final Process process;
  private final SandboxProxyServer proxy;
  private final Optional<ControlPlaneRelay> controlPlaneRelay;
  private final BwrapSession session;
  private final Optional<URI> resolvedControlPlaneUri;

  BwrapSandboxedProcess(
      Process process,
      SandboxProxyServer proxy,
      Optional<ControlPlaneRelay> controlPlaneRelay,
      BwrapSession session,
      Optional<URI> resolvedControlPlaneUri
  ) {
    this.process = process;
    this.proxy = proxy;
    this.controlPlaneRelay = controlPlaneRelay;
    this.session = session;
    this.resolvedControlPlaneUri = resolvedControlPlaneUri;
  }

  @Override
  public boolean isAlive() {
    return process.isAlive();
  }

  @Override
  public long pid() {
    return process.pid();
  }

  @Override
  public Optional<Integer> exitCode() {
    if (process.isAlive()) {
      return Optional.empty();
    }
    try {
      return Optional.of(process.exitValue());
    } catch (IllegalThreadStateException _) {
      return Optional.empty();
    }
  }

  // Deliberately does not signal the process warden holds. That one is bwrap, which installs no
  // SIGTERM handler, and --die-with-parent takes the pid namespace's init down with it - the kernel
  // then kills the payload where it stands, mid-handler. Everything that has to receive the request
  // is inside the namespace already, and bwrap exits on its own once the payload has.
  @Override
  public void destroy() {
    descendants()
        .forEach(ProcessHandle::destroy);
  }

  @Override
  public void destroyForcibly() {
    descendants()
        .forEach(ProcessHandle::destroyForcibly);
    process.destroyForcibly();
  }

  @Override
  public boolean waitFor(Duration timeout) {
    try {
      return process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
    } catch (InterruptedException _) {
      Thread.currentThread()
          .interrupt();
      return false;
    }
  }

  @Override
  public Optional<URI> controlPlaneUri() {
    return resolvedControlPlaneUri;
  }

  @Override
  public void close() {
    stopProcessIfAlive();
    controlPlaneRelay.ifPresent(ControlPlaneRelay::close);
    proxy.close();
    session.close();
  }

  private void stopProcessIfAlive() {
    if (!process.isAlive()) {
      return;
    }
    destroy();
    if (waitFor(GRACEFUL_SHUTDOWN_TIMEOUT)) {
      return;
    }
    destroyForcibly();
  }

  private List<ProcessHandle> descendants() {
    return process.toHandle()
        .descendants()
        .toList();
  }
}
