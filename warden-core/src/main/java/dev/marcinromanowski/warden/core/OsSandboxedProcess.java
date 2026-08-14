package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.SandboxedProcess;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

// Wraps the raw sandbox-exec-launched Process plus the two other resources a launch() call
// establishes alongside it: the SandboxProxyServer (network-egress enforcement) and the temporary
// SBPL profile file. close() tears all three down together - a caller reaching past this
// interface to destroy the underlying Process directly (which is exactly why SandboxedProcess
// doesn't expose it) would leak the proxy and the profile file.
//
// Process-tree-aware, not just single-PID: sandbox-exec itself execve()s into the target (same
// PID, no extra process layer), but the sandboxed process itself can spawn descendants that a
// plain Process.destroy() would not reach. Descendants are re-queried fresh on every
// destroy()/destroyForcibly() call, deliberately not cached: a hostile or merely busy shell can
// fork a new descendant at any point up to the moment it is actually killed, and a snapshot taken
// once (e.g. at the first destroy() call) would miss anything forked afterward but still alive
// when destroyForcibly() runs the forceful pass a few seconds later.
final class OsSandboxedProcess implements SandboxedProcess {

  private static final Duration GRACEFUL_SHUTDOWN_TIMEOUT = Duration.ofSeconds(5);

  private final Process process;
  private final SandboxProxyServer proxy;
  private final Path profilePath;
  private final Optional<URI> resolvedControlPlaneUri;
  private final Optional<SandboxControlPlaneBindGuard> controlPlaneBindGuard;

  OsSandboxedProcess(
      Process process,
      SandboxProxyServer proxy,
      Path profilePath,
      Optional<URI> controlPlaneUri,
      Consumer<String> diagnostics
  ) {
    this.process = process;
    this.proxy = proxy;
    this.profilePath = profilePath;
    this.resolvedControlPlaneUri = controlPlaneUri;
    // Starts here, not in the launcher, so the guard's kill callback can be this::destroyForcibly -
    // the same process-tree-aware teardown every other caller gets, not a raw Process.destroyForcibly()
    // that would miss descendants.
    this.controlPlaneBindGuard = controlPlaneUri
        .map(URI::getPort)
        .filter(port -> port > 0)
        .map(port -> SandboxControlPlaneBindGuard.start(process, port, this::destroyForcibly, diagnostics));
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

  @Override
  public void destroy() {
    descendants()
        .forEach(ProcessHandle::destroy);
    process.destroy();
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
    controlPlaneBindGuard.ifPresent(SandboxControlPlaneBindGuard::close);
    stopProcessIfAlive();
    proxy.close();
    deleteProfile();
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

  private void deleteProfile() {
    try {
      Files.deleteIfExists(profilePath);
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to delete sandbox profile file " + profilePath, e);
    }
  }
}
