package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.SandboxedProcess;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

// Linux counterpart to OsSandboxedProcess: wraps the bwrap-launched Process plus every resource a
// Linux launch establishes alongside it - the AppArmor filesystem profile, its px bwrap-stacking
// attachment, SandboxProxyServer (bound over a Unix domain socket here, not loopback TCP, since
// loopback does not cross network-namespace boundaries), the optional ControlPlaneRelay, and the
// session directory. close() tears all of these down together, in the reverse order they were
// established (bwrap attachment before the profile it references, so the stacking rule never
// briefly points at an already-unloaded profile).
//
// Process-tree-aware teardown, same reasoning as OsSandboxedProcess documents for its own close().
final class BwrapSandboxedProcess implements SandboxedProcess {

  private static final Duration GRACEFUL_SHUTDOWN_TIMEOUT = Duration.ofSeconds(5);

  private final Process process;
  private final SandboxProxyServer proxy;
  private final Optional<ControlPlaneRelay> controlPlaneRelay;
  private final AppArmorBwrapAttachment bwrapAttachment;
  private final AppArmorProfile profile;
  private final Path sessionDirectory;
  private final Optional<URI> resolvedControlPlaneUri;

  BwrapSandboxedProcess(
      Process process,
      SandboxProxyServer proxy,
      Optional<ControlPlaneRelay> controlPlaneRelay,
      AppArmorBwrapAttachment bwrapAttachment,
      AppArmorProfile profile,
      Path sessionDirectory,
      Optional<URI> resolvedControlPlaneUri
  ) {
    this.process = process;
    this.proxy = proxy;
    this.controlPlaneRelay = controlPlaneRelay;
    this.bwrapAttachment = bwrapAttachment;
    this.profile = profile;
    this.sessionDirectory = sessionDirectory;
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
    stopProcessIfAlive();
    controlPlaneRelay.ifPresent(ControlPlaneRelay::close);
    proxy.close();
    bwrapAttachment.close();
    profile.close();
    SandboxSessionDirectories.deleteQuietly(sessionDirectory);
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
