package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.SandboxEstablishmentException;
import dev.marcinromanowski.warden.api.SandboxLaunchRequest;
import dev.marcinromanowski.warden.api.SandboxedProcess;
import dev.marcinromanowski.warden.api.SandboxedProcessLauncher;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * The public entry point of this module: wraps a raw process launch request in an OS-level
 * filesystem+network sandbox - macOS's Seatbelt (a generated SBPL profile plus a loopback
 * {@code SandboxProxyServer}) or Linux's AppArmor+bwrap. On any other platform this fails closed
 * with {@link SandboxEstablishmentException} rather than silently running the target process
 * unsandboxed.
 */
public final class OsSandboxedProcessLauncher implements SandboxedProcessLauncher {

  private static final String DARWIN_PLATFORM_PREFIX = "darwin";
  private static final String LINUX_PLATFORM_PREFIX = "linux";
  private static final String SANDBOX_EXEC_PATH = "/usr/bin/sandbox-exec";
  private static final String SANDBOX_EXEC_FLAG = "-f";
  private static final String HTTP_PROXY_ENV = "HTTP_PROXY";
  private static final String HTTPS_PROXY_ENV = "HTTPS_PROXY";
  private static final String PROFILE_FILE_PREFIX = "warden-sandbox-profile-";
  private static final String PROFILE_FILE_SUFFIX = ".sb";

  private final Consumer<String> diagnostics;
  private final Optional<Function<String, Path>> linuxToolResolver;

  /** Creates a launcher with no diagnostics output and the default PATH-based Linux tool resolver. */
  public OsSandboxedProcessLauncher() {
    this(message -> {});
  }

  /** Creates a launcher with the default PATH-based Linux tool resolver. */
  public OsSandboxedProcessLauncher(Consumer<String> diagnostics) {
    this(diagnostics, Optional.empty());
  }

  /**
   * Creates a launcher with a custom Linux tool resolver - the seam a stricter embedder supplies
   * to resolve bwrap/socat itself (e.g. from its own vendored/Managed-Tool installation) instead
   * of this module's own PATH-scan default. macOS has no equivalent of this, since sandbox-exec
   * is always a fixed system path.
   */
  public OsSandboxedProcessLauncher(Consumer<String> diagnostics, Function<String, Path> linuxToolResolver) {
    this(diagnostics, Optional.of(Preconditions.nonNull(linuxToolResolver, "linuxToolResolver")));
  }

  private OsSandboxedProcessLauncher(Consumer<String> diagnostics, Optional<Function<String, Path>> linuxToolResolver) {
    this.diagnostics = Preconditions.nonNull(diagnostics, "diagnostics");
    this.linuxToolResolver = Preconditions.nonNull(linuxToolResolver, "linuxToolResolver");
  }

  @Override
  public SandboxedProcess launch(SandboxLaunchRequest request) {
    Preconditions.nonNull(request, "request");
    String currentPlatform = CurrentPlatform.current();
    if (currentPlatform.startsWith(LINUX_PLATFORM_PREFIX)) {
      LinuxTools linuxTools = linuxToolResolver.map(LinuxTools::new)
          .orElseGet(LinuxTools::new);
      return new BwrapSandboxedProcessLauncher(linuxTools, diagnostics)
          .launch(request);
    }
    return launchOnMacOs(request, currentPlatform);
  }

  // suppression-reason: proxy's ownership is transferred to the returned OsSandboxedProcess
  // (which closes it from its own close()) on the success path, and released explicitly via
  // releasePartialLaunchResources() in the finally block on every failure path - it is not an
  // unmanaged resource, PMD just cannot see either the transfer-of-ownership or the finally-block
  // cleanup pattern here.
  @SuppressWarnings("PMD.CloseResource")
  private SandboxedProcess launchOnMacOs(SandboxLaunchRequest request, String currentPlatform) {
    requireMacOs(currentPlatform);
    SandboxProxyServer proxy = startProxy(request);
    Path profilePath = null;
    Process process = null;
    boolean established = false;
    try {
      profilePath = writeProfile(request, proxy.port());
      process = startProcess(request, profilePath, proxy.port());
      diagnostics.accept("sandboxed process started pid=" + process.pid());
      SandboxedProcess sandboxedProcess =
          new OsSandboxedProcess(process, proxy, profilePath, request.controlPlaneHint(), diagnostics);
      established = true;
      return sandboxedProcess;
    } finally {
      if (!established) {
        releasePartialLaunchResources(profilePath, proxy, process);
      }
    }
  }

  // Takes the raw, not-yet-wrapped Process too: a throw at any point after startProcess()
  // succeeds must still not leave that process running with no handle left anywhere to find or
  // kill it later. Tracking it here, independent of whether OsSandboxedProcess ever got
  // constructed, closes that gap.
  private void releasePartialLaunchResources(Path profilePath, SandboxProxyServer proxy, Process process) {
    if (process != null) {
      process.destroyForcibly();
    }
    if (profilePath != null) {
      deleteProfileQuietly(profilePath);
    }
    proxy.close();
  }

  private SandboxProxyServer startProxy(SandboxLaunchRequest request) {
    return SandboxProxyServer.start(
        request.networkRules(),
        request.networkAskHandler(),
        request.sandboxRoot()
            .toString(),
        diagnostics
    );
  }

  private static void requireMacOs(String currentPlatform) {
    if (!currentPlatform.startsWith(DARWIN_PLATFORM_PREFIX)) {
      throw new SandboxEstablishmentException(
          "OsSandboxedProcessLauncher only supports macOS (darwin-*) and Linux (linux-*); current"
              + " platform is " + currentPlatform
      );
    }
  }

  private static Path writeProfile(SandboxLaunchRequest request, int proxyPort) {
    Optional<Integer> listenPort = request.controlPlaneHint()
        .map(URI::getPort)
        .filter(port -> port > 0);
    String profile = SeatbeltProfileGenerator.generate(request.filesystemRules(), proxyPort, listenPort);
    try {
      Path profilePath = SecureTempFiles.createOwnerOnlyTempFile(PROFILE_FILE_PREFIX, PROFILE_FILE_SUFFIX);
      Files.writeString(profilePath, profile);
      return profilePath;
    } catch (IOException e) {
      throw new SandboxEstablishmentException("Failed to write sandbox profile file", e);
    }
  }

  private static Process startProcess(SandboxLaunchRequest request, Path profilePath, int proxyPort) {
    List<String> wrappedCommand = wrappedCommand(profilePath, request.command());
    ProcessBuilder processBuilder = new ProcessBuilder(wrappedCommand)
        .redirectErrorStream(true)
        .redirectOutput(request.logFile());
    processBuilder.environment()
        .putAll(proxyEnvironment(request.environmentVariables(), proxyPort));
    if (request.workingDirectory() != null) {
      processBuilder.directory(request.workingDirectory());
    }
    try {
      return processBuilder.start();
    } catch (IOException e) {
      throw new SandboxEstablishmentException("Failed to start sandboxed process", e);
    }
  }

  private static List<String> wrappedCommand(Path profilePath, List<String> originalCommand) {
    List<String> wrapped = new ArrayList<>();
    wrapped.add(SANDBOX_EXEC_PATH);
    wrapped.add(SANDBOX_EXEC_FLAG);
    wrapped.add(profilePath.toString());
    wrapped.addAll(originalCommand);
    return wrapped;
  }

  // HTTP_PROXY/HTTPS_PROXY are a convenience for tools that respect them, not the real
  // enforcement boundary - the generated SBPL profile pins all network-outbound traffic to
  // localhost:<proxyPort> regardless of what a sandboxed process's own environment or proxy
  // handling does, so a tool that ignores these variables entirely is still confined by the OS
  // itself, not left unsandboxed.
  private static Map<String, String> proxyEnvironment(Map<String, String> baseEnvironment, int proxyPort) {
    Map<String, String> environment = new LinkedHashMap<>(baseEnvironment);
    String loopbackHost = InetAddress.getLoopbackAddress()
        .getHostAddress();
    String proxyUrl = "http://" + loopbackHost + ":" + proxyPort;
    environment.put(HTTP_PROXY_ENV, proxyUrl);
    environment.put(HTTPS_PROXY_ENV, proxyUrl);
    return environment;
  }

  private void deleteProfileQuietly(Path profilePath) {
    try {
      Files.deleteIfExists(profilePath);
    } catch (IOException e) {
      diagnostics.accept("failed to delete sandbox profile file " + profilePath + ": " + e);
    }
  }
}
