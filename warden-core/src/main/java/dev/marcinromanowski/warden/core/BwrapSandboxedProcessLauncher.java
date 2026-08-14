package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.SandboxEstablishmentException;
import dev.marcinromanowski.warden.api.SandboxLaunchRequest;
import dev.marcinromanowski.warden.api.SandboxedProcess;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

// Linux counterpart to the macOS flow OsSandboxedProcessLauncher runs inline: loads a per-session
// AppArmor filesystem profile (AppArmorProfile), attaches the px bwrap-stacking rule that lets an
// unprivileged userns creation actually run under it (AppArmorBwrapAttachment), then composes
// BwrapArgvGenerator (pure argv assembly - network isolation + reachability only, AppArmor does
// the fine-grained filesystem access control) + BwrapNetworkBridgeScript (the in-sandbox bridge
// entrypoint) + SandboxProxyServer bound over a Unix domain socket (loopback TCP does not cross
// network-namespace boundaries) + an optional ControlPlaneRelay into one real bwrap launch.
//
// Deliberately does not vendor bwrap/socat/apparmor_parser/aa-exec - all resolved via LinuxTools
// (PATH by default), a real fail-closed launch failure when any is missing, exactly like macOS's
// own requireMacOs() fails closed on the wrong platform.
final class BwrapSandboxedProcessLauncher {

  private static final Path IN_SANDBOX_BRIDGE_DIRECTORY = Path.of(AppArmorProfileGenerator.BWRAP_BRIDGE_DIRECTORY);
  private static final String BRIDGE_SCRIPT_FILE_NAME = "bridge-entrypoint.sh";
  private static final String PROXY_SOCKET_FILE_NAME = "proxy.sock";
  private static final String CONTROL_SOCKET_FILE_NAME = "control.sock";
  private static final String TARGET_BINARY_FILE_NAME = "target-shell";
  private static final String SESSION_DIRECTORY_PREFIX = "warden-sandbox-session-";
  private static final String SOURCE_SHELL_EXECUTABLE = "/bin/sh";
  private static final String HTTP_PROXY_ENV = "HTTP_PROXY";
  private static final String HTTPS_PROXY_ENV = "HTTPS_PROXY";
  private static final String BWRAP_TOOL_NAME = "bwrap";
  private static final String SOCAT_TOOL_NAME = "socat";

  private final LinuxTools linuxTools;
  private final Consumer<String> diagnostics;

  BwrapSandboxedProcessLauncher(LinuxTools linuxTools, Consumer<String> diagnostics) {
    this.linuxTools = Preconditions.nonNull(linuxTools, "linuxTools");
    this.diagnostics = Preconditions.nonNull(diagnostics, "diagnostics");
  }

  // suppression-reason: proxy's/relay's/profile's/attachment's ownership is transferred to the
  // returned BwrapSandboxedProcess (which closes them from its own close()) on the success path,
  // and released explicitly via releasePartialLaunchResources() in the finally block on every
  // failure path - mirrors OsSandboxedProcessLauncher.launchOnMacOs()'s identical, already-approved
  // reasoning.
  @SuppressWarnings("PMD.CloseResource")
  SandboxedProcess launch(SandboxLaunchRequest request) {
    Path bwrapExecutable = linuxTools.resolveExecutable(BWRAP_TOOL_NAME);
    linuxTools.resolveExecutable(SOCAT_TOOL_NAME);

    Path sessionDirectory = createSessionDirectory();
    Path uniqueTargetBinary;
    AppArmorProfile profile = null;
    AppArmorBwrapAttachment attachment = null;
    SandboxProxyServer proxy = null;
    Optional<ControlPlaneRelay> controlPlaneRelay = Optional.empty();
    Process process = null;
    boolean established = false;

    try {
      uniqueTargetBinary = createUniqueTargetBinary(sessionDirectory);
      profile = AppArmorProfile.load(request.filesystemRules(), sessionDirectory);
      attachment = AppArmorBwrapAttachment.attach(uniqueTargetBinary, profile.name());

      proxy = startProxy(request, sessionDirectory);
      Optional<Integer> controlPlanePort = controlPlanePort(request);
      controlPlaneRelay = controlPlanePort.isPresent()
          ? Optional.of(startControlPlaneRelay(sessionDirectory))
          : Optional.empty();

      writeBridgeScript(sessionDirectory, controlPlanePort);
      List<String> argv = buildArgv(bwrapExecutable, sessionDirectory, request.sandboxRoot(), uniqueTargetBinary, request.command());

      process = startProcess(request, argv);
      diagnostics.accept("sandboxed process started pid=" + process.pid());
      Optional<URI> resolvedControlPlaneUri = resolvedControlPlaneUri(request, controlPlaneRelay);
      SandboxedProcess sandboxedProcess = new BwrapSandboxedProcess(
          process,
          proxy,
          controlPlaneRelay,
          attachment,
          profile,
          sessionDirectory,
          resolvedControlPlaneUri
      );
      established = true;
      return sandboxedProcess;
    } finally {
      if (!established) {
        releasePartialLaunchResources(sessionDirectory, proxy, controlPlaneRelay, attachment, profile, process);
      }
    }
  }

  private static Optional<URI> resolvedControlPlaneUri(
      SandboxLaunchRequest request,
      Optional<ControlPlaneRelay> controlPlaneRelay
  ) {
    return controlPlaneRelay.map(
        relay -> withPort(
            request.controlPlaneHint()
                .orElseThrow(),
            relay.port()
        )
    );
  }

  private static void releasePartialLaunchResources(
      Path sessionDirectory,
      SandboxProxyServer proxy,
      Optional<ControlPlaneRelay> controlPlaneRelay,
      AppArmorBwrapAttachment attachment,
      AppArmorProfile profile,
      Process process
  ) {
    if (process != null) {
      process.destroyForcibly();
    }
    controlPlaneRelay.ifPresent(ControlPlaneRelay::close);
    if (proxy != null) {
      proxy.close();
    }
    if (attachment != null) {
      attachment.close();
    }
    if (profile != null) {
      profile.close();
    }
    SandboxSessionDirectories.deleteQuietly(sessionDirectory);
  }

  private static Path createSessionDirectory() {
    try {
      return SecureTempFiles.createOwnerOnlyTempDirectory(SESSION_DIRECTORY_PREFIX);
    } catch (IOException e) {
      throw new SandboxEstablishmentException("Failed to create sandbox session directory", e);
    }
  }

  // A copy (not a symlink or bind-only reference) of a plain shell, at a unique per-session path -
  // this is what AppArmorBwrapAttachment's px stacking rule targets, and what bwrap itself execs
  // as the sandboxed process's entrypoint (which in turn execs the bridge script). Must be a real,
  // independent path per session: the kernel's own no_new_privs exec-time stacking rule has no way
  // to scope itself to "this one session" other than by the exec target's own filesystem path.
  private static Path createUniqueTargetBinary(Path sessionDirectory) {
    try {
      Path targetBinary = sessionDirectory.resolve(TARGET_BINARY_FILE_NAME);
      Files.copy(Path.of(SOURCE_SHELL_EXECUTABLE), targetBinary, StandardCopyOption.COPY_ATTRIBUTES);
      Files.setPosixFilePermissions(
          targetBinary,
          PosixFilePermissions.fromString("r-xr-x---")
      );
      return targetBinary;
    } catch (IOException e) {
      throw new SandboxEstablishmentException("Failed to create unique per-session sandbox target binary", e);
    }
  }

  private SandboxProxyServer startProxy(SandboxLaunchRequest request, Path sessionDirectory) {
    Path proxySocketPath = sessionDirectory.resolve(PROXY_SOCKET_FILE_NAME);
    return SandboxProxyServer.start(
        request.networkRules(),
        request.networkAskHandler(),
        request.sandboxRoot()
            .toString(),
        diagnostics,
        Optional.of(proxySocketPath)
    );
  }

  private static Optional<Integer> controlPlanePort(SandboxLaunchRequest request) {
    return request.controlPlaneHint()
        .map(URI::getPort)
        .filter(port -> port > 0);
  }

  private ControlPlaneRelay startControlPlaneRelay(Path sessionDirectory) {
    Path controlSocketPath = sessionDirectory.resolve(CONTROL_SOCKET_FILE_NAME);
    try {
      return ControlPlaneRelay.start(controlSocketPath, diagnostics);
    } catch (UncheckedIOException e) {
      throw new SandboxEstablishmentException("Failed to start sandbox control-plane relay", e);
    }
  }

  private static void writeBridgeScript(Path sessionDirectory, Optional<Integer> controlPlanePort) {
    String script = BwrapNetworkBridgeScript.generate(IN_SANDBOX_BRIDGE_DIRECTORY, controlPlanePort);
    try {
      Files.writeString(sessionDirectory.resolve(BRIDGE_SCRIPT_FILE_NAME), script);
    } catch (IOException e) {
      throw new SandboxEstablishmentException("Failed to write sandbox network bridge script", e);
    }
  }

  private static List<String> buildArgv(
      Path bwrapExecutable,
      Path sessionDirectory,
      Path sandboxRoot,
      Path uniqueTargetBinary,
      List<String> originalCommand
  ) {
    Path inSandboxScriptPath = IN_SANDBOX_BRIDGE_DIRECTORY.resolve(BRIDGE_SCRIPT_FILE_NAME);
    List<String> wrappedCommand = new ArrayList<>();
    wrappedCommand.add(uniqueTargetBinary.toString());
    wrappedCommand.add(inSandboxScriptPath.toString());
    wrappedCommand.addAll(originalCommand);

    BwrapBridgeMount bridgeMount = new BwrapBridgeMount(sessionDirectory, IN_SANDBOX_BRIDGE_DIRECTORY);
    List<String> generated =
        BwrapArgvGenerator.generate(sandboxRoot, uniqueTargetBinary, bridgeMount, wrappedCommand);

    List<String> argv = new ArrayList<>(generated);
    argv.set(0, bwrapExecutable.toString());
    return argv;
  }

  private static Process startProcess(SandboxLaunchRequest request, List<String> argv) {
    ProcessBuilder processBuilder = new ProcessBuilder(argv)
        .redirectErrorStream(true)
        .redirectOutput(request.logFile());
    processBuilder.environment()
        .putAll(proxyEnvironment(request.environmentVariables()));
    if (request.workingDirectory() != null) {
      processBuilder.directory(request.workingDirectory());
    }
    try {
      return processBuilder.start();
    } catch (IOException e) {
      throw new SandboxEstablishmentException("Failed to start sandboxed process", e);
    }
  }

  // Points at the in-sandbox egress-bridge port, not the proxy's own host-side port: loopback TCP
  // does not cross network-namespace boundaries. A tool that ignores these variables entirely is
  // still confined, since --unshare-net leaves no other route out.
  private static Map<String, String> proxyEnvironment(Map<String, String> baseEnvironment) {
    Map<String, String> environment = new LinkedHashMap<>(baseEnvironment);
    String proxyUrl = "http://127.0.0.1:" + BwrapNetworkBridgeScript.EGRESS_BRIDGE_PORT;
    environment.put(HTTP_PROXY_ENV, proxyUrl);
    environment.put(HTTPS_PROXY_ENV, proxyUrl);
    return environment;
  }

  private static URI withPort(URI original, int newPort) {
    try {
      return new URI(
          original.getScheme(),
          original.getUserInfo(),
          original.getHost(),
          newPort,
          original.getPath(),
          original.getQuery(),
          original.getFragment()
      );
    } catch (URISyntaxException e) {
      throw new SandboxEstablishmentException("Failed to construct sandbox control-plane relay URI", e);
    }
  }
}
