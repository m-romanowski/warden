package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.PathMount;
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

// Linux counterpart to the macOS flow OsSandboxedProcessLauncher runs inline: loads the
// per-session AppArmor policy (AppArmorProfile - bwrap's own confinement profile, attached to a
// per-session copy of the caller's bwrap, plus the payload's filesystem profile), then composes
// BwrapArgvGenerator (pure argv assembly - network isolation + reachability only, AppArmor does
// the fine-grained filesystem access control) + BwrapNetworkBridgeScript (the in-sandbox bridge
// entrypoint) + SandboxProxyServer bound over a Unix domain socket (loopback TCP does not cross
// network-namespace boundaries) + an optional ControlPlaneRelay into one real bwrap launch.
//
// Deliberately does not vendor bwrap or socat - both resolved via LinuxTools (PATH by default), a
// real fail-closed launch failure when either is missing, exactly like macOS's own requireMacOs()
// fails closed on the wrong platform. apparmor_parser is not resolved here at all: it is reached
// only through the root-owned helper AppArmorProfile runs, which names it itself.
final class BwrapSandboxedProcessLauncher {

  private static final Path IN_SANDBOX_BRIDGE_DIRECTORY = Path.of(AppArmorProfileGenerator.BWRAP_BRIDGE_DIRECTORY);
  private static final String BRIDGE_SCRIPT_FILE_NAME = BwrapSessionPaths.BRIDGE_SCRIPT_FILE_NAME;
  private static final String PROXY_SOCKET_FILE_NAME = BwrapSessionPaths.PROXY_SOCKET_FILE_NAME;
  private static final String CONTROL_SOCKET_FILE_NAME = BwrapSessionPaths.CONTROL_SOCKET_FILE_NAME;
  private static final String TARGET_BINARY_FILE_NAME = BwrapSessionPaths.TARGET_BINARY_FILE_NAME;
  private static final String SESSION_BWRAP_FILE_NAME = "bwrap";
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
    Path socatExecutable = linuxTools.resolveExecutable(SOCAT_TOOL_NAME);

    AppArmorSessionPolicy.requireInstalled();
    AppArmorSessionProfileNames names = AppArmorSessionProfileNames.forNewSession();
    BwrapSession session = BwrapSessionStore.open(names.sessionId(), diagnostics);
    Path sessionDirectory = session.sessionDirectory();
    Path uniqueTargetBinary;
    SandboxProxyServer proxy = null;
    Optional<ControlPlaneRelay> controlPlaneRelay = Optional.empty();
    Process process = null;
    boolean established = false;
    boolean policyOutcomeUnknown = false;

    try {
      uniqueTargetBinary = createUniqueTargetBinary(sessionDirectory);
      final Path sessionBwrapExecutable = copyExecutable(
          bwrapExecutable,
          session.toolsDirectory()
              .resolve(SESSION_BWRAP_FILE_NAME),
          "sandbox bwrap"
      );
      Optional<Integer> controlPlanePort = controlPlanePort(request);
      try {
        AppArmorSessionPolicy.load(
            request.filesystemRules(),
            names,
            new BwrapSessionPaths(sessionDirectory, controlPlanePort.isPresent()),
            socatExecutable
        );
      } catch (PrivilegedOutcomeUnknownException e) {
        policyOutcomeUnknown = true;
        throw e;
      }

      proxy = startProxy(request, sessionDirectory);
      controlPlaneRelay = controlPlanePort.isPresent()
          ? Optional.of(startControlPlaneRelay(sessionDirectory))
          : Optional.empty();

      writeBridgeScript(sessionDirectory, socatExecutable, controlPlanePort);
      List<String> argv = buildArgv(sessionBwrapExecutable, socatExecutable, sessionDirectory, request, uniqueTargetBinary);

      process = startProcess(request, argv);
      diagnostics.accept("sandboxed process started pid=" + process.pid());
      Optional<URI> resolvedControlPlaneUri = resolvedControlPlaneUri(request, controlPlaneRelay);
      SandboxedProcess sandboxedProcess = new BwrapSandboxedProcess(
          process,
          proxy,
          controlPlaneRelay,
          session,
          resolvedControlPlaneUri
      );
      established = true;
      return sandboxedProcess;
    } finally {
      if (!established) {
        releasePartialLaunchResources(session, proxy, controlPlaneRelay, process, policyOutcomeUnknown);
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
      BwrapSession session,
      SandboxProxyServer proxy,
      Optional<ControlPlaneRelay> controlPlaneRelay,
      Process process,
      boolean policyOutcomeUnknown
  ) {
    if (process != null) {
      process.destroyForcibly();
    }
    controlPlaneRelay.ifPresent(ControlPlaneRelay::close);
    if (proxy != null) {
      proxy.close();
    }
    if (policyOutcomeUnknown) {
      BwrapSessionStore.abandon(session);
      return;
    }
    session.close();
  }

  // Copies, not symlinks: AppArmor attaches a profile and resolves an exec transition by the fully
  // resolved path, so a symlink to a shared binary is the shared binary as far as policy goes
  // (a profile naming the link matched nothing when the link was exec'd). Each of these
  // needs a path no other session shares, because the path is the only thing scoping a profile to
  // one session: bwrap's copy is what warden's own confinement profile attaches to, and the shell
  // copy is what that profile's px rule names as the way into the payload's filesystem profile.
  //
  // A caller supplying a setuid bwrap loses the setuid bit here. That costs nothing on a kernel
  // offering unprivileged user namespaces, which is the only kind this mechanism works on at all.
  private static Path createUniqueTargetBinary(Path sessionDirectory) {
    return copyExecutable(
        Path.of(SOURCE_SHELL_EXECUTABLE),
        sessionDirectory.resolve(TARGET_BINARY_FILE_NAME),
        "sandbox target binary"
    );
  }

  private static Path copyExecutable(Path source, Path destination, String description) {
    try {
      Files.copy(source, destination, StandardCopyOption.COPY_ATTRIBUTES);
      Files.setPosixFilePermissions(destination, PosixFilePermissions.fromString("r-xr-x---"));
      return destination;
    } catch (IOException e) {
      throw new SandboxEstablishmentException("Failed to create unique per-session " + description, e);
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

  private static void writeBridgeScript(
      Path sessionDirectory,
      Path socatExecutable,
      Optional<Integer> controlPlanePort
  ) {
    String script = BwrapNetworkBridgeScript.generate(IN_SANDBOX_BRIDGE_DIRECTORY, socatExecutable, controlPlanePort);
    try {
      Files.writeString(sessionDirectory.resolve(BRIDGE_SCRIPT_FILE_NAME), script);
    } catch (IOException e) {
      throw new SandboxEstablishmentException("Failed to write sandbox network bridge script", e);
    }
  }

  private static List<String> buildArgv(
      Path sessionBwrapExecutable,
      Path socatExecutable,
      Path sessionDirectory,
      SandboxLaunchRequest request,
      Path uniqueTargetBinary
  ) {
    Path inSandboxScriptPath = IN_SANDBOX_BRIDGE_DIRECTORY.resolve(BRIDGE_SCRIPT_FILE_NAME);
    List<String> wrappedCommand = new ArrayList<>();
    wrappedCommand.add(uniqueTargetBinary.toString());
    wrappedCommand.add(inSandboxScriptPath.toString());
    wrappedCommand.addAll(request.command());

    BwrapBridgeMount bridgeMount = new BwrapBridgeMount(sessionDirectory, IN_SANDBOX_BRIDGE_DIRECTORY);
    List<PathMount> mounts = new ArrayList<>(request.pathMounts());
    mounts.add(PathMount.readOnly(socatExecutable));
    List<String> generated = BwrapArgvGenerator.generate(
        request.sandboxRoot(),
        List.copyOf(mounts),
        uniqueTargetBinary,
        bridgeMount,
        wrappedCommand
    );

    List<String> argv = new ArrayList<>(generated);
    argv.set(0, sessionBwrapExecutable.toString());
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
