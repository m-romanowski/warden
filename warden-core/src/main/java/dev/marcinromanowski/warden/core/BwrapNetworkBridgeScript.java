package dev.marcinromanowski.warden.core;

import java.nio.file.Path;
import java.util.Optional;

// Generates the in-sandbox shell entrypoint bwrap execs instead of the original command directly:
// starts a background socat translating the isolated netns's own loopback egress port into the
// bind-mounted UDS reaching SandboxProxyServer on the host (loopback TCP does not cross network
// namespace boundaries), optionally a second socat exposing the sandboxed process's own
// control-plane port back out the same way, waits for both to be ready, then execs the real
// command. Pure string generation - no filesystem/process side effects here.
//
// socat is named by the absolute path the caller's resolver produced, never by bare name. Inside the
// sandbox PATH resolves against whatever the bootstrap binds happen to expose, so a bare name would
// silently pick a different socat than the one the embedder resolved and vouched for, or find none
// at all on a host that has no distribution socat installed.
final class BwrapNetworkBridgeScript {

  static final int EGRESS_BRIDGE_PORT = 18080;

  private static final String PROXY_SOCKET_FILE_NAME = BwrapSessionPaths.PROXY_SOCKET_FILE_NAME;
  private static final String CONTROL_SOCKET_FILE_NAME = BwrapSessionPaths.CONTROL_SOCKET_FILE_NAME;
  private static final int READINESS_POLL_ATTEMPTS = 40;
  private static final double READINESS_POLL_INTERVAL_SECONDS = 0.25;

  private BwrapNetworkBridgeScript() {
  }

  static String generate(Path inSandboxBridgeDirectory, Path socatExecutable, Optional<Integer> controlPlanePort) {
    String socat = shellQuoted(
        Preconditions.nonNull(socatExecutable, "socatExecutable")
            .toString()
    );
    String proxySocketPath = shellQuoted(inSandboxBridgeDirectory.resolve(PROXY_SOCKET_FILE_NAME));
    String controlSocketPath = shellQuoted(inSandboxBridgeDirectory.resolve(CONTROL_SOCKET_FILE_NAME));
    StringBuilder script = new StringBuilder();
    script.append("#!/bin/sh\n")
        .append("set -e\n\n")
        .append(socat)
        .append(" TCP-LISTEN:")
        .append(EGRESS_BRIDGE_PORT)
        .append(",bind=127.0.0.1,fork UNIX-CONNECT:")
        .append(proxySocketPath)
        .append(" &\n");
    controlPlanePort.ifPresent(
        port -> script.append(socat)
            .append(" UNIX-LISTEN:")
            .append(controlSocketPath)
            .append(",fork TCP:127.0.0.1:")
            .append(port)
            .append(" &\n")
    );
    script.append('\n')
        .append("ready=0\n")
        .append("i=0\n")
        .append("while [ \"$i\" -lt ")
        .append(READINESS_POLL_ATTEMPTS)
        .append(" ]; do\n")
        .append("  if ")
        .append(socat)
        .append(" -u OPEN:/dev/null TCP:127.0.0.1:")
        .append(EGRESS_BRIDGE_PORT)
        .append(" 2>/dev/null");
    controlPlanePort.ifPresent(port -> script.append(" && [ -S ")
        .append(controlSocketPath)
        .append(" ]"));
    script.append("; then\n")
        .append("    ready=1\n")
        .append("    break\n")
        .append("  fi\n")
        .append("  i=$((i + 1))\n")
        .append("  sleep ")
        .append(READINESS_POLL_INTERVAL_SECONDS)
        .append('\n')
        .append("done\n\n")
        .append("if [ \"$ready\" -ne 1 ]; then\n")
        .append("  echo \"sandbox network bridge did not become ready in time\" >&2\n")
        .append("  exit 1\n")
        .append("fi\n\n")
        .append("exec \"$@\"\n");
    return script.toString();
  }

  private static String shellQuoted(Path path) {
    return shellQuoted(path.toString());
  }

  private static String shellQuoted(String value) {
    return "'" + value.replace("'", "'\\''") + "'";
  }
}
