package dev.marcinromanowski.warden.core;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

record BwrapSessionPaths(Path sessionDirectory, boolean withControlSocket) {

  static final String TARGET_BINARY_FILE_NAME = "target-shell";
  static final String PROXY_SOCKET_FILE_NAME = "proxy.sock";
  static final String CONTROL_SOCKET_FILE_NAME = "control.sock";
  static final String BRIDGE_SCRIPT_FILE_NAME = "bridge-entrypoint.sh";

  BwrapSessionPaths {
    Preconditions.nonNull(sessionDirectory, "sessionDirectory");
  }

  Path targetBinary() {
    return sessionDirectory.resolve(TARGET_BINARY_FILE_NAME);
  }

  Path proxySocket() {
    return sessionDirectory.resolve(PROXY_SOCKET_FILE_NAME);
  }

  Optional<Path> controlSocket() {
    return withControlSocket
        ? Optional.of(sessionDirectory.resolve(CONTROL_SOCKET_FILE_NAME))
        : Optional.empty();
  }

  Path inSandboxBridgeScript() {
    return Path.of(AppArmorProfileGenerator.BWRAP_BRIDGE_DIRECTORY, BRIDGE_SCRIPT_FILE_NAME);
  }

  Path inSandboxProxySocket() {
    return Path.of(AppArmorProfileGenerator.BWRAP_BRIDGE_DIRECTORY, PROXY_SOCKET_FILE_NAME);
  }

  Optional<Path> inSandboxControlSocket() {
    return withControlSocket
        ? Optional.of(Path.of(AppArmorProfileGenerator.BWRAP_BRIDGE_DIRECTORY, CONTROL_SOCKET_FILE_NAME))
        : Optional.empty();
  }

  List<Path> all() {
    List<Path> paths = new ArrayList<>(
        List.of(targetBinary(), proxySocket(), inSandboxBridgeScript(), inSandboxProxySocket())
    );
    controlSocket()
        .ifPresent(paths::add);
    inSandboxControlSocket()
        .ifPresent(paths::add);
    return List.copyOf(paths);
  }
}
