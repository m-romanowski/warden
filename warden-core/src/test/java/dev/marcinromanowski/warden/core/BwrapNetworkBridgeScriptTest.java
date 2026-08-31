package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BwrapNetworkBridgeScriptTest {

  private static final Path BRIDGE_DIRECTORY = Path.of("/run/warden-bridge");
  private static final Path SOCAT = Path.of("/opt/vendored/socat");
  private static final String SHELL = "/bin/sh";

  @Test
  void namesSocatByAbsolutePathSoTheSandboxDoesNotResolveItFromPath() {
    String script = BwrapNetworkBridgeScript.generate(BRIDGE_DIRECTORY, SOCAT, Optional.of(4096));

    assertThat(script)
        .contains(SOCAT.toString())
        .doesNotContain("\nsocat ")
        .doesNotContain(" socat ");
  }

  @Test
  void runsTheSocatThatLivesUnderThePathContainingSpaces(@TempDir Path tempDirParameter) throws IOException {
    Path tools = tempDirParameter.resolve("my tools");
    Files.createDirectories(tools);
    Path socat = tools.resolve("socat stub");
    Files.writeString(socat, "#!/bin/sh\nexit 0\n");
    Files.setPosixFilePermissions(socat, PosixFilePermissions.fromString("rwx------"));
    Path script = tempDirParameter.resolve("bridge.sh");
    Files.writeString(script, BwrapNetworkBridgeScript.generate(BRIDGE_DIRECTORY, socat, Optional.empty()));

    SandboxExecResult result = TestProcesses.run(
        List.of(SHELL, script.toString(), "/bin/echo", "bridge reached the command")
    );

    assertThat(result.output())
        .as("the bridge must reach the command it wraps: %s", result.output())
        .contains("bridge reached the command");
    assertThat(result.exitCode())
        .isZero();
  }
}
