package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class BwrapNetworkBridgeScriptTest {

  private static final Path BRIDGE_DIRECTORY = Path.of("/run/warden-bridge");
  private static final Path SOCAT = Path.of("/opt/vendored/socat");

  @Test
  void namesSocatByAbsolutePathSoTheSandboxDoesNotResolveItFromPath() {
    String script = BwrapNetworkBridgeScript.generate(BRIDGE_DIRECTORY, SOCAT, Optional.of(4096));

    assertThat(script)
        .contains(SOCAT.toString())
        .doesNotContain("\nsocat ")
        .doesNotContain(" socat ");
  }

  @Test
  void usesTheSameExecutableForTheReadinessProbe() {
    String script = BwrapNetworkBridgeScript.generate(BRIDGE_DIRECTORY, SOCAT, Optional.empty());

    assertThat(script)
        .contains(SOCAT + " -u OPEN:/dev/null");
  }
}
