package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.marcinromanowski.warden.api.SandboxEstablishmentException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class LinuxToolsTest {

  @Test
  void resolvesRealExecutableAlreadyOnPath() {
    LinuxTools tools = new LinuxTools();

    Path resolved = tools.resolveExecutable("sh");

    assertThat(resolved)
        .isAbsolute();
    assertThat(resolved.getFileName().toString())
        .hasToString("sh");
  }

  @Test
  void failsClosedRatherThanReturningNullWhenNothingOnPathMatches() {
    LinuxTools tools = new LinuxTools();

    assertThatThrownBy(() -> tools.resolveExecutable("warden-test-tool-that-does-not-exist"))
        .isInstanceOf(SandboxEstablishmentException.class)
        .hasMessageContaining("warden-test-tool-that-does-not-exist")
        .hasMessageContaining("not found on PATH");
  }

  @Test
  void usesTheInjectedResolverInsteadOfThePathDefaultWhenSupplied() {
    LinuxTools tools = new LinuxTools(name -> Path.of("/custom/" + name));

    Path resolved = tools.resolveExecutable("bwrap");

    assertThat(resolved)
        .isEqualTo(Path.of("/custom/bwrap"));
  }
}
