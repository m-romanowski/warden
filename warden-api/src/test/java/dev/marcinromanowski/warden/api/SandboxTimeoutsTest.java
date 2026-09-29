package dev.marcinromanowski.warden.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.File;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;

class SandboxTimeoutsTest {

  @Test
  void defaultsCarryEveryWaitTheSandboxCanMake() {
    SandboxTimeouts timeouts = SandboxTimeouts.defaults();

    assertThat(timeouts.privilegedCommand())
        .isEqualTo(SandboxTimeouts.DEFAULT_PRIVILEGED_COMMAND);
    assertThat(timeouts.privilegedOutputDrain())
        .isEqualTo(SandboxTimeouts.DEFAULT_PRIVILEGED_OUTPUT_DRAIN);
    assertThat(timeouts.gracefulShutdown())
        .isEqualTo(SandboxTimeouts.DEFAULT_GRACEFUL_SHUTDOWN);
    assertThat(timeouts.controlPlaneRelayDrain())
        .isEqualTo(SandboxTimeouts.DEFAULT_CONTROL_PLANE_RELAY_DRAIN);
  }

  @Test
  void overridingOneLeavesTheOthersAtTheirDefaults() {
    SandboxTimeouts timeouts = SandboxTimeouts.defaults()
        .withPrivilegedCommand(Duration.ofMinutes(20));

    assertThat(timeouts.privilegedCommand())
        .isEqualTo(Duration.ofMinutes(20));
    assertThat(timeouts.gracefulShutdown())
        .isEqualTo(SandboxTimeouts.DEFAULT_GRACEFUL_SHUTDOWN);
  }

  @Test
  void privilegedCommandDefaultClearsMeasuredPolicyLoad() {
    assertThat(SandboxTimeouts.DEFAULT_PRIVILEGED_COMMAND)
        .isGreaterThan(Duration.ofSeconds(60));
  }

  @Test
  void rejectsTimeoutThatWouldNeverWait() {
    assertThatThrownBy(() -> SandboxTimeouts.defaults()
        .withGracefulShutdown(Duration.ZERO))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("gracefulShutdown");
  }

  @Test
  void requestBuiltWithoutTimeoutsGetsTheDefaults() {
    SandboxLaunchRequest request = SandboxLaunchRequest.command("true")
        .logFile(new File("log.txt"))
        .sandboxRoot(Path.of("/tmp/warden-timeouts-test"))
        .build();

    assertThat(request.timeouts())
        .isEqualTo(SandboxTimeouts.defaults());
  }

}
