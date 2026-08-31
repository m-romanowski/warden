package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;

import dev.marcinromanowski.warden.api.SandboxLaunchRequest;
import dev.marcinromanowski.warden.api.SandboxedProcess;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

@EnabledOnOs(OS.LINUX)
class OsSandboxedProcessLauncherLinuxTerminationTest {

  private static final Duration LAUNCH_TIMEOUT = Duration.ofSeconds(30);
  private static final Duration READY_TIMEOUT = Duration.ofSeconds(20);
  private static final Duration POLL_INTERVAL = Duration.ofMillis(50);
  private static final Duration UNINTERRUPTED_RUN = Duration.ofSeconds(2);
  private static final String READY_MARKER = "PAYLOAD-READY";
  private static final String HANDLER_ENTERED = "HANDLER-ENTERED";
  private static final String HANDLER_COMPLETED = "HANDLER-COMPLETED";
  private static final int PAYLOAD_EXIT_CODE = 7;
  private static final int HANDLER_SECONDS = 1;

  private static final String SHUTS_ITSELF_DOWN = String.join(
      "; ",
      "trap 'echo " + HANDLER_ENTERED + "; sleep " + HANDLER_SECONDS + "; echo " + HANDLER_COMPLETED
          + "; exit " + PAYLOAD_EXIT_CODE + "' TERM",
      "echo " + READY_MARKER,
      "sleep 600 & wait"
  );

  private static final String NEVER_ACTS_ON_THE_REQUEST = String.join(
      "; ",
      "trap '' TERM",
      "echo " + READY_MARKER,
      "sleep 600 & wait"
  );

  @Test
  void letsThePayloadsOwnTerminationHandlerRunToCompletion(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path logFile = Files.createTempFile("warden-termination-handler-", ".log");

    try (SandboxedProcess process = launch(tempDirParameter.toRealPath(), logFile, SHUTS_ITSELF_DOWN)) {
      awaitReady(logFile);
      process.destroy();

      assertThat(process.waitFor(LAUNCH_TIMEOUT))
          .as("the sandboxed process did not terminate in time")
          .isTrue();
      assertThat(Files.readString(logFile))
          .as("destroy() offers a chance to shut down cleanly, so a handler that takes %s second(s)"
              + " has to reach its own end", HANDLER_SECONDS)
          .contains(HANDLER_ENTERED)
          .contains(HANDLER_COMPLETED);
    }
  }

  @Test
  void reportsThePayloadsOwnExitCodeAfterItShutsItselfDown(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path logFile = Files.createTempFile("warden-termination-exit-code-", ".log");

    try (SandboxedProcess process = launch(tempDirParameter.toRealPath(), logFile, SHUTS_ITSELF_DOWN)) {
      awaitReady(logFile);
      process.destroy();

      assertThat(process.waitFor(LAUNCH_TIMEOUT))
          .as("the sandboxed process did not terminate in time")
          .isTrue();
      assertThat(process.exitCode())
          .as("the code the caller reads has to be the payload's own, not one belonging to a"
              + " process warden wrapped it in")
          .contains(PAYLOAD_EXIT_CODE);
    }
  }

  @Test
  void runsThePayloadAsAnOrdinaryProcessBesideTheNamespacesOwnInit(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path logFile = Files.createTempFile("warden-termination-pid-", ".log");

    try (
        SandboxedProcess process = launch(tempDirParameter.toRealPath(), logFile, "echo " + READY_MARKER + "=$$")
    ) {
      assertThat(process.waitFor(LAUNCH_TIMEOUT))
          .as("the sandboxed process did not terminate in time")
          .isTrue();
      assertThat(Files.readString(logFile))
          .as("the payload must not be its namespace's init, which would ignore every signal it"
              + " installs no handler for and so be beyond destroy()'s reach")
          .contains(READY_MARKER + "=2");
    }
  }

  @Test
  void boundsTheGraceGivenToPayloadsThatNeverActOnTheRequest(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path logFile = Files.createTempFile("warden-termination-ignored-", ".log");
    SandboxedProcess process = launch(tempDirParameter.toRealPath(), logFile, NEVER_ACTS_ON_THE_REQUEST);

    try {
      awaitReady(logFile);
      process.destroy();

      assertThat(process.waitFor(UNINTERRUPTED_RUN))
          .as("a payload that ignores the request has to outlive the request itself, or destroy()"
              + " is killing rather than asking")
          .isFalse();
    } finally {
      process.close();
    }

    assertThat(process.isAlive())
        .as("the grace a payload gets is bounded: a close() has to end a payload that never took"
            + " the offer")
        .isFalse();
  }

  private static SandboxedProcess launch(Path workspaceRoot, Path logFile, String payload) {
    return new OsSandboxedProcessLauncher()
        .launch(
            SandboxLaunchRequest.command("/bin/sh", "-c", payload)
                .sandboxRoot(workspaceRoot)
                .logFile(logFile.toFile())
                .build()
        );
  }

  private static void awaitReady(Path logFile) throws IOException {
    Instant deadline = Instant.now()
        .plus(READY_TIMEOUT);
    while (Instant.now()
        .isBefore(deadline)) {
      if (Files.readString(logFile)
          .contains(READY_MARKER)) {
        return;
      }
      sleep();
    }
    throw new AssertionError("the payload never reported itself ready, output: " + Files.readString(logFile));
  }

  private static void sleep() {
    try {
      Thread.sleep(POLL_INTERVAL.toMillis());
    } catch (InterruptedException _) {
      Thread.currentThread()
          .interrupt();
    }
  }
}
