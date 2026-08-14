package dev.marcinromanowski.warden.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

final class TestProcesses {

  private static final Duration COMMAND_TIMEOUT = Duration.ofSeconds(10);

  private TestProcesses() {
  }

  static SandboxExecResult run(List<String> command) throws IOException {
    Process process = new ProcessBuilder(command)
        .redirectErrorStream(true)
        .start();
    boolean finished = awaitTermination(process);
    if (!finished) {
      process.destroyForcibly();
      throw new AssertionError("command did not complete in time: " + command);
    }
    String output = new String(
        process.getInputStream()
            .readAllBytes(),
        StandardCharsets.UTF_8
    );
    return new SandboxExecResult(process.exitValue(), output);
  }

  private static boolean awaitTermination(Process process) {
    try {
      return process.waitFor(COMMAND_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
    } catch (InterruptedException _) {
      Thread.currentThread()
          .interrupt();
      return false;
    }
  }
}
