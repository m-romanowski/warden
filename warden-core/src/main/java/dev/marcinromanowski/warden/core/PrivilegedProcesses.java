package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.SandboxEstablishmentException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

// Runs a command under sudo - the one-time-privileged operations AppArmor confinement needs
// (loading/removing a profile, editing the local bwrap-userns-restrict override) all require
// CAP_MAC_ADMIN, which this JVM does not run with. This is the project's one narrow, auditable
// privileged surface: using an already-loaded profile (aa-exec -p <name>) needs no privilege at
// all, only loading/removing one does. Deployment must grant passwordless sudo for exactly these
// commands - see AppArmorProfile/AppArmorBwrapAttachment for the exact argv shapes this runs.
final class PrivilegedProcesses {

  private static final Duration COMMAND_TIMEOUT = Duration.ofSeconds(30);

  private PrivilegedProcesses() {
  }

  static void run(List<String> command) {
    List<String> withSudo = new ArrayList<>();
    withSudo.add("sudo");
    withSudo.addAll(Preconditions.nonNull(command, "command"));
    Process process = start(withSudo);
    String output = readOutput(process);
    int exitCode = awaitExit(process, withSudo);
    if (exitCode != 0) {
      throw new SandboxEstablishmentException(
          "Privileged command failed (exit=" + exitCode + "): " + withSudo + " output: " + output
      );
    }
  }

  private static Process start(List<String> command) {
    try {
      return new ProcessBuilder(command)
          .redirectErrorStream(true)
          .start();
    } catch (IOException e) {
      throw new SandboxEstablishmentException("Failed to start privileged command: " + command, e);
    }
  }

  private static String readOutput(Process process) {
    try {
      return new String(
          process.getInputStream()
              .readAllBytes(),
          StandardCharsets.UTF_8
      );
    } catch (IOException e) {
      throw new SandboxEstablishmentException("Failed to read privileged command output", e);
    }
  }

  private static int awaitExit(Process process, List<String> command) {
    boolean finished;
    try {
      finished = process.waitFor(COMMAND_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread()
          .interrupt();
      throw new SandboxEstablishmentException("Interrupted while running privileged command: " + command, e);
    }
    if (!finished) {
      process.destroyForcibly();
      throw new SandboxEstablishmentException("Privileged command timed out: " + command);
    }
    return process.exitValue();
  }
}
