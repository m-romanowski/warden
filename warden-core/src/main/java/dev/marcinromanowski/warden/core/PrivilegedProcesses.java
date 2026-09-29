package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.SandboxEstablishmentException;
import dev.marcinromanowski.warden.api.SandboxTimeouts;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

// Runs a command under sudo. Loading and removing an AppArmor profile requires CAP_MAC_ADMIN,
// which this JVM does not run with, and it is the only thing warden ever needs privilege for -
// running under an already-loaded profile needs none. Deployment grants passwordless sudo for
// one root-owned helper and nothing else - see AppArmorProfile for the argv shapes this runs, and
// scripts/install-apparmor-policy.sh for the helper and the grant.
//
// Policy text goes over stdin rather than into a file the command is pointed at. A path the daemon
// user can write is a path it can replace with a symlink between the check and the open, and the
// parser follows one - so there is no path to hand over.
final class PrivilegedProcesses {

  private PrivilegedProcesses() {
  }

  static void run(List<String> command, String standardInput, SandboxTimeouts timeouts) {
    List<String> withSudo = new ArrayList<>();
    withSudo.add("sudo");
    withSudo.addAll(Preconditions.nonNull(command, "command"));
    Process process = start(withSudo);
    // Drained on its own thread, and the input written while that drain runs. Reading to EOF on
    // this thread blocks until the child exits, which puts the read ahead of the only timeout
    // there is and makes COMMAND_TIMEOUT unreachable for the hang it exists to bound - measured,
    // a 929 s privileged command completed without the 30 s limit firing. Draining concurrently
    // also keeps a child that answers before consuming a 1 MiB body from deadlocking on a full
    // pipe.
    PrivilegedCommandOutputDrain drain = PrivilegedCommandOutputDrain.start(process);
    writeInput(process, Preconditions.nonNull(standardInput, "standardInput"));
    int exitCode = awaitExit(process, withSudo, timeouts.privilegedCommand());
    String output = drain.await(timeouts.privilegedOutputDrain());
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

  private static void writeInput(Process process, String standardInput) {
    try (var sink = process.getOutputStream()) {
      sink.write(standardInput.getBytes(StandardCharsets.UTF_8));
    } catch (IOException e) {
      throw new SandboxEstablishmentException("Failed to hand the privileged command its input", e);
    }
  }

  private static int awaitExit(Process process, List<String> command, Duration commandTimeout) {
    boolean finished;
    try {
      finished = process.waitFor(commandTimeout.toMillis(), TimeUnit.MILLISECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread()
          .interrupt();
      throw new PrivilegedOutcomeUnknownException("Interrupted while running privileged command: " + command, e);
    }
    if (!finished) {
      process.destroyForcibly();
      throw new PrivilegedOutcomeUnknownException("Privileged command timed out: " + command);
    }
    return process.exitValue();
  }
}
