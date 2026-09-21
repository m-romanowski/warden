package dev.marcinromanowski.warden.core;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

final class PseudoTerminal {

  private static final String RUNNER_SOURCE =
      """
      #include <stdio.h>
      #include <stdlib.h>
      #include <string.h>
      #include <unistd.h>
      #include <util.h>
      #include <signal.h>
      #include <sys/ioctl.h>
      #include <sys/select.h>
      #include <sys/wait.h>

      int main(int argc, char **argv) {
        struct winsize size;
        int master = -1;
        pid_t child;
        char buffer[4096];
        int status = 0;
        int timedOut = 0;
        memset(&size, 0, sizeof size);
        size.ws_row = 40;
        size.ws_col = 120;
        if (argc < 2) {
          return 127;
        }
        child = forkpty(&master, NULL, NULL, &size);
        if (child < 0) {
          return 127;
        }
        if (child == 0) {
          execv(argv[1], &argv[1]);
          _exit(127);
        }
        for (;;) {
          fd_set readable;
          struct timeval timeout;
          ssize_t taken;
          FD_ZERO(&readable);
          FD_SET(master, &readable);
          timeout.tv_sec = 10;
          timeout.tv_usec = 0;
          if (select(master + 1, &readable, NULL, NULL, &timeout) <= 0) {
            timedOut = 1;
            kill(child, SIGKILL);
            break;
          }
          taken = read(master, buffer, sizeof buffer);
          if (taken <= 0) {
            break;
          }
          fwrite(buffer, 1, (size_t) taken, stdout);
        }
        waitpid(child, &status, 0);
        fflush(stdout);
        if (timedOut) {
          return 126;
        }
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
      }
      """;

  private PseudoTerminal() {
  }

  static SandboxExecResult run(Path directory, List<String> command) throws IOException {
    Path program = runner(directory);
    List<String> full = new ArrayList<>();
    full.add(program.toString());
    full.addAll(command);
    return TestProcesses.run(full);
  }

  private static Path runner(Path directory) throws IOException {
    Path binary = directory.resolve("pty-runner");
    if (Files.isExecutable(binary)) {
      return binary;
    }
    Path source = directory.resolve("pty-runner.c");
    Files.writeString(source, RUNNER_SOURCE);
    SandboxExecResult compilation = TestProcesses.run(
        List.of("cc", "-o", binary.toString(), source.toString())
    );
    assumeTrue(
        compilation.exitCode() == 0,
        "a C compiler is required to build the pseudoterminal runner: " + compilation.output()
    );
    return binary;
  }
}
