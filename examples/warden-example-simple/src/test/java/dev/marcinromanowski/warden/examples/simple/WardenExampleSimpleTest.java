package dev.marcinromanowski.warden.examples.simple;

import static org.assertj.core.api.Assertions.assertThat;

import dev.marcinromanowski.warden.api.AccessKind;
import dev.marcinromanowski.warden.api.FilesystemRule;
import dev.marcinromanowski.warden.api.SandboxLaunchRequest;
import dev.marcinromanowski.warden.api.SandboxedProcess;
import dev.marcinromanowski.warden.core.OsSandboxedProcessLauncher;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

// Runs the exact scenario Main demonstrates through a real launch (real Seatbelt on macOS, real
// AppArmor+bwrap on Linux - whichever platform this runs on) and asserts the outcome, so a
// regression in the underlying enforcement is caught here, not just left as a human-eyeballed demo.
class WardenExampleSimpleTest {

  private static final Duration LAUNCH_TIMEOUT = Duration.ofSeconds(20);
  private static final String SECTION_SEPARATOR = "---SEP---";

  @Test
  void allowedFileIsReadableAndDeniedFileIsNot(@TempDir Path workspaceParameter) throws IOException {
    // toRealPath() matters here: on macOS, a JUnit @TempDir commonly lands under /var/folders/...,
    // itself a symlink to /private/var/folders/... - Seatbelt enforces against the kernel-resolved
    // canonical path, not the symlinked one, so a rule built from the raw path would silently
    // never match.
    Path workspace = workspaceParameter.toRealPath();
    Path allowedFile = workspace.resolve("allowed.txt");
    Path deniedFile = workspace.resolve("denied.txt");
    Files.writeString(allowedFile, "hello from an allowed file");
    Files.writeString(deniedFile, "TOP-SECRET");
    // Inside the workspace, not a separate system temp file - the log file needs its own grant
    // just like any other path the sandboxed process touches.
    Path logFile = workspace.resolve("output.log");

    SandboxLaunchRequest request = SandboxLaunchRequest.command(
        "/bin/sh", "-c",
        "cat " + allowedFile + " 2>&1; echo " + SECTION_SEPARATOR + "; cat " + deniedFile + " 2>&1"
    )
        .sandboxRoot(workspace)
        // Sets the child's own cwd inside the granted workspace - left unset, it would inherit
        // this JVM's own cwd, which the sandbox has no rule for at all.
        .workingDirectory(workspace.toFile())
        .logFile(logFile.toFile())
        // Rule order is priority order (first = highest priority) - the deny must be listed
        // before the broader allow it's meant to carve an exception out of.
        .filesystemRule(FilesystemRule.deny(deniedFile.toString(), "test: denied file", AccessKind.READ))
        .filesystemRule(FilesystemRule.allow(workspace.toString(), "test: workspace root itself, for traversal", AccessKind.READ))
        .filesystemRule(FilesystemRule.allow(workspace + "/**", "test: everything inside the workspace", AccessKind.READ, AccessKind.WRITE))
        .build();

    try (
        SandboxedProcess process = new OsSandboxedProcessLauncher()
            .launch(request)
    ) {
      boolean finished = process.waitFor(LAUNCH_TIMEOUT);
      String output = Files.readString(logFile);
      assertThat(finished)
          .as("sandboxed process did not finish in time, output so far: %s", output)
          .isTrue();
      String[] sections = output.split(SECTION_SEPARATOR, 2);
      assertThat(sections[0])
          .as("the allow rule must let this read through: %s", output)
          .contains("hello from an allowed file");
      assertThat(sections[1])
          .as("the deny rule must block this read: %s", output)
          .doesNotContain("TOP-SECRET");
    }
  }
}
