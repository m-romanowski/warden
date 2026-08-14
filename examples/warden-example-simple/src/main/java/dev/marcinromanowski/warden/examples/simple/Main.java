package dev.marcinromanowski.warden.examples.simple;

import dev.marcinromanowski.warden.api.AccessKind;
import dev.marcinromanowski.warden.api.FilesystemRule;
import dev.marcinromanowski.warden.api.SandboxLaunchRequest;
import dev.marcinromanowski.warden.api.SandboxedProcess;
import dev.marcinromanowski.warden.core.OsSandboxedProcessLauncher;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

// Minimal end-to-end usage: sandbox a plain shell command with a broad workspace allow and one
// narrower deny, print the result.
// Run it: ./gradlew :examples:warden-example-simple:run
public final class Main {

  private static final Duration LAUNCH_TIMEOUT = Duration.ofSeconds(20);

  private Main() {
  }

  public static void main(String[] args) throws IOException {
    // toRealPath() matters here: on macOS, the system temp directory commonly lands under
    // /var/folders/..., itself a symlink to /private/var/folders/... - Seatbelt enforces against
    // the kernel-resolved canonical path, not the symlinked one, so a rule built from the raw
    // path would silently never match.
    Path workspace = Files.createTempDirectory("warden-example-simple-")
        .toRealPath();
    Path allowedFile = workspace.resolve("allowed.txt");
    Path deniedFile = workspace.resolve("denied.txt");
    Files.writeString(allowedFile, "hello from a file the sandbox allows reading");
    Files.writeString(deniedFile, "TOP-SECRET - the sandbox should deny reading this");
    // Inside the workspace too, not a separate system temp file - a caller's own log/output file
    // needs an explicit grant just like any other path the sandboxed process touches, and putting
    // it under the already-granted workspace root is the simplest way to get that for free.
    Path logFile = workspace.resolve("output.log");

    SandboxLaunchRequest request = SandboxLaunchRequest.command(
        "/bin/sh", "-c",
        "echo '--- allowed file ---'; cat " + allowedFile
            + "; echo; echo '--- denied file ---'; cat " + deniedFile
    )
        .sandboxRoot(workspace)
        // Sets the child's own cwd inside the granted workspace - left unset, it would inherit
        // this JVM's own cwd, which the sandbox has no rule for at all.
        .workingDirectory(workspace.toFile())
        .logFile(logFile.toFile())
        // Rule order is priority order (first = highest priority) - the deny must be listed
        // before the broader allow it's meant to carve an exception out of.
        .filesystemRule(FilesystemRule.deny(deniedFile.toString(), "example: denied file", AccessKind.READ))
        .filesystemRule(
            FilesystemRule.allow(workspace.toString(), "example: workspace root itself, for traversal", AccessKind.READ)
        )
        .filesystemRule(
            FilesystemRule.allow(
                workspace + "/**", "example: everything inside the workspace", AccessKind.READ, AccessKind.WRITE
            )
        )
        .build();

    System.out.println("Launching a sandboxed shell in " + workspace + " ...");
    try (
        SandboxedProcess process = new OsSandboxedProcessLauncher()
            .launch(request)
    ) {
      boolean finished = process.waitFor(LAUNCH_TIMEOUT);
      if (!finished) {
        System.out.println("Sandboxed process did not finish in time.");
        return;
      }
      System.out.println(Files.readString(logFile));
      System.out.println("(the second cat should have failed - the deny rule blocked it)");
    }
  }
}
