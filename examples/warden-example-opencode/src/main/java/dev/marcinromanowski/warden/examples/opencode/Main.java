package dev.marcinromanowski.warden.examples.opencode;

import dev.marcinromanowski.warden.api.AccessKind;
import dev.marcinromanowski.warden.api.FilesystemRule;
import dev.marcinromanowski.warden.api.NetworkRule;
import dev.marcinromanowski.warden.api.SandboxLaunchRequest;
import dev.marcinromanowski.warden.api.SandboxedProcess;
import dev.marcinromanowski.warden.core.OsSandboxedProcessLauncher;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Optional;

// Sandboxes a real OpenCode (https://opencode.ai) install to show warden wrapping a non-trivial
// third-party CLI with a realistic filesystem+network rule set. Needs a real `opencode` executable
// and, to do anything beyond print its version, real provider API credentials of your own.
// Run it: ./gradlew :examples:warden-example-opencode:run
public final class Main {

  private static final Duration LAUNCH_TIMEOUT = Duration.ofSeconds(30);
  private static final String OPENCODE_PATH_FLAG = "--opencode-path";

  private Main() {
  }

  public static void main(String[] args) throws IOException {
    Path opencodeExecutable = resolveOpencodeExecutable(args);
    // toRealPath() matters here: on macOS, the system temp directory commonly lands under
    // /var/folders/..., itself a symlink to /private/var/folders/... - Seatbelt enforces against
    // the kernel-resolved canonical path, not the symlinked one, so a rule built from the raw
    // path would silently never match.
    Path workspace = Files.createTempDirectory("warden-example-opencode-")
        .toRealPath();
    Path logFile = workspace.resolve("output.log");

    SandboxLaunchRequest request = SandboxLaunchRequest.command(opencodeExecutable.toString(), "--version")
        .sandboxRoot(workspace)
        // Sets the child's own cwd inside the granted workspace - left unset, it would inherit
        // this JVM's own cwd, which the sandbox has no rule for at all.
        .workingDirectory(workspace.toFile())
        .logFile(logFile.toFile())
        // Rule order is priority order (first = highest priority) - the denies must be listed
        // before the broader allow they're meant to carve exceptions out of.
        .filesystemRule(FilesystemRule.denyRead("**/.env*", "example: never let a credential file be read"))
        .filesystemRule(FilesystemRule.denyRead("**/id_rsa*", "example: never let an SSH private key be read"))
        .filesystemRule(FilesystemRule.allow(workspace.toString(), "example: workspace root itself, for traversal", AccessKind.READ))
        .filesystemRule(FilesystemRule.allowReadWrite(workspace + "/**", "example: the workspace OpenCode operates on"))
        .networkRule(NetworkRule.allowHost("api.example.com", "example: an LLM provider host"))
        .build();

    System.out.println("Launching a sandboxed OpenCode (" + opencodeExecutable + ") in " + workspace + " ...");
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
    }
  }

  private static Path resolveOpencodeExecutable(String[] args) {
    Optional<String> explicitPath = explicitOpencodePath(args);
    return explicitPath.map(Path::of)
        .orElseGet(() -> resolveFromPath("opencode")
            .orElseThrow(() -> new IllegalStateException(
                "opencode not found on PATH and no " + OPENCODE_PATH_FLAG + " argument was given -"
                    + " install OpenCode (see this module's README) or pass " + OPENCODE_PATH_FLAG
                    + " <path>."
            )));
  }

  private static Optional<String> explicitOpencodePath(String[] args) {
    for (int index = 0; index < args.length - 1; index++) {
      if (OPENCODE_PATH_FLAG.equals(args[index])) {
        return Optional.of(args[index + 1]);
      }
    }
    return Optional.empty();
  }

  private static Optional<Path> resolveFromPath(String name) {
    String pathValue = System.getenv("PATH");
    if (pathValue == null || pathValue.isBlank()) {
      return Optional.empty();
    }
    for (String entry : pathValue.split(File.pathSeparator)) {
      if (entry.isBlank()) {
        continue;
      }
      Path candidate = Path.of(entry)
          .resolve(name)
          .toAbsolutePath()
          .normalize();
      if (Files.isExecutable(candidate)) {
        return Optional.of(candidate);
      }
    }
    return Optional.empty();
  }
}
