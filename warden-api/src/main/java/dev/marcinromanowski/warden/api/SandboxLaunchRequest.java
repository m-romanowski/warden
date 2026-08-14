package dev.marcinromanowski.warden.api;

import java.io.File;
import java.net.URI;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A fully-specified request to launch a command inside an OS-level sandbox. Build one with
 * {@link #command(String...)} or {@link #command(List)}.
 *
 * @param command the argv to launch, never empty
 * @param workingDirectory the child process's own working directory, or {@code null} to inherit
 *     the launching JVM's own
 * @param environmentVariables environment variables to set on the child process
 * @param logFile where the child process's stdout/stderr are redirected
 * @param filesystemRules filesystem allow/deny rules, in priority order (first entry wins)
 * @param networkRules network egress allow/deny rules, in priority order (first entry wins)
 * @param sandboxRoot the workspace root the sandbox is scoped around
 * @param controlPlaneHint a hint URI for a control-plane endpoint the child process exposes, if
 *     any - see {@link SandboxedProcess#controlPlaneUri()} for why the resolved URI can differ
 * @param networkAskHandler resolves an unmatched network-egress request live, if supplied
 */
public record SandboxLaunchRequest(
    List<String> command,
    File workingDirectory,
    Map<String, String> environmentVariables,
    File logFile,
    List<FilesystemRule> filesystemRules,
    List<NetworkRule> networkRules,
    Path sandboxRoot,
    Optional<URI> controlPlaneHint,
    Optional<NetworkAskHandler> networkAskHandler
) {

  /** Validates and normalizes the components above. */
  public SandboxLaunchRequest {
    command = List.copyOf(Preconditions.nonNull(command, "command"));
    if (command.isEmpty()) {
      throw new IllegalArgumentException("command must not be empty");
    }
    environmentVariables = normalizedEnvironment(environmentVariables);
    logFile = Preconditions.nonNull(logFile, "logFile");
    filesystemRules = List.copyOf(Preconditions.nonNull(filesystemRules, "filesystemRules"));
    networkRules = List.copyOf(Preconditions.nonNull(networkRules, "networkRules"));
    sandboxRoot = Preconditions.nonNull(sandboxRoot, "sandboxRoot")
        .toAbsolutePath()
        .normalize();
    controlPlaneHint = Preconditions.nonNull(controlPlaneHint, "controlPlaneHint");
    networkAskHandler = Preconditions.nonNull(networkAskHandler, "networkAskHandler");
  }

  /** Returns a defensive copy of the environment variables. */
  @Override
  public Map<String, String> environmentVariables() {
    return Map.copyOf(environmentVariables);
  }

  /** Starts building a request for the given argv. */
  public static SandboxLaunchRequestBuilder command(String... argv) {
    return new SandboxLaunchRequestBuilder(List.of(argv));
  }

  /** Starts building a request for the given argv. */
  public static SandboxLaunchRequestBuilder command(List<String> argv) {
    return new SandboxLaunchRequestBuilder(argv);
  }

  private static Map<String, String> normalizedEnvironment(Map<String, String> environmentVariables) {
    Map<String, String> normalized = new LinkedHashMap<>();
    for (Map.Entry<String, String> entry : Preconditions.nonNull(environmentVariables, "environmentVariables")
        .entrySet()) {
      normalized.put(
          Preconditions.nonBlank(entry.getKey(), "environment variable name"),
          Preconditions.nonBlank(entry.getValue(), "environment variable value")
      );
    }
    return Map.copyOf(normalized);
  }
}
