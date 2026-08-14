package dev.marcinromanowski.warden.api;

import java.io.File;
import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Builds a {@link SandboxLaunchRequest}. Start with {@link SandboxLaunchRequest#command(String...)}. */
public final class SandboxLaunchRequestBuilder {

  private final List<String> command;
  private File workDir;
  private final Map<String, String> environmentVariables = new LinkedHashMap<>();
  private File logOutputFile;
  private final List<FilesystemRule> filesystemRules = new ArrayList<>();
  private final List<NetworkRule> networkRules = new ArrayList<>();
  private Path sandboxRootPath;
  private URI controlPlaneHintUri;
  private NetworkAskHandler askHandler;

  SandboxLaunchRequestBuilder(List<String> command) {
    this.command = List.copyOf(Preconditions.nonNull(command, "command"));
  }

  /** Sets the child process's own working directory. Left unset, it inherits the launching JVM's own. */
  public SandboxLaunchRequestBuilder workingDirectory(File dir) {
    this.workDir = dir;
    return this;
  }

  /** Adds the given environment variables to the child process's environment. */
  public SandboxLaunchRequestBuilder environment(Map<String, String> env) {
    this.environmentVariables.putAll(Preconditions.nonNull(env, "env"));
    return this;
  }

  /** Adds a single environment variable to the child process's environment. */
  public SandboxLaunchRequestBuilder environment(String key, String value) {
    this.environmentVariables.put(
        Preconditions.nonBlank(key, "key"),
        Preconditions.nonBlank(value, "value")
    );
    return this;
  }

  /** Sets where the child process's stdout/stderr are redirected. Required before {@link #build()}. */
  public SandboxLaunchRequestBuilder logFile(File file) {
    this.logOutputFile = Preconditions.nonNull(file, "file");
    return this;
  }

  /** Sets the workspace root the sandbox is scoped around. Required before {@link #build()}. */
  public SandboxLaunchRequestBuilder sandboxRoot(Path root) {
    this.sandboxRootPath = Preconditions.nonNull(root, "root");
    return this;
  }

  /** Sets a hint URI for a control-plane endpoint the child process exposes. */
  public SandboxLaunchRequestBuilder controlPlaneHint(URI uri) {
    this.controlPlaneHintUri = Preconditions.nonNull(uri, "uri");
    return this;
  }

  /** Sets the handler that resolves an unmatched network-egress request live. */
  public SandboxLaunchRequestBuilder networkAskHandler(NetworkAskHandler handler) {
    this.askHandler = Preconditions.nonNull(handler, "handler");
    return this;
  }

  /** Adds an {@code ALLOW} filesystem rule for the given pattern and access kinds. */
  public SandboxLaunchRequestBuilder allowFilesystem(String pattern, String reason, AccessKind... kinds) {
    return filesystemRule(FilesystemRule.allow(pattern, reason, kinds));
  }

  /** Adds a {@code DENY} filesystem rule for the given pattern and access kinds. */
  public SandboxLaunchRequestBuilder denyFilesystem(String pattern, String reason, AccessKind... kinds) {
    return filesystemRule(FilesystemRule.deny(pattern, reason, kinds));
  }

  /** Adds a filesystem rule. Rules are evaluated in the order they were added - first match wins. */
  public SandboxLaunchRequestBuilder filesystemRule(FilesystemRule rule) {
    this.filesystemRules.add(Preconditions.nonNull(rule, "rule"));
    return this;
  }

  /** Adds an {@code ALLOW} network rule for the given host, any port. */
  public SandboxLaunchRequestBuilder allowNetwork(String hostPattern, String reason) {
    return networkRule(NetworkRule.allowHost(hostPattern, reason));
  }

  /** Adds a {@code DENY} network rule for the given host, any port. */
  public SandboxLaunchRequestBuilder denyNetwork(String hostPattern, String reason) {
    return networkRule(new NetworkRule(hostPattern, Optional.empty(), Decision.DENY, reason));
  }

  /** Adds a network rule. Rules are evaluated in the order they were added - first match wins. */
  public SandboxLaunchRequestBuilder networkRule(NetworkRule rule) {
    this.networkRules.add(Preconditions.nonNull(rule, "rule"));
    return this;
  }

  /**
   * Builds the request.
   *
   * @throws IllegalStateException if {@link #logFile(File)} or {@link #sandboxRoot(Path)} was
   *     never called
   */
  public SandboxLaunchRequest build() {
    if (logOutputFile == null) {
      throw new IllegalStateException("logFile must be set before build() - call logFile(File)");
    }
    if (sandboxRootPath == null) {
      throw new IllegalStateException("sandboxRoot must be set before build() - call sandboxRoot(Path)");
    }
    return new SandboxLaunchRequest(
        command,
        workDir,
        environmentVariables,
        logOutputFile,
        filesystemRules,
        networkRules,
        sandboxRootPath,
        Optional.ofNullable(controlPlaneHintUri),
        Optional.ofNullable(askHandler)
    );
  }
}
