package dev.marcinromanowski.warden.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.File;
import java.nio.file.Path;
import java.util.Set;
import org.junit.jupiter.api.Test;

class SandboxLaunchRequestBuilderTest {

  private static final String COMMAND_NAME = "agent";

  @Test
  void buildsWithHelpersForTheCommonCase() {
    SandboxLaunchRequest request = SandboxLaunchRequest.command(COMMAND_NAME, "run")
        .workingDirectory(new File("/tmp/work"))
        .sandboxRoot(Path.of("/tmp/workspace"))
        .logFile(new File("/tmp/work/launch.log"))
        .allowFilesystem("/tmp/workspace/**", "workspace root", AccessKind.READ, AccessKind.WRITE)
        .denyFilesystem("**/*.pem", "credential material", AccessKind.READ, AccessKind.WRITE)
        .allowNetwork("api.example.com", "remote service")
        .build();

    assertThat(request.command())
        .containsExactly(COMMAND_NAME, "run");
    assertThat(request.filesystemRules())
        .containsExactly(
            FilesystemRule.allow("/tmp/workspace/**", "workspace root", AccessKind.READ, AccessKind.WRITE),
            FilesystemRule.deny("**/*.pem", "credential material", AccessKind.READ, AccessKind.WRITE)
        );
    assertThat(request.networkRules())
        .containsExactly(NetworkRule.allowHost("api.example.com", "remote service"));
    assertThat(request.controlPlaneHint())
        .isEmpty();
    assertThat(request.networkAskHandler())
        .isEmpty();
  }

  @Test
  void requiresLogFileBeforeBuild() {
    assertThatThrownBy(this::buildWithoutLogFile)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("logFile");
  }

  @Test
  void requiresSandboxRootBeforeBuild() {
    assertThatThrownBy(this::buildWithoutSandboxRoot)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("sandboxRoot");
  }

  @Test
  void filesystemRuleAcceptsAskDecision() {
    FilesystemRule rule = new FilesystemRule(
        "**/*.env", Set.of(AccessKind.READ), Decision.ASK, "explicit ask example"
    );

    assertThat(rule.decision())
        .isEqualTo(Decision.ASK);
  }

  private void buildWithoutLogFile() {
    SandboxLaunchRequest.command(COMMAND_NAME)
        .sandboxRoot(Path.of("/tmp/workspace"))
        .build();
  }

  private void buildWithoutSandboxRoot() {
    SandboxLaunchRequest.command(COMMAND_NAME)
        .logFile(new File("/tmp/launch.log"))
        .build();
  }
}
