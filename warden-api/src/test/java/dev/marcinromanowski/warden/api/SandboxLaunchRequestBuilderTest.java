package dev.marcinromanowski.warden.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.File;
import java.nio.file.Path;
import java.util.Set;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;

class SandboxLaunchRequestBuilderTest {

  private static final String COMMAND_NAME = "agent";
  private static final String WORKSPACE_ROOT = "/tmp/workspace";

  @Test
  void buildsWithHelpersForTheCommonCase() {
    SandboxLaunchRequest request = SandboxLaunchRequest.command(COMMAND_NAME, "run")
        .workingDirectory(new File("/tmp/work"))
        .sandboxRoot(Path.of(WORKSPACE_ROOT))
        .logFile(new File("/tmp/work/launch.log"))
        .allowFilesystem(RulePath.tree("/tmp/workspace"), "workspace root", AccessKind.READ, AccessKind.WRITE)
        .denyFilesystem(RulePath.glob("**/*.pem"), "credential material", AccessKind.READ, AccessKind.WRITE)
        .allowNetwork("api.example.com", "remote service")
        .build();

    assertThat(request.command())
        .containsExactly(COMMAND_NAME, "run");
    assertThat(request.filesystemRules())
        .containsExactly(
            FilesystemRule.allow(RulePath.tree("/tmp/workspace"), "workspace root", AccessKind.READ, AccessKind.WRITE),
            FilesystemRule.deny(RulePath.glob("**/*.pem"), "credential material", AccessKind.READ, AccessKind.WRITE)
        );
    assertThat(request.networkRules())
        .containsExactly(NetworkRule.allowHost("api.example.com", "remote service"));
    assertThat(request.pathMounts())
        .isEmpty();
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
  void collectsDeclaredMountsInDeclarationOrder() {
    SandboxLaunchRequest request = requestWithMounts(
        builder -> builder.mountReadOnly(Path.of("/opt/toolchain"))
            .mountReadWrite(Path.of("/var/lib/agent-state"))
            .pathMount(PathMount.readOnly(Path.of("/etc/agent")))
    );

    assertThat(request.pathMounts())
        .containsExactly(
            PathMount.readOnly(Path.of("/opt/toolchain")),
            PathMount.readWrite(Path.of("/var/lib/agent-state")),
            PathMount.readOnly(Path.of("/etc/agent"))
        );
  }

  @Test
  void normalizesDeclaredMountPaths() {
    SandboxLaunchRequest request =
        requestWithMounts(builder -> builder.mountReadOnly(Path.of("/opt/toolchain/../shared")));

    assertThat(request.pathMounts())
        .containsExactly(PathMount.readOnly(Path.of("/opt/shared")));
  }

  @Test
  void acceptsDeclaredMountsNestedInsideTheSandboxRoot() {
    SandboxLaunchRequest request =
        requestWithMounts(builder -> builder.mountReadWrite(Path.of(WORKSPACE_ROOT + "/cache")));

    assertThat(request.pathMounts())
        .containsExactly(PathMount.readWrite(Path.of(WORKSPACE_ROOT + "/cache")));
  }

  @Test
  void rejectsDeclaredMountsEqualToTheSandboxRoot() {
    assertThatThrownBy(() -> requestWithMounts(builder -> builder.mountReadWrite(Path.of(WORKSPACE_ROOT))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining(WORKSPACE_ROOT);
  }

  @Test
  void rejectsDeclaredMountsAboveTheSandboxRoot() {
    assertThatThrownBy(() -> requestWithMounts(builder -> builder.mountReadOnly(Path.of("/tmp"))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("/tmp");
  }

  @Test
  void rejectsTwoDeclaredMountsOfTheSamePath() {
    assertThatThrownBy(this::buildWithDuplicateMount)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("duplicate path mount /opt/toolchain");
  }

  @Test
  void filesystemRuleAcceptsAskDecision() {
    FilesystemRule rule = new FilesystemRule(
        RulePath.glob("**/*.env"), Set.of(AccessKind.READ), Decision.ASK, "explicit ask example"
    );

    assertThat(rule.decision())
        .isEqualTo(Decision.ASK);
  }

  private void buildWithDuplicateMount() {
    requestWithMounts(
        builder -> builder.mountReadOnly(Path.of("/opt/toolchain"))
            .mountReadWrite(Path.of("/opt/toolchain"))
    );
  }

  private static SandboxLaunchRequest requestWithMounts(UnaryOperator<SandboxLaunchRequestBuilder> mounts) {
    SandboxLaunchRequestBuilder builder = SandboxLaunchRequest.command(COMMAND_NAME)
        .sandboxRoot(Path.of(WORKSPACE_ROOT))
        .logFile(new File("/tmp/launch.log"));
    return mounts.apply(builder)
        .build();
  }

  private void buildWithoutLogFile() {
    SandboxLaunchRequest.command(COMMAND_NAME)
        .sandboxRoot(Path.of(WORKSPACE_ROOT))
        .build();
  }

  private void buildWithoutSandboxRoot() {
    SandboxLaunchRequest.command(COMMAND_NAME)
        .logFile(new File("/tmp/launch.log"))
        .build();
  }
}
