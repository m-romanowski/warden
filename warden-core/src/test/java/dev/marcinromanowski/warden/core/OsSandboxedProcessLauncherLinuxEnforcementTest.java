package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;

import dev.marcinromanowski.warden.api.AccessKind;
import dev.marcinromanowski.warden.api.FilesystemRule;
import dev.marcinromanowski.warden.api.SandboxLaunchRequest;
import dev.marcinromanowski.warden.api.SandboxedProcess;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

// AppArmorProfile load, AppArmorBwrapAttachment's px stacking rule, and bwrap's own network/mount
// setup all composed together through the real public entry point. Not a duplicate of
// AppArmorProfileGeneratorEnforcementTest: that one drives aa-exec directly against a generated
// profile, with no bwrap and no stacking attachment in the loop at all - it cannot catch a bug in
// the stacking rule, the unique-binary handling, or the argv assembly itself, all of which are new
// here. Requires passwordless sudo for apparmor_parser, same convention as the sibling test.
@EnabledOnOs(OS.LINUX)
class OsSandboxedProcessLauncherLinuxEnforcementTest {

  private static final Duration LAUNCH_TIMEOUT = Duration.ofSeconds(20);
  private static final String SECTION_SEPARATOR = "---SEP---";

  @Test
  void deniesCredentialPatternWhilePermittingOtherWorkspaceReadsThroughTheFullBwrapAppArmorChain(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path workspaceRoot = tempDirParameter.toRealPath();
    Path secret = workspaceRoot.resolve("secret.pem");
    Files.writeString(secret, "TOP-SECRET");
    Path readme = workspaceRoot.resolve("readme.txt");
    Files.writeString(readme, "hello world");
    Path logFile = Files.createTempFile("warden-linux-enforcement-", ".log");

    SandboxLaunchRequest request = SandboxLaunchRequest.command(
        "/bin/sh", "-c",
        "cat " + secret + " 2>&1; echo " + SECTION_SEPARATOR + "; cat " + readme + " 2>&1"
    )
        .sandboxRoot(workspaceRoot)
        .logFile(logFile.toFile())
        .filesystemRule(FilesystemRule.allow(workspaceRoot + "/**", "workspace read", AccessKind.READ))
        .filesystemRule(FilesystemRule.deny(secret.toString(), "credential carve-out", AccessKind.READ))
        .build();

    try (
        SandboxedProcess process = new OsSandboxedProcessLauncher()
            .launch(request)
    ) {
      boolean finished = process.waitFor(LAUNCH_TIMEOUT);
      String output = Files.readString(logFile);
      assertThat(finished)
          .as("sandboxed process did not terminate in time, output so far: %s", output)
          .isTrue();
      String[] sections = output.split(SECTION_SEPARATOR, 2);
      assertThat(sections[0])
          .as("credential-path DENY carve-out must be enforced through the full bwrap+AppArmor"
              + " chain, not just a bare aa-exec: %s", output)
          .doesNotContain("TOP-SECRET");
      assertThat(sections[1])
          .as("a workspace read outside the DENY carve-out must still succeed: %s", output)
          .contains("hello world");
    }
  }

  @Test
  void isolatesNetworkEgressThroughTheFullBwrapAppArmorChain(@TempDir Path tempDirParameter) throws IOException {
    Path workspaceRoot = tempDirParameter.toRealPath();
    Path logFile = Files.createTempFile("warden-linux-enforcement-network-", ".log");

    SandboxLaunchRequest request = SandboxLaunchRequest.command(
        "/bin/sh", "-c",
        "curl -s -m 3 http://example.com > /dev/null 2>&1; echo CURL_EXIT:$?"
    )
        .sandboxRoot(workspaceRoot)
        .logFile(logFile.toFile())
        .build();

    try (
        SandboxedProcess process = new OsSandboxedProcessLauncher()
            .launch(request)
    ) {
      boolean finished = process.waitFor(LAUNCH_TIMEOUT);
      String output = Files.readString(logFile);
      assertThat(finished)
          .as("sandboxed process did not terminate in time, output so far: %s", output)
          .isTrue();
      assertThat(output)
          .as("with no networkRules supplied, egress must default-deny end to end through the"
              + " full chain: bwrap's --unshare-net leaves only `lo` reachable directly, and curl's"
              + " HTTP_PROXY env var (pointing at the in-sandbox bridge) routes the request through"
              + " SandboxProxyServer instead, which itself denies an unmatched host by default - so"
              + " this must fail either way, never succeed: %s", output)
          .doesNotContain("CURL_EXIT:0");
    }
  }
}
