package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.marcinromanowski.warden.api.AccessKind;
import dev.marcinromanowski.warden.api.FilesystemRule;
import dev.marcinromanowski.warden.api.PathMount;
import dev.marcinromanowski.warden.api.RulePath;
import dev.marcinromanowski.warden.api.SandboxLaunchRequest;
import dev.marcinromanowski.warden.api.SandboxRuleRejectedException;
import dev.marcinromanowski.warden.api.SandboxedProcess;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

// warden's own AppArmor policy, its px stacking transition, and bwrap's own network/mount setup
// all composed together through the real public entry point. Not a duplicate of
// AppArmorProfileGeneratorEnforcementTest: that one drives aa-exec directly against a generated
// profile, with no bwrap and no stacking transition in the loop at all - it cannot catch a bug in
// the transition, the unique-binary handling, or the argv assembly itself.
//
// Every launch here execs a per-session copy of bwrap, never the distribution's own binary, so no
// vendor profile attaches to it and every verdict below is warden's own policy doing the work. That
// is what makes these tests the guard against the case they were written for: where an
// administrator has turned the userns restriction off, a caller-supplied bwrap that no profile
// covers runs its payload unconfined, and every deny asserted here would silently pass through.
// Requires the one-time install step, same convention as the sibling test.
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
        .filesystemRule(FilesystemRule.allow(RulePath.tree(workspaceRoot), "workspace read", AccessKind.READ))
        .filesystemRule(FilesystemRule.deny(RulePath.literal(secret), "credential carve-out", AccessKind.READ))
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
  void deniesAndPermitsTheSameWayUnderAWorkspacePathWithASpace(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path workspaceRoot = Files.createDirectories(
        tempDirParameter.toRealPath()
            .resolve("my project")
    );
    Path secret = workspaceRoot.resolve("secret.pem");
    Files.writeString(secret, "TOP-SECRET");
    Path readme = workspaceRoot.resolve("readme.txt");
    Files.writeString(readme, "hello world");
    Path logFile = Files.createTempFile("warden-linux-enforcement-spaced-", ".log");

    SandboxLaunchRequest request = SandboxLaunchRequest.command(
        "/bin/sh", "-c",
        "cat '" + secret + "' 2>&1; echo " + SECTION_SEPARATOR + "; cat '" + readme + "' 2>&1"
    )
        .sandboxRoot(workspaceRoot)
        .logFile(logFile.toFile())
        .filesystemRule(FilesystemRule.allow(RulePath.tree(workspaceRoot), "workspace read", AccessKind.READ))
        .filesystemRule(FilesystemRule.deny(RulePath.literal(secret), "credential carve-out", AccessKind.READ))
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
          .as("the deny carve-out must hold under a path that needs escaping: %s", output)
          .doesNotContain("TOP-SECRET");
      assertThat(sections[1])
          .as("and the allow must still reach the rest of the workspace: %s", output)
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

  @Test
  void pathOutsideTheSandboxRootIsAbsentWhenNoMountDeclaresIt(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path root = tempDirParameter.toRealPath();
    Path workspaceRoot = Files.createDirectory(root.resolve("workspace"));
    Path outside = Files.createDirectory(root.resolve("outside"));
    Path data = outside.resolve("data.txt");
    Files.writeString(data, "OUTSIDE-CONTENT");
    Path logFile = Files.createTempFile("warden-mount-absent-", ".log");

    SandboxLaunchRequest request = SandboxLaunchRequest.command("/bin/sh", "-c", "cat " + data + " 2>&1")
        .sandboxRoot(workspaceRoot)
        .logFile(logFile.toFile())
        .filesystemRule(FilesystemRule.allowReadWrite(RulePath.tree(outside), "outside allowed by rule alone"))
        .build();

    assertThat(runToCompletion(request, logFile))
        .as("an allow rule cannot make an unmounted path exist inside the sandbox")
        .doesNotContain("OUTSIDE-CONTENT");
  }

  @Test
  void declaredReadWriteMountMakesAnOutsidePathReachable(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path root = tempDirParameter.toRealPath();
    Path workspaceRoot = Files.createDirectory(root.resolve("workspace"));
    Path outside = Files.createDirectory(root.resolve("outside"));
    Path data = outside.resolve("data.txt");
    Files.writeString(data, "OUTSIDE-CONTENT");
    Path written = outside.resolve("written.txt");
    Path logFile = Files.createTempFile("warden-mount-readwrite-", ".log");

    SandboxLaunchRequest request = SandboxLaunchRequest.command(
        "/bin/sh", "-c",
        "cat " + data + " 2>&1; echo " + SECTION_SEPARATOR + "; echo WRITTEN > " + written + " 2>&1 && cat " + written
    )
        .sandboxRoot(workspaceRoot)
        .logFile(logFile.toFile())
        .filesystemRule(FilesystemRule.allowReadWrite(RulePath.tree(outside), "outside allowed"))
        .pathMount(PathMount.readWrite(outside))
        .build();

    String output = runToCompletion(request, logFile);

    assertThat(output)
        .contains("OUTSIDE-CONTENT")
        .contains("WRITTEN");
  }

  @Test
  void declaredReadOnlyMountRefusesWritesEvenWhenTheRulesAllowThem(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path root = tempDirParameter.toRealPath();
    Path workspaceRoot = Files.createDirectory(root.resolve("workspace"));
    Path outside = Files.createDirectory(root.resolve("outside"));
    Path data = outside.resolve("data.txt");
    Files.writeString(data, "OUTSIDE-CONTENT");
    Path logFile = Files.createTempFile("warden-mount-readonly-", ".log");

    SandboxLaunchRequest request = SandboxLaunchRequest.command(
        "/bin/sh", "-c",
        "cat " + data + " 2>&1; echo " + SECTION_SEPARATOR + "; echo WRITTEN > " + outside.resolve("written.txt") + " 2>&1"
    )
        .sandboxRoot(workspaceRoot)
        .logFile(logFile.toFile())
        .filesystemRule(FilesystemRule.allowReadWrite(RulePath.tree(outside), "rules allow, the mount does not"))
        .pathMount(PathMount.readOnly(outside))
        .build();

    String output = runToCompletion(request, logFile);
    String[] sections = output.split(SECTION_SEPARATOR, 2);

    assertThat(sections[0])
        .contains("OUTSIDE-CONTENT");
    assertThat(sections[1])
        .doesNotContain("WRITTEN");
  }

  @Test
  void wardensOwnSessionDirectoryIsNoPlaceToStageAndRunAnExecutable(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path workspaceRoot = tempDirParameter.toRealPath();
    Path logFile = Files.createTempFile("warden-session-staging-", ".log");
    String alias = AppArmorProfileGenerator.BWRAP_BRIDGE_DIRECTORY;
    String script = "SESSION=" + alias + ";"
        + " head -c 1 \"$SESSION/" + BwrapSessionPaths.BRIDGE_SCRIPT_FILE_NAME + "\" > /dev/null 2>&1"
        + " && echo FOUND;"
        + " cp /bin/sh \"$SESSION/staged\" 2>&1 && echo STAGED;"
        + " \"$SESSION/staged\" -c 'echo RAN' 2>&1;"
        + " ls -d " + BwrapSessionStore.SESSIONS_DIRECTORY + "/* > /dev/null 2>&1 && echo NAMED";

    SandboxLaunchRequest request = SandboxLaunchRequest.command("/bin/sh", "-c", script)
        .sandboxRoot(workspaceRoot)
        .logFile(logFile.toFile())
        .filesystemRule(FilesystemRule.allow(RulePath.literal("/tmp"), "list the temp root, as an ancestor grant does", AccessKind.READ))
        .filesystemRule(FilesystemRule.allow(RulePath.tree("/tmp"), "read the temp root", AccessKind.READ))
        .build();

    String output = runToCompletion(request, logFile);

    assertThat(output)
        .as("the session directory has to be reachable under its bridge alias for this to be"
            + " testing anything: %s", output)
        .contains("FOUND");
    assertThat(output)
        .as("warden must not grant write over its own session directory: %s", output)
        .doesNotContain("STAGED");
    assertThat(output)
        .as("and must not grant execute there either: %s", output)
        .doesNotContain("RAN");
    assertThat(output)
        .as("nor may the payload name warden's own state directory, which is what stops a leaked"
            + " profile from being a userns grant to whoever recreates the path: %s", output)
        .doesNotContain("NAMED");
  }

  @Test
  void theInSandboxBridgeCanReachTheProxySocketWardenBoundForIt(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path workspaceRoot = tempDirParameter.toRealPath();
    Path logFile = Files.createTempFile("warden-bridge-connect-", ".log");
    String proxySocket = AppArmorProfileGenerator.BWRAP_BRIDGE_DIRECTORY + "/proxy.sock";

    SandboxLaunchRequest request = SandboxLaunchRequest.command(
        "/bin/sh", "-c", "socat -u OPEN:/dev/null UNIX-CONNECT:" + proxySocket + " && echo CONNECTED"
    )
        .sandboxRoot(workspaceRoot)
        .logFile(logFile.toFile())
        .build();

    assertThat(runToCompletion(request, logFile))
        .as("the confined bridge must be able to connect to warden's own proxy socket")
        .contains("CONNECTED");
  }

  @Test
  void refusesTheLaunchWhenTheDenyCoversWardensOwnReservedPaths(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path workspaceRoot = tempDirParameter.toRealPath();
    Path logFile = Files.createTempFile("warden-reserved-refusal-", ".log");

    SandboxLaunchRequest request = SandboxLaunchRequest.command("/bin/sh", "-c", "echo UNREACHED")
        .sandboxRoot(workspaceRoot)
        .logFile(logFile.toFile())
        .filesystemRule(FilesystemRule.deny(RulePath.glob("**/tmp/**"), "a credential blacklist shape", AccessKind.READ))
        .build();

    assertThatThrownBy(() -> new OsSandboxedProcessLauncher().launch(request))
        .isInstanceOf(SandboxRuleRejectedException.class)
        .as("the refusal must name the caller's own rule, which is the thing they can edit")
        .hasMessageContaining("**/tmp/**");
  }

  @Test
  void concurrentSessionsEachEnforceTheirOwnRulesAndNeitherSeesTheOthers(
      @TempDir Path tempDirParameter
  ) throws Exception {
    Path root = tempDirParameter.toRealPath();
    Path firstWorkspace = Files.createDirectory(root.resolve("first"));
    Path secondWorkspace = Files.createDirectory(root.resolve("second"));
    Files.writeString(firstWorkspace.resolve("data.txt"), "FIRST-CONTENT");
    Files.writeString(secondWorkspace.resolve("data.txt"), "SECOND-CONTENT");

    try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
      Future<String> first = executor.submit(() -> runSessionScopedTo(firstWorkspace, secondWorkspace, "first"));
      Future<String> second = executor.submit(() -> runSessionScopedTo(secondWorkspace, firstWorkspace, "second"));
      String firstOutput = first.get(LAUNCH_TIMEOUT.toSeconds() * 2, TimeUnit.SECONDS);
      String secondOutput = second.get(LAUNCH_TIMEOUT.toSeconds() * 2, TimeUnit.SECONDS);

      assertThat(firstOutput)
          .as("nothing is shared between two sessions - not a profile name, not a bwrap path, not a"
              + " file - and this is the guard against what made sharing impossible: two profiles"
              + " attached to one exec path attach neither, and both launches then run unconfined."
              + " A session must read its own workspace: %s", firstOutput)
          .contains("FIRST-CONTENT")
          .as("and must not read a concurrent session's: %s", firstOutput)
          .doesNotContain("SECOND-CONTENT");
      assertThat(secondOutput)
          .as("a session must read its own workspace: %s", secondOutput)
          .contains("SECOND-CONTENT")
          .as("and must not read a concurrent session's: %s", secondOutput)
          .doesNotContain("FIRST-CONTENT");
    }
  }

  private static String runSessionScopedTo(Path own, Path other, String name) throws IOException {
    Path logFile = Files.createTempFile("warden-concurrent-" + name + "-", ".log");
    SandboxLaunchRequest request = SandboxLaunchRequest.command(
        "/bin/sh", "-c",
        "cat " + own.resolve("data.txt") + " 2>&1; cat " + other.resolve("data.txt") + " 2>&1"
    )
        .sandboxRoot(own)
        .logFile(logFile.toFile())
        .filesystemRule(FilesystemRule.allow(RulePath.tree(own), "this session's own workspace", AccessKind.READ))
        .pathMount(PathMount.readOnly(other))
        .build();
    return runToCompletion(request, logFile);
  }

  private static String runToCompletion(SandboxLaunchRequest request, Path logFile) throws IOException {
    try (
        SandboxedProcess process = new OsSandboxedProcessLauncher()
            .launch(request)
    ) {
      boolean finished = process.waitFor(LAUNCH_TIMEOUT);
      String output = Files.readString(logFile);
      assertThat(finished)
          .as("sandboxed process did not terminate in time, output so far: %s", output)
          .isTrue();
      return output;
    }
  }
}
