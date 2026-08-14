package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;

import dev.marcinromanowski.warden.api.AccessKind;
import dev.marcinromanowski.warden.api.Decision;
import dev.marcinromanowski.warden.api.FilesystemRule;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

// Runs generated profiles through the real /usr/bin/sandbox-exec rather than only asserting on
// generated-string substrings. Exists specifically because a string-only test suite can stay
// fully green while the generator emits rules in an order that lets SBPL's real (last-match-wins)
// semantics defeat every credential-path deny carve-out - a bug only a real sandbox-exec run
// against the generated profile can catch. macOS-only: sandbox-exec doesn't exist elsewhere.
//
// Every rule pattern and path handed to sandbox-exec is built from Path.toRealPath(), not the
// raw @TempDir path: on macOS /var (and therefore JUnit's default temp root) is a symlink to
// /private/var, and the kernel canonicalizes through that symlink before matching a sandbox
// profile's patterns - a rule built from the non-canonical path silently never matches anything.
@EnabledOnOs(OS.MAC)
class SeatbeltProfileGeneratorEnforcementTest {

  private static final int PROXY_PORT = 18080;
  private static final String CAT_EXECUTABLE = "/bin/cat";
  private static final Duration WAIT_TIMEOUT = Duration.ofSeconds(10);

  @Test
  void denyCarveOutInsideBroaderAllowActuallyDeniesTheRead(@TempDir Path tempDirParameter) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path secret = tempDir.resolve("secret.txt");
    Files.writeString(secret, "TOP-SECRET");
    List<FilesystemRule> rules = List.of(
        allowCatExecutable(),
        denyRule(secret.toString()),
        allowRule(tempDir + "/**")
    );

    SandboxExecResult result = runSandboxed(tempDir, rules, CAT_EXECUTABLE, secret.toString());

    assertThat(result.exitCode())
        .as("reading a DENY-carved-out path inside a broader ALLOW must fail: %s", result.output())
        .isNotZero();
    assertThat(result.output())
        .doesNotContain("TOP-SECRET");
  }

  @Test
  void broaderAllowStillPermitsReadsOutsideTheDenyCarveOut(@TempDir Path tempDirParameter) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path secret = tempDir.resolve("secret.txt");
    Files.writeString(secret, "TOP-SECRET");
    Path readme = tempDir.resolve("readme.txt");
    Files.writeString(readme, "hello world");
    List<FilesystemRule> rules = List.of(
        allowCatExecutable(),
        denyRule(secret.toString()),
        allowRule(tempDir + "/**")
    );

    SandboxExecResult result = runSandboxed(tempDir, rules, CAT_EXECUTABLE, readme.toString());

    assertThat(result.exitCode())
        .as("reading a path not covered by the DENY must still succeed: %s", result.output())
        .isZero();
    assertThat(result.output())
        .contains("hello world");
  }

  @Test
  void narrowAllowCarvedOutOfBroaderDenyNowResolvesCorrectly(@TempDir Path tempDirParameter) throws IOException {
    // The shape a naive emission-order implementation gets backwards (see class-level comment):
    // a specific higher-priority ALLOW exception inside an otherwise denied glob.
    Path tempDir = tempDirParameter.toRealPath();
    Path envExample = tempDir.resolve(".env.example");
    Files.writeString(envExample, "PLACEHOLDER");
    Path envReal = tempDir.resolve(".env");
    Files.writeString(envReal, "REAL-SECRET");
    List<FilesystemRule> rules = List.of(
        allowCatExecutable(),
        rule(Set.of(AccessKind.READ), envExample.toString(), Decision.ALLOW),
        denyRule(tempDir + "/.env*")
    );

    SandboxExecResult exampleResult = runSandboxed(tempDir, rules, CAT_EXECUTABLE, envExample.toString());
    SandboxExecResult realResult = runSandboxed(tempDir, rules, CAT_EXECUTABLE, envReal.toString());

    assertThat(exampleResult.exitCode())
        .as("the narrower, higher-priority ALLOW exception must win: %s", exampleResult.output())
        .isZero();
    assertThat(exampleResult.output())
        .contains("PLACEHOLDER");
    assertThat(realResult.exitCode())
        .as("everything else still under the broader DENY: %s", realResult.output())
        .isNotZero();
    assertThat(realResult.output())
        .doesNotContain("REAL-SECRET");
  }

  private static FilesystemRule allowCatExecutable() {
    return allowRule(CAT_EXECUTABLE);
  }

  private static FilesystemRule allowRule(String pattern) {
    return rule(Set.of(AccessKind.READ), pattern, Decision.ALLOW);
  }

  private static FilesystemRule denyRule(String pattern) {
    return rule(Set.of(AccessKind.READ), pattern, Decision.DENY);
  }

  private static FilesystemRule rule(Set<AccessKind> kinds, String pattern, Decision decision) {
    return new FilesystemRule(pattern, kinds, decision, "test reason");
  }

  private static SandboxExecResult runSandboxed(
      Path tempDir,
      List<FilesystemRule> rules,
      String... command
  ) throws IOException {
    String profile = SeatbeltProfileGenerator.generate(rules, PROXY_PORT, Optional.empty());
    Path profilePath = tempDir.resolve("profile-" + UUID.randomUUID() + ".sb");
    Files.writeString(profilePath, profile);
    List<String> fullCommand = new ArrayList<>();
    fullCommand.add("/usr/bin/sandbox-exec");
    fullCommand.add("-f");
    fullCommand.add(profilePath.toString());
    fullCommand.addAll(List.of(command));
    Process process = new ProcessBuilder(fullCommand)
        .redirectErrorStream(true)
        .start();
    // Wait for exit BEFORE reading stdout: readAllBytes() blocks until EOF, which is only
    // guaranteed once the process is gone, so reading first would leave a hung sandbox-exec with
    // no way to time out or be force-killed at all.
    boolean finished = awaitTermination(process);
    if (!finished) {
      process.destroyForcibly();
      throw new AssertionError("sandbox-exec did not complete in time");
    }
    String output = new String(
        process.getInputStream()
            .readAllBytes(),
        StandardCharsets.UTF_8
    );
    return new SandboxExecResult(process.exitValue(), output);
  }

  private static boolean awaitTermination(Process process) {
    try {
      return process.waitFor(WAIT_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
    } catch (InterruptedException _) {
      Thread.currentThread()
          .interrupt();
      return false;
    }
  }
}
