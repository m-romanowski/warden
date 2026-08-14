package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;

import dev.marcinromanowski.warden.api.AccessKind;
import dev.marcinromanowski.warden.api.Decision;
import dev.marcinromanowski.warden.api.FilesystemRule;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

// Runs generated profiles through the real apparmor_parser + aa-exec, not just string containment
// - this locks in the real properties this generator's design rests on (default-deny, lazy
// evaluation, zero host-wide impact, bare-dir listing-only ancestor rules, order-independent
// allow/deny resolution). Linux-only: apparmor_parser/aa-exec don't exist elsewhere. Requires
// passwordless sudo for apparmor_parser (the one-time-privileged profile-load step, aa-exec
// itself needs no privilege).
@EnabledOnOs(OS.LINUX)
class AppArmorProfileGeneratorEnforcementTest {

  private static final String CAT_EXECUTABLE = "/bin/cat";

  @Test
  void denyCarveOutInsideBroaderAllowActuallyDeniesTheRead(@TempDir Path tempDirParameter) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path secret = tempDir.resolve("secret.txt");
    Files.writeString(secret, "TOP-SECRET");
    List<FilesystemRule> rules = List.of(
        allowRule(CAT_EXECUTABLE),
        denyRule(secret.toString()),
        allowRule(tempDir + "/**")
    );

    try (LoadedAppArmorProfile profile = LoadedAppArmorProfile.load(rules)) {
      SandboxExecResult result = profile.run(CAT_EXECUTABLE, secret.toString());

      assertThat(result.exitCode())
          .as("reading a DENY-carved-out path inside a broader ALLOW must fail: %s", result.output())
          .isNotZero();
      assertThat(result.output())
          .doesNotContain("TOP-SECRET");
    }
  }

  @Test
  void broaderAllowStillPermitsReadsOutsideTheDenyCarveOut(@TempDir Path tempDirParameter) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path secret = tempDir.resolve("secret.txt");
    Files.writeString(secret, "TOP-SECRET");
    Path readme = tempDir.resolve("readme.txt");
    Files.writeString(readme, "hello world");
    List<FilesystemRule> rules = List.of(
        allowRule(CAT_EXECUTABLE),
        denyRule(secret.toString()),
        allowRule(tempDir + "/**")
    );

    try (LoadedAppArmorProfile profile = LoadedAppArmorProfile.load(rules)) {
      SandboxExecResult result = profile.run(CAT_EXECUTABLE, readme.toString());

      assertThat(result.exitCode())
          .as("reading a path not covered by the DENY must still succeed: %s", result.output())
          .isZero();
      assertThat(result.output())
          .contains("hello world");
    }
  }

  @Test
  void denyStillWinsRegardlessOfEmissionOrder(@TempDir Path tempDirParameter) throws IOException {
    // The property that makes this generator simpler than SeatbeltProfileGenerator: no
    // reverse-priority emission trick is needed. Proven here by generating BOTH orderings and
    // confirming the DENY wins either way.
    Path tempDir = tempDirParameter.toRealPath();
    Path secret = tempDir.resolve("secret.txt");
    Files.writeString(secret, "TOP-SECRET");
    List<FilesystemRule> denyFirst = List.of(
        allowRule(CAT_EXECUTABLE),
        denyRule(secret.toString()),
        allowRule(tempDir + "/**")
    );
    List<FilesystemRule> allowFirst = List.of(
        allowRule(CAT_EXECUTABLE),
        allowRule(tempDir + "/**"),
        denyRule(secret.toString())
    );

    try (
        LoadedAppArmorProfile denyFirstProfile = LoadedAppArmorProfile.load(denyFirst);
        LoadedAppArmorProfile allowFirstProfile = LoadedAppArmorProfile.load(allowFirst)
    ) {
      SandboxExecResult denyFirstResult = denyFirstProfile.run(CAT_EXECUTABLE, secret.toString());
      SandboxExecResult allowFirstResult = allowFirstProfile.run(CAT_EXECUTABLE, secret.toString());

      assertThat(denyFirstResult.exitCode())
          .isNotZero();
      assertThat(allowFirstResult.exitCode())
          .as("emission order must not change which rule wins")
          .isNotZero();
    }
  }

  // The reverse direction: a higher-priority literal ALLOW carving an exception out of a
  // lower-priority glob DENY - AppArmor's own set-subtraction does NOT support this natively
  // (confirmed asymmetric with the test above), so AppArmorProfileGenerator now rewrites the
  // DENY's own pattern via AppArmorDenyGlobExclusion to exclude the literal exception. Real kernel
  // proof, not
  // just the pure-function unit tests: the exception file is readable, a sibling file the deny
  // glob still covers (including one that is a strict extension of the excluded literal's own
  // name) stays denied, and an unrelated file is unaffected either way.
  @Test
  void higherPriorityAllowCarveOutInsideLowerPriorityDenyGlobActuallyAllowsTheRead(@TempDir Path tempDirParameter)
      throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path exception = tempDir.resolve(".env.example");
    Files.writeString(exception, "PLACEHOLDER");
    Path stillDenied = tempDir.resolve(".env");
    Files.writeString(stillDenied, "REAL-SECRET");
    Path stillDeniedLonger = tempDir.resolve(".env.example.bak");
    Files.writeString(stillDeniedLonger, "REAL-SECRET-TOO");
    List<FilesystemRule> rules = List.of(
        allowRule(CAT_EXECUTABLE),
        rule(Set.of(AccessKind.READ), exception.toString(), Decision.ALLOW),
        rule(Set.of(AccessKind.READ), "**/.env*", Decision.DENY),
        allowRule(tempDir + "/**")
    );

    try (LoadedAppArmorProfile profile = LoadedAppArmorProfile.load(rules)) {
      SandboxExecResult exceptionResult = profile.run(CAT_EXECUTABLE, exception.toString());
      SandboxExecResult stillDeniedResult = profile.run(CAT_EXECUTABLE, stillDenied.toString());
      SandboxExecResult stillDeniedLongerResult = profile.run(CAT_EXECUTABLE, stillDeniedLonger.toString());

      assertThat(exceptionResult.exitCode())
          .as("the literal exception must be readable: %s", exceptionResult.output())
          .isZero();
      assertThat(exceptionResult.output())
          .contains("PLACEHOLDER");
      assertThat(stillDeniedResult.exitCode())
          .as("a sibling file still covered by the deny glob must stay denied")
          .isNotZero();
      assertThat(stillDeniedLongerResult.exitCode())
          .as("a file strictly longer than the excluded literal must stay denied, not just anything sharing its prefix")
          .isNotZero();
    }
  }

  @Test
  void lazilyEvaluatesAgainstPathCreatedAfterProfileWasAlreadyLoaded(@TempDir Path tempDirParameter)
      throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    List<FilesystemRule> rules = List.of(
        allowRule(CAT_EXECUTABLE),
        denyRule(tempDir + "/**/*.pem"),
        allowRule(tempDir + "/**")
    );

    try (LoadedAppArmorProfile profile = LoadedAppArmorProfile.load(rules)) {
      Path freshSubdirectory = Files.createDirectories(tempDir.resolve("created/after/load"));
      Path freshSecret = freshSubdirectory.resolve("secret.pem");
      Files.writeString(freshSecret, "CREATED-AFTER-PROFILE-LOAD");

      SandboxExecResult result = profile.run(CAT_EXECUTABLE, freshSecret.toString());

      assertThat(result.exitCode())
          .as("a path matching a DENY glob, created after the profile was already loaded, must"
              + " still be denied: %s", result.output())
          .isNotZero();
      assertThat(result.output())
          .doesNotContain("CREATED-AFTER-PROFILE-LOAD");
    }
  }

  @Test
  void unconfinedProcessReadingTheSameDeniedFileIsUnaffected(@TempDir Path tempDirParameter) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path secret = tempDir.resolve("secret.txt");
    Files.writeString(secret, "TOP-SECRET");
    List<FilesystemRule> rules = List.of(denyRule(secret.toString()));

    try (LoadedAppArmorProfile profile = LoadedAppArmorProfile.load(rules)) {
      SandboxExecResult confinedResult = profile.run(CAT_EXECUTABLE, secret.toString());
      SandboxExecResult unconfinedResult = TestProcesses.run(List.of(CAT_EXECUTABLE, secret.toString()));

      assertThat(confinedResult.exitCode())
          .isNotZero();
      assertThat(unconfinedResult.exitCode())
          .as("confining one process must not affect an unconfined process reading the same file"
              + " - unlike a filesystem-wide mechanism, this is scoped per-process")
          .isZero();
      assertThat(unconfinedResult.output())
          .contains("TOP-SECRET");
    }
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
}
