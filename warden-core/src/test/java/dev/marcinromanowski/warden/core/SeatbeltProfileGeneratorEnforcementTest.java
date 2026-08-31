package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import dev.marcinromanowski.warden.api.AccessKind;
import dev.marcinromanowski.warden.api.Decision;
import dev.marcinromanowski.warden.api.FilesystemRule;
import dev.marcinromanowski.warden.api.RulePath;
import dev.marcinromanowski.warden.api.SandboxRuleRejectedException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
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
  private static final String LIST_EXECUTABLE = "/bin/ls";
  private static final String BYTE_COUNT_EXECUTABLE = "/usr/bin/wc";
  private static final String TLS_ROOT_STORE = "/private/etc/ssl/cert.pem";
  private static final String STAT_EXECUTABLE = "/usr/bin/stat";
  private static final Duration WAIT_TIMEOUT = Duration.ofSeconds(10);

  @Test
  void denyCarveOutInsideBroaderAllowActuallyDeniesTheRead(@TempDir Path tempDirParameter) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path secret = tempDir.resolve("secret.txt");
    Files.writeString(secret, "TOP-SECRET");
    List<FilesystemRule> rules = List.of(
        allowCatExecutable(),
        denyRule(RulePath.literal(secret.toString())),
        allowRule(RulePath.tree(tempDir))
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
        denyRule(RulePath.literal(secret.toString())),
        allowRule(RulePath.tree(tempDir))
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
        rule(Set.of(AccessKind.READ), RulePath.literal(envExample.toString()), Decision.ALLOW),
        denyRule(RulePath.glob(RulePath.quote(tempDir.toString()) + "/.env*"))
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

  @Test
  void denyingExecuteStopsNativeBinaryWithoutTakingAwayItsRead(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path probe = compiledNativeBinary(tempDir);
    List<FilesystemRule> denied = List.of(
        rule(Set.of(AccessKind.EXECUTE), RulePath.literal(probe.toString()), Decision.DENY),
        allowRule(RulePath.tree(tempDir)),
        allowRule(RulePath.literal(BYTE_COUNT_EXECUTABLE))
    );
    List<FilesystemRule> permitted = List.of(allowRule(RulePath.tree(tempDir)), allowRule(RulePath.literal(BYTE_COUNT_EXECUTABLE)));

    SandboxExecResult control = runSandboxed(tempDir, permitted, probe.toString(), "RAN");
    SandboxExecResult refused = runSandboxed(tempDir, denied, probe.toString(), "RAN");
    SandboxExecResult read = runSandboxed(tempDir, denied, BYTE_COUNT_EXECUTABLE, "-c", probe.toString());

    assertThat(control.exitCode())
        .as("positive control: the same binary must run when nothing denies its execute: %s", control.output())
        .isZero();
    assertThat(control.output())
        .contains("RAN");
    assertThat(refused.exitCode())
        .as("a DENY on EXECUTE must refuse a native binary, which denying its read does not: %s", refused.output())
        .isNotZero();
    assertThat(refused.output())
        .doesNotContain("RAN");
    assertThat(read.exitCode())
        .as("and it must take nothing away from the read the rules still grant: %s", read.output())
        .isZero();
  }

  @Test
  void denyingExecuteStopsScriptTheProfileStillLetsItRead(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path script = tempDir.resolve("probe.sh");
    Files.writeString(script, "#!/bin/sh\necho RAN\n");
    Files.setPosixFilePermissions(script, PosixFilePermissions.fromString("r-xr-xr-x"));
    List<FilesystemRule> denied = List.of(
        rule(Set.of(AccessKind.EXECUTE), RulePath.literal(script.toString()), Decision.DENY),
        allowRule(RulePath.tree(tempDir)),
        allowCatExecutable()
    );
    List<FilesystemRule> permitted = List.of(allowRule(RulePath.tree(tempDir)), allowCatExecutable());

    SandboxExecResult control = runSandboxed(tempDir, permitted, script.toString());
    SandboxExecResult refused = runSandboxed(tempDir, denied, script.toString());

    assertThat(control.exitCode())
        .as("positive control: the script must run when nothing denies its execute: %s", control.output())
        .isZero();
    assertThat(control.output())
        .contains("RAN");
    assertThat(refused.exitCode())
        .as("a DENY on EXECUTE must refuse a script too: %s", refused.output())
        .isNotZero();
    assertThat(refused.output())
        .doesNotContain("RAN");
  }

  @Test
  void externalDirectoryResolvesThroughDirectoryWithoutListingIt(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path ancestor = Files.createDirectory(tempDir.resolve("ancestor"));
    Path nested = Files.createDirectory(ancestor.resolve("nested"));
    Files.writeString(nested.resolve("data.txt"), "NESTED-CONTENT");
    Files.writeString(ancestor.resolve("sibling.txt"), "SIBLING-CONTENT");
    List<FilesystemRule> traversalOnly = List.of(
        rule(Set.of(AccessKind.EXTERNAL_DIRECTORY), RulePath.literal(ancestor.toString()), Decision.ALLOW),
        allowRule(RulePath.tree(nested)),
        allowRule(RulePath.literal(CAT_EXECUTABLE)),
        allowRule(RulePath.literal(LIST_EXECUTABLE))
    );
    List<FilesystemRule> withRead = List.of(
        allowRule(RulePath.literal(ancestor.toString())),
        allowRule(RulePath.tree(nested)),
        allowRule(RulePath.literal(CAT_EXECUTABLE)),
        allowRule(RulePath.literal(LIST_EXECUTABLE))
    );

    SandboxExecResult listed = runSandboxed(tempDir, traversalOnly, LIST_EXECUTABLE, ancestor.toString());
    SandboxExecResult resolved = runSandboxed(tempDir, traversalOnly, CAT_EXECUTABLE, nested + "/data.txt");
    SandboxExecResult listedWithRead = runSandboxed(tempDir, withRead, LIST_EXECUTABLE, ancestor.toString());

    assertThat(listed.exitCode())
        .as("EXTERNAL_DIRECTORY must not disclose the directory's own entries: %s", listed.output())
        .isNotZero();
    assertThat(listed.output())
        .doesNotContain("sibling.txt");
    assertThat(resolved.exitCode())
        .as("but a granted path underneath it must still open: %s", resolved.output())
        .isZero();
    assertThat(resolved.output())
        .contains("NESTED-CONTENT");
    assertThat(listedWithRead.exitCode())
        .as("positive control: READ over the same directory does grant the listing: %s", listedWithRead.output())
        .isZero();
    assertThat(listedWithRead.output())
        .contains("sibling.txt");
  }

  @Test
  void denyingExternalDirectoryWithoutReadRefusesTheContentsToo(@TempDir Path tempDirParameter) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path secret = tempDir.resolve("secret.txt");
    Files.writeString(secret, "TOP-SECRET");
    Path readable = tempDir.resolve("readable.txt");
    Files.writeString(readable, "PUBLIC");
    List<FilesystemRule> rules = List.of(
        allowCatExecutable(),
        rule(Set.of(AccessKind.EXTERNAL_DIRECTORY), RulePath.literal(secret.toString()), Decision.DENY),
        allowRule(RulePath.tree(tempDir))
    );

    SandboxExecResult refused = runSandboxed(tempDir, rules, CAT_EXECUTABLE, secret.toString());
    SandboxExecResult control = runSandboxed(tempDir, rules, CAT_EXECUTABLE, readable.toString());

    assertThat(refused.exitCode())
        .as("a DENY naming EXTERNAL_DIRECTORY must refuse the bytes, not only the metadata: %s", refused.output())
        .isNotZero();
    assertThat(refused.output())
        .doesNotContain("TOP-SECRET");
    assertThat(control.exitCode())
        .as("positive control: the surrounding ALLOW still reads every path the deny does not name: %s", control.output())
        .isZero();
    assertThat(control.output())
        .contains("PUBLIC");
  }

  @Test
  void bootstrapReadsTheTlsRootStoreWithoutDisclosingTheRestOfSystemConfiguration(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    List<FilesystemRule> nothingOfItsOwn = List.of(
        allowCatExecutable(), allowRule(RulePath.literal(LIST_EXECUTABLE)), allowRule(RulePath.literal(BYTE_COUNT_EXECUTABLE))
    );

    // Counted rather than printed: the root store is hundreds of kilobytes and this harness waits
    // for exit before draining the pipe.
    SandboxExecResult certificates = runSandboxed(tempDir, nothingOfItsOwn, BYTE_COUNT_EXECUTABLE, "-c", TLS_ROOT_STORE);
    SandboxExecResult accounts = runSandboxed(tempDir, nothingOfItsOwn, CAT_EXECUTABLE, "/private/etc/passwd");
    SandboxExecResult daemonConfiguration = runSandboxed(
        tempDir, nothingOfItsOwn, CAT_EXECUTABLE, "/private/etc/ssh/sshd_config"
    );
    SandboxExecResult listed = runSandboxed(tempDir, nothingOfItsOwn, LIST_EXECUTABLE, "/private/etc");

    assertThat(certificates.exitCode())
        .as("positive control: without the root store no payload can make an https request at"
            + " all, which is what the removed subtree grant was actually carrying: %s", certificates.output())
        .isZero();
    assertThat(accounts.exitCode())
        .as("a blanket read of system configuration is not something every consumer of this library"
            + " should inherit: %s", accounts.output())
        .isNotZero();
    assertThat(daemonConfiguration.exitCode())
        .as("nor the configuration of the machine's own daemons: %s", daemonConfiguration.output())
        .isNotZero();
    assertThat(listed.exitCode())
        .as("nor the names of what is there: %s", listed.output())
        .isNotZero();
  }

  @Test
  void externalDirectoryAloneGrantsFileMetadataAndNotItsContents(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path secret = tempDir.resolve("secret.txt");
    Files.writeString(secret, "TOP-SECRET");
    List<FilesystemRule> rules = List.of(
        allowCatExecutable(),
        allowRule(RulePath.literal(STAT_EXECUTABLE)),
        rule(Set.of(AccessKind.EXTERNAL_DIRECTORY), RulePath.tree(tempDir), Decision.ALLOW),
        rule(Set.of(AccessKind.EXTERNAL_DIRECTORY), RulePath.literal(tempDir.toString()), Decision.ALLOW)
    );

    SandboxExecResult described = runSandboxed(tempDir, rules, STAT_EXECUTABLE, "-f%z", secret.toString());
    SandboxExecResult read = runSandboxed(tempDir, rules, CAT_EXECUTABLE, secret.toString());

    assertThat(described.exitCode())
        .as("positive control: the kind does grant a path's metadata: %s", described.output())
        .isZero();
    assertThat(read.exitCode())
        .as("and refuses its contents on this platform, which AppArmor cannot express: %s", read.output())
        .isNotZero();
    assertThat(read.output())
        .doesNotContain("TOP-SECRET");
  }

  @Test
  void enforcesRulesOverDirectoriesWhoseNamesNeedEscaping(@TempDir Path tempDirParameter) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();

    for (String name : AwkwardPathNames.ALL) {
      Path workspace = Files.createDirectories(tempDir.resolve(name));
      Path readable = workspace.resolve("readme.txt");
      Files.writeString(readable, "hello world");
      Path secret = workspace.resolve("secret.txt");
      Files.writeString(secret, "TOP-SECRET");
      Path decoy = Files.createDirectories(tempDir.resolve(AwkwardPathNames.decoyOf(name)));
      Path decoyFile = decoy.resolve("readme.txt");
      Files.writeString(decoyFile, "DECOY-CONTENT");
      List<FilesystemRule> rules = List.of(
          allowCatExecutable(),
          denyRule(RulePath.literal(secret.toString())),
          allowRule(RulePath.tree(workspace))
      );

      SandboxExecResult allowed = runSandboxed(tempDir, rules, CAT_EXECUTABLE, readable.toString());
      SandboxExecResult denied = runSandboxed(tempDir, rules, CAT_EXECUTABLE, secret.toString());
      SandboxExecResult decoyRead = runSandboxed(tempDir, rules, CAT_EXECUTABLE, decoyFile.toString());

      assertThat(allowed.output())
          .as("the allow must reach the path it names, for %s: %s", name, allowed.output())
          .contains("hello world");
      assertThat(denied.output())
          .as("the deny carve-out must still hold, for %s: %s", name, denied.output())
          .doesNotContain("TOP-SECRET");
      assertThat(decoyRead.output())
          .as("the rule must not reach a directory whose name differs by that character, for %s: %s",
              name, decoyRead.output())
          .doesNotContain("DECOY-CONTENT");
    }
  }

  @Test
  void grantsOnlyTheDirectoryWhoseNameHoldsTheWildcardWhenTheRuleNamesItLiterally(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path named = payloadDirectory(tempDir, "My*Project");
    Path characterDropped = payloadDirectory(tempDir, "MyProject");
    Path characterReplaced = payloadDirectory(tempDir, "MyXProject");
    Path sibling = payloadDirectory(tempDir, "MyOtherProject");
    List<FilesystemRule> asGlob = List.of(allowCatExecutable(), allowRule(RulePath.glob(named + "/**")));
    List<FilesystemRule> asLiteral = List.of(allowCatExecutable(), allowRule(RulePath.tree(named)));

    assertThat(runSandboxed(tempDir, asGlob, CAT_EXECUTABLE, sibling.resolve("f").toString()).output())
        .as("a live wildcard is what makes the over-grant reachable, and this is the control for it")
        .contains("PAYLOAD");
    assertThat(runSandboxed(tempDir, asLiteral, CAT_EXECUTABLE, named.resolve("f").toString()).output())
        .as("the directory the rule names must still be reachable")
        .contains("PAYLOAD");
    for (Path decoy : List.of(characterDropped, characterReplaced, sibling)) {
      assertThat(runSandboxed(tempDir, asLiteral, CAT_EXECUTABLE, decoy.resolve("f").toString()).output())
          .as("no directory but the one named, and %s is not it", decoy)
          .doesNotContain("PAYLOAD");
    }
  }

  @Test
  void refusesTheBraceGroupDenyRatherThanEmittingOneThatEnforcesNothing(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path certificate = payloadFile(tempDir, "secret.pem");
    Path key = payloadFile(tempDir, "secret.key");
    List<FilesystemRule> allowOnly = List.of(allowCatExecutable(), allowRule(RulePath.tree(tempDir)));
    List<FilesystemRule> perAlternative = List.of(
        allowCatExecutable(),
        denyRule(RulePath.glob("**/*.pem")),
        denyRule(RulePath.glob("**/*.key")),
        allowRule(RulePath.tree(tempDir))
    );

    assertThatThrownBy(() -> SeatbeltProfileGenerator.generate(
        List.of(denyRule(RulePath.glob("**/*.{pem,key}"))), PROXY_PORT, Optional.empty()
    ))
        .isInstanceOf(SandboxRuleRejectedException.class)
        .hasMessageContaining("**/*.{pem,key}");
    for (Path credential : List.of(certificate, key)) {
      assertThat(runSandboxed(tempDir, allowOnly, CAT_EXECUTABLE, credential.toString()).output())
          .as("positive control: with no deny at all, %s reads out", credential)
          .contains("PAYLOAD");
      assertThat(runSandboxed(tempDir, perAlternative, CAT_EXECUTABLE, credential.toString()).output())
          .as("the spelling the refusal names must be one that enforces, for %s", credential)
          .doesNotContain("PAYLOAD");
    }
  }

  private static Path payloadDirectory(Path parent, String name) throws IOException {
    Path directory = Files.createDirectories(parent.resolve(name));
    Files.writeString(directory.resolve("f"), "PAYLOAD");
    return directory;
  }

  private static Path payloadFile(Path parent, String name) throws IOException {
    Path file = parent.resolve(name);
    Files.writeString(file, "PAYLOAD");
    return file;
  }

  private static Path compiledNativeBinary(Path directory) throws IOException {
    Path source = directory.resolve("probe.c");
    Files.writeString(source, "#include <stdio.h>\nint main(void){ printf(\"RAN\\n\"); return 0; }\n");
    Path binary = directory.resolve("probe");
    SandboxExecResult compilation = TestProcesses.run(
        List.of("cc", "-o", binary.toString(), source.toString())
    );
    assumeTrue(compilation.exitCode() == 0, "a C compiler is required to build the native probe binary");
    return binary;
  }

  private static FilesystemRule allowCatExecutable() {
    return allowRule(RulePath.literal(CAT_EXECUTABLE));
  }

  private static FilesystemRule allowRule(RulePath target) {
    return rule(Set.of(AccessKind.READ), target, Decision.ALLOW);
  }

  private static FilesystemRule denyRule(RulePath target) {
    return rule(Set.of(AccessKind.READ), target, Decision.DENY);
  }

  private static FilesystemRule rule(Set<AccessKind> kinds, RulePath target, Decision decision) {
    return new FilesystemRule(target, kinds, decision, "test reason");
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
