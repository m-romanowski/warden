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
  private static final String SYMLINKED_TLS_ROOT_STORE = "/etc/ssl/cert.pem";
  private static final String STAT_EXECUTABLE = "/usr/bin/stat";
  private static final String SHELL_EXECUTABLE = "/bin/sh";
  private static final String DEVICE_DIRECTORY = "/dev";
  // Mode 0666, so the filesystem does not refuse it and this profile is the only thing that does.
  // A disk node would not serve: /dev/disk0 is root:operator 0640 and is refused to an ordinary
  // payload wide open and unsandboxed alike, which makes it evidence of nothing here.
  private static final String WORLD_READABLE_DEVICE = "/dev/autofs_nowait";
  private static final Duration WAIT_TIMEOUT = Duration.ofSeconds(10);
  private static final String TERMINAL_PROBE_SOURCE =
      """
      #include <stdio.h>
      #include <string.h>
      #include <termios.h>
      #include <unistd.h>
      #include <fcntl.h>
      #include <sys/ioctl.h>

      static const char *outcome(int result) {
        return result == 0 ? "granted" : "refused";
      }

      int main(void) {
        struct termios saved;
        struct termios raw;
        int discipline = 0;
        char keystroke = 'X';
        char *name;
        if (tcgetattr(0, &saved) != 0) {
          printf("terminalStateUnreadable\\n");
          return 1;
        }
        raw = saved;
        cfmakeraw(&raw);
        printf("rawMode=%s\\n", outcome(tcsetattr(0, TCSANOW, &raw)));
        tcsetattr(0, TCSANOW, &saved);
        printf("lineDiscipline=%s\\n", outcome(ioctl(0, TIOCGETD, &discipline)));
        printf("keystrokeInjection=%s\\n", outcome(ioctl(0, TIOCSTI, &keystroke)));
        name = ttyname(0);
        printf("terminalName=%s\\n", name == NULL ? "none" : name);
        if (name != NULL) {
          int reopened = open(name, O_RDWR);
          printf("terminalReopen=%s\\n", reopened < 0 ? "refused" : "granted");
          if (reopened >= 0) {
            close(reopened);
          }
        }
        return 0;
      }
      """;
  private static final String DESCRIPTOR_IOCTL_PROBE_SOURCE =
      """
      #include <stdio.h>
      #include <errno.h>
      #include <sys/disk.h>
      #include <sys/ioctl.h>

      int main(void) {
        uint32_t blockSize = 0;
        errno = 0;
        ioctl(0, DKIOCGETBLOCKSIZE, &blockSize);
        printf("inherited=%s\\n", errno == EPERM ? "EPERM" : "answered-by-the-kernel");
        return 0;
      }
      """;

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

  @Test
  void bootstrapGrantsTheTerminalIoctlsRawModeNeeds(@TempDir Path tempDirParameter) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path probe = compiledTerminalProbe(tempDir);
    List<FilesystemRule> rules = List.of(allowRule(RulePath.tree(tempDir)));

    SandboxExecResult result = runSandboxedOnTerminal(tempDir, rules, probe.toString());

    assertThat(result.output())
        .as("a terminal UI cannot start without this, which is the whole of the gap: %s", result.output())
        .contains("rawMode=granted");
    assertThat(result.output())
        .as("and stty needs the line discipline the same grant carries: %s", result.output())
        .contains("lineDiscipline=granted");
  }

  @Test
  void keystrokeInjectionNeedsOneMoreOperationThisGeneratorCannotEmit(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path probe = compiledTerminalProbe(tempDir);
    List<FilesystemRule> rules = List.of(allowRule(RulePath.tree(tempDir)));

    SandboxExecResult emitted = runSandboxedOnTerminal(tempDir, rules, probe.toString());
    SandboxExecResult secondOperationOpened = runSandboxedOnTerminalWithExtraClauses(
        tempDir, rules, "(allow hid-control)\n", probe.toString()
    );

    assertThat(emitted.output())
        .as("the profile as emitted must refuse the injection: %s", emitted.output())
        .contains("keystrokeInjection=refused");
    assertThat(secondOperationOpened.output())
        .as("and the refusal above must be hid-control's doing, or it asserts nothing: %s",
            secondOperationOpened.output())
        .contains("keystrokeInjection=granted");
  }

  @Test
  void terminalIoctlGrantDecidesAnInheritedDescriptorTheOtherClausesNeverSee(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path probe = compiledDescriptorIoctlProbe(tempDir);
    Path ungranted = Files.writeString(tempDir.resolve("inherited.txt"), "PAYLOAD");
    List<FilesystemRule> rules = List.of(allowRule(RulePath.literal(probe.toString())));

    SandboxExecResult scoped = runSandboxedWithInheritedDescriptor(tempDir, rules, "", probe, ungranted);
    SandboxExecResult unscoped = runSandboxedWithInheritedDescriptor(
        tempDir, rules, "(allow file-ioctl)\n", probe, ungranted
    );

    assertThat(scoped.output())
        .as("the sandbox refuses the ioctl on a path no clause of this profile names: %s", scoped.output())
        .contains("inherited=EPERM");
    assertThat(unscoped.output())
        .as("and without the scoping the kernel answers instead, which is the unsandboxed"
            + " outcome: %s", unscoped.output())
        .doesNotContain("inherited=EPERM");
  }

  @Test
  void bootstrapResolvesTheTerminalByNameWithoutOpeningAnythingUnderTheDeviceDirectory(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path probe = compiledTerminalProbe(tempDir);
    List<FilesystemRule> rules = List.of(
        allowRule(RulePath.tree(tempDir)),
        allowRule(RulePath.literal(LIST_EXECUTABLE)),
        allowRule(RulePath.literal(BYTE_COUNT_EXECUTABLE))
    );

    SandboxExecResult named = runSandboxedOnTerminal(tempDir, rules, probe.toString());
    SandboxExecResult listed = runSandboxed(tempDir, rules, LIST_EXECUTABLE, DEVICE_DIRECTORY);
    SandboxExecResult worldReadableDevice = runSandboxed(
        tempDir, rules, BYTE_COUNT_EXECUTABLE, "-c", WORLD_READABLE_DEVICE
    );

    assertThat(named.output())
        .as("ttyname scans the device directory and matches by device number, so without its"
            + " entries a payload resolving its own terminal gets nothing: %s", named.output())
        .contains("terminalName=/dev/tty");
    assertThat(listed.exitCode())
        .as("the entries are granted to a readdir and not to a stat, so the listing stays refused: %s", listed.output())
        .isNotZero();
    assertThat(worldReadableDevice.exitCode())
        .as("a subtree grant here would hand over every device node this user's own permissions"
            + " already allow, and %s is one that opens under it: %s",
            WORLD_READABLE_DEVICE, worldReadableDevice.output())
        .isNotZero();
    assertThat(worldReadableDevice.output())
        .as("and the refusal has to be this profile's rather than the filesystem's, or the"
            + " assertion above holds for a reason that has nothing to do with the grant: %s",
            worldReadableDevice.output())
        .contains("Operation not permitted");
    assertThat(named.output())
        .as("resolving the name is all the slave device is granted for. Reading it by that name is"
            + " a second thing, and the regex covers every pty on the machine: %s", named.output())
        .contains("terminalReopen=refused");
  }

  @Test
  void bootstrapDiscardsOutputRedirectedToTheNullDeviceWithoutMakingOtherDevicesWritable(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    List<FilesystemRule> rules = List.of(allowRule(RulePath.literal(SHELL_EXECUTABLE)));

    SandboxExecResult discarded = runSandboxed(
        tempDir, rules, SHELL_EXECUTABLE, "-c", "echo SWALLOWED > /dev/null && echo REDIRECT-DONE"
    );
    SandboxExecResult diagnostics = runSandboxed(
        tempDir, rules, SHELL_EXECUTABLE, "-c", "ls /no-such-path-here 2>/dev/null; echo DIAGNOSTICS-DONE"
    );
    SandboxExecResult otherDevice = runSandboxed(tempDir, rules, SHELL_EXECUTABLE, "-c", "echo x > /dev/zero");

    assertThat(discarded.output())
        .as("a redirect that cannot open its sink stops the command it is attached to: %s", discarded.output())
        .contains("REDIRECT-DONE");
    assertThat(discarded.output())
        .as("and what it swallowed must not surface anywhere else: %s", discarded.output())
        .doesNotContain("SWALLOWED");
    assertThat(diagnostics.output())
        .as("2>/dev/null is the same grant and the more common spelling: %s", diagnostics.output())
        .contains("DIAGNOSTICS-DONE");
    assertThat(diagnostics.output())
        .as("with the sink refused the diagnostics it was meant to swallow reach the terminal instead: %s",
            diagnostics.output())
        .doesNotContain("No such file or directory");
    assertThat(otherDevice.exitCode())
        .as("the write half belongs to the discard sink alone, not to every device beside it: %s",
            otherDevice.output())
        .isNotZero();
  }

  @Test
  void bootstrapReachesTheTrustStoreThroughTheEtcSymlinkAndNothingElseUnderIt(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    List<FilesystemRule> rules = List.of(
        allowCatExecutable(),
        allowRule(RulePath.literal(LIST_EXECUTABLE)),
        allowRule(RulePath.literal(BYTE_COUNT_EXECUTABLE))
    );

    SandboxExecResult certificates = runSandboxed(tempDir, rules, BYTE_COUNT_EXECUTABLE, "-c", SYMLINKED_TLS_ROOT_STORE);
    SandboxExecResult accounts = runSandboxed(tempDir, rules, CAT_EXECUTABLE, "/etc/passwd");
    SandboxExecResult daemonConfiguration = runSandboxed(tempDir, rules, CAT_EXECUTABLE, "/etc/ssh/sshd_config");
    SandboxExecResult listed = runSandboxed(tempDir, rules, LIST_EXECUTABLE, "/etc/");

    assertThat(certificates.exitCode())
        .as("/etc/ssl is the path every TLS client compiles in, so the trust store this bootstrap"
            + " grants was reachable only by a spelling nothing uses: %s", certificates.output())
        .isZero();
    assertThat(accounts.exitCode())
        .as("a symlink entry grants what it names and not what it points at: %s", accounts.output())
        .isNotZero();
    assertThat(daemonConfiguration.exitCode())
        .as("nor the configuration of the machine's own daemons, through this spelling either: %s",
            daemonConfiguration.output())
        .isNotZero();
    assertThat(listed.exitCode())
        .as("nor the names of what is there: %s", listed.output())
        .isNotZero();
  }

  @Test
  void grantingTheSymlinkEntryDoesNotReachWhatItPointsAt(@TempDir Path tempDirParameter) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path behind = Files.createDirectory(tempDir.resolve("behind"));
    Files.writeString(behind.resolve("target.txt"), "TOP-SECRET");
    Path link = tempDir.resolve("link.txt");
    Files.createSymbolicLink(link, behind.resolve("target.txt"));
    List<FilesystemRule> throughTheEntry = List.of(
        allowRule(RulePath.literal(BYTE_COUNT_EXECUTABLE)),
        allowRule(RulePath.literal(link.toString())),
        denyRule(RulePath.tree(behind)),
        allowRule(RulePath.tree(tempDir))
    );
    List<FilesystemRule> throughTheTarget = List.of(
        allowRule(RulePath.literal(BYTE_COUNT_EXECUTABLE)),
        allowRule(RulePath.tree(tempDir))
    );

    SandboxExecResult named = runSandboxed(tempDir, throughTheEntry, BYTE_COUNT_EXECUTABLE, "-c", link.toString());
    SandboxExecResult control = runSandboxed(tempDir, throughTheTarget, BYTE_COUNT_EXECUTABLE, "-c", link.toString());

    assertThat(named.exitCode())
        .as("the kernel matches the resolved path, so granting the entry grants nothing: %s", named.output())
        .isNotZero();
    assertThat(control.exitCode())
        .as("positive control: the same read goes through once the target itself is granted: %s", control.output())
        .isZero();
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

  private static Path compiledDescriptorIoctlProbe(Path directory) throws IOException {
    return compiledProbe(directory, "descriptor-ioctl-probe", DESCRIPTOR_IOCTL_PROBE_SOURCE);
  }

  private static Path compiledTerminalProbe(Path directory) throws IOException {
    return compiledProbe(directory, "terminal-probe", TERMINAL_PROBE_SOURCE);
  }

  private static Path compiledProbe(Path directory, String name, String source) throws IOException {
    Path sourcePath = directory.resolve(name + ".c");
    Files.writeString(sourcePath, source);
    Path binary = directory.resolve(name);
    SandboxExecResult compilation = TestProcesses.run(
        List.of("cc", "-o", binary.toString(), sourcePath.toString())
    );
    assumeTrue(
        compilation.exitCode() == 0,
        "a C compiler is required to build " + name + ": " + compilation.output()
    );
    return binary;
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

  private static SandboxExecResult runSandboxedOnTerminal(
      Path tempDir,
      List<FilesystemRule> rules,
      String... command
  ) throws IOException {
    return runSandboxedOnTerminalWithExtraClauses(tempDir, rules, "", command);
  }

  private static SandboxExecResult runSandboxedOnTerminalWithExtraClauses(
      Path tempDir,
      List<FilesystemRule> rules,
      String extraClauses,
      String... command
  ) throws IOException {
    Path profilePath = writtenProfile(tempDir, rules, extraClauses);
    List<String> fullCommand = new ArrayList<>();
    fullCommand.add("/usr/bin/sandbox-exec");
    fullCommand.add("-f");
    fullCommand.add(profilePath.toString());
    fullCommand.addAll(List.of(command));
    return PseudoTerminal.run(tempDir, fullCommand);
  }

  private static SandboxExecResult runSandboxedWithInheritedDescriptor(
      Path tempDir,
      List<FilesystemRule> rules,
      String extraClauses,
      Path command,
      Path inherited
  ) throws IOException {
    Path profilePath = writtenProfile(tempDir, rules, extraClauses);
    Process process = new ProcessBuilder(
        "/usr/bin/sandbox-exec", "-f", profilePath.toString(), command.toString()
    )
        .redirectInput(inherited.toFile())
        .redirectErrorStream(true)
        .start();
    return drained(process);
  }

  private static Path writtenProfile(Path tempDir, List<FilesystemRule> rules) throws IOException {
    return writtenProfile(tempDir, rules, "");
  }

  private static Path writtenProfile(
      Path tempDir,
      List<FilesystemRule> rules,
      String extraClauses
  ) throws IOException {
    String profile = SeatbeltProfileGenerator.generate(rules, PROXY_PORT, Optional.empty());
    Path profilePath = tempDir.resolve("profile-" + UUID.randomUUID() + ".sb");
    Files.writeString(profilePath, profile + extraClauses);
    return profilePath;
  }

  private static SandboxExecResult runSandboxed(
      Path tempDir,
      List<FilesystemRule> rules,
      String... command
  ) throws IOException {
    Path profilePath = writtenProfile(tempDir, rules);
    List<String> fullCommand = new ArrayList<>();
    fullCommand.add("/usr/bin/sandbox-exec");
    fullCommand.add("-f");
    fullCommand.add(profilePath.toString());
    fullCommand.addAll(List.of(command));
    Process process = new ProcessBuilder(fullCommand)
        .redirectErrorStream(true)
        .start();
    return drained(process);
  }

  private static SandboxExecResult drained(Process process) throws IOException {
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
