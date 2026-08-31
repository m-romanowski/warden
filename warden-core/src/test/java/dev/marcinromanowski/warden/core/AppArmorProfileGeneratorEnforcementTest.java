package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.marcinromanowski.warden.api.AccessKind;
import dev.marcinromanowski.warden.api.Decision;
import dev.marcinromanowski.warden.api.FilesystemRule;
import dev.marcinromanowski.warden.api.RulePath;
import dev.marcinromanowski.warden.api.SandboxRuleRejectedException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
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
  private static final String LIST_EXECUTABLE = "/bin/ls";
  private static final String MAKE_DIRECTORY_EXECUTABLE = "/bin/mkdir";
  private static final String TRUE_EXECUTABLE = "/bin/true";
  private static final String FLOCK_EXECUTABLE = "/usr/bin/flock";
  private static final String SHELL_EXECUTABLE = "/bin/sh";
  private static final String MOVE_EXECUTABLE = "/bin/mv";
  private static final String PROCESS_DIRECTORY = "/proc";

  @Test
  void denyCarveOutInsideBroaderAllowActuallyDeniesTheRead(@TempDir Path tempDirParameter) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path secret = tempDir.resolve("secret.txt");
    Files.writeString(secret, "TOP-SECRET");
    List<FilesystemRule> rules = List.of(
        allowRule(RulePath.literal(CAT_EXECUTABLE)),
        denyRule(RulePath.literal(secret.toString())),
        allowRule(RulePath.tree(tempDir))
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
        allowRule(RulePath.literal(CAT_EXECUTABLE)),
        denyRule(RulePath.literal(secret.toString())),
        allowRule(RulePath.tree(tempDir))
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
        allowRule(RulePath.literal(CAT_EXECUTABLE)),
        denyRule(RulePath.literal(secret.toString())),
        allowRule(RulePath.tree(tempDir))
    );
    List<FilesystemRule> allowFirst = List.of(
        allowRule(RulePath.literal(CAT_EXECUTABLE)),
        allowRule(RulePath.tree(tempDir)),
        denyRule(RulePath.literal(secret.toString()))
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

  @Test
  void higherPriorityAllowCarveOutInsideLowerPriorityDenyGlobActuallyAllowsTheRead(
      @TempDir Path tempDirParameter
  ) throws IOException {
    // The reverse direction: a higher-priority literal ALLOW carving an exception out of a
    // lower-priority glob DENY - AppArmor's own set-subtraction does NOT support this natively
    // (confirmed asymmetric with the test above), so AppArmorProfileGenerator now rewrites the
    // DENY's own pattern via AppArmorDenyGlobExclusion to exclude the literal exception. Real kernel
    // proof, not
    // just the pure-function unit tests: the exception file is readable, a sibling file the deny
    // glob still covers (including one that is a strict extension of the excluded literal's own
    // name) stays denied, and an unrelated file is unaffected either way.
    Path tempDir = tempDirParameter.toRealPath();
    Path exception = tempDir.resolve(".env.example");
    Files.writeString(exception, "PLACEHOLDER");
    Path stillDenied = tempDir.resolve(".env");
    Files.writeString(stillDenied, "REAL-SECRET");
    Path stillDeniedLonger = tempDir.resolve(".env.example.bak");
    Files.writeString(stillDeniedLonger, "REAL-SECRET-TOO");
    List<FilesystemRule> rules = List.of(
        allowRule(RulePath.literal(CAT_EXECUTABLE)),
        rule(Set.of(AccessKind.READ), RulePath.literal(exception.toString()), Decision.ALLOW),
        rule(Set.of(AccessKind.READ), RulePath.glob("**/.env*"), Decision.DENY),
        allowRule(RulePath.tree(tempDir))
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
        allowRule(RulePath.literal(CAT_EXECUTABLE)),
        denyRule(RulePath.glob("**/*.pem")),
        allowRule(RulePath.tree(tempDir))
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
    List<FilesystemRule> rules = List.of(denyRule(RulePath.literal(secret.toString())));

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

  @Test
  void executeRunsTheBinaryTheBootstrapLocationsDoNotCover(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    // Copied under its own name, not renamed: the system binary this borrows is a multicall
    // executable that dispatches on argv[0] and refuses to run under any other name, which would
    // read as an exec failure without being one.
    Path toolDirectory = Files.createDirectory(tempDir.resolve("tools"));
    Path tool = Files.copy(Path.of(CAT_EXECUTABLE), toolDirectory.resolve("cat"));
    Files.setPosixFilePermissions(tool, PosixFilePermissions.fromString("rwxr-xr-x"));
    Path readable = tempDir.resolve("readable.txt");
    Files.writeString(readable, "RAN-THE-TOOL");
    List<FilesystemRule> readOnly = List.of(allowRule(RulePath.tree(tempDir)));
    List<FilesystemRule> readAndExecute = List.of(
        rule(Set.of(AccessKind.READ, AccessKind.EXECUTE), RulePath.tree(tempDir), Decision.ALLOW)
    );

    try (
        LoadedAppArmorProfile withoutExecute = LoadedAppArmorProfile.load(readOnly);
        LoadedAppArmorProfile withExecute = LoadedAppArmorProfile.load(readAndExecute)
    ) {
      // Run through a shell rather than as the profile's own first command. aa-exec applies the
      // profile on the exec it performs itself, so that exec is authorised by whatever confined the
      // caller and never by the profile under test - only an exec performed by an already-confined
      // process is mediated, which is also how the sandbox reaches a backend binary for real.
      String command = "exec " + tool + " " + readable;
      SandboxExecResult refused = withoutExecute.run(SHELL_EXECUTABLE, "-c", command);
      SandboxExecResult permitted = withExecute.run(SHELL_EXECUTABLE, "-c", command);

      assertThat(refused.exitCode())
          .as("a readable-but-not-executable binary must not run: %s", refused.output())
          .isNotZero();
      assertThat(refused.output())
          .doesNotContain("RAN-THE-TOOL");
      assertThat(permitted.exitCode())
          .as("granting execute must make the same binary runnable: %s", permitted.output())
          .isZero();
      assertThat(permitted.output())
          .contains("RAN-THE-TOOL");
    }
  }

  @Test
  void lockTakesTheFileLockThatWriteAccessAloneRefuses(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path lockable = tempDir.resolve("state.db");
    Files.writeString(lockable, "");
    List<FilesystemRule> writeOnly = List.of(
        rule(Set.of(AccessKind.READ, AccessKind.WRITE), RulePath.tree(tempDir), Decision.ALLOW)
    );
    List<FilesystemRule> writeAndLock = List.of(
        rule(Set.of(AccessKind.READ, AccessKind.WRITE, AccessKind.LOCK), RulePath.tree(tempDir), Decision.ALLOW)
    );

    try (
        LoadedAppArmorProfile withoutLock = LoadedAppArmorProfile.load(writeOnly);
        LoadedAppArmorProfile withLock = LoadedAppArmorProfile.load(writeAndLock)
    ) {
      SandboxExecResult refused = withoutLock.run(FLOCK_EXECUTABLE, "-n", "-x", lockable.toString(), TRUE_EXECUTABLE);
      SandboxExecResult permitted = withLock.run(FLOCK_EXECUTABLE, "-n", "-x", lockable.toString(), TRUE_EXECUTABLE);

      assertThat(refused.exitCode())
          .as("a writable file must not be lockable without an explicit lock grant: %s", refused.output())
          .isNotZero();
      assertThat(permitted.exitCode())
          .as("granting lock must make the same file lockable: %s", permitted.output())
          .isZero();
    }
  }

  @Test
  void directoryRuleListsTheDirectoryWithoutOpeningWhatIsInside(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path inside = tempDir.resolve("inside.txt");
    Files.writeString(inside, "NOT-GRANTED");
    List<FilesystemRule> rules = List.of(allowRule(RulePath.literal(tempDir.toString())));

    try (LoadedAppArmorProfile profile = LoadedAppArmorProfile.load(rules)) {
      SandboxExecResult listing = profile.run(LIST_EXECUTABLE, tempDir.toString());
      SandboxExecResult read = profile.run(CAT_EXECUTABLE, inside.toString());

      assertThat(listing.exitCode())
          .as("a rule naming the directory must permit listing it: %s", listing.output())
          .isZero();
      assertThat(listing.output())
          .contains("inside.txt");
      assertThat(read.exitCode())
          .as("naming the directory must not grant reads of what is inside it")
          .isNotZero();
    }
  }

  @Test
  void denyNamingTheDirectoryAlsoRefusesCreatingIt(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    String blocked = tempDir.resolve("blocked")
        .toString();
    List<FilesystemRule> writableTree = List.of(
        rule(Set.of(AccessKind.READ, AccessKind.WRITE), RulePath.literal(tempDir.toString()), Decision.ALLOW),
        rule(Set.of(AccessKind.READ, AccessKind.WRITE), RulePath.tree(tempDir), Decision.ALLOW)
    );
    List<FilesystemRule> rules = withDenyOfDirectory(blocked, writableTree);

    try (
        LoadedAppArmorProfile control = LoadedAppArmorProfile.load(writableTree);
        LoadedAppArmorProfile profile = LoadedAppArmorProfile.load(rules)
    ) {
      SandboxExecResult permitted = control.run(MAKE_DIRECTORY_EXECUTABLE, blocked);
      assertThat(permitted.exitCode())
          .as("without the deny the same command must succeed, or the check below proves nothing: %s",
              permitted.output())
          .isZero();
      Files.delete(Path.of(blocked));

      SandboxExecResult created = profile.run(MAKE_DIRECTORY_EXECUTABLE, blocked);

      assertThat(created.exitCode())
          .as("creating a denied directory must fail: %s", created.output())
          .isNotZero();
      assertThat(Path.of(blocked))
          .doesNotExist();
    }
  }

  @Test
  void denyNamingTheDirectoryAlsoRefusesRenamingStagedContentOntoIt(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path staging = Files.createDirectory(tempDir.resolve("staging"));
    Files.writeString(staging.resolve("plugin.js"), "INJECTED");
    String blocked = tempDir.resolve("plugin")
        .toString();
    List<FilesystemRule> writableTree = List.of(
        rule(Set.of(AccessKind.READ, AccessKind.WRITE), RulePath.literal(tempDir.toString()), Decision.ALLOW),
        rule(Set.of(AccessKind.READ, AccessKind.WRITE), RulePath.tree(tempDir), Decision.ALLOW)
    );
    List<FilesystemRule> rules = withDenyOfDirectory(blocked, writableTree);

    try (
        LoadedAppArmorProfile control = LoadedAppArmorProfile.load(writableTree);
        LoadedAppArmorProfile profile = LoadedAppArmorProfile.load(rules)
    ) {
      SandboxExecResult permitted = control.run(MOVE_EXECUTABLE, staging.toString(), blocked);
      assertThat(permitted.exitCode())
          .as("without the deny the same rename must succeed, or the check below proves nothing: %s",
              permitted.output())
          .isZero();
      Files.move(Path.of(blocked), staging);

      SandboxExecResult renamed = profile.run(MOVE_EXECUTABLE, staging.toString(), blocked);

      assertThat(renamed.exitCode())
          .as("renaming a staged directory onto a denied name must fail: %s", renamed.output())
          .isNotZero();
      assertThat(Path.of(blocked)
          .resolve("plugin.js"))
          .doesNotExist();
    }
  }

  @Test
  void allowNamingTheDirectoryGrantsListingItWithoutGrantingItsRelocation(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path granted = Files.createDirectory(tempDir.resolve("granted"));
    Files.writeString(granted.resolve("inside.txt"), "CONTENT");
    Path elsewhere = Files.createDirectory(tempDir.resolve("elsewhere"));
    List<FilesystemRule> rules = List.of(
        rule(Set.of(AccessKind.READ, AccessKind.WRITE), RulePath.literal(granted.toString()), Decision.ALLOW),
        rule(Set.of(AccessKind.READ, AccessKind.WRITE), RulePath.tree(granted), Decision.ALLOW),
        rule(Set.of(AccessKind.READ, AccessKind.WRITE), RulePath.literal(elsewhere.toString()), Decision.ALLOW),
        rule(Set.of(AccessKind.READ, AccessKind.WRITE), RulePath.tree(elsewhere), Decision.ALLOW)
    );

    try (LoadedAppArmorProfile profile = LoadedAppArmorProfile.load(rules)) {
      SandboxExecResult relocated = profile.run(MOVE_EXECUTABLE, granted.toString(), elsewhere + "/stolen");
      SandboxExecResult listing = profile.run(LIST_EXECUTABLE, granted.toString());
      SandboxExecResult insideWork = profile.run(
          SHELL_EXECUTABLE, "-c",
          "mkdir " + granted + "/sub && touch " + granted + "/file && mv " + granted + "/file "
              + granted + "/renamed && rmdir " + granted + "/sub"
      );

      assertThat(relocated.exitCode())
          .as("renaming the granted directory itself must fail: %s", relocated.output())
          .isNotZero();
      assertThat(granted)
          .exists();
      assertThat(listing.exitCode())
          .as("listing the granted directory must still work - that is what the companion is for: %s",
              listing.output())
          .isZero();
      assertThat(listing.output())
          .contains("inside.txt");
      assertThat(insideWork.exitCode())
          .as("mkdir, touch, rename and rmdir inside the granted tree must all still work: %s",
              insideWork.output())
          .isZero();
    }
  }

  @Test
  void externalDirectoryPermitsTraversalWhileRefusingTheListing(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path root = tempDirParameter.toRealPath();
    Path traversed = Files.createDirectory(root.resolve("traversed"));
    Path listed = Files.createDirectory(root.resolve("listed"));
    Files.writeString(traversed.resolve("inside.txt"), "REACHED-THROUGH");
    Files.writeString(listed.resolve("inside.txt"), "ALSO-REACHED");
    List<FilesystemRule> rules = List.of(
        rule(Set.of(AccessKind.EXTERNAL_DIRECTORY), RulePath.literal(traversed.toString()), Decision.ALLOW),
        rule(Set.of(AccessKind.READ), RulePath.tree(traversed), Decision.ALLOW),
        rule(Set.of(AccessKind.READ), RulePath.literal(listed.toString()), Decision.ALLOW)
    );

    try (LoadedAppArmorProfile profile = LoadedAppArmorProfile.load(rules)) {
      Path readThroughTarget = traversed.resolve("inside.txt");
      SandboxExecResult readThrough = profile.run(CAT_EXECUTABLE, readThroughTarget.toString());
      SandboxExecResult listTraversed = profile.run(LIST_EXECUTABLE, traversed.toString());
      SandboxExecResult listRead = profile.run(LIST_EXECUTABLE, listed.toString());

      assertThat(readThrough.output())
          .as("a file below the directory must still be reachable through it")
          .contains("REACHED-THROUGH");
      assertThat(listTraversed.exitCode())
          .as("EXTERNAL_DIRECTORY alone must not list the directory: %s", listTraversed.output())
          .isNotZero();
      assertThat(listRead.exitCode())
          .as("a rule that names READ must still list it: %s", listRead.output())
          .isZero();
    }
  }

  @Test
  void externalDirectoryAloneGrantsFileContentsBecauseAppArmorHasNoMetadataOnlyRead() throws IOException {
    // The Linux half of a divergence macOS records from the other side. EXTERNAL_DIRECTORY alone means
    // "addressable, not listable", which for a directory both mechanisms produce. For a FILE, macOS
    // grants metadata and refuses the bytes, and AppArmor's narrowest read letter is the one that reads
    // them - there is no metadata-only file permission to map the kind onto. So the same rule hands out
    // a file's contents here and not there. Asserted rather than left to be discovered: a caller
    // writing this kind over a pattern that matches files is writing a read grant on this platform.
    Path tempDir = Files.createTempDirectory("warden-external-directory-");
    Path secret = tempDir.resolve("secret.txt");
    Files.writeString(secret, "TOP-SECRET");
    List<FilesystemRule> rules = List.of(
        rule(Set.of(AccessKind.EXTERNAL_DIRECTORY), RulePath.tree(tempDir), Decision.ALLOW)
    );

    try (LoadedAppArmorProfile profile = LoadedAppArmorProfile.load(rules)) {
      SandboxExecResult read = profile.run(CAT_EXECUTABLE, secret.toString());

      assertThat(read.output())
          .as("the divergence macOS's own enforcement test records from the other side: %s", read.output())
          .contains("TOP-SECRET");
    } finally {
      SandboxSessionDirectories.deleteQuietly(tempDir);
    }
  }

  @Test
  void denyingExecuteRefusesRunningWhatTheBroaderAllowStillMakesReadable(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path toolDirectory = Files.createDirectory(tempDir.resolve("tools"));
    Path tool = Files.copy(Path.of(CAT_EXECUTABLE), toolDirectory.resolve("cat"));
    Files.setPosixFilePermissions(tool, PosixFilePermissions.fromString("rwxr-xr-x"));
    Path readable = tempDir.resolve("readable.txt");
    Files.writeString(readable, "RAN-THE-TOOL");
    List<FilesystemRule> rules = List.of(
        rule(Set.of(AccessKind.EXECUTE), RulePath.literal(tool.toString()), Decision.DENY),
        rule(Set.of(AccessKind.READ, AccessKind.EXECUTE), RulePath.tree(tempDir), Decision.ALLOW)
    );

    try (LoadedAppArmorProfile profile = LoadedAppArmorProfile.load(rules)) {
      SandboxExecResult refused = profile.run(SHELL_EXECUTABLE, "-c", "exec " + tool + " " + readable);
      SandboxExecResult stillReadable = profile.run(CAT_EXECUTABLE, readable.toString());

      assertThat(refused.exitCode())
          .as("a denied-execute binary must not run: %s", refused.output())
          .isNotZero();
      assertThat(refused.output())
          .doesNotContain("RAN-THE-TOOL");
      assertThat(stillReadable.exitCode())
          .as("denying execute must not take away the read the same tree grants: %s", stillReadable.output())
          .isZero();
    }
  }

  @Test
  void denyGlobMatchingAnywhereAlsoRefusesTheSameNameAtTheFilesystemRoot() throws IOException {
    List<FilesystemRule> withoutDeny = List.of(allowRule(RulePath.literal(PROCESS_DIRECTORY)));
    List<FilesystemRule> withDeny = List.of(
        denyRule(RulePath.glob("**/" + PROCESS_DIRECTORY.substring(1))),
        allowRule(RulePath.literal(PROCESS_DIRECTORY))
    );

    try (
        LoadedAppArmorProfile permitted = LoadedAppArmorProfile.load(withoutDeny);
        LoadedAppArmorProfile denied = LoadedAppArmorProfile.load(withDeny)
    ) {
      SandboxExecResult allowedListing = permitted.run(LIST_EXECUTABLE, PROCESS_DIRECTORY);
      SandboxExecResult refusedListing = denied.run(LIST_EXECUTABLE, PROCESS_DIRECTORY);

      assertThat(allowedListing.exitCode())
          .as("the allow alone must list it, or the deny below proves nothing: %s", allowedListing.output())
          .isZero();
      assertThat(refusedListing.exitCode())
          .as("a deny written to match anywhere must also refuse the root-level name: %s", refusedListing.output())
          .isNotZero();
    }
  }

  @Test
  void enforcesRulesOverDirectoriesWhoseNamesNeedEscaping(
      @TempDir Path tempDirParameter
  ) throws IOException {
    // Every character a path can hold that this generator has to do something about, driven through
    // the real privileged helper, apparmor_parser and aa-exec against directories actually created
    // with those names. Two things are on trial: that the parser takes the profile at all - a bare
    // space in a pattern refused every launch under a workspace whose name had one - and that the
    // escaped clause lands on the path it names. The decoy is the name with those characters
    // dropped, which is where a collapsing escape sends the whole rule set.
    Path tempDir = tempDirParameter.toRealPath();

    for (String name : AwkwardPathNames.ALL) {
      Path workspace = Files.createDirectories(tempDir.resolve(name));
      Path readable = workspace.resolve("readme.txt");
      Files.writeString(readable, "hello world");
      Path secret = workspace.resolve("secret.txt");
      Files.writeString(secret, "TOP-SECRET");
      Path decoyFile = Files.createDirectories(tempDir.resolve(AwkwardPathNames.decoyOf(name)))
          .resolve("readme.txt");
      Files.writeString(decoyFile, "DECOY-CONTENT");
      List<FilesystemRule> rules = List.of(
          allowRule(RulePath.literal(CAT_EXECUTABLE)),
          denyRule(RulePath.literal(secret.toString())),
          allowRule(RulePath.tree(workspace))
      );

      try (LoadedAppArmorProfile profile = LoadedAppArmorProfile.load(rules)) {
        SandboxExecResult allowed = profile.run(CAT_EXECUTABLE, readable.toString());
        SandboxExecResult denied = profile.run(CAT_EXECUTABLE, secret.toString());
        SandboxExecResult decoyRead = profile.run(CAT_EXECUTABLE, decoyFile.toString());

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
  }

  @Test
  void carriesTheBraceInThePathWithoutPuttingOneInTheBodyThePrivilegedHelperReads() {
    String body = AppArmorProfileGenerator.sessionProfileBody(
        "warden-sandbox-test", List.of(allowRule(RulePath.tree("/workspace/e{f}g"))),
        Optional.empty(), Optional.empty(), Optional.empty()
    );

    assertThat(body)
        .as("a brace here would be refused by the helper, taking the launch down with it")
        .doesNotContain("{")
        .doesNotContain("}")
        .contains("\\173")
        .contains("\\175");
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

    try (
        LoadedAppArmorProfile asGlob = LoadedAppArmorProfile.load(
            List.of(allowRule(RulePath.literal(CAT_EXECUTABLE)), allowRule(RulePath.glob(named + "/**")))
        )
    ) {
      assertThat(asGlob.run(CAT_EXECUTABLE, sibling.resolve("f").toString()).output())
          .as("a live wildcard is what makes the over-grant reachable, and this is the control for it")
          .contains("PAYLOAD");
    }

    try (
        LoadedAppArmorProfile asLiteral = LoadedAppArmorProfile.load(
            List.of(allowRule(RulePath.literal(CAT_EXECUTABLE)), allowRule(RulePath.tree(named)))
        )
    ) {
      assertThat(asLiteral.run(CAT_EXECUTABLE, named.resolve("f").toString()).output())
          .as("the directory the rule names must still be reachable")
          .contains("PAYLOAD");
      for (Path decoy : List.of(characterDropped, characterReplaced, sibling)) {
        assertThat(asLiteral.run(CAT_EXECUTABLE, decoy.resolve("f").toString()).output())
            .as("no directory but the one named, and %s is not it", decoy)
            .doesNotContain("PAYLOAD");
      }
    }
  }

  @Test
  void refusesTheBraceGroupDenyRatherThanEmittingOneThatEnforcesNothing(
      @TempDir Path tempDirParameter
  ) throws IOException {
    Path tempDir = tempDirParameter.toRealPath();
    Path certificate = payloadFile(tempDir, "secret.pem");
    Path key = payloadFile(tempDir, "secret.key");
    List<FilesystemRule> allowOnly = List.of(allowRule(RulePath.literal(CAT_EXECUTABLE)), allowRule(RulePath.tree(tempDir)));
    List<FilesystemRule> perAlternative = List.of(
        allowRule(RulePath.literal(CAT_EXECUTABLE)),
        denyRule(RulePath.glob("**/*.pem")),
        denyRule(RulePath.glob("**/*.key")),
        allowRule(RulePath.tree(tempDir))
    );

    assertThatThrownBy(() -> AppArmorProfileGenerator.generate(
        "warden-sandbox-test", List.of(denyRule(RulePath.glob("**/*.{pem,key}")))
    ))
        .isInstanceOf(SandboxRuleRejectedException.class)
        .hasMessageContaining("**/*.{pem,key}");
    try (LoadedAppArmorProfile withoutDeny = LoadedAppArmorProfile.load(allowOnly)) {
      for (Path credential : List.of(certificate, key)) {
        assertThat(withoutDeny.run(CAT_EXECUTABLE, credential.toString()).output())
            .as("positive control: with no deny at all, %s reads out", credential)
            .contains("PAYLOAD");
      }
    }
    try (LoadedAppArmorProfile withDeny = LoadedAppArmorProfile.load(perAlternative)) {
      for (Path credential : List.of(certificate, key)) {
        assertThat(withDeny.run(CAT_EXECUTABLE, credential.toString()).output())
            .as("the spelling the refusal names must be one that enforces, for %s", credential)
            .doesNotContain("PAYLOAD");
      }
    }
  }

  private static Path payloadFile(Path parent, String name) throws IOException {
    Path file = parent.resolve(name);
    Files.writeString(file, "PAYLOAD");
    return file;
  }

  private static Path payloadDirectory(Path parent, String name) throws IOException {
    Path directory = Files.createDirectories(parent.resolve(name));
    Files.writeString(directory.resolve("f"), "PAYLOAD");
    return directory;
  }

  private static List<FilesystemRule> withDenyOfDirectory(String directory, List<FilesystemRule> writableTree) {
    List<FilesystemRule> rules = new ArrayList<>();
    rules.add(rule(Set.of(AccessKind.WRITE), RulePath.literal(directory), Decision.DENY));
    rules.add(rule(Set.of(AccessKind.WRITE), RulePath.tree(directory), Decision.DENY));
    rules.addAll(writableTree);
    return List.copyOf(rules);
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
}
