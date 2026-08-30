package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.marcinromanowski.warden.api.AccessKind;
import dev.marcinromanowski.warden.api.Decision;
import dev.marcinromanowski.warden.api.FilesystemRule;
import dev.marcinromanowski.warden.api.SandboxRuleRejectedException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

// Actual kernel enforcement is covered separately in AppArmorProfileGeneratorEnforcementTest via
// a real apparmor_parser + aa-exec run - see that class's comment for why string containment alone
// is not sufficient evidence of correctness.
class AppArmorProfileGeneratorTest {

  private static final String PROFILE_NAME = "warden-test-profile";
  private static final String WORKSPACE_ROOT_PATTERN = "/workspace/**";

  @Test
  void namesTheGeneratedProfile() {
    String profile = generate(List.of());

    assertThat(profile)
        .contains("profile " + PROFILE_NAME + " ");
  }

  @Test
  void includesTheGenericBootstrapAbstraction() {
    String profile = generate(List.of());

    assertThat(profile)
        .contains("#include <abstractions/base>");
  }

  @Test
  void emitsAllowClauseForAllowedWorkspaceRoot() {
    FilesystemRule workspaceWrite = rule(Set.of(AccessKind.WRITE), WORKSPACE_ROOT_PATTERN, Decision.ALLOW);

    String profile = generate(List.of(workspaceWrite));

    assertThat(profile)
        .contains("allow " + WORKSPACE_ROOT_PATTERN + " w,");
  }

  @Test
  void emitsDenyClauseForDeniedCredentialGlob() {
    FilesystemRule denyCredential = rule(Set.of(AccessKind.READ), "**/.env", Decision.DENY);

    String profile = generate(List.of(denyCredential));

    assertThat(profile)
        .contains("deny /**/.env r,");
  }

  @Test
  void emitsBothReadAndWriteModeLettersWhenBothAreGranted() {
    FilesystemRule readWrite = rule(Set.of(AccessKind.READ, AccessKind.WRITE), WORKSPACE_ROOT_PATTERN, Decision.ALLOW);

    String profile = generate(List.of(readWrite));

    assertThat(profile)
        .contains("allow " + WORKSPACE_ROOT_PATTERN + " rw,");
  }

  @Test
  void asksFoldToDenyBecauseThereIsNoSynchronousApprovalChannelAtTheSyscallBoundary() {
    FilesystemRule askRule = rule(Set.of(AccessKind.WRITE), "/workspace/scratch/**", Decision.ASK);

    String profile = generate(List.of(askRule));

    assertThat(profile)
        .contains("deny /workspace/scratch/** w,")
        .doesNotContain("allow /workspace/scratch/** w,");
  }

  @Test
  void externalDirectoryAloneFoldsIntoReadModeEmission() {
    FilesystemRule externalDirectoryOnly = rule(
        Set.of(AccessKind.EXTERNAL_DIRECTORY), "/some/external/root/**", Decision.ALLOW
    );

    String profile = generate(List.of(externalDirectoryOnly));

    assertThat(profile)
        .contains("allow /some/external/root/** r,");
  }

  @Test
  void bareDirectoryPatternIsEmittedVerbatimForAncestorListingRules() {
    // The caller (not this generator) decides whether a rule is "listing only" by the pattern
    // shape it supplies - a bare directory path with no /** suffix. Confirmed empirically in
    // AppArmorProfileGeneratorEnforcementTest that AppArmor itself treats this as listing-only.
    FilesystemRule ancestorListing = rule(Set.of(AccessKind.READ), "/workspace/parent/", Decision.ALLOW);

    String profile = generate(List.of(ancestorListing));

    assertThat(profile)
        .contains("allow /workspace/parent/ r,");
  }

  @Test
  void executeEmitsInheritExecSoTheChildStaysUnderTheSameProfile() {
    FilesystemRule executable = rule(Set.of(AccessKind.READ, AccessKind.EXECUTE), "/tools/backend", Decision.ALLOW);

    String profile = generate(List.of(executable));

    assertThat(profile)
        .contains("allow /tools/backend rix,");
  }

  @Test
  void executeOnDenyEmitsBareExecLetterWithNoTransitionQualifier() {
    // apparmor_parser refuses a whole profile carrying "deny <path> ix," ("Invalid perms, in deny
    // rules 'x' must not be preceded by exec qualifier 'i', 'p', or 'u'"), and a refused profile is a
    // failed sandbox launch, not a rejected rule.
    FilesystemRule unrunnable = rule(Set.of(AccessKind.EXECUTE), "/workspace/**/*.sh", Decision.DENY);

    String profile = generate(List.of(unrunnable));

    assertThat(profile)
        .contains("deny /workspace/**/*.sh x,")
        .doesNotContain("deny /workspace/**/*.sh ix,");
  }

  @Test
  void readAndExecuteOnDenyKeepsReadAndDropsTheTransitionQualifier() {
    FilesystemRule unreadableAndUnrunnable = rule(
        Set.of(AccessKind.READ, AccessKind.EXECUTE), "/tools/backend", Decision.DENY
    );

    String profile = generate(List.of(unreadableAndUnrunnable));

    assertThat(profile)
        .contains("deny /tools/backend rx,")
        .doesNotContain("deny /tools/backend rix,");
  }

  @Test
  void lockOnDenyEmitsTheSameLockModeLetter() {
    FilesystemRule unlockable = rule(Set.of(AccessKind.READ, AccessKind.LOCK), "/state/**", Decision.DENY);

    String profile = generate(List.of(unlockable));

    assertThat(profile)
        .contains("deny /state/** rk,");
  }

  @Test
  void lockEmitsTheDistinctLockModeLetter() {
    FilesystemRule lockable = rule(
        Set.of(AccessKind.READ, AccessKind.WRITE, AccessKind.LOCK), "/state/**", Decision.ALLOW
    );

    String profile = generate(List.of(lockable));

    assertThat(profile)
        .contains("allow /state/** rwk,");
  }

  @Test
  void writeWithoutLockStillEmitsNoLockModeLetter() {
    FilesystemRule readWrite = rule(Set.of(AccessKind.READ, AccessKind.WRITE), "/state/**", Decision.ALLOW);

    String profile = generate(List.of(readWrite));

    assertThat(profile)
        .contains("allow /state/** rw,")
        .doesNotContain("rwk");
  }

  @Test
  void namesTheDirectoryFormOfAnAllowWithReadAccessOnly() {
    // Listing the directory is the whole reason the companion exists on the allow side, and "r" is
    // what mediates listing. Carrying the rule's own "w" there was a real capability rather than a
    // formality: it is what mediates renaming the named directory itself, which needs no emptying and
    // let a confined process relocate a granted tree wholesale.
    FilesystemRule workspaceRoot = rule(Set.of(AccessKind.READ, AccessKind.WRITE), "/workspace", Decision.ALLOW);

    String profile = generate(List.of(workspaceRoot));

    assertThat(profile)
        .contains("allow /workspace rw,")
        .contains("allow /workspace/ r,")
        .doesNotContain("allow /workspace/ rw,");
  }

  @Test
  void namesNoDirectoryFormForAnAllowThatGrantsNoReadToListWith() {
    FilesystemRule writeOnly = rule(Set.of(AccessKind.WRITE), "/dev/null", Decision.ALLOW);

    String profile = generate(List.of(writeOnly));

    assertThat(profile)
        .contains("allow /dev/null w,")
        .doesNotContain("allow /dev/null/ ");
  }

  @Test
  void namesTheDirectoryFormOfDenyClausesTooAndKeepsTheRulesOwnMode() {
    // A deny pair of "<dir>" and "<dir>/**" alone still lets a confined process mkdir that directory,
    // because mkdir is mediated against the trailing-slash name only. The deny companion keeps the
    // rule's own mode, unlike the allow one: "w" there is exactly what refuses mkdir and rename.
    FilesystemRule pluginDirectory = rule(Set.of(AccessKind.WRITE), "/workspace/.opencode/plugin", Decision.DENY);

    String profile = generate(List.of(pluginDirectory));

    assertThat(profile)
        .contains("deny /workspace/.opencode/plugin w,")
        .contains("deny /workspace/.opencode/plugin/ w,");
  }

  @Test
  void denyGlobMatchingAnywhereAlsoNamesTheRootLevelFormItsRecursiveGlobMisses() {
    // "**" does not match the empty string between two slashes, so "/**/.env" leaves a file sitting
    // directly at "/" uncovered. On a deny that hole is closed by naming the zero-segment reading.
    FilesystemRule credentials = rule(Set.of(AccessKind.READ), "**/.env", Decision.DENY);

    String profile = generate(List.of(credentials));

    assertThat(profile)
        .contains("deny /**/.env r,")
        .contains("deny /.env r,");
  }

  @Test
  void allowGlobMatchingAnywhereIsLeftWithoutTheRootLevelGrantADenyWouldGet() {
    // The root-level reading is emitted on a deny and not on an allow, and the reason is risk
    // asymmetry rather than authorship. Under the java.nio.file PathMatcher semantics these patterns
    // are authored against, "**/.env.example" does match "/.env.example" - so the caller did write
    // this case, and macOS grants it. Getting it wrong on a deny costs one unreachable path, and
    // getting it wrong on an allow hands out access at the filesystem root.
    FilesystemRule templates = rule(Set.of(AccessKind.READ), "**/.env.example", Decision.ALLOW);

    String profile = generate(List.of(templates));

    assertThat(profile)
        .contains("allow /**/.env.example r,")
        .doesNotContain("allow /.env.example r,");
  }

  @Test
  void grantsWardensOwnReservedFilesWithoutOutrankingAnythingTheCallerWrote() {
    String profile = AppArmorProfileGenerator.generate(
        PROFILE_NAME,
        List.of(rule(Set.of(AccessKind.READ), "/unrelated/**", Decision.DENY)),
        Optional.of(new BwrapSessionPaths(Path.of("/tmp/warden-session-xyz"), true)),
        Optional.of(Path.of("/opt/tools/socat"))
    );

    assertThat(profile)
        .as("no clause anywhere in a generated profile out-ranks another")
        .doesNotContain("priority=")
        .contains("/tmp/warden-session-xyz/target-shell mrix,")
        .contains("/tmp/warden-session-xyz/proxy.sock rw,")
        .contains("/tmp/warden-session-xyz/control.sock rw,")
        .contains(AppArmorProfileGenerator.BWRAP_BRIDGE_DIRECTORY + "/bridge-entrypoint.sh r,")
        .contains(AppArmorProfileGenerator.BWRAP_BRIDGE_DIRECTORY + "/proxy.sock rw,")
        .contains("/opt/tools/socat rix,")
        .as("neither warden's own session directory nor the bridge alias is granted as a tree - a"
            + " tree grant there is a tree the confined process can write into")
        .doesNotContain("/tmp/warden-session-xyz/**")
        .doesNotContain(AppArmorProfileGenerator.BWRAP_BRIDGE_DIRECTORY + "/**")
        .contains("deny /unrelated/** r,");
  }

  @Test
  void omitsTheControlSocketClauseWhenTheLaunchHasNoControlPlane() {
    String profile = AppArmorProfileGenerator.generate(
        PROFILE_NAME,
        List.of(),
        Optional.of(new BwrapSessionPaths(Path.of("/tmp/warden-session-xyz"), false)),
        Optional.empty()
    );

    assertThat(profile)
        .contains("/tmp/warden-session-xyz/proxy.sock rw,")
        .doesNotContain("control.sock");
  }

  @Test
  void refusesTheCallerDenyThatCoversWhatWardenItselfNeeds() {
    assertThatThrownBy(() -> AppArmorProfileGenerator.generate(
        PROFILE_NAME,
        List.of(rule(Set.of(AccessKind.READ), "**/tmp/**", Decision.DENY)),
        Optional.of(new BwrapSessionPaths(Path.of("/tmp/warden-session-xyz"), true)),
        Optional.of(Path.of("/opt/tools/socat"))
    ))
        .isInstanceOf(SandboxRuleRejectedException.class)
        .hasMessageContaining("**/tmp/**")
        .hasMessageContaining("/tmp/warden-session-xyz/target-shell");
  }

  @Test
  void doesNotRefuseTheDenyThatTakesNothingWardenNeeds() {
    String profile = AppArmorProfileGenerator.generate(
        PROFILE_NAME,
        List.of(rule(Set.of(AccessKind.EXTERNAL_DIRECTORY), "/tmp/**", Decision.DENY)),
        Optional.of(new BwrapSessionPaths(Path.of("/tmp/warden-session-xyz"), true)),
        Optional.of(Path.of("/opt/tools/socat"))
    );

    assertThat(profile)
        .contains("deny /tmp/** r,");
  }

  @Test
  void permitsSignalsWithinThisProfileAndNoWider() {
    // Signals are how JavaScriptCore suspends its own threads, and an enforcing profile that names no
    // signal rule denies them - measured as a backend that prints its own "listening" line and then
    // dies. Scoped to this profile's own label, in both the spellings a launch can carry.
    String profile = AppArmorProfileGenerator.generate(PROFILE_NAME, List.of());

    assertThat(profile)
        .contains("signal peer=" + PROFILE_NAME + ",")
        .contains("signal peer=bwrap//&unpriv_bwrap//&" + PROFILE_NAME + ",")
        .as("never a blanket signal grant")
        .doesNotContain("\n  signal,");
  }

  @Test
  void externalDirectoryAloneGrantsTraversalWithoutTheListing() {
    String profile = AppArmorProfileGenerator.generate(
        PROFILE_NAME,
        List.of(
            rule(Set.of(AccessKind.EXTERNAL_DIRECTORY), "/home/someone", Decision.ALLOW),
            rule(Set.of(AccessKind.READ), "/home/other", Decision.ALLOW)
        )
    );

    assertThat(profile)
        .contains("allow /home/someone r,")
        .doesNotContain("allow /home/someone/ r,")
        .as("a rule that names READ still gets the listing companion it always had")
        .contains("allow /home/other/ r,");
  }

  @Test
  void denyGlobNamingEveryDirectoryDoesNotNameTheFilesystemRootItself() {
    FilesystemRule everyDirectory = rule(Set.of(AccessKind.WRITE), "**/", Decision.DENY);

    String profile = generate(List.of(everyDirectory));

    assertThat(profile)
        .contains("deny /**/ w,")
        .doesNotContain("deny / w,");
  }

  @Test
  void leavesRecursivePatternsAloneBecauseTheyAlreadySpanDirectoryNames() {
    FilesystemRule recursive = rule(Set.of(AccessKind.READ), "/workspace/**", Decision.ALLOW);

    String profile = generate(List.of(recursive));

    assertThat(profile)
        .contains("allow /workspace/** r,")
        .doesNotContain("allow /workspace/**/ r,");
  }

  @Test
  void leavesPatternsAlreadyInDirectoryFormAlone() {
    FilesystemRule directoryForm = rule(Set.of(AccessKind.READ), "/workspace/parent/", Decision.ALLOW);

    String profile = generate(List.of(directoryForm));

    assertThat(profile)
        .contains("allow /workspace/parent/ r,")
        .doesNotContain("allow /workspace/parent// r,");
  }

  @Test
  void denyGlobWithARepeatedLeadingRecursiveGlobNamesEveryDepthItMisses() {
    FilesystemRule credentials = rule(Set.of(AccessKind.READ), "**/**/.env", Decision.DENY);

    String profile = generate(List.of(credentials));

    assertThat(profile)
        .contains("deny /**/**/.env r,")
        .contains("deny /**/.env r,")
        .contains("deny /.env r,");
  }

  @Test
  void orderOfNonOverlappingConflictingRulesDoesNotAffectWhichClausesAreEmitted() {
    // For a single overlapping allow/deny pair (not a carve-out case - see the two tests below
    // for that), AppArmor resolves by set-subtraction, not last-clause-wins (empirically
    // confirmed on a real kernel - see AppArmorProfileGeneratorEnforcementTest). This test only
    // asserts both clauses are present in the given input order. The actual order-independence
    // property is proven by running both orderings through a real kernel in the enforcement test.
    FilesystemRule denyCredential = rule(Set.of(AccessKind.READ), "**/.env", Decision.DENY);
    FilesystemRule allowWorkspace = rule(Set.of(AccessKind.READ), WORKSPACE_ROOT_PATTERN, Decision.ALLOW);

    String profile = generate(List.of(denyCredential, allowWorkspace));

    assertThat(profile)
        .contains("deny /**/.env r,")
        .contains("allow " + WORKSPACE_ROOT_PATTERN + " r,");
  }

  @Test
  void higherPriorityLiteralAllowGivenFirstCarvesExceptionOutOfLowerPriorityGlobDeny() {
    // A higher-priority literal ALLOW carving an exception out of a lower-priority glob DENY - the
    // real, asymmetric AppArmor limitation this generator now works around (see
    // AppArmorDenyGlobExclusion). Requires the ALLOW to appear FIRST in the given rule list - see
    // this class's own header comment for why that's a real, deliberate input-order dependence, not
    // an oversight.
    FilesystemRule allowException = rule(
        Set.of(AccessKind.READ), "/workspace/.env.example", Decision.ALLOW
    );
    FilesystemRule denyCredentialGlob = rule(Set.of(AccessKind.READ), "**/.env*", Decision.DENY);

    String profile = generate(List.of(allowException, denyCredentialGlob));

    assertThat(profile)
        .as("the literal exception must never be re-covered by the broader deny glob")
        .doesNotContain("deny /**/.env.example r,")
        .doesNotContain("deny /**/.env* r,")
        .contains("deny /**/.env.example?* r,");
  }

  @Test
  void denyGivenBeforeTheAllowItShouldHaveExcludedIsEmittedUnchanged() {
    // The reverse of the case above: if the lower-priority DENY is given FIRST (before the ALLOW
    // it should have been overridden by), this generator has no way to know the exception was
    // supposed to apply yet, so it correctly falls back to emitting the deny glob unchanged - a
    // real, named consequence of requiring priority-ordered input, not a silent bug.
    FilesystemRule denyCredentialGlob = rule(Set.of(AccessKind.READ), "**/.env*", Decision.DENY);
    FilesystemRule allowException = rule(
        Set.of(AccessKind.READ), "/workspace/.env.example", Decision.ALLOW
    );

    String profile = generate(List.of(denyCredentialGlob, allowException));

    assertThat(profile)
        .contains("deny /**/.env* r,");
  }

  @Test
  void rejectsReasonContainingLineBreak() {
    FilesystemRule ruleWithNewlineInReason = new FilesystemRule(
        WORKSPACE_ROOT_PATTERN,
        Set.of(AccessKind.READ),
        Decision.ALLOW,
        "harmless\nallow /** rwx,"
    );
    List<FilesystemRule> filesystemRules = List.of(ruleWithNewlineInReason);

    assertThatThrownBy(() -> generate(filesystemRules))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void rejectsBlankProfileName() {
    assertThatThrownBy(() -> AppArmorProfileGenerator.generate(" ", List.of()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  private static String generate(List<FilesystemRule> rules) {
    return AppArmorProfileGenerator.generate(PROFILE_NAME, rules);
  }

  private static FilesystemRule rule(Set<AccessKind> kinds, String pattern, Decision decision) {
    return new FilesystemRule(pattern, kinds, decision, "test reason");
  }
}
