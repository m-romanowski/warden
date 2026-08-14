package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.marcinromanowski.warden.api.AccessKind;
import dev.marcinromanowski.warden.api.Decision;
import dev.marcinromanowski.warden.api.FilesystemRule;
import java.util.List;
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

  // A higher-priority literal ALLOW carving an exception out of a lower-priority glob DENY - the
  // real, asymmetric AppArmor limitation this generator now works around (see
  // AppArmorDenyGlobExclusion). Requires the ALLOW to appear FIRST in the given rule list - see
  // this class's own header comment for why that's a real, deliberate input-order dependence, not
  // an oversight.
  @Test
  void higherPriorityLiteralAllowGivenFirstCarvesExceptionOutOfLowerPriorityGlobDeny() {
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

  // The reverse of the case above: if the lower-priority DENY is given FIRST (before the ALLOW
  // it should have been overridden by), this generator has no way to know the exception was
  // supposed to apply yet, so it correctly falls back to emitting the deny glob unchanged - a
  // real, named consequence of requiring priority-ordered input, not a silent bug.
  @Test
  void denyGivenBeforeTheAllowItShouldHaveExcludedIsEmittedUnchanged() {
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
