package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.marcinromanowski.warden.api.AccessKind;
import dev.marcinromanowski.warden.api.Decision;
import dev.marcinromanowski.warden.api.FilesystemRule;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

// Actual OS enforcement (whether the generated profile really denies
// what it claims to) is covered separately in SeatbeltProfileGeneratorEnforcementTest via a real
// sandbox-exec run - see that class's comment for why string containment alone is not sufficient
// evidence of correctness for this generator.
class SeatbeltProfileGeneratorTest {

  private static final int PROXY_PORT = 18080;
  private static final String WORKSPACE_ROOT_PATTERN = "/workspace/**";
  private static final String FILE_READ_OPERATION = "file-read*";

  @Test
  void deniesEverythingByDefault() {
    String profile = generate(List.of());

    assertThat(profile)
        .contains("(deny default)");
  }

  @Test
  void pinsNetworkOutboundToTheLocalProxyPortOnly() {
    String profile = generate(List.of());

    assertThat(profile)
        .contains("(deny network*)")
        .contains("(allow network-outbound (remote tcp \"localhost:" + PROXY_PORT + "\"))");
  }

  @Test
  void omitsNetworkBindClauseWhenNoListenPortIsGiven() {
    String profile = generate(List.of());

    assertThat(profile)
        .doesNotContain("network-bind");
  }

  @Test
  void pinsNetworkBindToTheExactGivenPortWithNoAddressWildcard() {
    String profile = SeatbeltProfileGenerator.generate(List.of(), PROXY_PORT, Optional.of(4096));

    assertThat(profile)
        .contains("(allow network-bind (local tcp \"localhost:4096\"))")
        .doesNotContain("(local ip)");
  }

  @Test
  void emitsAllowClauseForAllowedWorkspaceRoot() {
    FilesystemRule workspaceWrite = rule(Set.of(AccessKind.WRITE), WORKSPACE_ROOT_PATTERN, Decision.ALLOW);

    String profile = generate(List.of(workspaceWrite));

    assertThat(profile)
        .contains(allowClause("file-write*", WORKSPACE_ROOT_PATTERN));
  }

  @Test
  void denyCarveOutInsideBroaderAllowEmitsTheDenyClauseAfterTheAllowClause() {
    FilesystemRule denyCredential = rule(Set.of(AccessKind.READ), "**/.env", Decision.DENY);
    FilesystemRule allowWorkspace = rule(Set.of(AccessKind.READ), WORKSPACE_ROOT_PATTERN, Decision.ALLOW);
    // First-match-wins priority order: narrower DENY first, broader ALLOW second. SBPL is
    // last-match-wins, so the generator must emit these in REVERSE - the ALLOW clause before the
    // DENY clause - for the DENY to actually win. Asserted here as clause order, and separately
    // proven to actually enforce correctly in SeatbeltProfileGeneratorEnforcementTest.
    String profile = SeatbeltProfileGenerator.generate(
        List.of(denyCredential, allowWorkspace), PROXY_PORT, Optional.empty()
    );

    String denyClause = denyClause(FILE_READ_OPERATION, "**/.env");
    String allowClause = allowClause(FILE_READ_OPERATION, WORKSPACE_ROOT_PATTERN);
    assertThat(profile)
        .contains(denyClause)
        .contains(allowClause);
    assertThat(profile.indexOf(allowClause))
        .as("the lower-priority ALLOW must be emitted before the higher-priority DENY")
        .isLessThan(profile.indexOf(denyClause));
  }

  @Test
  void asksFoldToDenyBecauseThereIsNoSynchronousApprovalChannelAtTheSyscallBoundary() {
    FilesystemRule askRule = rule(Set.of(AccessKind.WRITE), "/workspace/scratch/**", Decision.ASK);

    String profile = generate(List.of(askRule));

    assertThat(profile)
        .contains(denyClause("file-write*", "/workspace/scratch/**"))
        .doesNotContain(allowClause("file-write*", "/workspace/scratch/**"));
  }

  @Test
  void externalDirectoryAloneFoldsIntoReadClauseEmission() {
    FilesystemRule externalDirectoryOnly = rule(
        Set.of(AccessKind.EXTERNAL_DIRECTORY), "/some/external/root/**", Decision.ALLOW
    );

    String profile = generate(List.of(externalDirectoryOnly));

    assertThat(profile)
        .contains(allowClause(FILE_READ_OPERATION, "/some/external/root/**"));
  }

  @Test
  void rejectsNonPositiveProxyPort() {
    assertThatThrownBy(() -> SeatbeltProfileGenerator.generate(List.of(), 0, Optional.empty()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void rejectsNonPositiveListenPort() {
    List<FilesystemRule> filesystemRules = List.of();
    Optional<Integer> listenPort = Optional.of(0);

    assertThatThrownBy(() -> SeatbeltProfileGenerator.generate(filesystemRules, PROXY_PORT, listenPort))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void rejectsReasonContainingLineBreak() {
    FilesystemRule ruleWithNewlineInReason = new FilesystemRule(
        "/workspace/**",
        Set.of(AccessKind.READ),
        Decision.ALLOW,
        "harmless\n(allow file-read* (regex #\"^.*$\"))"
    );
    List<FilesystemRule> filesystemRules = List.of(ruleWithNewlineInReason);

    assertThatThrownBy(() -> generate(filesystemRules))
        .isInstanceOf(IllegalArgumentException.class);
  }

  private static String generate(List<FilesystemRule> rules) {
    return SeatbeltProfileGenerator.generate(rules, PROXY_PORT, Optional.empty());
  }

  private static String allowClause(String sbplOperation, String pattern) {
    return "(allow " + sbplOperation + " (regex #\"" + SeatbeltGlobTranslator.toRegex(pattern) + "\"))";
  }

  private static String denyClause(String sbplOperation, String pattern) {
    return "(deny " + sbplOperation + " (regex #\"" + SeatbeltGlobTranslator.toRegex(pattern) + "\"))";
  }

  private static FilesystemRule rule(Set<AccessKind> kinds, String pattern, Decision decision) {
    return new FilesystemRule(pattern, kinds, decision, "test reason");
  }
}
