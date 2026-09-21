package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.marcinromanowski.warden.api.AccessKind;
import dev.marcinromanowski.warden.api.Decision;
import dev.marcinromanowski.warden.api.FilesystemRule;
import dev.marcinromanowski.warden.api.RulePath;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

// Actual OS enforcement (whether the generated profile really denies
// what it claims to) is covered separately in SeatbeltProfileGeneratorEnforcementTest via a real
// sandbox-exec run - see that class's comment for why string containment alone is not sufficient
// evidence of correctness for this generator.
class SeatbeltProfileGeneratorTest {

  private static final int PROXY_PORT = 18080;
  private static final String WORKSPACE_ROOT_PATTERN = "/workspace/**";
  private static final String FILE_READ_OPERATION = "file-read*";
  private static final Pattern CLAUSE_OPERATIONS = Pattern.compile("\\((?:allow|deny) ([a-z0-9-*? ]+?)(?= \\(|\\)|$)", Pattern.MULTILINE);

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
    FilesystemRule workspaceWrite = rule(Set.of(AccessKind.WRITE), RulePath.glob(WORKSPACE_ROOT_PATTERN), Decision.ALLOW);

    String profile = generate(List.of(workspaceWrite));

    assertThat(profile)
        .contains(allowClause("file-write*", WORKSPACE_ROOT_PATTERN));
  }

  @Test
  void denyCarveOutInsideBroaderAllowEmitsTheDenyClauseAfterTheAllowClause() {
    FilesystemRule denyCredential = rule(Set.of(AccessKind.READ), RulePath.glob("**/.env"), Decision.DENY);
    FilesystemRule allowWorkspace = rule(Set.of(AccessKind.READ), RulePath.glob(WORKSPACE_ROOT_PATTERN), Decision.ALLOW);
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
    FilesystemRule askRule = rule(Set.of(AccessKind.WRITE), RulePath.glob("/workspace/scratch/**"), Decision.ASK);

    String profile = generate(List.of(askRule));

    assertThat(profile)
        .contains(denyClause("file-write*", "/workspace/scratch/**"))
        .doesNotContain(allowClause("file-write*", "/workspace/scratch/**"));
  }

  @Test
  void externalDirectoryAloneGrantsTraversalWithoutTheListing() {
    FilesystemRule externalDirectoryOnly = rule(
        Set.of(AccessKind.EXTERNAL_DIRECTORY), RulePath.literal("/some/external/root"), Decision.ALLOW
    );

    String profile = generate(List.of(externalDirectoryOnly));

    assertThat(profile)
        .contains(allowClause("file-read-metadata", "/some/external/root"))
        .doesNotContain(allowClause(FILE_READ_OPERATION, "/some/external/root"));
  }

  @Test
  void readAndExternalDirectoryTogetherGrantTheListingTheReadAsksFor() {
    FilesystemRule both = rule(
        Set.of(AccessKind.READ, AccessKind.EXTERNAL_DIRECTORY), RulePath.literal("/some/external/root"), Decision.ALLOW
    );

    String profile = generate(List.of(both));

    assertThat(profile)
        .contains(allowClause(FILE_READ_OPERATION, "/some/external/root"))
        .doesNotContain(allowClause("file-read-metadata", "/some/external/root"));
  }

  @Test
  void higherPriorityReadDenyOutranksLowerPriorityExternalDirectoryAllowOverTheSamePath() {
    // Both name file-read-metadata, one through file-read*. Emitting them in separate passes would
    // decide this by pass order instead of by priority, and the deny would lose its metadata half.
    List<FilesystemRule> rules = List.of(
        rule(Set.of(AccessKind.READ), RulePath.glob("/tree/**"), Decision.DENY),
        rule(Set.of(AccessKind.EXTERNAL_DIRECTORY), RulePath.glob("/tree/**"), Decision.ALLOW)
    );

    String profile = generate(rules);

    assertThat(profile.indexOf(denyClause(FILE_READ_OPERATION, "/tree/**")))
        .as("the higher-priority deny must be the last matching clause, since SBPL decides by"
            + " clause order")
        .isGreaterThan(profile.indexOf(allowClause("file-read-metadata", "/tree/**")));
  }

  @Test
  void executeGetsItsOwnOperationRatherThanTheReadClause() {
    FilesystemRule executableOnly = rule(Set.of(AccessKind.EXECUTE), RulePath.literal("/tools/backend"), Decision.ALLOW);

    String profile = generate(List.of(executableOnly));

    assertThat(profile)
        .contains(allowClause("process-exec", "/tools/backend"))
        .as("EXECUTE alone grants no read on either platform - a script needs READ as well,"
            + " because its interpreter has to open it")
        .doesNotContain(allowClause(FILE_READ_OPERATION, "/tools/backend"));
  }

  @Test
  void denyOnExecuteAloneRefusesTheExecAndLeavesTheReadAlone() {
    List<FilesystemRule> rules = List.of(rule(Set.of(AccessKind.EXECUTE), RulePath.literal("/tools/backend"), Decision.DENY));

    String profile = generate(rules);

    assertThat(profile)
        .contains(denyClause("process-exec", "/tools/backend"))
        .doesNotContain(denyClause(FILE_READ_OPERATION, "/tools/backend"));
  }

  @Test
  void acceptsDenyOnReadAndExecuteTogetherAndEmitsBoth() {
    FilesystemRule unreadable = rule(Set.of(AccessKind.READ, AccessKind.EXECUTE), RulePath.glob("/tools/**/*.sh"), Decision.DENY);

    String profile = generate(List.of(unreadable));

    assertThat(profile)
        .contains(denyClause(FILE_READ_OPERATION, "/tools/**/*.sh"))
        .contains(denyClause("process-exec", "/tools/**/*.sh"));
  }

  @Test
  void lockOnDenyContributesNoClauseForTheSameReasonAnAllowDoesNot() {
    FilesystemRule unlockable = rule(Set.of(AccessKind.LOCK), RulePath.glob("/state/**"), Decision.DENY);
    FilesystemRule readOnlyDeny = rule(Set.of(AccessKind.READ), RulePath.glob("/state/**"), Decision.DENY);

    String withLockRule = generate(List.of(unlockable, readOnlyDeny));

    assertThat(withLockRule)
        .as("the read deny beside it is what proves the comparison is not between two empty profiles")
        .contains(denyClause(FILE_READ_OPERATION, "/state/**"))
        .isEqualTo(generate(List.of(readOnlyDeny)));
  }

  @Test
  void lockContributesNoClauseBecauseMacOsMediatesLockingThroughTheDescriptor() {
    FilesystemRule lockable = rule(
        Set.of(AccessKind.READ, AccessKind.WRITE, AccessKind.LOCK), RulePath.glob("/state/**"), Decision.ALLOW
    );
    FilesystemRule sameWithoutLock = rule(
        Set.of(AccessKind.READ, AccessKind.WRITE), RulePath.glob("/state/**"), Decision.ALLOW
    );

    String withLockRule = generate(List.of(lockable));

    assertThat(withLockRule)
        .contains(allowClause(FILE_READ_OPERATION, "/state/**"))
        .isEqualTo(generate(List.of(sameWithoutLock)));
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
        RulePath.glob("/workspace/**"),
        Set.of(AccessKind.READ),
        Decision.ALLOW,
        "harmless\n(allow file-read* (regex #\"^.*$\"))"
    );
    List<FilesystemRule> filesystemRules = List.of(ruleWithNewlineInReason);

    assertThatThrownBy(() -> generate(filesystemRules))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void emitsNoKeystrokeInjectionOperationForAnyRuleTheCallerCanWrite() {
    List<FilesystemRule> everyKindBothWays = new ArrayList<>();
    for (AccessKind kind : AccessKind.values()) {
      for (Decision decision : Decision.values()) {
        everyKindBothWays.add(rule(Set.of(kind), RulePath.glob(WORKSPACE_ROOT_PATTERN), decision));
      }
    }

    String profile = generate(everyKindBothWays);

    assertThat(operationsIn(profile))
        .as("the vocabulary is closed, and hid-control is the one outside it that matters: %s", profile)
        .isSubsetOf(
            "file-read-data", FILE_READ_OPERATION, "file-read-metadata", "file-write*", "file-ioctl",
            "process-exec", "process-fork", "signal", "sysctl-read", "mach-lookup", "iokit-open",
            "network*", "network-outbound", "network-bind", "network-inbound", "default"
        );
  }

  private static List<String> operationsIn(String profile) {
    List<String> operations = new ArrayList<>();
    Matcher matcher = CLAUSE_OPERATIONS.matcher(profile);
    while (matcher.find()) {
      operations.addAll(
          List.of(
              matcher.group(1)
                  .trim()
                  .split("\\s+")
          )
      );
    }
    return operations;
  }

  private static String generate(List<FilesystemRule> rules) {
    return SeatbeltProfileGenerator.generate(rules, PROXY_PORT, Optional.empty());
  }

  private static String allowClause(String sbplOperation, String pattern) {
    return "(allow " + sbplOperation + " (regex #\"" + SeatbeltGlobTranslator.toRegex(RulePath.glob(pattern)) + "\"))";
  }

  private static String denyClause(String sbplOperation, String pattern) {
    return "(deny " + sbplOperation + " (regex #\"" + SeatbeltGlobTranslator.toRegex(RulePath.glob(pattern)) + "\"))";
  }

  private static FilesystemRule rule(Set<AccessKind> kinds, RulePath target, Decision decision) {
    return new FilesystemRule(target, kinds, decision, "test reason");
  }
}
