package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.AccessKind;
import dev.marcinromanowski.warden.api.Decision;
import dev.marcinromanowski.warden.api.FilesystemRule;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

// Generates a Linux AppArmor profile from a resolved filesystem rule list - the Seatbelt-parity
// mechanism for Linux. AppArmor evaluates rules lazily, at real access time, entirely in-kernel -
// unlike a static bwrap-only mount plan (decided once, before the sandboxed process starts, with
// no hook to re-evaluate a pattern against a path opened later), this generator needs no
// filesystem walk, no prune heuristics, and has no mid-session drift gap.
//
// Unlike SeatbeltProfileGenerator, no regex translation is needed: AppArmor's own path-pattern
// grammar already understands the glob subset used here natively (AppArmorGlobTranslator only
// rejects unsafe syntax, it doesn't rewrite anything). AppArmor resolves a *single* overlapping
// allow/deny pair by set-subtraction, not last-clause-wins - confirmed empirically that emission
// order never changes which one wins for that pair.
//
// That set-subtraction model is also, empirically, NOT symmetric with respect to specificity: a
// deny wins over any overlapping allow unconditionally, regardless of which one is "more
// specific." This generator DOES still depend on the *given* rule ordering for one thing because
// of that: a higher-priority literal ALLOW must appear before a lower-priority glob DENY it's
// meant to carve an exception out of, so this generator can track it and rewrite the DENY's own
// pattern to exclude it (see AppArmorDenyGlobExclusion) - reversing that specific input order
// silently loses the exception, same as the caller already has to give rules in priority order
// for every other reason.
//
// Network is deliberately out of scope here: on Linux, network isolation is bwrap's job
// (--unshare-net, a genuine kernel namespace boundary), not AppArmor's - this generator only ever
// produces filesystem rules.
final class AppArmorProfileGenerator {

  // Mirrors SeatbeltProfileGenerator's own bootstrap stance exactly: this sandbox's security
  // boundary is what a process can READ/WRITE, not which programs it's allowed to invoke - a
  // bash-tool-driving backend needs to run ordinary shells/coreutils as a basic capability, same
  // as any unsandboxed shell session would. `rix` (read+inherit-exec) keeps the child under this
  // same profile rather than transitioning or dropping confinement.
  //
  // The bridge-directory line is BwrapSandboxedProcessLauncher's fixed, session-independent
  // in-sandbox mount point (see its own IN_SANDBOX_BRIDGE_DIRECTORY, which must stay textually
  // identical to this constant) - a bind mount remaps the bridge script/sockets to this path
  // *inside* the sandbox's own mount namespace, and AppArmor mediates the path a confined process
  // actually opens, not the host path behind the bind mount, so a rule scoped to the host-side
  // session directory alone does not cover it (confirmed empirically against a real kernel).
  static final String BWRAP_BRIDGE_DIRECTORY = "/tmp/warden-sandbox-bridge";

  // /usr/lib, /lib, /lib64 get "mrix", not just "mr": on at least one real distro (Ubuntu
  // 26.04 aarch64) coreutils binaries like `sleep` resolve to a real path under
  // /usr/lib/**/coreutils/** rather than /usr/bin, so AppArmor's own exec-target resolution
  // (which checks the symlink's real resolved path, not the /usr/bin/sleep name a caller
  // invokes) denies it unless the library tree itself also carries exec permission (confirmed
  // empirically against a real kernel). This does not widen the actual
  // security boundary this sandbox exists to enforce - as this class's own header already
  // states, that boundary is the caller-supplied filesystemRules list, not which system
  // binaries can run. bwrap's own BOOTSTRAP_READ_ONLY_PATHS already makes this exact path set
  // visible read-only regardless.
  //
  // The blanket "network," rule mirrors this file's own header note that network is deliberately
  // out of scope for AppArmor: real egress reachability is bwrap's --unshare-net boundary alone,
  // so this only grants the socket()/bind() syscalls the in-sandbox bridge socats need to talk to
  // each other and to the host proxy over the bind-mounted UDS - AppArmor's own network mediation
  // would otherwise be pure friction duplicating a control bwrap already fully owns.
  private static final String BOOTSTRAP_ALLOWANCES =
      """
      #include <abstractions/base>
      network,
      /bin/** rix,
      /usr/bin/** rix,
      /usr/lib/** mrix,
      /lib/** mrix,
      /lib64/** mrix,
      /usr/share/** r,
      %s/** rw,
      """.formatted(BWRAP_BRIDGE_DIRECTORY);

  private AppArmorProfileGenerator() {
  }

  static String generate(String profileName, List<FilesystemRule> filesystemRules) {
    return generate(profileName, filesystemRules, Optional.empty());
  }

  // bwrapSessionDirectory, when present, is warden's own per-session scratch directory (the
  // unique px-stacking target binary bwrap execs into, plus the network-bridge script and
  // sockets it reads) - not caller policy, so it is not expressed via the FilesystemRule list
  // like everything else this generator emits. It needs "mrwix", not just "mrix": the kernel's
  // own ELF load of the unique target binary is itself checked against this profile once the px
  // stacking transition lands the process here, and denies with a distinct file_mmap "m" failure
  // if only read access is granted (confirmed empirically against a real kernel).
  // The "w" is separately required for a genuinely surprising reason, also confirmed empirically:
  // AppArmor mediates a connect() to a bind-mounted Unix domain socket against the socket's own
  // *bind-time* path (this session directory's real host path), not the path the confined process
  // used to reach it through the bridge's own bind-mounted alias (BWRAP_BRIDGE_DIRECTORY, granted
  // separately below) - so the in-sandbox socat's own connect() to the bridge's proxy.sock is
  // checked against this rule, not that one, and needs write access to succeed.
  static String generate(String profileName, List<FilesystemRule> filesystemRules, Optional<Path> bwrapSessionDirectory) {
    String requiredName = Preconditions.nonBlank(profileName, "profileName");
    List<FilesystemRule> requiredRules = List.copyOf(Preconditions.nonNull(filesystemRules, "filesystemRules"));
    Optional<Path> requiredSessionDirectory = Preconditions.nonNull(bwrapSessionDirectory, "bwrapSessionDirectory");
    StringBuilder profile = new StringBuilder();
    profile.append("#include <tunables/global>\n\n")
        .append("profile ")
        .append(requiredName)
        .append(" flags=(attach_disconnected) {\n")
        .append(indent(BOOTSTRAP_ALLOWANCES));
    requiredSessionDirectory.ifPresent(
        directory -> profile.append("  ")
            .append(directory)
            .append("/** mrwix,\n")
    );
    // Higher-priority literal ALLOW patterns seen so far, in the caller's own priority order -
    // used to carve exceptions out of a later, lower-priority DENY glob that would otherwise
    // silently re-cover them (see AppArmorDenyGlobExclusion's own header for the full "why" -
    // AppArmor's set-subtraction model has no native priority/specificity concept at all).
    List<String> higherPriorityLiteralAllows = new ArrayList<>();
    for (FilesystemRule rule : requiredRules) {
      appendRuleClause(profile, rule, higherPriorityLiteralAllows);
      String translatedPattern = AppArmorGlobTranslator.toAppArmorPattern(rule.targetPattern());
      if (effectiveDecisionIsAllow(rule.decision()) && isLiteralPattern(translatedPattern)) {
        higherPriorityLiteralAllows.add(translatedPattern);
      }
    }
    profile.append("}\n");
    return profile.toString();
  }

  private static void appendRuleClause(StringBuilder profile, FilesystemRule rule, List<String> higherPriorityLiteralAllows) {
    String pattern = AppArmorGlobTranslator.toAppArmorPattern(rule.targetPattern());
    String mode = accessMode(rule.accessKinds());
    String reason = requireSingleLineReason(rule.reason());
    boolean isAllow = effectiveDecisionIsAllow(rule.decision());
    String clauseVerb = isAllow ? "allow" : "deny";
    List<String> patterns = isAllow ? List.of(pattern) : denyPatternsExcludingHigherPriorityAllows(pattern, higherPriorityLiteralAllows);
    for (String emittedPattern : patterns) {
      profile.append("  ")
          .append(clauseVerb)
          .append(' ')
          .append(emittedPattern)
          .append(' ')
          .append(mode)
          .append(", # ")
          .append(reason)
          .append('\n');
    }
  }

  // Only the first higher-priority literal ALLOW that matches a given DENY pattern gets carved
  // out - a deliberate, narrower-than-general scope, not an oversight: composing more than one
  // exclusion would require re-running the match check against branches this class itself already
  // rewrote using AppArmor's own "[^x]" negation syntax, which java.nio.file's glob PathMatcher
  // parses differently ("!" for negation, "^" as a literal character) - reusing it there would
  // silently produce wrong matches. The realistic case (a caller wanting to carve out one
  // specific exception at a time) doesn't need more than this.
  private static List<String> denyPatternsExcludingHigherPriorityAllows(String denyPattern, List<String> higherPriorityLiteralAllows) {
    for (String literalAllow : higherPriorityLiteralAllows) {
      if (!matches(denyPattern, literalAllow)) {
        continue;
      }
      Optional<List<String>> excluded = AppArmorDenyGlobExclusion.excludeLiteralPath(denyPattern, literalAllow);
      if (excluded.isPresent()) {
        return excluded.get();
      }
    }
    return List.of(denyPattern);
  }

  private static boolean matches(String appArmorPattern, String literalCandidate) {
    PathMatcher matcher = FileSystems.getDefault()
        .getPathMatcher("glob:" + appArmorPattern);
    return matcher.matches(Path.of(literalCandidate));
  }

  private static boolean isLiteralPattern(String pattern) {
    return pattern.indexOf('*') < 0 && pattern.indexOf('?') < 0;
  }

  // EXTERNAL_DIRECTORY gates whether a directory outside the sandbox root is addressable at all -
  // a coarser concept with no distinct AppArmor equivalent. It folds into read access. Whether the
  // resulting rule is listing-only or full recursive content read is controlled entirely by the
  // caller's own pattern shape (a bare directory path vs. a `/**` suffix - see
  // AppArmorProfileGeneratorEnforcementTest for the empirically-verified distinction), not by
  // anything this generator decides.
  private static String accessMode(java.util.Set<AccessKind> accessKinds) {
    StringBuilder mode = new StringBuilder();
    if (accessKinds.contains(AccessKind.READ) || accessKinds.contains(AccessKind.EXTERNAL_DIRECTORY)) {
      mode.append('r');
    }
    if (accessKinds.contains(AccessKind.WRITE)) {
      mode.append('w');
    }
    if (mode.isEmpty()) {
      throw new IllegalArgumentException("Unsupported access kinds for a filesystem rule: " + accessKinds);
    }
    return mode.toString();
  }

  // The OS sandbox has no synchronous approval channel at the syscall boundary - ASK folds to
  // DENY here, deliberately, not a bug to "fix" later. Same stance as SeatbeltProfileGenerator.
  private static boolean effectiveDecisionIsAllow(Decision decision) {
    return decision == Decision.ALLOW;
  }

  // rule.reason() is interpolated after a '#' AppArmor line comment. An embedded newline would
  // let whatever follows it be parsed as live AppArmor syntax rather than comment text - the same
  // class of injection risk AppArmorGlobTranslator already guards against for targetPattern.
  private static String requireSingleLineReason(String reason) {
    if (reason.indexOf('\n') >= 0 || reason.indexOf('\r') >= 0) {
      throw new IllegalArgumentException("Sandbox rule reason must not contain a line break: " + reason);
    }
    return reason;
  }

  private static String indent(String block) {
    return block.lines()
        .map(line -> line.isBlank() ? line : "  " + line)
        .reduce("", (accumulated, line) -> accumulated + line + "\n");
  }
}
