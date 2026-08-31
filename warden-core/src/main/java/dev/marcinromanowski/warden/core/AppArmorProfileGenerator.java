package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.AccessKind;
import dev.marcinromanowski.warden.api.Decision;
import dev.marcinromanowski.warden.api.FilesystemRule;
import dev.marcinromanowski.warden.api.SandboxRuleRejectedException;
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
// grammar already spells the supported wildcards the same way (AppArmorGlobTranslator only escapes
// the literal characters around them). AppArmor resolves a *single* overlapping
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

  private static final String INCLUDE_KEYWORD = "include";
  private static final String TUNABLES_INCLUDE = "#include <tunables/global>\n\n";

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
  //
  // It is a path warden reserves. A caller is given no name for it, and nothing in a caller's rule
  // set is expected to mention it - but a caller's deny can still cover it by accident, and when it
  // does this generator refuses the launch and names the offending rule rather than out-ranking it.
  // See requireNoDenyOverReservedPaths.
  static final String BWRAP_BRIDGE_DIRECTORY = "/tmp/warden-sandbox-bridge";

  // AppArmor resolves an overlapping allow/deny pair by set-subtraction at equal priority, so a
  // caller's deny beats any warden grant it covers, however broadly the deny was written. With
  // the bridge grant above in place, adding "deny /tmp/** r," makes /tmp/warden-sandbox-bridge/proxy.info
  // unreadable, and the sandboxed process then cannot reach its own egress control plane. Reaching the
  // clause needs nothing exotic: "**/tmp/**" is a shape a credential-blacklist author writes, and it
  // covers "/tmp/**" under the java.nio.file PathMatcher semantics these patterns are authored against
  // (which is also why this generator derives that root-level clause for a deny).
  //
  // A generated profile is an addition to whatever policy the machine already has and to whatever the
  // caller wrote - never a silent override of it. The qualifier existed precisely to win over a
  // caller's deny, and a deny that loses without saying so is the failure mode this project exists
  // to prevent, "priority=1 <session>/** mrwix" let a confined process copy /bin/dash into the session
  // directory and execute it while the caller's "deny /tmp/** wx," was in force, and the same deny still
  // refused every other path it covered.
  //
  // What replaces it is a refusal the caller can act on. requireNoDenyOverReservedPaths checks each
  // emitted deny against the handful of literal paths warden itself must reach.

  // Both letters, because the kernel asks for both in turn on a Unix-domain socket: the connect()
  // that the in-sandbox bridge makes is refused first with requested_mask="r" and then, once read is
  // granted, with requested_mask="w". Measured against a real kernel through a real bwrap launch by
  // granting each letter alone and reading the audit record. A note here previously said "w" alone,
  // which was never tested on its own - the clause it described also carried a tree-wide "mrwix".
  private static final String SOCKET_MODE = "rw";

  // The AppArmor access letter that mediates reading a directory's own entries, which is what the
  // trailing-slash companion of an allow rule exists to grant. See withDirectoryForm.
  private static final char DIRECTORY_LISTING_MODE = 'r';

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
      """;

  private AppArmorProfileGenerator() {
  }

  static String generate(String profileName, List<FilesystemRule> filesystemRules) {
    return generate(profileName, filesystemRules, Optional.empty(), Optional.empty(), Optional.empty());
  }

  // sessionPaths, when present, names the individual files inside warden's own per-session scratch
  // directory that the confined process has to reach - not caller policy, so they are not expressed
  // through the FilesystemRule list like everything else this generator emits.
  //
  // Each one carries the narrowest mode that was measured to work, and nothing wider. The target
  // binary needs "mrix": the kernel's own ELF load of it is checked against this profile once the px
  // stacking transition lands the process here, and denies with a distinct file_mmap "m" failure if
  // only read access is granted. The host-side proxy socket needs "w" for a genuinely surprising
  // reason: AppArmor mediates a connect() to a bind-mounted Unix domain socket against the socket's
  // own *bind-time* path (its real host path), not the path the confined process used to reach it
  // through the bridge alias, so the in-sandbox socat's connect() is checked against that clause. The
  // bridge-alias spellings are the paths the process actually opens, and AppArmor mediates those rather
  // than the host paths behind the bind mount.
  //
  // What is deliberately NOT emitted is a clause covering the session directory or the bridge alias
  // as a tree. Both used to be granted tree-wide, and both were reachable: measured under a real
  // bwrap launch, the confined process created arbitrary files under the bridge alias - which is a
  // bind of warden's own session directory - and, while the session tree carried "mrwix", copied
  // /bin/dash into it and executed it.
  //
  // stackedLabel, when present, is the label a real launch's px transition lands the payload in -
  // needed only for the signal rule below.
  //
  // helperExecutable, when present, is a binary the bridge script runs by absolute path. The
  // bootstrap allowances cover the system locations a distribution would install it in and nothing
  // else, so a helper resolved from anywhere the embedder chose needs its own clause here. "rix"
  // rather than "mrix" for the same reason the bootstrap uses it: it is executed, not mapped, and it
  // stays under this profile.
  static String generate(
      String profileName,
      List<FilesystemRule> filesystemRules,
      Optional<BwrapSessionPaths> sessionPaths,
      Optional<Path> helperExecutable,
      Optional<String> stackedLabel
  ) {
    return TUNABLES_INCLUDE + profileBlock(profileName, filesystemRules, sessionPaths, helperExecutable, stackedLabel);
  }

  static String profileBlock(
      String profileName,
      List<FilesystemRule> filesystemRules,
      Optional<BwrapSessionPaths> sessionPaths,
      Optional<Path> helperExecutable,
      Optional<String> stackedLabel
  ) {
    return "profile " + Preconditions.nonBlank(profileName, "profileName") + " flags=(attach_disconnected) {\n"
        + sessionProfileBody(profileName, filesystemRules, sessionPaths, helperExecutable, stackedLabel)
        + "}\n";
  }

  static String sessionProfileBody(
      String profileName,
      List<FilesystemRule> filesystemRules,
      Optional<BwrapSessionPaths> sessionPaths,
      Optional<Path> helperExecutable,
      Optional<String> stackedLabel
  ) {
    String requiredName = Preconditions.nonBlank(profileName, "profileName");
    Optional<BwrapSessionPaths> requiredSessionPaths = Preconditions.nonNull(sessionPaths, "sessionPaths");
    Optional<Path> requiredHelper = Preconditions.nonNull(helperExecutable, "helperExecutable");
    List<FilesystemRule> requiredRules = List.copyOf(Preconditions.nonNull(filesystemRules, "filesystemRules"));
    requireNoDenyOverReservedPaths(requiredRules, requiredSessionPaths, requiredHelper);
    StringBuilder profile = new StringBuilder();
    profile.append(indent(BOOTSTRAP_ALLOWANCES))
        .append(indent(sameProfileSignalAllowances(requiredName, stackedLabel)));
    requiredSessionPaths.ifPresent(paths -> appendReservedClauses(profile, paths));
    requiredHelper.ifPresent(executable -> appendReservedClause(profile, executable, "rix"));
    // Higher-priority literal ALLOW patterns seen so far, in the caller's own priority order -
    // used to carve exceptions out of a later, lower-priority DENY glob that would otherwise
    // silently re-cover them (see AppArmorDenyGlobExclusion's own header for the full "why" and the
    // rewrite it does - AppArmor's "priority=" qualifier is not used anywhere in a generated
    // profile, for a caller's rules or for warden's own).
    List<String> higherPriorityLiteralAllows = new ArrayList<>();
    for (FilesystemRule rule : requiredRules) {
      appendRuleClause(profile, rule, higherPriorityLiteralAllows);
      String translatedPattern = AppArmorGlobTranslator.toAppArmorPattern(rule.target());
      if (effectiveDecisionIsAllow(rule.decision()) && isLiteralPattern(translatedPattern)) {
        higherPriorityLiteralAllows.add(translatedPattern);
      }
    }
    return profile.toString();
  }

  // Without this the sandbox does not work for a JavaScript-runtime backend at all, and the failure
  // names nothing. JavaScriptCore suspends its own threads with signals, and
  // an enforcing profile that names no signal rule denies them.
  //
  // Scoped to this profile's own label rather than granted outright, so it permits the confined
  // process signalling itself and its own children and nothing else. Two spellings because the peer
  // label differs by how the profile was entered: the bare name when a caller enters it directly,
  // and the full stacked label under the px transition a real launch takes. That stacked spelling
  // has to be the one the kernel renders, component-sorted - see AppArmorSessionProfileNames.
  private static String sameProfileSignalAllowances(String profileName, Optional<String> stackedLabel) {
    return "signal peer=" + profileName + ",\n"
        + stackedLabel.map(label -> "signal peer=" + label + ",\n")
            .orElse("");
  }

  private static void appendReservedClauses(StringBuilder profile, BwrapSessionPaths paths) {
    appendReservedClause(profile, paths.targetBinary(), "mrix");
    appendReservedClause(profile, paths.proxySocket(), SOCKET_MODE);
    paths.controlSocket()
        .ifPresent(socket -> appendReservedClause(profile, socket, SOCKET_MODE));
    appendReservedClause(profile, paths.inSandboxBridgeScript(), "r");
    appendReservedClause(profile, paths.inSandboxProxySocket(), SOCKET_MODE);
    paths.inSandboxControlSocket()
        .ifPresent(socket -> appendReservedClause(profile, socket, SOCKET_MODE));
  }

  private static void appendReservedClause(StringBuilder profile, Path path, String mode) {
    profile.append("  ")
        .append(AppArmorPathEscaping.escapeLiteralPath(path.toString()))
        .append(' ')
        .append(mode)
        .append(",\n");
  }

  // A caller's deny that covers one of warden's own paths is refused here, by name, instead of being
  // out-ranked. See the note on BWRAP_BRIDGE_DIRECTORY for why an override is the wrong answer: a
  // generated profile is an addition to the caller's policy, never a silent replacement of part of
  // it. The check runs against literal paths rather than by intersecting two globs, so it says yes
  // or no about exactly the files warden will open and never approximates.
  //
  // Modes are compared, not just paths. A caller denying execute on a tree that happens to contain
  // the proxy socket takes nothing away from warden, and refusing that launch would be refusing more
  // than the mechanism needs.
  private static void requireNoDenyOverReservedPaths(
      List<FilesystemRule> rules,
      Optional<BwrapSessionPaths> sessionPaths,
      Optional<Path> helperExecutable
  ) {
    List<Path> reserved = new ArrayList<>();
    sessionPaths.ifPresent(paths -> reserved.addAll(paths.all()));
    helperExecutable.ifPresent(reserved::add);
    if (reserved.isEmpty()) {
      return;
    }
    for (FilesystemRule rule : rules) {
      if (effectiveDecisionIsAllow(rule.decision()) || !subtractsFromWardensOwnAccess(rule)) {
        continue;
      }
      String pattern = AppArmorGlobTranslator.toAppArmorPattern(rule.target());
      List<String> spellings = new ArrayList<>();
      spellings.add(pattern);
      spellings.addAll(AppArmorGlobTranslator.zeroSegmentForms(pattern));
      for (String spelling : spellings) {
        for (Path reservedPath : reserved) {
          if (matches(spelling, reservedPath.toString())) {
            throw reservedPathConflict(rule, reservedPath);
          }
        }
      }
    }
  }

  private static boolean subtractsFromWardensOwnAccess(FilesystemRule rule) {
    return rule.accessKinds()
        .contains(AccessKind.READ)
        || rule.accessKinds()
            .contains(AccessKind.WRITE)
        || rule.accessKinds()
            .contains(AccessKind.EXECUTE);
  }

  private static SandboxRuleRejectedException reservedPathConflict(FilesystemRule rule, Path reservedPath) {
    return new SandboxRuleRejectedException(
        "A supplied DENY rule covers a path warden itself needs to establish the sandbox, so the"
            + " launch is refused rather than the rule being silently overridden. warden reserves"
            + " " + BWRAP_BRIDGE_DIRECTORY + " and a per-session directory under"
            + " " + BwrapSessionStore.SESSIONS_DIRECTORY + ", and reaches this path through them: " + reservedPath
            + ". Narrow the rule so it does not cover that path - a deny meant for the confined"
            + " program's reach into your own filesystem does not need to name warden's own control"
            + " plane, and warden's egress and mount behaviour are configured through network rules"
            + " and path mounts instead. Offending rule: pattern=" + rule.target().pattern()
            + ", kinds=" + rule.accessKinds() + ", reason=" + rule.reason(),
        rule.target().pattern()
    );
  }

  private static void appendRuleClause(StringBuilder profile, FilesystemRule rule, List<String> higherPriorityLiteralAllows) {
    String pattern = AppArmorGlobTranslator.toAppArmorPattern(rule.target());
    boolean isAllow = effectiveDecisionIsAllow(rule.decision());
    String mode = accessMode(rule.accessKinds(), isAllow);
    String reason = requireInertReason(rule.reason());
    String clauseVerb = isAllow ? "allow" : "deny";
    for (Spelling spelling : spellings(pattern, mode, isAllow, grantsDirectoryListing(rule))) {
      List<String> patterns = isAllow
          ? List.of(spelling.pattern())
          : denyPatternsExcludingHigherPriorityAllows(spelling.pattern(), higherPriorityLiteralAllows);
      for (String emittedPattern : patterns) {
        profile.append("  ")
            .append(clauseVerb)
            .append(' ')
            .append(emittedPattern)
            .append(' ')
            .append(spelling.mode())
            .append(", # ")
            .append(reason)
            .append('\n');
      }
    }
  }

  private static List<Spelling> spellings(String pattern, String mode, boolean isAllow, boolean grantsListing) {
    List<Spelling> spellings = new ArrayList<>(withDirectoryForm(pattern, mode, isAllow, grantsListing));
    if (!isAllow) {
      for (String rootLevel : AppArmorGlobTranslator.zeroSegmentForms(pattern)) {
        spellings.addAll(withDirectoryForm(rootLevel, mode, isAllow, grantsListing));
      }
    }
    return List.copyOf(spellings);
  }

  // EXTERNAL_DIRECTORY on its own means "this directory may be addressed", and addressing a
  // directory is not listing it. So a rule that names EXTERNAL_DIRECTORY without READ gets the
  // base clause and no trailing-slash companion: the path can be resolved through and stat'ed, and
  // "ls" on it is refused. READ is what asks for the listing, and a rule that names READ still gets
  // the companion exactly as before.
  private static boolean grantsDirectoryListing(FilesystemRule rule) {
    return rule.accessKinds()
        .contains(AccessKind.READ);
  }

  // AppArmor names a directory by the path a caller would write for it *plus a trailing slash*, and
  // a pattern without one never matches that name. So "/workspace r," grants reads of nothing but
  // the directory entry, while listing /workspace is mediated as "/workspace/" and denied - and
  // "/workspace/** rw," does not cover it either, because "**" does not match the empty string
  // there. A rule's pattern is written in a platform-neutral vocabulary that has no such convention
  // (macOS Seatbelt needs nothing of the sort), so naming both forms belongs here rather than in
  // every caller's own rule construction, where one missed site is a silent hole.
  //
  // On the DENY side this closes a live, exploitable bypass, not a cosmetic gap. A
  // "deny <dir> w," plus "deny <dir>/** w," pair leaves the trailing-slash name unmediated, and
  // mkdir, rmdir and rename all check that name and nothing else. E.g., writing a file into the
  // denied directory is refused, but staging that same file in a sibling directory and renaming
  // the sibling onto the denied name succeeded, and the file was then loaded and executed. Both
  // routes are refused once the trailing-slash name is denied too.
  //
  // On the ALLOW side the companion carries "r" and nothing else, whatever the rule's own mode is,
  // and is skipped entirely for a rule that grants no read at all. Listing a directory is the whole
  // reason the companion exists on this side, and "r" on the trailing-slash name is exactly what
  // mediates listing - nothing else the rule's mode could carry there names an operation the caller
  // asked for.
  //
  // A pattern already ending in "/" is the directory form. A pattern ending in "**" needs no
  // companion: "<prefix>/**/" matches a strict subset of what "<prefix>/**" already matches, since
  // "**" spans "/" freely.
  //
  // One limit, inherited rather than introduced, and partially defeating the carve-out mechanism
  // rather than merely not extending it: for a deny glob with a higher-priority literal allow to
  // carve out, the companion clause is emitted with no carve-out at all. The match check that gates
  // the carve-out (see matches below) asks java.nio.file's glob PathMatcher whether the deny pattern
  // covers the excluded literal, and a pattern ending in "/" matches no Path under those semantics,
  // so the check always says no - and AppArmorDenyGlobExclusion would refuse the shape anyway,
  // its filename portion being empty. The carved-out path therefore stays excepted from the base
  // deny clause and stays denied by the companion one. Latent rather than live: every "/**/"-shaped
  // deny in use names a file, and the companion of such a pattern matches only a directory of that
  // name. An exception that is itself a directory would silently not be excepted.
  private static List<Spelling> withDirectoryForm(String pattern, String mode, boolean isAllow, boolean grantsListing) {
    Spelling base = new Spelling(pattern, mode);
    if (pattern.endsWith("/") || pattern.endsWith("**")) {
      return List.of(base);
    }
    if (!isAllow) {
      return List.of(base, new Spelling(pattern + "/", mode));
    }
    if (!grantsListing || mode.indexOf(DIRECTORY_LISTING_MODE) < 0) {
      return List.of(base);
    }
    return List.of(base, new Spelling(pattern + "/", String.valueOf(DIRECTORY_LISTING_MODE)));
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
      if (!matches(denyPattern, AppArmorPathEscaping.unescape(literalAllow))) {
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
        .getPathMatcher("glob:" + AppArmorPathEscaping.toJavaGlobPattern(appArmorPattern));
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
  //
  // On an ALLOW that is where the two platforms part company, and it cannot be closed from here.
  // Seatbelt maps the kind to file-read-metadata, so a rule naming a FILE grants its metadata and
  // refuses its bytes there. AppArmor's narrowest read letter is the one that reads contents, so the
  // same rule hands the bytes out here. Both sides assert it in their own enforcement test rather
  // than claiming a parity that does not exist. On a DENY there is no divergence: SeatbeltProfileGenerator
  // emits the whole read operation, matching what "r" already takes away here.
  //
  // EXECUTE emits "ix" on an allow and a bare "x" on a deny, and the decision is a parameter here
  // for exactly that reason. An allow has to say which profile the child runs under - "i" (inherit)
  // keeps it under this same profile, matching the bootstrap allowances above. A deny must not:
  // apparmor_parser rejects the whole profile with "Invalid perms, in deny rules 'x' must not be
  // preceded by exec qualifier 'i', 'p', or 'u'", which reaches the caller as a failed sandbox
  // launch rather than as a rejected rule. Both measured against a real apparmor_parser, along with
  // a bare "deny <path> x," genuinely subtracting exec from a path the bootstrap allowances grant.
  // An operator override naming EXECUTE on a deny is a reachable, meaningful thing to write ("never
  // run anything under this tree"), so it is emitted rather than refused at the rule boundary.
  //
  // The allow form deliberately does not also emit "m" - a real kernel runs a dynamically linked
  // binary granted "ix" alone, so mapping permission would be a widening nothing needs.
  //
  // The exec letters go last because "i" is a transition mode qualifying the "x", and "k" before
  // them so the emitted mode reads in AppArmor's own conventional order. The parser accepts any
  // order.
  private static String accessMode(java.util.Set<AccessKind> accessKinds, boolean isAllow) {
    StringBuilder mode = new StringBuilder();
    if (accessKinds.contains(AccessKind.READ) || accessKinds.contains(AccessKind.EXTERNAL_DIRECTORY)) {
      mode.append('r');
    }
    if (accessKinds.contains(AccessKind.WRITE)) {
      mode.append('w');
    }
    if (accessKinds.contains(AccessKind.LOCK)) {
      mode.append('k');
    }
    if (accessKinds.contains(AccessKind.EXECUTE)) {
      mode.append(isAllow ? "ix" : "x");
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

  // rule.reason() is interpolated after a '#' AppArmor line comment, which is not the inert text it
  // looks like. A newline lets whatever follows it be parsed as live AppArmor syntax. A brace closes
  // the profile block the privileged helper opened, and the next one opens a profile of the caller's
  // choosing - which is the whole bound that helper rests on. And "include" is honoured by the
  // parser wherever it appears, comment or not: measured, "/tmp/z r, #include <abstractions/x>"
  // pulled the abstraction in, so a reason carrying that token could name a file to splice.
  private static String requireInertReason(String reason) {
    if (reason.indexOf('\n') >= 0 || reason.indexOf('\r') >= 0) {
      throw new IllegalArgumentException("Sandbox rule reason must not contain a line break: " + reason);
    }
    if (reason.indexOf('{') >= 0 || reason.indexOf('}') >= 0) {
      throw new IllegalArgumentException("Sandbox rule reason must not contain a brace: " + reason);
    }
    if (reason.contains(INCLUDE_KEYWORD)) {
      throw new IllegalArgumentException(
          "Sandbox rule reason must not contain \"" + INCLUDE_KEYWORD + "\", which AppArmor honours"
              + " inside a comment: " + reason
      );
    }
    return reason;
  }

  private static String indent(String block) {
    return block.lines()
        .map(line -> line.isBlank() ? line : "  " + line)
        .reduce("", (accumulated, line) -> accumulated + line + "\n");
  }

  private record Spelling(String pattern, String mode) {
  }
}
