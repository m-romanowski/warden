package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.AccessKind;
import dev.marcinromanowski.warden.api.Decision;
import dev.marcinromanowski.warden.api.FilesystemRule;
import java.util.List;
import java.util.Optional;

// Generates a macOS Seatbelt (SBPL) profile from an already priority-ordered (first-match-wins)
// rule list.
//
// SBPL resolves an operation against multiple matching clauses with LAST-clause-wins semantics
// (empirically confirmed against a real sandbox-exec: whichever of a conflicting allow/deny pair
// appears later in the profile decides the outcome, regardless of which is broader/narrower).
// That is the exact opposite of the first-match-wins input order, so this generator emits the
// given rule list in REVERSE - the lowest-priority rule first, the highest-priority rule last -
// which makes SBPL's last-wins behavior reproduce first-match-wins for every rule pair, not just
// the narrow-deny-inside-broad-allow shape. Getting emission order backwards here would silently
// invert every DENY carve-out, so this must be verified with a real sandbox-exec run, not just
// string containment.
final class SeatbeltProfileGenerator {

  private static final String PROFILE_HEADER = "(version 1)\n(deny default)\n";
  // (literal "/var") / (literal "/tmp") grant read-metadata on the symlink *entries* themselves
  // (not recursively into whatever they point at) - without this, a sandboxed process that
  // constructs a path via its own non-canonical "/var/..."/"/tmp/..." string (e.g. from $TMPDIR,
  // which macOS sets to the non-canonical form) can't even resolve past the first path segment.
  // Confirmed empirically: "mkdir: /var: Operation not permitted" via a real sandbox-exec run
  // using a profile that only granted access to the equivalent /private/var/... canonical path.
  //
  // (subpath "/bin") / (subpath "/usr/bin") grant read (and, combined with process-exec below,
  // execute) access to standard system binaries - this sandbox's security boundary is what a
  // process can READ, WRITE, and reach over the NETWORK, not which programs it's allowed to
  // invoke at all.
  private static final String BOOTSTRAP_ALLOWANCES =
      """
      (allow file-read* (literal "/") (literal "/var") (literal "/tmp") (subpath "/bin") \
      (subpath "/usr/bin") (subpath "/usr/lib") \
      (subpath "/usr/share") (subpath "/System/Library") (subpath "/private/var/db/dyld") \
      (subpath "/private/etc") \
      (literal "/dev/null") (literal "/dev/zero") (literal "/dev/urandom") (literal "/dev/random"))
      (allow file-read* file-write* (subpath "/dev/tty") (subpath "/dev/ptmx"))
      (allow file-write* (regex #"^/dev/tty[a-z0-9]+$"))
      (allow process-fork)
      (allow process-exec)
      (allow signal (target self))
      (allow sysctl-read)
      ; mach-lookup/iokit-open are unrestricted in this phase - a known, accepted gap, not solved
      ; here. Restricting mach-lookup to an explicit service allowlist is real follow-up work.
      (allow mach-lookup)
      (allow iokit-open)
      """;

  private SeatbeltProfileGenerator() {
  }

  static String generate(List<FilesystemRule> filesystemRules, int proxyPort, Optional<Integer> listenPort) {
    List<FilesystemRule> requiredRules = List.copyOf(Preconditions.nonNull(filesystemRules, "filesystemRules"));
    StringBuilder profile = new StringBuilder(PROFILE_HEADER);
    profile.append('\n')
        .append(BOOTSTRAP_ALLOWANCES);
    profile.append('\n');
    appendFilesystemClauses(profile, requiredRules, AccessKind.READ, "file-read*");
    profile.append('\n');
    appendFilesystemClauses(profile, requiredRules, AccessKind.WRITE, "file-write*");
    int requiredProxyPort = requirePositivePort(proxyPort, "proxyPort");
    Optional<Integer> requiredListenPort = requireOptionalPositivePort(listenPort, "listenPort");
    profile.append('\n')
        .append(networkClauses(requiredProxyPort, requiredListenPort));
    return profile.toString();
  }

  private static void appendFilesystemClauses(
      StringBuilder profile,
      List<FilesystemRule> rules,
      AccessKind kind,
      String sbplOperation
  ) {
    // Reverse order: the highest-priority rule (first in `rules`) must be the LAST matching SBPL
    // clause emitted, since SBPL's last-match-wins semantics decides ties by clause order.
    for (int index = rules.size() - 1; index >= 0; index--) {
      FilesystemRule rule = rules.get(index);
      if (!appliesToKind(rule, kind)) {
        continue;
      }
      String regex = SeatbeltGlobTranslator.toRegex(rule.targetPattern());
      String reason = requireSingleLineReason(rule.reason());
      String clauseVerb = effectiveDecisionIsAllow(rule.decision()) ? "allow" : "deny";
      profile.append('(')
          .append(clauseVerb)
          .append(' ')
          .append(sbplOperation)
          .append(" (regex #\"")
          .append(regex)
          .append("\")) ; ")
          .append(reason)
          .append('\n');
    }
  }

  // EXTERNAL_DIRECTORY gates whether a directory outside the sandbox root is addressable at all -
  // a coarser concept with no distinct SBPL equivalent. Seatbelt only cares about the actual
  // file-read/file-write syscalls, so an EXTERNAL_DIRECTORY rule folds into the read-clause
  // emission alongside READ.
  private static boolean appliesToKind(FilesystemRule rule, AccessKind kind) {
    if (rule.accessKinds()
        .contains(kind)) {
      return true;
    }
    return kind == AccessKind.READ
        && rule.accessKinds()
            .contains(AccessKind.EXTERNAL_DIRECTORY);
  }

  // The OS sandbox has no synchronous approval channel at the syscall boundary - ASK folds to
  // DENY here, deliberately, not a bug to "fix" later.
  private static boolean effectiveDecisionIsAllow(Decision decision) {
    return decision == Decision.ALLOW;
  }

  // rule.reason() is interpolated after a ';' SBPL line comment. An embedded newline would let
  // whatever follows it be parsed as live SBPL syntax rather than comment text - the same class
  // of injection risk SeatbeltGlobTranslator already guards against for targetPattern.
  private static String requireSingleLineReason(String reason) {
    if (reason.indexOf('\n') >= 0 || reason.indexOf('\r') >= 0) {
      throw new IllegalArgumentException("Sandbox rule reason must not contain a line break: " + reason);
    }
    return reason;
  }

  private static String networkClauses(int proxyPort, Optional<Integer> listenPort) {
    StringBuilder clauses = new StringBuilder();
    clauses.append("(deny network*)\n")
        .append("(allow network-outbound (remote tcp \"localhost:")
        .append(proxyPort)
        .append("\"))\n");
    // No wildcard bind allowance: SBPL enforces the port component of a `local` filter but NOT
    // the address component (empirically confirmed - "(local tcp \"localhost:*\")" alone still
    // permits binding 0.0.0.0). Absent an explicit port to pin, the safer default is to allow no
    // bind at all rather than a wildcard that silently exposes the sandboxed process's listen
    // socket to the LAN.
    //
    // network-bind and network-inbound are separate SBPL operations - the former covers bind(),
    // the latter covers accepting an incoming connection. Granting only network-bind lets the
    // process bind its control-plane server but denies every connection attempt to it, silent and
    // easy to miss in a synthetic test. Confirmed empirically via a real end-to-end launch and
    // macOS's own sandbox violation log.
    listenPort.ifPresent(
        port -> {
          clauses.append("(allow network-bind (local tcp \"localhost:")
              .append(port)
              .append("\"))\n");
          clauses.append("(allow network-inbound (local tcp \"localhost:")
              .append(port)
              .append("\"))\n");
        }
    );
    return clauses.toString();
  }

  private static int requirePositivePort(int port, String field) {
    Preconditions.positiveOrZero(port, field);
    if (port <= 0) {
      throw new IllegalArgumentException(field + " must be positive");
    }
    return port;
  }

  private static Optional<Integer> requireOptionalPositivePort(Optional<Integer> port, String field) {
    Preconditions.nonNull(port, field)
        .ifPresent(value -> requirePositivePort(value, field));
    return port;
  }
}
