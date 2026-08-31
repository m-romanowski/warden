package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.AccessKind;
import dev.marcinromanowski.warden.api.Decision;
import dev.marcinromanowski.warden.api.FilesystemRule;
import java.util.List;
import java.util.Optional;
import java.util.Set;

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
  // (literal "/") carries file-read-data and not file-read*, which is the narrowest grant any
  // process starts under at all: with metadata alone every launch aborts before reaching main,
  // and with neither nothing runs. Listing the root needs both operations, so withholding the
  // metadata half is what keeps "ls /" refused. A caller granting EXTERNAL_DIRECTORY on "/"
  // supplies the other half itself and gets the listing back - that is the caller's rule, not
  // this bootstrap's.
  //
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
  //
  // /private/etc is named entry by entry rather than as a subtree. A subtree grant is a blanket read
  // of the machine's system configuration handed to every consumer of this library, and it was one:
  // measured, /private/etc/passwd and /private/etc/ssh/sshd_config both returned their contents and
  // /private/etc listed. What is here instead is the TLS root store and the resolver, service and
  // timezone tables a networked payload consults through libc - files that carry no secret and that
  // nothing else in this bootstrap supplies. The discriminating measurement is TLS: with the whole
  // subtree removed an https request fails at "error setting certificate verify locations", and with
  // these entries it succeeds, while every disclosure above stays refused. See
  // SeatbeltProfileGeneratorEnforcementTest.
  //
  // Reaching any of them through the "/etc" symlink needs that entry granted too, which is a caller's
  // rule and not this bootstrap's - the same division as "/var" and "/tmp" above, except that those
  // two are named here because a process constructs them from its own environment.
  private static final String BOOTSTRAP_ALLOWANCES =
      """
      (allow file-read-data (literal "/"))
      (allow file-read* (literal "/var") (literal "/tmp") (subpath "/bin") \
      (subpath "/usr/bin") (subpath "/usr/lib") \
      (subpath "/usr/share") (subpath "/System/Library") (subpath "/private/var/db/dyld") \
      (subpath "/private/etc/ssl") (literal "/private/etc/hosts") (literal "/private/etc/resolv.conf") \
      (literal "/private/etc/localtime") (literal "/private/etc/services") (literal "/private/etc/protocols") \
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
    appendReadClauses(profile, requiredRules);
    profile.append('\n');
    appendFilesystemClauses(profile, requiredRules, AccessKind.WRITE, "file-write*");
    profile.append('\n');
    appendFilesystemClauses(profile, requiredRules, AccessKind.EXECUTE, "process-exec");
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
      if (!rule.accessKinds()
          .contains(kind)) {
        continue;
      }
      appendClause(profile, rule, sbplOperation);
    }
  }

  // READ and EXTERNAL_DIRECTORY share one pass rather than getting one each, because they name
  // overlapping SBPL operations - file-read-metadata is one of the operations file-read* expands
  // to. Emitted separately, the later pass would win over the earlier one for metadata whatever the
  // caller's priorities said, so a lower-priority EXTERNAL_DIRECTORY allow would punch a hole in a
  // higher-priority READ deny. One pass keeps clause order equal to priority order, which is the
  // only thing SBPL decides a conflict by.
  private static void appendReadClauses(StringBuilder profile, List<FilesystemRule> rules) {
    for (int index = rules.size() - 1; index >= 0; index--) {
      FilesystemRule rule = rules.get(index);
      Set<AccessKind> kinds = rule.accessKinds();
      if (kinds.contains(AccessKind.READ)) {
        appendClause(profile, rule, "file-read*");
      } else if (kinds.contains(AccessKind.EXTERNAL_DIRECTORY)) {
        appendClause(profile, rule, externalDirectoryReadOperation(rule.decision()));
      }
    }
  }

  // The narrowing EXTERNAL_DIRECTORY expresses only exists on an allow. Granting the metadata half
  // alone hands out a directory that can be resolved through and not listed. Refusing the metadata
  // half alone hands out a file that cannot be stat'ed and whose bytes still read out, which is not
  // what any caller writing a deny asked for and is a widening this generator would be inventing.
  // On AppArmor the same kind already contributes plain read access to a deny's mode letters, so a
  // deny means the same thing on both platforms only when it takes the whole read operation here.
  private static String externalDirectoryReadOperation(Decision decision) {
    return effectiveDecisionIsAllow(decision) ? "file-read-metadata" : "file-read*";
  }

  private static void appendClause(StringBuilder profile, FilesystemRule rule, String sbplOperation) {
    String regex = SeatbeltGlobTranslator.toRegex(rule.target());
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

  // An ALLOW naming EXTERNAL_DIRECTORY means a directory outside the sandbox root may be resolved
  // through and stat'ed, and not listed - the same thing it means on AppArmor. file-read-metadata is
  // what expresses that: measured against a real sandbox-exec, an ancestor granted file-read-metadata
  // refuses "ls" on itself while a file inside a granted subtree still opens through it, and the
  // same ancestor granted file-read* lists its own entries. Listing is what file-read* adds, and
  // nothing about addressing a directory needs it. A DENY takes file-read* instead, for the reason
  // externalDirectoryReadOperation states.
  //
  // EXECUTE maps to process-exec, an SBPL operation of its own that takes the same path filters as
  // the file operations. It does not fold into the read clause, matching what EXECUTE alone grants
  // on AppArmor: a native binary runs from a path with no read grant at all on both platforms, and
  // a script runs on neither, because its interpreter has to read it. Both measured, with a real
  // Mach-O and a real script.
  //
  // LOCK contributes no clause of its own, and that is the whole of Seatbelt's story for it: macOS
  // mediates flock/fcntl locking through the descriptor a process already opened, never through a
  // path, so there is no operation to allow and none to deny. A caller that needs a lock granted or
  // refused as a distinct capability gets that on Linux only.

  // The OS sandbox has no synchronous approval channel at the syscall boundary - ASK folds to
  // DENY here, deliberately, not a bug to "fix" later.
  private static boolean effectiveDecisionIsAllow(Decision decision) {
    return decision == Decision.ALLOW;
  }

  // rule.reason() is interpolated after a ';' SBPL line comment. An embedded newline would let
  // whatever follows it be parsed as live SBPL syntax rather than comment text - the same class
  // of injection risk GlobPattern already guards against for a rule pattern.
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
