package dev.marcinromanowski.warden.api;

import java.util.EnumSet;
import java.util.Set;

/**
 * An allow/deny rule for filesystem access, matched against a {@link RulePath}.
 * {@code decision=ASK} folds to {@code DENY} at enforcement time - filesystem access is mediated
 * in-kernel, with no synchronous channel to ask an operator mid-syscall.
 *
 * <p>{@link RulePath} carries whether the path is a glob or one exact path, and documents the
 * glob subset that is supported and the constructs that are refused.
 *
 * <p>Three consequences of the translation a caller has to know about, all measured rather than
 * assumed. A pattern ending in {@code "/"} names a directory on Linux, where AppArmor spells a
 * directory that way, and matches nothing at all on macOS, where a canonical path never ends in a
 * separator - so a trailing-slash pattern is a Linux-only rule. A {@code "**"} in the middle of a
 * pattern ({@code "<root>/**&#47;.config"}) does not match the zero-segment case
 * ({@code "<root>/.config"}) on Linux, because AppArmor's {@code "**"} does not match the empty
 * string between two separators - name that case in a rule of its own if it is meant. A leading
 * {@code "**"} needs no such care: the generator emits the zero-segment reading of it for a
 * {@code DENY}.
 *
 * @param target the path or pattern this rule is matched against
 * @param accessKinds the kinds of access this rule covers, never empty
 * @param decision whether matching access is allowed or denied
 * @param reason a short, human-readable reason surfaced in generated sandbox profiles
 */
public record FilesystemRule(
    RulePath target,
    Set<AccessKind> accessKinds,
    Decision decision,
    String reason
) {

  /** Validates the components above. */
  public FilesystemRule {
    target = Preconditions.nonNull(target, "target");
    accessKinds = Set.copyOf(Preconditions.nonNull(accessKinds, "accessKinds"));
    if (accessKinds.isEmpty()) {
      throw new IllegalArgumentException("accessKinds must not be empty");
    }
    decision = Preconditions.nonNull(decision, "decision");
    reason = Preconditions.nonBlank(reason, "reason");
  }

  /** An {@code ALLOW} rule for the given access kinds. */
  public static FilesystemRule allow(RulePath target, String reason, AccessKind... kinds) {
    return new FilesystemRule(target, EnumSet.copyOf(Set.of(kinds)), Decision.ALLOW, reason);
  }

  /** A {@code DENY} rule for the given access kinds. */
  public static FilesystemRule deny(RulePath target, String reason, AccessKind... kinds) {
    return new FilesystemRule(target, EnumSet.copyOf(Set.of(kinds)), Decision.DENY, reason);
  }

  /** An {@code ALLOW} rule for both {@link AccessKind#READ} and {@link AccessKind#WRITE}. */
  public static FilesystemRule allowReadWrite(RulePath target, String reason) {
    return allow(target, reason, AccessKind.READ, AccessKind.WRITE);
  }

  /** A {@code DENY} rule for {@link AccessKind#READ} only. */
  public static FilesystemRule denyRead(RulePath target, String reason) {
    return deny(target, reason, AccessKind.READ);
  }
}
