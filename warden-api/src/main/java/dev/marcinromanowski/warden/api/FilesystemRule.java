package dev.marcinromanowski.warden.api;

import java.util.EnumSet;
import java.util.Set;

/**
 * An allow/deny rule for filesystem access, matched against a glob-style {@code targetPattern}.
 * {@code decision=ASK} folds to {@code DENY} at enforcement time - filesystem access is mediated
 * in-kernel, with no synchronous channel to ask an operator mid-syscall.
 *
 * <p>Patterns are written against {@code java.nio.file} glob semantics and translated per platform.
 * Two consequences a caller has to know about, both measured rather than assumed. A pattern ending
 * in {@code "/"} names a directory on Linux, where AppArmor spells a directory that way, and
 * matches nothing at all on macOS, where a canonical path never ends in a separator - so a
 * trailing-slash pattern is a Linux-only rule. And a {@code "**"} in the middle of a pattern
 * ({@code "<root>/**&#47;.config"}) does not match the zero-segment case ({@code "<root>/.config"})
 * on Linux, because AppArmor's {@code "**"} does not match the empty string between two separators
 * - name that case in a rule of its own if it is meant. A leading {@code "**"} needs no such care:
 * the generator emits the zero-segment reading of it for a {@code DENY}.
 *
 * @param targetPattern a glob-style pattern (platform-translated at enforcement time)
 * @param accessKinds the kinds of access this rule covers, never empty
 * @param decision whether matching access is allowed or denied
 * @param reason a short, human-readable reason surfaced in generated sandbox profiles
 */
public record FilesystemRule(
    String targetPattern,
    Set<AccessKind> accessKinds,
    Decision decision,
    String reason
) {

  /** Validates the components above. */
  public FilesystemRule {
    targetPattern = Preconditions.nonBlank(targetPattern, "targetPattern");
    accessKinds = Set.copyOf(Preconditions.nonNull(accessKinds, "accessKinds"));
    if (accessKinds.isEmpty()) {
      throw new IllegalArgumentException("accessKinds must not be empty");
    }
    decision = Preconditions.nonNull(decision, "decision");
    reason = Preconditions.nonBlank(reason, "reason");
  }

  /** An {@code ALLOW} rule for the given access kinds. */
  public static FilesystemRule allow(String targetPattern, String reason, AccessKind... kinds) {
    return new FilesystemRule(targetPattern, EnumSet.copyOf(Set.of(kinds)), Decision.ALLOW, reason);
  }

  /** A {@code DENY} rule for the given access kinds. */
  public static FilesystemRule deny(String targetPattern, String reason, AccessKind... kinds) {
    return new FilesystemRule(targetPattern, EnumSet.copyOf(Set.of(kinds)), Decision.DENY, reason);
  }

  /** An {@code ALLOW} rule for both {@link AccessKind#READ} and {@link AccessKind#WRITE}. */
  public static FilesystemRule allowReadWrite(String targetPattern, String reason) {
    return allow(targetPattern, reason, AccessKind.READ, AccessKind.WRITE);
  }

  /** A {@code DENY} rule for {@link AccessKind#READ} only. */
  public static FilesystemRule denyRead(String targetPattern, String reason) {
    return deny(targetPattern, reason, AccessKind.READ);
  }
}
