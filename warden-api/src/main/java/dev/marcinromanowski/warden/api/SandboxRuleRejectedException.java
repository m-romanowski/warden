package dev.marcinromanowski.warden.api;

import java.io.Serial;

/**
 * Thrown when a supplied {@link FilesystemRule} cannot be turned into a profile for the current
 * platform, and the launch is refused rather than silently given a different meaning. Two shapes
 * reach it: a pattern naming a construct neither platform's policy language has - a character
 * class, an alternation, a double quote - and a rule that would subtract from a path warden itself
 * needs to establish the sandbox at all.
 */
public class SandboxRuleRejectedException extends SandboxEstablishmentException {

  @Serial
  private static final long serialVersionUID = 1L;

  private final String targetPattern;

  /** Creates the exception for the rule with the given pattern. */
  public SandboxRuleRejectedException(String message, String targetPattern) {
    super(message);
    this.targetPattern = targetPattern;
  }

  /** The pattern of the rule that was refused. */
  public String targetPattern() {
    return targetPattern;
  }
}
