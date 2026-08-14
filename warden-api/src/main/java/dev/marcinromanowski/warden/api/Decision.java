package dev.marcinromanowski.warden.api;

/**
 * The outcome of evaluating a rule against a real access attempt. {@code ASK} behaves
 * differently per rule domain - see {@link FilesystemRule} and {@link NetworkAskHandler}.
 */
public enum Decision {
  /** The access is permitted. */
  ALLOW,
  /** The access is refused. */
  DENY,
  /** No rule resolved this with a definite allow/deny - see the consuming rule type for how this is handled. */
  ASK
}
