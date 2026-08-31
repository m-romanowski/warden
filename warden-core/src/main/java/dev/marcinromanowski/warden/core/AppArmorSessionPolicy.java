package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.FilesystemRule;
import dev.marcinromanowski.warden.api.SandboxEstablishmentException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

// The AppArmor policy one Linux session loads: bwrap's own confinement profile, the
// capability-stripping profile stacked with it, and the payload's filesystem profile, all loaded
// and removed as a unit.
//
// Removing it belongs to the session directory rather than to a handle returned from load(), which
// is not a stylistic choice. A load that is interrupted after the kernel has taken the policy but
// before this method returns leaves no handle for anyone to close, and the profiles then outlive
// every session and every JVM: measured, three profiles still loaded with their session directory
// already deleted. Every teardown path closes a session, so BwrapSession removes the policy named
// by its own directory whether a load reached the kernel or not.
//
// Everything about a session's policy is private to that session: its own profile names, its own
// bwrap path to attach to. Nothing is shared between sessions, so nothing needs a lock, and no file
// outside warden's own state directory is written or reloaded.
//
// Loading and removing go through a root-owned helper rather than apparmor_parser directly, and the
// helper is handed no path. It is given a session id and, for a load, the rule body of the one
// profile whose content is the caller's policy - so the daemon user cannot name a file for a
// privileged parser to open, and cannot declare a profile that attaches to anything on the machine.
// The two confinement profiles are the helper's own, generated there from the session id alone.
// See scripts/install-apparmor-policy.sh.
//
// Removal is by name. The profile the kernel holds outlives the file it was parsed from, and taking
// a file for the removal meant a failed unload could delete the only thing that could ever undo it.
// If the install step has not run, every launch fails closed with a message naming what is missing.
final class AppArmorSessionPolicy {

  static final Path POLICY_HELPER = Path.of("/usr/local/sbin/warden-apparmor-policy");

  private static final String LOAD_ACTION = "load";
  private static final String UNLOAD_ACTION = "unload";
  private static final int WORLD_WRITABLE_MODE_BITS = 0b000_010_010;

  private AppArmorSessionPolicy() {
  }

  static void load(
      List<FilesystemRule> filesystemRules,
      AppArmorSessionProfileNames names,
      BwrapSessionPaths sessionPaths,
      Path helperExecutable
  ) {
    String body = AppArmorProfileGenerator.sessionProfileBody(
        names.sessionProfile(),
        filesystemRules,
        Optional.of(sessionPaths),
        Optional.of(helperExecutable),
        Optional.of(names.stackedLabel())
    );
    PrivilegedProcesses.run(List.of(POLICY_HELPER.toString(), LOAD_ACTION, names.sessionId()), body);
  }

  static void unload(String sessionId) {
    PrivilegedProcesses.run(List.of(POLICY_HELPER.toString(), UNLOAD_ACTION, sessionId), "");
  }

  static void requireInstalled() {
    Optional<String> missing = missingPrerequisite();
    if (missing.isEmpty()) {
      return;
    }
    String message = "Linux sandboxing requires a one-time install step"
        + " (see scripts/install-apparmor-policy.sh) before any session can launch: it creates "
        + BwrapSessionStore.SESSIONS_DIRECTORY + ", writable by this user, and installs the"
        + " root-owned " + POLICY_HELPER + " with a passwordless sudo grant for it. Problem: "
        + missing.get() + ".";
    throw new SandboxEstablishmentException(message);
  }

  private static Optional<String> missingPrerequisite() {
    Path sessions = BwrapSessionStore.SESSIONS_DIRECTORY;
    if (!Files.isDirectory(sessions) || !Files.isWritable(sessions)) {
      return Optional.of(sessions + " is missing or not writable by this user");
    }
    if (!Files.isExecutable(POLICY_HELPER)) {
      return Optional.of(POLICY_HELPER + " is missing or not executable");
    }
    return rootOwnedAndOnlyRootWritable(POLICY_HELPER);
  }

  static Optional<String> rootOwnedAndOnlyRootWritable(Path path) {
    try {
      if ((int) Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS) != 0) {
        return Optional.of(path + " is not owned by root");
      }
      int mode = (int) Files.getAttribute(path, "unix:mode", LinkOption.NOFOLLOW_LINKS);
      if ((mode & WORLD_WRITABLE_MODE_BITS) != 0) {
        return Optional.of(path + " is writable by a group or by everyone");
      }
      return Optional.empty();
    } catch (IOException | UnsupportedOperationException e) {
      return Optional.of("could not read the ownership of " + path + ": " + e);
    }
  }
}
