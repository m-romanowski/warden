package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.SandboxEstablishmentException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

// Registers/removes the per-session "px <uniqueTargetBinary> -> bwrap//&unpriv_bwrap//&<profile>,"
// stacking rule in /etc/apparmor.d/local/bwrap-userns-restrict, the documented local-override
// extension point for Ubuntu's own bwrap-userns-restrict profile. Confirmed empirically on a real
// kernel: the kernel's own no_new_privs exec-time stacking rule only permits a profile-label
// change if the new stack's base component literally matches the currently-active profile - a
// unique per-session target-binary path is what makes this rule apply to exactly one session, not
// every bwrap invocation on the machine.
//
// The read-modify-write-reload sequence against this shared, root-owned file runs as a single
// privileged shell script (not a JVM-side file lock) for two reasons: the JVM does not run as
// root and cannot open a root-owned /etc file for writing at all, and pushing the whole sequence
// into one sudo'd script lets a real flock(1) provide cross-process mutual exclusion between
// concurrent sessions (including sessions started by a different warden-embedding process
// entirely) without the JVM needing to coordinate locking itself.
//
// This class deliberately never writes MANAGEMENT_SCRIPT to disk itself - an earlier version did
// (to a path under the JVM's own tmpdir, always writable by whatever user runs the JVM), which
// meant the "narrow, auditable" sudo grant this class's own design depends on was only as narrow
// as trusting the daemon process never to tamper with its own script before invoking sudo against
// it - a real privilege-escalation surface, not just a style concern, in a project whose entire
// point is closing exactly this class of gap. Deployment must install MANAGEMENT_SCRIPT's exact
// content to INSTALL_PATH as a one-time, root-owned, daemon-user-non-writable step (see the real
// content and required permissions below) and grant passwordless sudo for exactly
// "sh <INSTALL_PATH> *" - if that install step hasn't happened, every attach()/close() call fails
// closed with a message naming exactly what's missing, never silently degrading to something less
// trustworthy.
final class AppArmorBwrapAttachment implements AutoCloseable {

  // Real deployment step (see the class comment above for why this is not done automatically):
  // run scripts/install-apparmor-bwrap-override.sh <daemon-user> as an account that can sudo. That
  // script embeds MANAGEMENT_SCRIPT's own content by hand in its own heredoc.
  static final Path INSTALL_PATH = Path.of("/etc/warden/apparmor-bwrap-override.sh");
  static final String MANAGEMENT_SCRIPT =
      """
      #!/bin/sh
      set -e
      ACTION="$1"
      TARGET_PATH="$2"
      PROFILE_NAME="$3"
      OVERRIDE_FILE="/etc/apparmor.d/local/bwrap-userns-restrict"
      VENDOR_FILE="/etc/apparmor.d/bwrap-userns-restrict"
      LOCK_FILE="/var/lock/warden-apparmor-bwrap-override.lock"

      exec 9>"$LOCK_FILE"
      flock 9

      TMP_FILE=$(mktemp)
      if [ -f "$OVERRIDE_FILE" ]; then
        grep -v -F "$TARGET_PATH ->" "$OVERRIDE_FILE" > "$TMP_FILE" || true
      else
        : > "$TMP_FILE"
      fi

      if [ "$ACTION" = "attach" ]; then
        echo "px $TARGET_PATH -> bwrap//&unpriv_bwrap//&$PROFILE_NAME," >> "$TMP_FILE"
      fi

      # cp preserves mktemp's own restrictive 0600 mode on first creation, leaving the file
      # unreadable to non-root readers unless corrected explicitly.
      cp "$TMP_FILE" "$OVERRIDE_FILE"
      chmod 0644 "$OVERRIDE_FILE"
      rm -f "$TMP_FILE"
      apparmor_parser -r "$VENDOR_FILE"
      """;

  private final Path uniqueTargetBinary;
  private boolean closed;

  private AppArmorBwrapAttachment(Path uniqueTargetBinary) {
    this.uniqueTargetBinary = uniqueTargetBinary;
  }

  static AppArmorBwrapAttachment attach(Path uniqueTargetBinary, String profileName) {
    Path requiredTargetBinary = Preconditions.nonNull(uniqueTargetBinary, "uniqueTargetBinary");
    String requiredProfileName = requireSafeLineComponent(
        Preconditions.nonBlank(profileName, "profileName")
    );
    runManagementScript("attach", requiredTargetBinary.toString(), requiredProfileName);
    return new AppArmorBwrapAttachment(requiredTargetBinary);
  }

  @Override
  public void close() {
    if (closed) {
      return;
    }
    closed = true;
    runManagementScript(
        "detach",
        uniqueTargetBinary.toString(),
        ""
    );
  }

  private static void runManagementScript(String action, String targetPath, String profileName) {
    requireSafeLineComponent(targetPath);
    requireManagementScriptInstalled();
    PrivilegedProcesses.run(List.of("sh", INSTALL_PATH.toString(), action, targetPath, profileName));
  }

  private static void requireManagementScriptInstalled() {
    if (Files.isRegularFile(INSTALL_PATH)) {
      return;
    }
    String message = "AppArmor bwrap-attachment management script is not installed at " + INSTALL_PATH
        + " - Linux sandboxing requires a one-time, root-owned install step (see"
        + " AppArmorBwrapAttachment's own class comment for the exact commands) before any session"
        + " can launch. This is not done automatically, since auto-installing it from a path the"
        + " daemon process could itself tamper with would defeat the whole point of the sudo grant"
        + " this mechanism depends on.";
    throw new SandboxEstablishmentException(message);
  }

  // The target path is grep -F-matched and interpolated into a generated apparmor rule line by
  // the management script above. A comma or line break in either value would let a caller inject
  // extra AppArmor syntax or corrupt the override file - the same injection class
  // AppArmorGlobTranslator already guards against for rule patterns.
  private static String requireSafeLineComponent(String value) {
    if (value.indexOf(',') >= 0 || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
      throw new IllegalArgumentException("Unsafe character in AppArmor stacking line component: " + value);
    }
    return value;
  }
}
