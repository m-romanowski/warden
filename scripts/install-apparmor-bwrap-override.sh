#!/bin/sh
# One-time, root-owned install step for warden's Linux (AppArmor+bwrap) sandboxing. Run once per
# machine before any warden-based session can launch on Linux - AppArmorBwrapAttachment
# deliberately never installs this itself (see its own class comment for why: auto-installing from
# a path the daemon process could tamper with would defeat the whole point of the sudo grant this
# mechanism depends on).
#
# The embedded script content below MUST stay byte-identical to
# warden-core/src/main/java/dev/marcinromanowski/warden/core/AppArmorBwrapAttachment.java's own
set -e

INSTALL_PATH="/etc/warden/apparmor-bwrap-override.sh"
SUDOERS_FILE="/etc/sudoers.d/warden-apparmor-bwrap-override"
DAEMON_USER="${1:?usage: $0 <daemon-user>}"

sudo install -d -m 0755 /etc/warden

sudo tee "$INSTALL_PATH" > /dev/null <<'MANAGEMENT_SCRIPT'
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
MANAGEMENT_SCRIPT

sudo chmod 0755 "$INSTALL_PATH"

# apparmor_parser itself is also invoked directly (AppArmorProfile.load()/close(), loading and
# unloading each session's own filesystem profile) - a broader grant than the bwrap-override
# script above, since "apparmor_parser -r <any-file>" lets the caller load arbitrary profile
# content, not just append one narrow, syntax-constrained stacking line. Accepted, documented
# residual risk for now (same trust boundary as the daemon process itself already has for
# everything else it does) - not yet narrowed further.
{
  echo "$DAEMON_USER ALL=(root) NOPASSWD: $INSTALL_PATH *"
  echo "$DAEMON_USER ALL=(root) NOPASSWD: /usr/sbin/apparmor_parser -r *"
  echo "$DAEMON_USER ALL=(root) NOPASSWD: /usr/sbin/apparmor_parser -R *"
} | sudo tee "$SUDOERS_FILE" > /dev/null
sudo chmod 0440 "$SUDOERS_FILE"
sudo visudo -c -f "$SUDOERS_FILE"

echo "Installed $INSTALL_PATH and granted $DAEMON_USER passwordless sudo for it plus apparmor_parser."
