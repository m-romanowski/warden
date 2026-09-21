#!/bin/sh
# One-time, root-owned install step for warden's Linux (AppArmor+bwrap) sandboxing. Run once per
# machine, as an account that can sudo, before any warden-based session can launch on Linux.
#
# It creates the state directories a session needs, installs the only command the daemon user is
# ever allowed to run as root, and grants passwordless sudo for exactly that command. A running
# session writes nothing under /etc/apparmor.d and reloads no profile the distribution ships.
#
# The helper exists because the grant cannot be narrowed in sudoers itself: sudo-rs, the default
# sudo on Ubuntu 25.10 and later, rejects a wildcard in a command argument outright, so
# "apparmor_parser -r <directory>/*" is not a rule that loads at all. Naming the bare command
# instead would permit any arguments, which is no narrowing.
#
# The helper takes no path from the daemon user, and authors every profile header itself from one
# argument: a 32-hex session id. A path argument bounds nothing when the grantee owns the directory
# it names - it can plant a symlink in it, and the parser follows one. Content is what has to be
# bounded, so the daemon supplies rule lines for one non-attaching profile and nothing else. See the
# helper's own comments for the invariant that makes that hold.
set -e

STATE_DIRECTORY="/var/lib/warden"
SESSIONS_DIRECTORY="$STATE_DIRECTORY/sessions"
POLICY_DIRECTORY="$STATE_DIRECTORY/policy"
HELPER_PATH="/usr/local/sbin/warden-apparmor-policy"
SUDOERS_FILE="/etc/sudoers.d/warden-apparmor"

DAEMON_USER="${1:?usage: $0 <daemon-user>}"
case "$DAEMON_USER" in
  *[!A-Za-z0-9._-]* | -*) echo "refusing unsafe daemon user name: $DAEMON_USER" >&2; exit 64 ;;
esac
id -u "$DAEMON_USER" > /dev/null 2>&1 || { echo "no such user: $DAEMON_USER" >&2; exit 64; }

sudo install -d -m 0755 -o root -g root "$STATE_DIRECTORY"
sudo install -d -m 0700 -o "$DAEMON_USER" "$SESSIONS_DIRECTORY"
sudo install -d -m 0700 -o root -g root "$POLICY_DIRECTORY"

STAGED_HELPER=$(mktemp)
trap 'rm -f "$STAGED_HELPER" "${STAGED_SUDOERS:-}"' EXIT INT TERM

cat > "$STAGED_HELPER" <<HELPER
#!/bin/sh
# warden-policy-helper-contract: 2
#
# Installed by warden's install-apparmor-policy.sh. Root-owned, and the single command warden's
# daemon user may run as root.
#
# The contract line above is what the library checks before it launches anything, because the
# helper on disk is a copy taken at install time and nothing else about it says which release wrote
# it. Bump it whenever a change here makes an older helper refuse a body this release now emits,
# and add the new number to POLICY_HELPER_CONTRACTS in AppArmorSessionPolicy. Contract 2 is the
# include allowlist admitting <abstractions/ssl_certs>: a machine still running contract 1 refuses
# every session launch of this release, with this script's own wording as the only clue.
#
# It accepts no path and no policy text that could name a profile. The one argument is a session id,
# and every profile header - names, flags and the bwrap attachment - is written here. What the
# daemon supplies is the rule body of warden-sandbox-<id>, a profile with no attachment
# specification, which therefore attaches to no executable on the machine and replaces nothing the
# distribution ships.
#
# That bound rests on one invariant: a body containing no brace cannot close the block this script
# opened, so every "{" and "}" in the file handed to the parser is one written here, and so is every
# profile declaration between them. The single-file include allowlist is the other half of it - an
# include is textual, so a wider allowlist would be a way to bring in a brace without writing one.
# apparmor_parser -N over the assembled file is the backstop that would catch a profile declared by
# any route this reasoning missed, and it is checked against the exact three names expected.
#
# -N is a backstop and not the boundary, because it reports a profile's name and not its attachment:
# "profile warden-sandbox-<id> /usr/sbin/sshd { }" prints only the name while confining sshd.
set -e

# Every command below is run as root by name. sudo preserves the invoking user's PATH on a machine
# whose sudoers sets no secure_path, and the daemon user would then choose which "mktemp" root runs.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

SESSIONS_DIRECTORY="$SESSIONS_DIRECTORY"
POLICY_DIRECTORY="$POLICY_DIRECTORY"
PARSER="/usr/sbin/apparmor_parser"
LOADED_PROFILES="/sys/kernel/security/apparmor/profiles"
MAXIMUM_BODY_BYTES=1048576

ACTION="\${1:-}"
SESSION_ID="\${2:-}"

refuse() {
  echo "\$1" >&2
  exit 64
}

case "\$SESSION_ID" in
  *[!0-9a-f]* | "") refuse "session id must be 32 lowercase hex characters" ;;
esac
[ "\${#SESSION_ID}" -eq 32 ] || refuse "session id must be 32 lowercase hex characters"

BWRAP_PROFILE="warden-bwrap-\$SESSION_ID"
UNPRIVILEGED_PROFILE="warden-unpriv-\$SESSION_ID"
SESSION_PROFILE="warden-sandbox-\$SESSION_ID"
SESSION_ROOT="\$SESSIONS_DIRECTORY/\$SESSION_ID"

umask 077
WORK_DIRECTORY=\$(mktemp -d "\$POLICY_DIRECTORY/session.XXXXXXXX")
trap 'rm -rf "\$WORK_DIRECTORY"' EXIT INT TERM
POLICY_FILE="\$WORK_DIRECTORY/policy"

# Removal takes profile names, so a session that lost its policy file - or never wrote one - is
# still removable. The stub bodies are ignored by the parser, which matches on the name alone.
#
# The verdict is the kernel's own list of loaded profiles, not the parser's exit code, because the
# caller asks for this session's policy to be gone and the parser reports 254 when it was never
# there. Every teardown path runs this, including the ones where a load was interrupted after the
# kernel took the policy but before the caller learned it had, so "already absent" has to succeed.
remove_profiles() {
  printf 'profile %s {\n}\nprofile %s {\n}\nprofile %s {\n}\n' \\
    "\$BWRAP_PROFILE" "\$UNPRIVILEGED_PROFILE" "\$SESSION_PROFILE" > "\$POLICY_FILE"
  PARSER_OUTPUT=\$("\$PARSER" -R "\$POLICY_FILE" 2>&1) && return 0
  # An unreadable list is not evidence of absence. Reporting success there would tell the caller the
  # policy is gone while it is still loaded, and the caller then deletes the directory that names it.
  if [ ! -r "\$LOADED_PROFILES" ] \\
      || LC_ALL=C grep -qE "^warden-(bwrap|unpriv|sandbox)-\$SESSION_ID(//| )" "\$LOADED_PROFILES"; then
    echo "\$PARSER_OUTPUT" >&2
    return 1
  fi
  return 0
}

# The two confinement profiles carry no caller policy at all: they let an unprivileged bwrap build a
# user namespace on a kernel that restricts that to confined processes, and hand the payload on. The
# stacked peer label the kernel renders is component-sorted, which for these three names is bwrap,
# sandbox, unpriv.
write_policy() {
  BODY_FILE="\$WORK_DIRECTORY/body"
  head -c \$((MAXIMUM_BODY_BYTES + 1)) > "\$BODY_FILE"
  [ "\$(wc -c < "\$BODY_FILE")" -le "\$MAXIMUM_BODY_BYTES" ] || refuse "session profile body is too large"
  if LC_ALL=C grep -q '[{}]' "\$BODY_FILE"; then
    refuse "session profile body must contain no brace"
  fi
  # Each abstraction by name, not a pattern over a directory this script does not own. An abstraction
  # can declare a profile of its own, braces and all, so an allowlist shaped like "abstractions/*"
  # hands the body a way to bring in both without writing either. Naming the exact files warden emits
  # is what makes the no-brace invariant above true rather than merely usually true.
  #
  # ssl_certs is the second, and it is here because the generator started emitting it and this list
  # did not follow: measured against a real kernel, every session launch on Linux was refused at this
  # line, and warden's own AppArmor enforcement suite failed thirty cases with this refusal as the
  # message. Naming a second file costs the allowlist nothing that naming one did not already cost,
  # because the bound on what either file may itself declare is the -N check below and not the count.
  #
  # Which abstractions those are belongs to the distribution, and this project has measured one:
  # asked file by file, apparmor_parser -N names seven of the ones Ubuntu 26.04 ships, and the
  # directory holding three of them is an eighth spelling that declares the same profiles. That is a
  # limit on the survey and not on this allowlist, which names one file and reads the same everywhere. What that one file
  # itself contains belongs to the distribution too, and is bounded by the -N check below rather than
  # by a survey: -N reads through an include and names what the included file declares, so an
  # <abstractions/base> that grew a profile declaration would refuse the launch rather than load it.
  #
  # Matched at a token boundary, because "include" is also an ordinary path component: /usr/include
  # appears in real rule sets, and an unanchored search refused every launch that mentioned it.
  # Anchoring to the start of a line is not enough the other way either - apparmor honours an
  # include after a rule on the same line, measured.
  if LC_ALL=C grep -oE '(^|[[:space:]]|#)include.*' "\$BODY_FILE" \\
      | LC_ALL=C sed -E 's/^[[:space:]#]+//' \\
      | LC_ALL=C grep -qvE '^include[[:space:]]*<abstractions/(base|ssl_certs)>[[:space:]]*\$'; then
    refuse "session profile body may include nothing but <abstractions/base> and <abstractions/ssl_certs>"
  fi

  {
    printf '#include <tunables/global>\n\n'
    printf 'profile %s %s/tools/bwrap flags=(attach_disconnected,mediate_deleted) {\n' \\
      "\$BWRAP_PROFILE" "\$SESSION_ROOT"
    printf '  allow capability,\n'
    printf '%s' "\$NAMESPACE_SETUP_ALLOWANCES"
    printf '  allow pix /** -> &%s//&%s,\n' "\$BWRAP_PROFILE" "\$UNPRIVILEGED_PROFILE"
    printf '  px %s/session/target-shell -> %s//&%s//&%s,\n' \\
      "\$SESSION_ROOT" "\$BWRAP_PROFILE" "\$UNPRIVILEGED_PROFILE" "\$SESSION_PROFILE"
    printf '}\n\n'
    printf 'profile %s flags=(attach_disconnected,mediate_deleted) {\n' "\$UNPRIVILEGED_PROFILE"
    printf '%s' "\$NAMESPACE_SETUP_ALLOWANCES"
    printf '  allow pix /** -> &%s,\n' "\$UNPRIVILEGED_PROFILE"
    printf '  audit deny capability,\n'
    printf '}\n\n'
    printf 'profile %s flags=(attach_disconnected) {\n' "\$SESSION_PROFILE"
    cat "\$BODY_FILE"
    printf '}\n'
  } > "\$POLICY_FILE"

  "\$PARSER" -N "\$POLICY_FILE" > "\$WORK_DIRECTORY/names"
  DECLARED=\$(LC_ALL=C sort < "\$WORK_DIRECTORY/names")
  EXPECTED=\$(printf '%s\n%s\n%s\n' "\$BWRAP_PROFILE" "\$SESSION_PROFILE" "\$UNPRIVILEGED_PROFILE" | LC_ALL=C sort)
  [ "\$DECLARED" = "\$EXPECTED" ] || refuse "policy declares profiles outside this session: \$DECLARED"
}

NAMESPACE_SETUP_ALLOWANCES='  allow file rwlkm /{**,},
  allow network,
  allow unix,
  allow ptrace,
  allow signal,
  allow mqueue,
  allow io_uring,
  allow userns,
  allow mount,
  allow umount,
  allow pivot_root,
  allow dbus,
'

case "\$ACTION" in
  load)
    write_policy
    "\$PARSER" -r "\$POLICY_FILE"
    ;;
  unload)
    remove_profiles
    ;;
  *) refuse "unknown action: \$ACTION" ;;
esac
HELPER

sudo install -m 0755 -o root -g root "$STAGED_HELPER" "$HELPER_PATH"

STAGED_SUDOERS=$(mktemp)
echo "$DAEMON_USER ALL=(root) NOPASSWD: $HELPER_PATH" > "$STAGED_SUDOERS"
chmod 0440 "$STAGED_SUDOERS"
# Validated before it is anywhere sudo reads. A malformed file already dropped into /etc/sudoers.d
# breaks sudo for every user on the machine, and validating it there is validating it too late.
sudo visudo -c -f "$STAGED_SUDOERS" > /dev/null
sudo install -m 0440 -o root -g root "$STAGED_SUDOERS" "$SUDOERS_FILE"

# Without this an upgraded machine keeps a grant for "apparmor_parser -r *", which is every narrowing
# above undone. Safe to run when none of it is present, and safe to run twice.
sudo rm -f /etc/sudoers.d/warden-apparmor-bwrap-override
sudo rm -f /etc/warden/apparmor-bwrap-override.sh
sudo rmdir /etc/warden 2> /dev/null || true
sudo rmdir /var/lib/warden/apparmor 2> /dev/null || true

LEGACY_OVERRIDE_FILE="/etc/apparmor.d/local/bwrap-userns-restrict"
LEGACY_LINE_MARKER=" -> bwrap//&unpriv_bwrap//&warden-sandbox-"
if sudo test -f "$LEGACY_OVERRIDE_FILE" && sudo grep -qF "$LEGACY_LINE_MARKER" "$LEGACY_OVERRIDE_FILE"; then
  # Only warden's own lines go, and only then is the vendor profile reloaded - the file belongs to
  # the distribution and may hold an administrator's own rules.
  sudo sh -c "grep -vF '$LEGACY_LINE_MARKER' '$LEGACY_OVERRIDE_FILE' > '$LEGACY_OVERRIDE_FILE.warden-new' || true"
  sudo chmod --reference="$LEGACY_OVERRIDE_FILE" "$LEGACY_OVERRIDE_FILE.warden-new"
  sudo mv "$LEGACY_OVERRIDE_FILE.warden-new" "$LEGACY_OVERRIDE_FILE"
  sudo /usr/sbin/apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict
  echo "Removed warden 1.3.0 stacking lines from $LEGACY_OVERRIDE_FILE and reloaded the vendor profile."
fi

echo "Created $SESSIONS_DIRECTORY and $POLICY_DIRECTORY, installed $HELPER_PATH, and granted $DAEMON_USER passwordless sudo for it."
