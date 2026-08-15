#!/usr/bin/env bash
set -euo pipefail

# Conventional Commits (https://www.conventionalcommits.org/en/v1.0.0/).

readonly TYPES='build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test'
readonly HEADER_PATTERN="^(${TYPES})(\([a-z0-9._-]+\))?!?: .+"

header="$(head -n 1)"

if [[ "$header" == Merge\ * ]]; then
  exit 0
fi

if [[ "$header" =~ $HEADER_PATTERN ]]; then
  exit 0
fi

echo "Commit message header does not follow Conventional Commits:" >&2
echo "  $header" >&2
echo >&2
echo "Expected: <type>[(scope)][!]: <description>" >&2
echo "Allowed types: ${TYPES//|/, }" >&2
echo "Example: feat(warden-core): add AppArmor bwrap attachment" >&2
exit 1
