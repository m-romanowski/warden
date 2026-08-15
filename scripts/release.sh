#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/release.sh <major|minor|patch> [--repo-root <path>]
  scripts/release.sh --version <x.y.z> [--repo-root <path>]

Bumps this repo's SemVer version, commits, and tags. It derives everything from
the checked-out repo itself (gradle.properties's own version= line, nothing hardcoded to this
specific project's name) - meant to be copyable as a template into another Gradle project's own
release automation with no rewrite needed, only a different repo-root.

Reads the current version from <repo-root>/gradle.properties (a bare "version=x.y.z" or
"version=x.y.z-SNAPSHOT" line - the -SNAPSHOT suffix, if present, is stripped before bumping),
computes the next version, rewrites gradle.properties in place, commits
("chore: release v<version>"), and tags ("v<version>"). Does not push - the caller decides
whether/when to push the resulting commit and tag.

Prints the resulting version (without the "v" tag prefix) as the last line of stdout, for a
calling script/workflow to capture.
EOF
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bump_type=""
explicit_version=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    major | minor | patch)
      bump_type="$1"
      shift
      ;;
    --version)
      explicit_version="$2"
      shift 2
      ;;
    --repo-root)
      repo_root="$2"
      shift 2
      ;;
    --help | -h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$bump_type" && -z "$explicit_version" ]]; then
  echo "Missing required argument: a bump type (major|minor|patch) or --version <x.y.z>." >&2
  usage
  exit 1
fi

properties_file="$repo_root/gradle.properties"
if [[ ! -f "$properties_file" ]]; then
  echo "gradle.properties not found at $properties_file" >&2
  exit 1
fi

current_line="$(grep -E '^version=' "$properties_file" || true)"
if [[ -z "$current_line" ]]; then
  echo "No 'version=' line found in $properties_file" >&2
  exit 1
fi
current_version="${current_line#version=}"
current_version="${current_version%-SNAPSHOT}"

if [[ -n "$explicit_version" ]]; then
  next_version="$explicit_version"
else
  IFS='.' read -r major minor patch <<< "$current_version"
  case "$bump_type" in
    major)
      next_version="$((major + 1)).0.0"
      ;;
    minor)
      next_version="$major.$((minor + 1)).0"
      ;;
    patch)
      next_version="$major.$minor.$((patch + 1))"
      ;;
  esac
fi

if ! [[ "$next_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Computed version '$next_version' is not a valid MAJOR.MINOR.PATCH SemVer string." >&2
  exit 1
fi

sed -i.bak "s/^version=.*/version=$next_version/" "$properties_file"
rm -f "$properties_file.bak"

git -C "$repo_root" add gradle.properties
git -C "$repo_root" commit -m "chore: release v$next_version" >&2
git -C "$repo_root" tag "v$next_version" >&2

echo "Released v$next_version (was $current_version)" >&2
echo "$next_version"
