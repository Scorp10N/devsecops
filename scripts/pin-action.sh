#!/usr/bin/env bash
# pin-action.sh — resolve a GitHub Action ref to its commit SHA
#
# Usage: pin-action.sh <owner/repo@ref>
#
# Prints:   owner/repo@<40-char-sha>  # ref
# suitable for pasting directly into workflow YAML as a pinned action ref.
#
# Handles both lightweight and annotated tags (dereferences tag objects
# to the underlying commit SHA). Also accepts branch names and full SHAs.
#
# Examples:
#   pin-action.sh actions/checkout@v4
#   pin-action.sh actions/setup-node@v3.8.1
#   pin-action.sh github/codeql-action/init@v3

set -euo pipefail

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
die() { echo "ERROR: $*" >&2; exit 1; }

usage() {
  grep '^#' "$0" | sed 's/^# \?//' | head -20
  exit 1
}

# ---------------------------------------------------------------------------
# arg parsing
# ---------------------------------------------------------------------------
[[ $# -eq 1 ]] || usage

input="$1"

# Strip leading action path (e.g. "github/codeql-action/init@v3" → owner=github, repo=codeql-action, ref=v3)
# We need only owner/repo for the API; keep the full path for display.
display_path="${input%@*}"    # everything before the last @
ref="${input##*@}"            # everything after the last @

[[ "$ref" == "$display_path" ]] && die "Input must be in 'owner/repo@ref' format (got: $input)"

# Normalise to owner/repo (drop sub-paths like /init, /analyze)
owner_repo=$(echo "$display_path" | cut -d'/' -f1-2)
owner="${owner_repo%%/*}"
repo="${owner_repo#*/}"

[[ -n "$owner" && -n "$repo" ]] || die "Could not parse owner/repo from: $display_path"

# ---------------------------------------------------------------------------
# SHA resolution
# ---------------------------------------------------------------------------

# Step 1: if ref looks like a full 40-char SHA, nothing to resolve
if [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then
  echo "${display_path}@${ref}  # ${ref}"
  exit 0
fi

# Step 2: try resolving as a tag ref
tag_url="repos/${owner}/${repo}/git/refs/tags/${ref}"
object_type=""
object_sha=""

tag_json=$(gh api "$tag_url" 2>/dev/null || true)
if [[ -n "$tag_json" ]]; then
  object_type=$(echo "$tag_json" | jq -r '.object.type')
  object_sha=$(echo  "$tag_json" | jq -r '.object.sha')
fi

# Step 3: if it was an annotated tag (type=tag), dereference to the commit
if [[ "$object_type" == "tag" ]]; then
  commit_sha=$(gh api "repos/${owner}/${repo}/git/tags/${object_sha}" \
    --jq '.object.sha' 2>/dev/null) \
    || die "Failed to dereference annotated tag object ${object_sha} for ${owner}/${repo}"
  [[ ${#commit_sha} -eq 40 ]] || die "Unexpected SHA length after dereference: '$commit_sha'"
  echo "${display_path}@${commit_sha}  # ${ref}"
  exit 0
fi

# Step 4: lightweight tag — sha is already the commit sha
if [[ "$object_type" == "commit" ]]; then
  echo "${display_path}@${object_sha}  # ${ref}"
  exit 0
fi

# Step 5: try as a branch ref
branch_url="repos/${owner}/${repo}/git/refs/heads/${ref}"
branch_json=$(gh api "$branch_url" 2>/dev/null || true)
if [[ -n "$branch_json" ]]; then
  commit_sha=$(echo "$branch_json" | jq -r '.object.sha')
  [[ ${#commit_sha} -eq 40 ]] || die "Unexpected SHA for branch ref: '$commit_sha'"
  echo "${display_path}@${commit_sha}  # ${ref}"
  exit 0
fi

# Step 6: try the commits API directly (handles full/short SHAs and branch names)
commit_json=$(gh api "repos/${owner}/${repo}/commits/${ref}" 2>/dev/null || true)
if [[ -n "$commit_json" ]]; then
  commit_sha=$(echo "$commit_json" | jq -r '.sha')
  [[ ${#commit_sha} -eq 40 ]] || die "Unexpected SHA from commits API: '$commit_sha'"
  echo "${display_path}@${commit_sha}  # ${ref}"
  exit 0
fi

die "Could not resolve ref '${ref}' for ${owner}/${repo}. Check that the tag/branch exists and you have access."
