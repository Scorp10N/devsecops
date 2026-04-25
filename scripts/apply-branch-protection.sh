#!/usr/bin/env bash
# apply-branch-protection.sh — apply Level A branch protection to a GitHub repo
#
# Level A definition:
#   - CI-gated: one or more required status checks must pass before merging
#   - Strict (branch must be up-to-date before merging)
#   - No force-pushes
#   - No branch deletion
#   - No code-owner reviews required (use apply-branch-protection-reviewed.sh for that)
#   - Admins ARE bound by the rules (enforce_admins: true)
#
# Usage:
#   apply-branch-protection.sh <owner/repo> <check-name> [<check-name> ...]
#
# Arguments:
#   owner/repo      Full repo slug (e.g. Scorp10N/resumeforge)
#   check-name      One or more required status check context strings.
#                   Use as many as needed; they map to your workflow job names.
#
# Options:
#   --branch <name>   Target branch (default: main)
#   --no-enforce-admins  Allow admins to bypass protection (default: admins are bound)
#   --dry-run         Print the JSON payload without making the API call
#
# Examples:
#   apply-branch-protection.sh Scorp10N/resumeforge ci
#   apply-branch-protection.sh Scorp10N/devsecops "lint" "test" "security-scan"
#   apply-branch-protection.sh Scorp10N/resumeforge ci --branch develop
#   apply-branch-protection.sh Scorp10N/resumeforge ci --dry-run

set -euo pipefail

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[branch-protect] $*"; }

usage() {
  grep '^#' "$0" | sed 's/^# \?//' | head -35
  exit 1
}

# ---------------------------------------------------------------------------
# arg parsing
# ---------------------------------------------------------------------------
[[ $# -ge 2 ]] || usage

REPO="$1"; shift

BRANCH="main"
ENFORCE_ADMINS="true"
DRY_RUN=false
CHECK_NAMES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --branch)
      [[ $# -ge 2 ]] || die "--branch requires a value"
      BRANCH="$2"; shift 2 ;;
    --no-enforce-admins)
      ENFORCE_ADMINS="false"; shift ;;
    --dry-run)
      DRY_RUN=true; shift ;;
    -*)
      die "Unknown option: $1" ;;
    *)
      CHECK_NAMES+=("$1"); shift ;;
  esac
done

[[ ${#CHECK_NAMES[@]} -ge 1 ]] || die "At least one check name is required"
[[ "$REPO" =~ ^[^/]+/[^/]+$ ]] || die "Repo must be 'owner/repo' (got: $REPO)"

# ---------------------------------------------------------------------------
# build the required_status_checks contexts array
# ---------------------------------------------------------------------------
contexts_json=$(printf '%s\n' "${CHECK_NAMES[@]}" | jq -R . | jq -s .)

# ---------------------------------------------------------------------------
# build the full protection payload
# ---------------------------------------------------------------------------
# Level A: CI-gated, strict, no force-push, no deletion, no PR review requirements
payload=$(jq -n \
  --argjson contexts "$contexts_json" \
  --argjson enforce_admins "$ENFORCE_ADMINS" \
  '{
    required_status_checks: {
      strict: true,
      contexts: $contexts
    },
    enforce_admins: $enforce_admins,
    required_pull_request_reviews: null,
    restrictions: null,
    allow_force_pushes: false,
    allow_deletions: false,
    block_creations: false,
    required_conversation_resolution: false
  }')

# ---------------------------------------------------------------------------
# dry-run mode
# ---------------------------------------------------------------------------
if $DRY_RUN; then
  info "DRY RUN — would call:"
  echo "  gh api repos/${REPO}/branches/${BRANCH}/protection \\"
  echo "    -X PUT \\"
  echo "    --input -"
  echo ""
  info "Payload:"
  echo "$payload" | jq .
  exit 0
fi

# ---------------------------------------------------------------------------
# apply the protection
# ---------------------------------------------------------------------------
info "Applying Level A branch protection to ${REPO}:${BRANCH} ..."
info "Required checks: ${CHECK_NAMES[*]}"
info "enforce_admins:  ${ENFORCE_ADMINS}"

response=$(echo "$payload" | gh api \
  "repos/${REPO}/branches/${BRANCH}/protection" \
  -X PUT \
  --input - \
  2>&1) || {
  echo "ERROR: gh api call failed:" >&2
  echo "$response" >&2
  exit 1
}

# Verify a few key fields from the response
enabled_checks=$(echo "$response" | jq -r '.required_status_checks.contexts[]?' 2>/dev/null | tr '\n' ', ' | sed 's/,$//')
no_force_push=$(echo  "$response" | jq -r '.allow_force_pushes.enabled // .allow_force_pushes // "false"' 2>/dev/null)
no_deletion=$(echo    "$response" | jq -r '.allow_deletions.enabled    // .allow_deletions    // "false"' 2>/dev/null)

echo ""
info "Protection applied successfully."
info "  Branch:           ${BRANCH}"
info "  Required checks:  ${enabled_checks:-<none returned>}"
info "  Force pushes:     ${no_force_push} (should be false)"
info "  Deletions:        ${no_deletion}   (should be false)"
echo ""

# Print URL for convenience
owner="${REPO%%/*}"
repo_name="${REPO#*/}"
info "Settings: https://github.com/${owner}/${repo_name}/settings/branches"
