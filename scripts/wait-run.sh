#!/usr/bin/env bash
# wait-run.sh — wait for the latest GitHub Actions run on a repo/workflow to complete
#
# Usage:
#   wait-run.sh <owner/repo> <workflow-name-or-file> [--sha <commit-sha>] [--timeout <seconds>]
#
# Arguments:
#   owner/repo            Full repo slug (e.g. Scorp10N/resumeforge)
#   workflow-name-or-file Workflow name string or filename (e.g. "CI" or "ci.yml")
#
# Options:
#   --sha <sha>       Wait for a run triggered on this specific commit (first 7+ chars OK)
#   --timeout <sec>   Give up after this many seconds (default: 300)
#   --poll <sec>      Polling interval in seconds (default: 5)
#
# On completion, prints each job name and its conclusion.
# Exits 0 if all jobs succeeded, 1 if any failed/cancelled, 2 if timed out.
#
# Examples:
#   wait-run.sh Scorp10N/resumeforge ci.yml
#   wait-run.sh Scorp10N/devsecops "Security Scan" --sha a1b2c3d --timeout 120

set -euo pipefail

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[wait-run] $*"; }

usage() {
  grep '^#' "$0" | sed 's/^# \?//' | head -30
  exit 1
}

# ---------------------------------------------------------------------------
# arg parsing
# ---------------------------------------------------------------------------
[[ $# -ge 2 ]] || usage

REPO="$1"; shift
WORKFLOW="$1"; shift

FILTER_SHA=""
TIMEOUT=300
POLL=5

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sha)
      [[ $# -ge 2 ]] || die "--sha requires a value"
      FILTER_SHA="$2"; shift 2 ;;
    --timeout)
      [[ $# -ge 2 ]] || die "--timeout requires a value"
      TIMEOUT="$2"; shift 2 ;;
    --poll)
      [[ $# -ge 2 ]] || die "--poll requires a value"
      POLL="$2"; shift 2 ;;
    *)
      die "Unknown argument: $1" ;;
  esac
done

[[ "$REPO" =~ ^[^/]+/[^/]+$ ]] || die "Repo must be 'owner/repo' (got: $REPO)"

# ---------------------------------------------------------------------------
# find the target run
# ---------------------------------------------------------------------------

# Build jq filter: optionally match on SHA prefix
if [[ -n "$FILTER_SHA" ]]; then
  sha_filter="| select(.headSha | startswith(\"${FILTER_SHA}\"))"
  info "Looking for run on commit ${FILTER_SHA} in ${REPO} / ${WORKFLOW} ..."
else
  sha_filter=""
  info "Looking for latest run in ${REPO} / ${WORKFLOW} ..."
fi

find_run_id() {
  gh run list \
    --repo "$REPO" \
    --workflow "$WORKFLOW" \
    --limit 20 \
    --json databaseId,status,conclusion,headSha \
    --jq "[.[] ${sha_filter}] | first | .databaseId // empty" \
    2>/dev/null || true
}

# Wait up to TIMEOUT seconds for a matching run to appear at all
start=$(date +%s)
run_id=""
while true; do
  run_id=$(find_run_id)
  [[ -n "$run_id" ]] && break
  now=$(date +%s)
  elapsed=$(( now - start ))
  if (( elapsed >= TIMEOUT )); then
    die "Timed out waiting for a matching run to appear (${TIMEOUT}s). Is the workflow name correct?"
  fi
  info "No matching run found yet — waiting ${POLL}s ..."
  sleep "$POLL"
done

info "Found run ID ${run_id}. Waiting for completion ..."

# ---------------------------------------------------------------------------
# poll until complete
# ---------------------------------------------------------------------------
while true; do
  status=$(gh run view "$run_id" --repo "$REPO" --json status --jq '.status' 2>/dev/null || echo "unknown")

  if [[ "$status" == "completed" ]]; then
    break
  fi

  now=$(date +%s)
  elapsed=$(( now - start ))
  if (( elapsed >= TIMEOUT )); then
    info "Run ${run_id} status: ${status}"
    echo "TIMEOUT: run did not complete within ${TIMEOUT}s." >&2
    exit 2
  fi

  info "  status=${status}  (${elapsed}s elapsed) — polling again in ${POLL}s ..."
  sleep "$POLL"
done

# ---------------------------------------------------------------------------
# print results
# ---------------------------------------------------------------------------
echo ""
info "Run ${run_id} completed. Job results:"
echo ""

# Collect job outcomes
jobs_json=$(gh run view "$run_id" --repo "$REPO" --json jobs --jq '.jobs[] | "\(.name)\t\(.conclusion)"' 2>/dev/null || true)

all_success=true
if [[ -n "$jobs_json" ]]; then
  while IFS=$'\t' read -r job_name conclusion; do
    icon="✓"
    [[ "$conclusion" == "success" ]] || { icon="✗"; all_success=false; }
    printf "  %s  %-50s  %s\n" "$icon" "$job_name" "$conclusion"
  done <<< "$jobs_json"
else
  # Fallback: just print overall conclusion
  conclusion=$(gh run view "$run_id" --repo "$REPO" --json conclusion --jq '.conclusion' 2>/dev/null || echo "unknown")
  echo "  Overall conclusion: ${conclusion}"
  [[ "$conclusion" == "success" ]] || all_success=false
fi

echo ""

# Print URL for easy navigation
run_url=$(gh run view "$run_id" --repo "$REPO" --json url --jq '.url' 2>/dev/null || true)
[[ -n "$run_url" ]] && info "View run: ${run_url}"

if $all_success; then
  info "All jobs succeeded."
  exit 0
else
  info "One or more jobs did not succeed."
  exit 1
fi
