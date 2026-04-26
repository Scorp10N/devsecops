#!/usr/bin/env bash
# run-logs.sh — fetch failed job logs from a workflow run with smart filtering
#
# Wraps `gh run view --log-failed` with opinionated grep patterns tuned for
# common CI failure types (CVEs, proto errors, auth failures, build errors).
#
# Usage:
#   run-logs.sh [RUN-ID] [options]
#
# Arguments:
#   RUN-ID         Numeric run ID. Omit to auto-detect latest run for --workflow.
#
# Options:
#   --repo <owner/repo>       Repo slug (default: current repo)
#   --workflow <name>         Workflow name or file for auto-detecting latest run
#   --branch <branch>         Filter runs by branch when auto-detecting
#   --filter <pattern>        Extra grep -E pattern appended to default filters
#   --raw                     Show full log output (no grep filtering)
#   --lines <n>               Number of lines to show per job (default: 80)
#   --job <name>              Show only logs for jobs matching this substring
#
# Built-in filter patterns (always applied unless --raw):
#   error|Error|ERROR|FAIL|failed|exit code [^0]
#   CVE-|GHSA-|vulnerability|vuln
#   proto:|unknown field|parse error
#   BASE and HEAD|base.*head.*same
#   token|unauthorized|forbidden|403|401
#
# Exit codes:
#   0  Logs fetched successfully
#   1  Run not found or gh CLI error
#
# Examples:
#   run-logs.sh                                    # latest run, current repo
#   run-logs.sh 24950371275
#   run-logs.sh --workflow Security --branch main
#   run-logs.sh 24950371275 --filter "TruffleHog|trufflehog"
#   run-logs.sh --repo Scorp10N/resumeforge --workflow Security --raw

set -euo pipefail

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[run-logs] $*" >&2; }

# ---------------------------------------------------------------------------
# defaults
# ---------------------------------------------------------------------------
RUN_ID=""
REPO=""
WORKFLOW=""
BRANCH=""
EXTRA_FILTER=""
RAW=false
LINES=80
JOB_FILTER=""

# ---------------------------------------------------------------------------
# arg parsing
# ---------------------------------------------------------------------------
if [[ $# -ge 1 ]] && [[ "$1" =~ ^[0-9]+$ ]]; then
  RUN_ID="$1"; shift
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)     [[ $# -ge 2 ]] || die "--repo requires a value"; REPO="$2"; shift 2 ;;
    --workflow) [[ $# -ge 2 ]] || die "--workflow requires a value"; WORKFLOW="$2"; shift 2 ;;
    --branch)   [[ $# -ge 2 ]] || die "--branch requires a value"; BRANCH="$2"; shift 2 ;;
    --filter)   [[ $# -ge 2 ]] || die "--filter requires a value"; EXTRA_FILTER="$2"; shift 2 ;;
    --raw)      RAW=true; shift ;;
    --lines)    [[ $# -ge 2 ]] || die "--lines requires a value"; LINES="$2"; shift 2 ;;
    --job)      [[ $# -ge 2 ]] || die "--job requires a value"; JOB_FILTER="$2"; shift 2 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

# Resolve repo
if [[ -z "$REPO" ]]; then
  REPO=$(gh repo view --json nameWithOwner --jq '.nameWithOwner' 2>/dev/null) \
    || die "Could not detect repo — use --repo owner/repo"
fi

REPO_FLAG="--repo $REPO"

# ---------------------------------------------------------------------------
# resolve run ID
# ---------------------------------------------------------------------------
if [[ -z "$RUN_ID" ]]; then
  [[ -n "$WORKFLOW" ]] || die "Provide a RUN-ID or --workflow to auto-detect latest run"

  list_args=($REPO_FLAG "--workflow" "$WORKFLOW" "--limit" "5" "--json" "databaseId,status,conclusion,headBranch,createdAt")
  [[ -n "$BRANCH" ]] && list_args+=("--branch" "$BRANCH")

  RUN_ID=$(gh run list "${list_args[@]}" \
    --jq 'first | .databaseId // empty' 2>/dev/null) || true

  [[ -n "$RUN_ID" ]] || die "No runs found for workflow '${WORKFLOW}'${BRANCH:+ on branch ${BRANCH}}"
  info "Auto-detected run ID: ${RUN_ID}"
fi

# ---------------------------------------------------------------------------
# show run summary
# ---------------------------------------------------------------------------
echo ""
info "Run ${RUN_ID} on ${REPO}"
gh run view "$RUN_ID" $REPO_FLAG --json status,conclusion,displayTitle,createdAt,url \
  --jq '"  status=\(.status) conclusion=\(.conclusion // "n/a") | \(.displayTitle) | \(.url)"' 2>/dev/null || true

echo ""
info "Failed job logs (last ${LINES} lines each):"
echo ""

# ---------------------------------------------------------------------------
# build grep pattern
# ---------------------------------------------------------------------------
BASE_PATTERN='error|Error|ERROR|FAIL|failed|exit code [^0]|CVE-|GHSA-|vulnerability|proto:|unknown field|parse error|BASE and HEAD|token.*invalid|Unauthorized|Forbidden|✗'
FULL_PATTERN="$BASE_PATTERN"
[[ -n "$EXTRA_FILTER" ]] && FULL_PATTERN="${FULL_PATTERN}|${EXTRA_FILTER}"

# ---------------------------------------------------------------------------
# fetch logs
# ---------------------------------------------------------------------------
raw_logs=$(gh run view "$RUN_ID" $REPO_FLAG --log-failed 2>&1) || {
  # Fallback: run may have succeeded, try full log
  info "No failed jobs found — fetching full log instead"
  raw_logs=$(gh run view "$RUN_ID" $REPO_FLAG --log 2>&1) || die "Could not fetch logs for run ${RUN_ID}"
}

if [[ -z "$raw_logs" ]]; then
  info "No log output returned (run may still be in progress)."
  exit 0
fi

# Apply job filter if given
if [[ -n "$JOB_FILTER" ]]; then
  raw_logs=$(echo "$raw_logs" | awk -v pat="$JOB_FILTER" '
    /^\[/ { in_job = ($0 ~ pat) }
    in_job { print }
  ')
fi

# Apply content filter
if $RAW; then
  echo "$raw_logs" | head -$(( LINES * 10 ))
else
  echo "$raw_logs" | grep --color=never -E "$FULL_PATTERN" | head -"$LINES" || {
    info "(grep found no matching lines — showing last ${LINES} lines of raw log)"
    echo "$raw_logs" | tail -"$LINES"
  }
fi

echo ""
exit 0
