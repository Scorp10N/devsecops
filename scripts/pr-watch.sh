#!/usr/bin/env bash
# pr-watch.sh — poll a PR's required checks until all settle, then optionally merge
#
# Usage:
#   pr-watch.sh <PR-NUMBER> [options]
#
# Arguments:
#   PR-NUMBER        Pull request number (e.g. 34)
#
# Options:
#   --repo <owner/repo>         Repo slug (default: current repo from git remote)
#   --merge                     Auto-merge when all checks pass
#   --merge-method <method>     squash (default) | merge | rebase
#   --squash-title <title>      Commit title for squash merge
#   --squash-body <body>        Commit body for squash merge
#   --timeout <seconds>         Give up after this many seconds (default: 1800)
#   --poll <seconds>            Polling interval (default: 30)
#
# Exit codes:
#   0  All checks passed (and merged if --merge was given)
#   1  One or more checks failed
#   2  Timed out waiting for checks to settle
#
# Examples:
#   pr-watch.sh 34
#   pr-watch.sh 34 --merge
#   pr-watch.sh 34 --merge --squash-title "feat: my feature"
#   pr-watch.sh 34 --repo Scorp10N/resumeforge --merge --timeout 3600

set -euo pipefail

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[pr-watch] $*"; }

# ---------------------------------------------------------------------------
# defaults
# ---------------------------------------------------------------------------
PR_NUMBER=""
REPO=""
DO_MERGE=false
MERGE_METHOD="squash"
SQUASH_TITLE=""
SQUASH_BODY=""
TIMEOUT=1800
POLL=30

# ---------------------------------------------------------------------------
# arg parsing
# ---------------------------------------------------------------------------
[[ $# -ge 1 ]] || die "Usage: pr-watch.sh <PR-NUMBER> [options]"
PR_NUMBER="$1"; shift
[[ "$PR_NUMBER" =~ ^[0-9]+$ ]] || die "PR-NUMBER must be an integer (got: $PR_NUMBER)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)           [[ $# -ge 2 ]] || die "--repo requires a value"; REPO="$2"; shift 2 ;;
    --merge)          DO_MERGE=true; shift ;;
    --merge-method)   [[ $# -ge 2 ]] || die "--merge-method requires a value"; MERGE_METHOD="$2"; shift 2 ;;
    --squash-title)   [[ $# -ge 2 ]] || die "--squash-title requires a value"; SQUASH_TITLE="$2"; shift 2 ;;
    --squash-body)    [[ $# -ge 2 ]] || die "--squash-body requires a value"; SQUASH_BODY="$2"; shift 2 ;;
    --timeout)        [[ $# -ge 2 ]] || die "--timeout requires a value"; TIMEOUT="$2"; shift 2 ;;
    --poll)           [[ $# -ge 2 ]] || die "--poll requires a value"; POLL="$2"; shift 2 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

# Resolve repo from git remote if not given
if [[ -z "$REPO" ]]; then
  REPO=$(gh repo view --json nameWithOwner --jq '.nameWithOwner' 2>/dev/null) \
    || die "Could not detect repo from git remote — use --repo owner/repo"
fi

REPO_FLAG="--repo $REPO"
info "Watching PR #${PR_NUMBER} on ${REPO} (timeout: ${TIMEOUT}s, poll: ${POLL}s)"

# ---------------------------------------------------------------------------
# poll until all checks settle
# ---------------------------------------------------------------------------
start=$(date +%s)

while true; do
  # Get check states: pending / in_progress / queued = not done yet
  checks_json=$(gh pr checks "$PR_NUMBER" $REPO_FLAG --json name,state,conclusion 2>/dev/null) || {
    info "  (gh pr checks returned error — retrying)"
    sleep "$POLL"
    continue
  }

  pending_count=$(echo "$checks_json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(sum(1 for c in data if c['state'] in ('pending','in_progress','queued','waiting')))
" 2>/dev/null || echo "0")

  failed_count=$(echo "$checks_json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(sum(1 for c in data if c.get('conclusion') in ('failure','error','cancelled','timed_out')))
" 2>/dev/null || echo "0")

  passed_count=$(echo "$checks_json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(sum(1 for c in data if c.get('conclusion') in ('success','skipped','neutral')))
" 2>/dev/null || echo "0")

  total=$(echo "$checks_json" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "?")

  now=$(date +%s)
  elapsed=$(( now - start ))

  info "  [${elapsed}s] total=${total}  passed=${passed_count}  pending=${pending_count}  failed=${failed_count}"

  if [[ "$pending_count" -eq 0 ]]; then
    # All checks have concluded
    break
  fi

  if (( elapsed >= TIMEOUT )); then
    echo ""
    echo "TIMEOUT: PR #${PR_NUMBER} checks did not settle within ${TIMEOUT}s." >&2
    exit 2
  fi

  sleep "$POLL"
done

# ---------------------------------------------------------------------------
# print final state
# ---------------------------------------------------------------------------
echo ""
info "All checks settled for PR #${PR_NUMBER}:"
echo ""
gh pr checks "$PR_NUMBER" $REPO_FLAG 2>/dev/null | while IFS=$'\t' read -r name state url; do
  # Map state to icon
  icon="?"
  case "$state" in
    pass|success)                   icon="✓" ;;
    fail|failure|error|cancelled)   icon="✗" ;;
    skipping|skipped|neutral)       icon="⊘" ;;
    pending|in_progress|queued)     icon="…" ;;
  esac
  printf "  %s  %-55s  %s\n" "$icon" "$name" "$state"
done || true

echo ""

# ---------------------------------------------------------------------------
# check outcome
# ---------------------------------------------------------------------------
failed_names=$(gh pr checks "$PR_NUMBER" $REPO_FLAG --json name,conclusion 2>/dev/null \
  | python3 -c "
import sys, json
data = json.load(sys.stdin)
names = [c['name'] for c in data if c.get('conclusion') in ('failure','error','cancelled','timed_out')]
print('\n'.join(names))
" 2>/dev/null || true)

if [[ -n "$failed_names" ]]; then
  info "The following checks FAILED:"
  echo "$failed_names" | while read -r name; do echo "  ✗ $name"; done
  echo ""
  exit 1
fi

info "All required checks passed."

# ---------------------------------------------------------------------------
# auto-merge
# ---------------------------------------------------------------------------
if $DO_MERGE; then
  echo ""
  info "Merging PR #${PR_NUMBER} (method: ${MERGE_METHOD}) ..."

  merge_args=("$PR_NUMBER" $REPO_FLAG "--$MERGE_METHOD")
  [[ -n "$SQUASH_TITLE" ]] && merge_args+=("--subject" "$SQUASH_TITLE")
  [[ -n "$SQUASH_BODY"  ]] && merge_args+=("--body" "$SQUASH_BODY")
  merge_args+=("--delete-branch")

  gh pr merge "${merge_args[@]}"
  info "Merged and branch deleted."
fi

exit 0
