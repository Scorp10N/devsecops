#!/usr/bin/env bash
# retrigger-ci.sh — push an empty commit to trigger a fresh CI run
#
# Use this when upstream changes (e.g. a devsecops workflow or config update)
# need to be picked up by an in-flight PR or a branch that hasn't changed.
#
# Usage:
#   retrigger-ci.sh [options]
#
# Options:
#   --branch <name>     Branch to push to (default: current branch)
#   --repo <path>       Local repo path (default: current working directory)
#   --message <msg>     Commit message (default: "ci: retrigger CI run")
#   --watch             After pushing, call pr-watch.sh on the open PR for this branch
#   --merge             Pass --merge to pr-watch.sh (implies --watch)
#
# Examples:
#   retrigger-ci.sh
#   retrigger-ci.sh --branch fix/my-fix
#   retrigger-ci.sh --repo /home/yarin/Projects/resumeforge --watch
#   retrigger-ci.sh --repo /home/yarin/Projects/resumeforge --merge

set -euo pipefail

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[retrigger-ci] $*"; }

# ---------------------------------------------------------------------------
# defaults
# ---------------------------------------------------------------------------
BRANCH=""
REPO_PATH="."
MESSAGE="ci: retrigger CI run"
DO_WATCH=false
DO_MERGE=false

# ---------------------------------------------------------------------------
# arg parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --branch)   [[ $# -ge 2 ]] || die "--branch requires a value"; BRANCH="$2"; shift 2 ;;
    --repo)     [[ $# -ge 2 ]] || die "--repo requires a value"; REPO_PATH="$2"; shift 2 ;;
    --message)  [[ $# -ge 2 ]] || die "--message requires a value"; MESSAGE="$2"; shift 2 ;;
    --watch)    DO_WATCH=true; shift ;;
    --merge)    DO_MERGE=true; DO_WATCH=true; shift ;;
    *) die "Unknown argument: $1" ;;
  esac
done

# Locate the script dir so we can call pr-watch.sh as a sibling
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# resolve branch
# ---------------------------------------------------------------------------
pushd "$REPO_PATH" > /dev/null

if [[ -z "$BRANCH" ]]; then
  BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null) \
    || die "Could not determine current branch — use --branch"
fi

info "Pushing empty commit to ${BRANCH} in $(pwd) ..."

COAUTHOR="Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
git commit --allow-empty -m "${MESSAGE}

${COAUTHOR}"

git push origin "$BRANCH"
info "Pushed. New SHA: $(git rev-parse --short HEAD)"

# ---------------------------------------------------------------------------
# optional: find the PR and watch it
# ---------------------------------------------------------------------------
if $DO_WATCH; then
  echo ""
  info "Looking for open PR on branch ${BRANCH} ..."
  pr_number=$(gh pr list --head "$BRANCH" --json number --jq '.[0].number' 2>/dev/null || true)

  if [[ -z "$pr_number" || "$pr_number" == "null" ]]; then
    info "No open PR found for branch ${BRANCH} — skipping watch."
  else
    info "Found PR #${pr_number}. Handing off to pr-watch.sh ..."
    echo ""
    watch_args=("$pr_number")
    $DO_MERGE && watch_args+=("--merge")
    exec "$SCRIPT_DIR/pr-watch.sh" "${watch_args[@]}"
  fi
fi

popd > /dev/null
exit 0
