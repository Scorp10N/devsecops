#!/usr/bin/env bash
# trivy-ignore-add.sh — append a CVE entry to trivy-ignore.txt in canonical format
#
# Enforces the format required by Trivy's --ignorefile:
#   CVE-YYYY-NNNNN  # <comment>
#
# Also checks that the CVE is not already present before adding.
# Optionally records a SECURITY.md tracking reference.
#
# Usage:
#   trivy-ignore-add.sh <CVE-ID> <comment> [options]
#
# Arguments:
#   CVE-ID       CVE identifier (e.g. CVE-2024-21538)
#   comment      Human-readable note: package, version, fix version, and impact
#                (e.g. "cross-spawn 7.0.3 → fixed in 7.0.5 (ReDoS)")
#
# Options:
#   --file <path>      Path to trivy-ignore.txt (default: configs/trivy-ignore.txt
#                      relative to the script's repo root, or current dir)
#   --dry-run          Print what would be appended without writing
#   --force            Add even if the CVE is already present (adds duplicate)
#
# Exit codes:
#   0   Entry added (or already present with no --force)
#   1   Validation error
#
# Examples:
#   trivy-ignore-add.sh CVE-2024-21538 "cross-spawn 7.0.3 → fixed in 7.0.5"
#   trivy-ignore-add.sh CVE-2026-31802 "tar 6.2.1 → fixed in 7.5.11 (hardlink path traversal)" \
#     --file /home/yarin/Projects/devsecops/configs/trivy-ignore.txt
#   trivy-ignore-add.sh CVE-2025-99999 "libfoo 1.0 — no fix yet" --dry-run

set -euo pipefail

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[trivy-ignore-add] $*"; }

# ---------------------------------------------------------------------------
# defaults
# ---------------------------------------------------------------------------
CVE_ID=""
COMMENT=""
TARGET_FILE=""
DRY_RUN=false
FORCE=false

# ---------------------------------------------------------------------------
# arg parsing
# ---------------------------------------------------------------------------
[[ $# -ge 2 ]] || die "Usage: trivy-ignore-add.sh <CVE-ID> <comment> [options]"
CVE_ID="$1"; shift
COMMENT="$1"; shift

while [[ $# -gt 0 ]]; do
  case "$1" in
    --file)     [[ $# -ge 2 ]] || die "--file requires a value"; TARGET_FILE="$2"; shift 2 ;;
    --dry-run)  DRY_RUN=true; shift ;;
    --force)    FORCE=true; shift ;;
    *) die "Unknown argument: $1" ;;
  esac
done

# ---------------------------------------------------------------------------
# validate CVE ID format
# ---------------------------------------------------------------------------
[[ "$CVE_ID" =~ ^CVE-[0-9]{4}-[0-9]+$ ]] \
  || die "CVE-ID must match CVE-YYYY-NNNNN (got: ${CVE_ID})"

[[ -n "$COMMENT" ]] || die "Comment must not be empty"

# ---------------------------------------------------------------------------
# resolve target file
# ---------------------------------------------------------------------------
if [[ -z "$TARGET_FILE" ]]; then
  # Try relative to script's repo root
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(dirname "$SCRIPT_DIR")"
  CANDIDATE="${REPO_ROOT}/configs/trivy-ignore.txt"
  if [[ -f "$CANDIDATE" ]]; then
    TARGET_FILE="$CANDIDATE"
  elif [[ -f "configs/trivy-ignore.txt" ]]; then
    TARGET_FILE="configs/trivy-ignore.txt"
  elif [[ -f ".trivyignore" ]]; then
    TARGET_FILE=".trivyignore"
  else
    die "Could not find trivy-ignore.txt — use --file to specify the path"
  fi
fi

[[ -f "$TARGET_FILE" ]] || die "File not found: ${TARGET_FILE}"

# ---------------------------------------------------------------------------
# check for duplicates
# ---------------------------------------------------------------------------
if grep -q "^${CVE_ID}\b" "$TARGET_FILE" 2>/dev/null; then
  if $FORCE; then
    info "WARNING: ${CVE_ID} already present in ${TARGET_FILE} (adding anyway due to --force)"
  else
    info "${CVE_ID} is already present in ${TARGET_FILE} — nothing to do."
    grep "^${CVE_ID}" "$TARGET_FILE"
    exit 0
  fi
fi

# ---------------------------------------------------------------------------
# compose the entry line
# ---------------------------------------------------------------------------
ENTRY="${CVE_ID}  # ${COMMENT}"

# ---------------------------------------------------------------------------
# dry run
# ---------------------------------------------------------------------------
if $DRY_RUN; then
  info "DRY RUN — would append to ${TARGET_FILE}:"
  echo "  ${ENTRY}"
  exit 0
fi

# ---------------------------------------------------------------------------
# append
# ---------------------------------------------------------------------------
# Ensure the file ends with a newline before appending
[[ -s "$TARGET_FILE" ]] && tail -c1 "$TARGET_FILE" | grep -q $'\n' || echo "" >> "$TARGET_FILE"

echo "${ENTRY}" >> "$TARGET_FILE"
info "Added to ${TARGET_FILE}:"
echo "  ${ENTRY}"
