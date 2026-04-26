#!/usr/bin/env bash
# scan-all.sh — on-demand security scan of all repos in repo-map.yml
#
# Must be called via sops exec-env:
#   sops exec-env ../security-data/secrets.enc.yaml './scripts/scan-all.sh'
#
# Requires in env: DEFECTDOJO_API_KEY, GH_PAT
# Prereqs: trufflehog, semgrep, trivy, pip-audit, govulncheck, npm on PATH
#          DefectDojo running at http://localhost:8080
#          security-data cloned at ../security-data/

set -euo pipefail

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[scan-all] $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEVSECOPS_DIR="$(dirname "${SCRIPT_DIR}")"
SECURITY_DATA_DIR="${DEVSECOPS_DIR}/../security-data"
REPO_MAP="${SECURITY_DATA_DIR}/repo-map.yml"
FINDINGS_DIR="${SECURITY_DATA_DIR}/findings"
POSTURE_DIR="${SECURITY_DATA_DIR}/posture"
SCAN_TMP="/tmp/scans-$(date +%s)"
TODAY=$(date +%Y-%m-%d)
ENGAGEMENT="scan-${TODAY}"

[[ -n "${DEFECTDOJO_API_KEY:-}" ]] || die "DEFECTDOJO_API_KEY not set — run via sops exec-env"
[[ -n "${GH_PAT:-}" ]] || die "GH_PAT not set — run via sops exec-env"
[[ -f "${REPO_MAP}" ]] || die "repo-map.yml not found at ${REPO_MAP}"

# Source shared DD helpers
# shellcheck source=scripts/lib/dd-api.sh
source "${SCRIPT_DIR}/lib/dd-api.sh"

# Set GH_PAT for git clone authentication
export GITHUB_TOKEN="${GH_PAT}"

mkdir -p "${SCAN_TMP}"
trap 'info "Cleaning up ${SCAN_TMP}..."; rm -rf "${SCAN_TMP}"' EXIT

# Parse repo-map.yml
REPOS_JSON=$(python3 -c "
import yaml, json, sys
data = yaml.safe_load(open('${REPO_MAP}'))
print(json.dumps(data['repos']))
")

REPO_COUNT=$(echo "${REPOS_JSON}" | jq length)
info "Scanning ${REPO_COUNT} repos from ${REPO_MAP}"

for i in $(seq 0 $(( REPO_COUNT - 1 ))); do
  REPO_ENTRY=$(echo "${REPOS_JSON}" | jq ".[$i]")
  FULL_NAME=$(echo "${REPO_ENTRY}" | jq -r '.name')
  REPO_SLUG="${FULL_NAME#*/}"
  HAS_PYTHON=$(echo "${REPO_ENTRY}" | jq -r '.has_python')
  HAS_GO=$(echo "${REPO_ENTRY}" | jq -r '.has_go')
  HAS_NODE=$(echo "${REPO_ENTRY}" | jq -r '.has_node')
  HAS_CONTAINERS=$(echo "${REPO_ENTRY}" | jq -r '.has_containers')

  info "──────────────────────────────────────────"
  info "Scanning ${FULL_NAME} ..."

  REPO_TMP="${SCAN_TMP}/${REPO_SLUG}"
  CLONE_URL="https://x-access-token:${GH_PAT}@github.com/${FULL_NAME}.git"

  git clone --depth=1 --quiet "${CLONE_URL}" "${REPO_TMP}" || {
    info "WARN: Could not clone ${FULL_NAME} — skipping"
    continue
  }

  FINDINGS_OUT="${SCAN_TMP}/findings-${REPO_SLUG}"
  mkdir -p "${FINDINGS_OUT}"

  # ── TruffleHog (always) ───────────────────────────────────────────────────
  info "  → TruffleHog"
  SCAN_FILE="${FINDINGS_OUT}/trufflehog.json"
  trufflehog git "file://${REPO_TMP}" \
    --only-verified \
    --config "${DEVSECOPS_DIR}/configs/trufflehog.toml" \
    --json 2>/dev/null > "${SCAN_FILE}" || true
  # TruffleHog outputs one JSON object per line — wrap in array for DD import
  python3 -c "
import sys, json
lines = [json.loads(l) for l in open('${SCAN_FILE}') if l.strip()]
json.dump(lines, open('${SCAN_FILE}', 'w'))
" 2>/dev/null || true
  dd_import_scan "${REPO_SLUG}" "Trufflehog Scan" "${SCAN_FILE}" "${ENGAGEMENT}"
  dd_save_and_archive "${SCAN_FILE}" "${FINDINGS_DIR}" "${REPO_SLUG}" "trufflehog"

  # ── Semgrep (always) ─────────────────────────────────────────────────────
  info "  → Semgrep"
  SCAN_FILE="${FINDINGS_OUT}/semgrep.json"
  semgrep scan \
    --config "${DEVSECOPS_DIR}/configs/semgrep.yml" \
    --json \
    --quiet \
    "${REPO_TMP}" > "${SCAN_FILE}" 2>/dev/null || true
  dd_import_scan "${REPO_SLUG}" "Semgrep JSON Report" "${SCAN_FILE}" "${ENGAGEMENT}"
  dd_save_and_archive "${SCAN_FILE}" "${FINDINGS_DIR}" "${REPO_SLUG}" "semgrep"

  # ── pip-audit (has_python) ────────────────────────────────────────────────
  if [[ "${HAS_PYTHON}" == "true" ]]; then
    info "  → pip-audit"
    SCAN_FILE="${FINDINGS_OUT}/pip-audit.json"
    (cd "${REPO_TMP}/engine" && \
      pip-audit --format json --output "${SCAN_FILE}" 2>/dev/null) || true
    dd_import_scan "${REPO_SLUG}" "pip-audit Scan" "${SCAN_FILE}" "${ENGAGEMENT}"
    dd_save_and_archive "${SCAN_FILE}" "${FINDINGS_DIR}" "${REPO_SLUG}" "pip-audit"
  fi

  # ── govulncheck (has_go) ──────────────────────────────────────────────────
  if [[ "${HAS_GO}" == "true" ]]; then
    info "  → govulncheck"
    SCAN_FILE="${FINDINGS_OUT}/govulncheck.json"
    (cd "${REPO_TMP}/cli" && \
      govulncheck -json ./... > "${SCAN_FILE}" 2>/dev/null) || true
    dd_import_scan "${REPO_SLUG}" "govulncheck Scanner" "${SCAN_FILE}" "${ENGAGEMENT}"
    dd_save_and_archive "${SCAN_FILE}" "${FINDINGS_DIR}" "${REPO_SLUG}" "govulncheck"
  fi

  # ── npm audit (has_node) ──────────────────────────────────────────────────
  if [[ "${HAS_NODE}" == "true" ]]; then
    info "  → npm audit"
    SCAN_FILE="${FINDINGS_OUT}/npm-audit.json"
    (cd "${REPO_TMP}/web" && \
      npm audit --json > "${SCAN_FILE}" 2>/dev/null) || true
    dd_import_scan "${REPO_SLUG}" "NPM Audit Scan" "${SCAN_FILE}" "${ENGAGEMENT}"
    dd_save_and_archive "${SCAN_FILE}" "${FINDINGS_DIR}" "${REPO_SLUG}" "npm-audit"
  fi

  # ── Trivy (has_containers) ────────────────────────────────────────────────
  if [[ "${HAS_CONTAINERS}" == "true" ]]; then
    info "  → Trivy"
    SCAN_FILE="${FINDINGS_OUT}/trivy.sarif"
    trivy fs \
      --format sarif \
      --ignorefile "${DEVSECOPS_DIR}/configs/trivy-ignore.txt" \
      --output "${SCAN_FILE}" \
      "${REPO_TMP}" 2>/dev/null || true
    dd_import_scan "${REPO_SLUG}" "Trivy Scan" "${SCAN_FILE}" "${ENGAGEMENT}"
    dd_save_and_archive "${SCAN_FILE}" "${FINDINGS_DIR}" "${REPO_SLUG}" "trivy"
  fi

  info "  ✓ ${FULL_NAME} done"
done

# ── Posture snapshot ──────────────────────────────────────────────────────────
info "Generating posture snapshot ..."
dd_posture_snapshot "${POSTURE_DIR}/snapshot-${TODAY}.json"

# ── Commit findings to security-data ─────────────────────────────────────────
info "Committing findings to security-data ..."
cd "${SECURITY_DATA_DIR}"
git add findings/ posture/
git diff --cached --quiet && info "No new findings to commit" || \
  git commit -m "chore(findings): scan run ${TODAY}" && \
  env -u GITHUB_TOKEN git push origin main

info ""
info "Scan complete. Open http://localhost:8080 to review findings."
