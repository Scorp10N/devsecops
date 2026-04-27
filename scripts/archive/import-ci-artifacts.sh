#!/usr/bin/env bash
# import-ci-artifacts.sh — import latest CI Security workflow artifacts into DefectDojo
#
# Must be called via sops exec-env:
#   sops exec-env ../security-data/secrets.enc.yaml './scripts/import-ci-artifacts.sh'
#
# Requires in env: DEFECTDOJO_API_KEY, GH_PAT
# Prereqs: gh CLI authenticated, DefectDojo running at http://localhost:8080
#          security-data cloned at ../security-data/

set -euo pipefail

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[import-ci] $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEVSECOPS_DIR="$(dirname "${SCRIPT_DIR}")"
SECURITY_DATA_DIR="${DEVSECOPS_DIR}/../security-data"
REPO_MAP="${SECURITY_DATA_DIR}/repo-map.yml"
FINDINGS_DIR="${SECURITY_DATA_DIR}/findings"
POSTURE_DIR="${SECURITY_DATA_DIR}/posture"
ARTIFACTS_TMP="/tmp/ci-artifacts-$(date +%s)"
TODAY=$(date +%Y-%m-%d)

[[ -n "${DEFECTDOJO_API_KEY:-}" ]] || die "DEFECTDOJO_API_KEY not set — run via sops exec-env"
[[ -n "${GH_PAT:-}" ]] || die "GH_PAT not set — run via sops exec-env"
[[ -f "${REPO_MAP}" ]] || die "repo-map.yml not found at ${REPO_MAP}"

# Source shared DD helpers
# shellcheck source=scripts/lib/dd-api.sh
source "${SCRIPT_DIR}/lib/dd-api.sh"

export GH_TOKEN="${GH_PAT}"

mkdir -p "${ARTIFACTS_TMP}"
trap 'info "Cleaning up ${ARTIFACTS_TMP}..."; rm -rf "${ARTIFACTS_TMP}"' EXIT

# DefectDojo scan_type by file extension and name patterns
detect_scan_type() {
  local filename="$1"
  case "${filename}" in
    *trufflehog*)                   echo "Trufflehog Scan" ;;
    *semgrep*)                      echo "Semgrep JSON Report" ;;
    *.sarif)                        echo "SARIF" ;;          # Trivy Scan parser expects JSON; SARIF files use generic SARIF parser
    *trivy*.json)                   echo "Trivy Scan" ;;
    *pip-audit* | *pip_audit*)      echo "pip-audit Scan" ;;
    *govulncheck*)                  echo "Govulncheck Scanner" ;;
    *npm-audit* | *npm_audit*)      echo "ARCHIVE_ONLY" ;;   # DD doesn't support npm audit v2 format (npm 7+)
    *codeql* | *sarif*)             echo "SARIF" ;;
    *)                              echo "" ;;
  esac
}

REPOS_JSON=$(python3 -c "
import yaml, json
data = yaml.safe_load(open('${REPO_MAP}'))
print(json.dumps(data['repos']))
")

REPO_COUNT=$(echo "${REPOS_JSON}" | jq length)
info "Importing CI artifacts for ${REPO_COUNT} repos"

for i in $(seq 0 $(( REPO_COUNT - 1 ))); do
  REPO_ENTRY=$(echo "${REPOS_JSON}" | jq ".[$i]")
  FULL_NAME=$(echo "${REPO_ENTRY}" | jq -r '.name')
  REPO_SLUG="${FULL_NAME#*/}"

  info "──────────────────────────────────────────"
  info "Processing ${FULL_NAME} ..."

  # Find latest successful Security workflow run
  RUN_ID=$(gh run list \
    --repo "${FULL_NAME}" \
    --workflow "Security" \
    --status success \
    --limit 1 \
    --json databaseId \
    --jq '.[0].databaseId // empty' 2>/dev/null || true)

  if [[ -z "${RUN_ID}" ]]; then
    info "  WARN: No successful Security workflow run found for ${FULL_NAME} — skipping"
    continue
  fi

  info "  Latest successful Security run: ${RUN_ID}"
  REPO_ARTIFACTS="${ARTIFACTS_TMP}/${REPO_SLUG}"
  mkdir -p "${REPO_ARTIFACTS}"

  gh run download "${RUN_ID}" \
    --repo "${FULL_NAME}" \
    --dir "${REPO_ARTIFACTS}" 2>/dev/null || {
    info "  WARN: Could not download artifacts for run ${RUN_ID} — skipping"
    continue
  }

  ENGAGEMENT="ci-import-${TODAY}"
  FOUND_FILES=0

  # Walk all downloaded files and import each one
  while IFS= read -r -d '' artifact_file; do
    filename=$(basename "${artifact_file}")
    scan_type=$(detect_scan_type "${filename}")

    if [[ -z "${scan_type}" ]]; then
      info "  SKIP: Unknown scan type for ${filename}"
      continue
    fi

    if [[ "${scan_type}" == "ARCHIVE_ONLY" ]]; then
      info "  → Archiving ${filename} (DD import not supported for this format)"
      dd_save_and_archive "${artifact_file}" "${FINDINGS_DIR}" "${REPO_SLUG}" "${filename%.*}"
      continue
    fi

    info "  → Importing ${filename} as '${scan_type}'"
    dd_import_scan "${REPO_SLUG}" "${scan_type}" "${artifact_file}" "${ENGAGEMENT}"
    dd_save_and_archive "${artifact_file}" "${FINDINGS_DIR}" "${REPO_SLUG}" "${filename%.*}"
    FOUND_FILES=$(( FOUND_FILES + 1 ))
  done < <(find "${REPO_ARTIFACTS}" -type f \( -name "*.json" -o -name "*.sarif" \) -print0)

  info "  ✓ ${FULL_NAME}: imported ${FOUND_FILES} artifact(s)"
done

# ── Posture snapshot ──────────────────────────────────────────────────────────
info "Generating posture snapshot ..."
dd_posture_snapshot "${POSTURE_DIR}/snapshot-${TODAY}.json"

# ── Commit findings to security-data ─────────────────────────────────────────
info "Committing findings to security-data ..."
cd "${SECURITY_DATA_DIR}"
git add findings/ posture/
git diff --cached --quiet && info "No new findings to commit" || \
  git commit -m "chore(findings): ci artifact import ${TODAY}" && \
  env -u GH_TOKEN git push origin main

info ""
info "Import complete. Open http://localhost:8080 to review findings."
