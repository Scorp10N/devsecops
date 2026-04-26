#!/usr/bin/env bash
# bootstrap.sh — one-time DefectDojo setup: products, OWASP regulations, API key
#
# Must be called via sops exec-env to receive DD_ADMIN_PASS in environment:
#   sops exec-env ../security-data/secrets.enc.yaml './platform/bootstrap.sh'
#
# Prereqs: DefectDojo must be running (docker compose up -d)
#          security-data cloned at ../security-data/

set -euo pipefail

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[bootstrap] $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_DATA_DIR="${SCRIPT_DIR}/../../security-data"
REPO_MAP="${SECURITY_DATA_DIR}/repo-map.yml"
AGE_KEY_FILE="${HOME}/.config/sops/age/keys.txt"
SOPS_CONFIG="${SECURITY_DATA_DIR}/.sops.yaml"
SECRETS_FILE="${SECURITY_DATA_DIR}/secrets.enc.yaml"
DD_URL="http://localhost:8080"

[[ -n "${DD_ADMIN_PASS:-}" ]] || die "DD_ADMIN_PASS not set — run via: sops exec-env ../security-data/secrets.enc.yaml './platform/bootstrap.sh'"
[[ -f "${REPO_MAP}" ]] || die "repo-map.yml not found at ${REPO_MAP}"

# ── 1. Wait for DefectDojo to be healthy ─────────────────────────────────────
info "Waiting for DefectDojo at ${DD_URL} ..."
for i in $(seq 1 40); do
  HTTP_CODE=$(curl -s --connect-timeout 2 -o /dev/null -w "%{http_code}" "${DD_URL}/api/v2/" 2>/dev/null || echo "000")
  if [[ "${HTTP_CODE}" != "000" ]]; then
    info "DefectDojo is up (HTTP ${HTTP_CODE})."
    break
  fi
  [[ $i -eq 40 ]] && die "DefectDojo did not respond after 200s. Is the stack running?"
  echo -n "."
  sleep 5
done
echo ""

# ── 2. Fetch admin API token (stays in memory only) ──────────────────────────
info "Fetching admin API token ..."
TOKEN=$(curl -sf -X POST "${DD_URL}/api/v2/api-key-auth/" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"admin\", \"password\": \"${DD_ADMIN_PASS}\"}" \
  | jq -r '.token') || die "Failed to authenticate with DefectDojo admin credentials"
[[ -n "${TOKEN}" ]] || die "Got empty token — check DD_ADMIN_PASS"
info "Token obtained."

# ── Helper: DD API call ───────────────────────────────────────────────────────
dd_api() {
  local method="$1" path="$2"
  shift 2
  curl -sf -X "${method}" "${DD_URL}/api/v2/${path}/" \
    -H "Authorization: Token ${TOKEN}" \
    -H "Content-Type: application/json" \
    "$@"
}

# ── 3. Ensure product type exists ────────────────────────────────────────────
info "Ensuring product type 'GitHub Repo' exists ..."
PROD_TYPE_ID=$(dd_api GET "product_types" | jq -r '.results[] | select(.name=="GitHub Repo") | .id')
if [[ -z "${PROD_TYPE_ID}" ]]; then
  PROD_TYPE_ID=$(dd_api POST "product_types" \
    -d '{"name":"GitHub Repo","critical_product":false,"key_product":false}' \
    | jq -r '.id')
  info "Created product type 'GitHub Repo' (id=${PROD_TYPE_ID})"
else
  info "Product type 'GitHub Repo' already exists (id=${PROD_TYPE_ID})"
fi

# ── 4. Discover OWASP regulation IDs ─────────────────────────────────────────
info "Looking up OWASP regulation IDs ..."
REGULATIONS_JSON=$(dd_api GET "regulations" | jq '.results')
ASVS_ID=$(echo "${REGULATIONS_JSON}" | jq -r '[.[] | select(.name | test("ASVS"; "i"))] | first | .id // empty')
TOP10_ID=$(echo "${REGULATIONS_JSON}" | jq -r '[.[] | select(.name | test("Top 10"; "i"))] | first | .id // empty')

[[ -n "${ASVS_ID}"  ]] || { info "WARN: OWASP ASVS regulation not found — will skip linking. Check /api/v2/regulations/ manually."; }
[[ -n "${TOP10_ID}" ]] || { info "WARN: OWASP Top 10 regulation not found — will skip linking."; }

REGULATION_IDS=()
[[ -n "${ASVS_ID}"  ]] && REGULATION_IDS+=("${ASVS_ID}")
[[ -n "${TOP10_ID}" ]] && REGULATION_IDS+=("${TOP10_ID}")

REGULATIONS_PAYLOAD=$(printf '%s\n' "${REGULATION_IDS[@]:-}" | jq -Rn '[inputs | tonumber]')
info "Regulations to link: ${REGULATION_IDS[*]:-none found}"

# ── 5. Create a DD product for each repo in repo-map.yml ─────────────────────
REPO_NAMES=$(python3 -c "
import yaml
repos = yaml.safe_load(open('${REPO_MAP}'))['repos']
for r in repos:
    print(r['name'])
")

while IFS= read -r full_name; do
  repo_short="${full_name#*/}"   # strip "Scorp10N/" prefix → "resumeforge"

  EXISTING_ID=$(dd_api GET "products" | \
    jq -r --arg n "${repo_short}" '.results[] | select(.name==$n) | .id')

  if [[ -n "${EXISTING_ID}" ]]; then
    info "Product '${repo_short}' already exists (id=${EXISTING_ID}) — skipping create"
    PRODUCT_ID="${EXISTING_ID}"
  else
    PRODUCT_ID=$(dd_api POST "products" \
      -d "{\"name\":\"${repo_short}\",\"description\":\"${full_name}\",\"prod_type\":${PROD_TYPE_ID}}" \
      | jq -r '.id')
    info "Created product '${repo_short}' (id=${PRODUCT_ID})"
  fi

  # Link OWASP regulations
  if [[ ${#REGULATION_IDS[@]} -gt 0 ]]; then
    dd_api PATCH "products/${PRODUCT_ID}" \
      -d "{\"regulations\": ${REGULATIONS_PAYLOAD}}" > /dev/null
    info "  Linked regulations [${REGULATION_IDS[*]}] to '${repo_short}'"
  fi
done <<< "${REPO_NAMES}"

# ── 6. Persist API token to secrets.enc.yaml (via /dev/shm — no disk write) ──
info "Updating DEFECTDOJO_API_KEY in secrets.enc.yaml ..."
TEMP_SECRETS=$(mktemp /dev/shm/sops-update-XXXXXX.yaml)
trap 'shred -u "${TEMP_SECRETS}" 2>/dev/null || rm -f "${TEMP_SECRETS}"' EXIT

SOPS_AGE_KEY_FILE="${AGE_KEY_FILE}" \
  sops --config "${SOPS_CONFIG}" --decrypt "${SECRETS_FILE}" > "${TEMP_SECRETS}"

python3 - "${TEMP_SECRETS}" "${TOKEN}" << 'PY'
import sys, yaml
path, token = sys.argv[1], sys.argv[2]
with open(path) as f:
    data = yaml.safe_load(f)
data['DEFECTDOJO_API_KEY'] = token
with open(path, 'w') as f:
    yaml.dump(data, f, default_flow_style=False)
PY

SOPS_AGE_KEY_FILE="${AGE_KEY_FILE}" \
  sops --config "${SOPS_CONFIG}" --encrypt "${TEMP_SECRETS}" > "${SECRETS_FILE}"

info "DEFECTDOJO_API_KEY updated in ${SECRETS_FILE}"

# ── 7. Commit secrets and sops config to security-data ───────────────────────
cd "${SECURITY_DATA_DIR}"
git add .sops.yaml secrets.enc.yaml
git commit -m "chore: bootstrap SOPS secrets and DefectDojo API key" || info "Nothing new to commit"
git push origin main
info ""
info "Bootstrap complete. Dashboard: ${DD_URL}"
info "Login: admin / (your DD_ADMIN_PASS)"
