#!/usr/bin/env bash
# setup-sops.sh — bootstrap age key + SOPS-encrypted secrets for the security platform
#
# Run once per machine. Secrets are entered interactively and held in /dev/shm
# (RAM-backed tmpfs) during encryption — they never touch disk.
#
# Prereqs: age, sops (brew install age sops), security-data cloned at ../security-data/
#
# Usage: ./scripts/setup-sops.sh

set -euo pipefail

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[setup-sops] $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_DATA_DIR="${SCRIPT_DIR}/../../security-data"
AGE_KEY_FILE="${HOME}/.config/sops/age/keys.txt"
SOPS_CONFIG="${SECURITY_DATA_DIR}/.sops.yaml"
SECRETS_FILE="${SECURITY_DATA_DIR}/secrets.enc.yaml"

[[ -d "${SECURITY_DATA_DIR}" ]] || \
  die "security-data not found at ${SECURITY_DATA_DIR} — clone Scorp10N/security-data as a sibling of devsecops"

# ── 1. Generate age key if absent ────────────────────────────────────────────
if [[ -f "${AGE_KEY_FILE}" ]]; then
  info "Using existing age key at ${AGE_KEY_FILE}"
else
  info "Generating new age key at ${AGE_KEY_FILE} ..."
  mkdir -p "$(dirname "${AGE_KEY_FILE}")"
  age-keygen -o "${AGE_KEY_FILE}"
  chmod 600 "${AGE_KEY_FILE}"
fi

AGE_PUBLIC_KEY=$(grep 'public key:' "${AGE_KEY_FILE}" | awk '{print $NF}')
info "Age public key: ${AGE_PUBLIC_KEY}"

# ── 2. Write .sops.yaml ───────────────────────────────────────────────────────
cat > "${SOPS_CONFIG}" << EOF
creation_rules:
  - path_regex: secrets\.enc\.yaml$
    age: ${AGE_PUBLIC_KEY}
EOF
info "Wrote ${SOPS_CONFIG}"

# ── 3. Prompt for secrets — plaintext lives only in /dev/shm (RAM) ───────────
TEMP_SECRETS=$(mktemp /dev/shm/sops-secrets-XXXXXX.yaml)
trap 'shred -u "${TEMP_SECRETS}" 2>/dev/null || rm -f "${TEMP_SECRETS}"' EXIT

echo ""
echo "Enter secrets (input is hidden). DEFECTDOJO_API_KEY will be populated by bootstrap.sh."
echo ""
read -rs -p "DD_ADMIN_PASS (choose a strong password for DefectDojo admin): " DD_ADMIN_PASS; echo
read -rs -p "GH_PAT (fine-grained PAT, read access on all Scorp10N repos): " GH_PAT; echo
echo ""

cat > "${TEMP_SECRETS}" << YAML
DD_ADMIN_PASS: "${DD_ADMIN_PASS}"
GH_PAT: "${GH_PAT}"
DEFECTDOJO_API_KEY: ""
YAML

# ── 4. Encrypt to secrets.enc.yaml ───────────────────────────────────────────
SOPS_AGE_KEY_FILE="${AGE_KEY_FILE}" \
  sops --config "${SOPS_CONFIG}" \
  --encrypt "${TEMP_SECRETS}" > "${SECRETS_FILE}"

info "Encrypted secrets written to ${SECRETS_FILE}"
info "Next: commit .sops.yaml and secrets.enc.yaml to security-data, then run platform/bootstrap.sh"
