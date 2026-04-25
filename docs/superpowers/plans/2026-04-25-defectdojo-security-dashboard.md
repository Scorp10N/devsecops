# DefectDojo Security Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add DefectDojo as a local security dashboard to `Scorp10N/devsecops`, with a private `Scorp10N/security-data` GitOps state store, SOPS+age JIT secrets, on-demand scanning, and CI artifact import — all mapped to OWASP ASVS Level 1 + OWASP Top 10.

**Architecture:** Two repos with clean separation. `devsecops` (public) holds all tooling, scripts, and the DefectDojo Docker Compose stack. `security-data` (private) holds the encrypted secrets file, `repo-map.yml`, findings artifacts, and posture snapshots. Scripts in `devsecops` reference `../security-data/` as a sibling directory. All secret access goes through `sops exec-env ../security-data/secrets.enc.yaml '<cmd>'` — decrypted values are injected into subprocess env only and never touch disk.

**Tech Stack:** DefectDojo (Django + PostgreSQL + Celery + Redis + nginx via Docker Compose), SOPS + age (already installed at `/home/linuxbrew/.linuxbrew/bin/`), `gh` CLI, `curl`, `jq`, `python3`, bash.

---

## File Map

**New files in `devsecops/` (public):**

| File | Responsibility |
|---|---|
| `platform/docker-compose.yml` | DefectDojo 6-service stack; reads `DD_ADMIN_PASS` from env |
| `platform/.env.example` | Shape-only template showing required env var names |
| `platform/bootstrap.sh` | One-time setup: fetch API token, create DD products, link OWASP regulations, update `secrets.enc.yaml` |
| `scripts/setup-sops.sh` | Generate age key, write `.sops.yaml`, interactively seed `secrets.enc.yaml` in RAM |
| `scripts/lib/dd-api.sh` | Shared helpers: `dd_import_scan`, `dd_get_product_id`, `dd_posture_snapshot` |
| `scripts/scan-all.sh` | Path A: clone all repos → run tools → import to DD → commit findings |
| `scripts/import-ci-artifacts.sh` | Path B: `gh run download` → import to DD → commit findings |

**New files in `security-data/` (private, new repo):**

| File | Responsibility |
|---|---|
| `.sops.yaml` | SOPS encryption config (written by `setup-sops.sh`) |
| `secrets.enc.yaml` | SOPS-encrypted: `DD_ADMIN_PASS`, `GH_PAT`, `DEFECTDOJO_API_KEY` |
| `repo-map.yml` | Repo list + per-repo scan profiles |
| `findings/<repo>/latest/<tool>.{sarif,json}` | Latest scan output per tool per repo |
| `findings/<repo>/history/YYYY-MM-DD/<tool>.*` | Timestamped archive |
| `posture/snapshot-YYYY-MM-DD.json` | DD API summary committed after each scan |

---

## Task 1: Create `security-data` private repo

**Files:**
- Create: `/home/yarin/Projects/security-data/` (local clone of new private GitHub repo)
- Create: `/home/yarin/Projects/security-data/repo-map.yml`
- Create: `/home/yarin/Projects/security-data/.gitignore`

- [ ] **Step 1: Create the private repo on GitHub**

```bash
gh repo create Scorp10N/security-data \
  --private \
  --description "GitOps state store: encrypted secrets, scan findings, posture snapshots"
```

Expected: `✓ Created repository Scorp10N/security-data on GitHub`

- [ ] **Step 2: Clone it locally**

```bash
git clone https://github.com/Scorp10N/security-data.git /home/yarin/Projects/security-data
```

Expected: `Cloning into '/home/yarin/Projects/security-data'...` (empty repo warning is fine)

- [ ] **Step 3: Create initial directory structure**

```bash
mkdir -p /home/yarin/Projects/security-data/findings
mkdir -p /home/yarin/Projects/security-data/posture
```

- [ ] **Step 4: Write `repo-map.yml`**

Write to `/home/yarin/Projects/security-data/repo-map.yml`:
```yaml
repos:
  - name: Scorp10N/resumeforge
    has_python: true
    has_go: true
    has_node: true
    has_containers: true
  - name: Scorp10N/resumeforge-cloud
    has_python: true
    has_go: false
    has_node: false
    has_containers: false
  - name: Scorp10N/devsecops
    has_python: false
    has_go: false
    has_node: false
    has_containers: false
```

- [ ] **Step 5: Write `.gitignore`**

Write to `/home/yarin/Projects/security-data/.gitignore`:
```
# Never commit plaintext secrets — only secrets.enc.yaml is safe to commit
*.env
.env.*
secrets.yaml
secrets.yml
# Temp scan dirs (cleaned up by scripts, but just in case)
/tmp/
```

- [ ] **Step 6: Add `.gitkeep` files so empty dirs are tracked**

```bash
touch /home/yarin/Projects/security-data/findings/.gitkeep
touch /home/yarin/Projects/security-data/posture/.gitkeep
```

- [ ] **Step 7: Commit and push**

```bash
cd /home/yarin/Projects/security-data
git add repo-map.yml .gitignore findings/.gitkeep posture/.gitkeep
git commit -m "chore: initialize security-data state store"
git push -u origin main
```

Expected: `Branch 'main' set up to track remote branch 'main' from 'origin'.`

---

## Task 2: Write `scripts/setup-sops.sh`

**Files:**
- Create: `/home/yarin/Projects/devsecops/scripts/setup-sops.sh`

This script generates the age key (if absent), writes `.sops.yaml` to `security-data`, then prompts interactively for secrets. All plaintext lives only in `/dev/shm` (RAM-backed tmpfs on Linux — never written to disk). The resulting `secrets.enc.yaml` is committed to `security-data`.

- [ ] **Step 1: Write the script**

Write to `/home/yarin/Projects/devsecops/scripts/setup-sops.sh`:
```bash
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
```

- [ ] **Step 2: Make executable**

```bash
chmod +x /home/yarin/Projects/devsecops/scripts/setup-sops.sh
```

- [ ] **Step 3: Syntax check**

```bash
bash -n /home/yarin/Projects/devsecops/scripts/setup-sops.sh && echo "SYNTAX OK"
```

Expected: `SYNTAX OK`

---

## Task 3: Write `platform/docker-compose.yml` and `.env.example`

**Files:**
- Create: `/home/yarin/Projects/devsecops/platform/docker-compose.yml`
- Create: `/home/yarin/Projects/devsecops/platform/.env.example`

DefectDojo reads `DD_ADMIN_PASS` from the shell environment. Start the stack with:
`sops exec-env ../security-data/secrets.enc.yaml 'docker compose -f platform/docker-compose.yml up -d'`

- [ ] **Step 1: Create the platform directory**

```bash
mkdir -p /home/yarin/Projects/devsecops/platform
```

- [ ] **Step 2: Write `docker-compose.yml`**

Write to `/home/yarin/Projects/devsecops/platform/docker-compose.yml`:
```yaml
# DefectDojo local security dashboard
# Start: sops exec-env ../security-data/secrets.enc.yaml 'docker compose -f platform/docker-compose.yml up -d'
# Stop:  docker compose -f platform/docker-compose.yml down
# Logs:  docker compose -f platform/docker-compose.yml logs -f uwsgi

services:
  nginx:
    image: defectdojo/defectdojo-nginx:latest
    depends_on:
      uwsgi:
        condition: service_healthy
    ports:
      - "8080:8080"
    environment:
      NGINX_METRICS_ENABLED: "false"

  uwsgi:
    image: defectdojo/defectdojo-django:latest
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_started
    environment:
      DD_DEBUG: "False"
      DD_ALLOWED_HOSTS: "localhost,127.0.0.1"
      DD_SECRET_KEY: "local-dev-only-change-for-vps"
      DD_DATABASE_URL: "postgresql://defectdojo:defectdojo@postgres:5432/defectdojo"
      DD_CELERY_BROKER_URL: "redis://redis:6379/0"
      DD_ADMIN_USER: "admin"
      DD_ADMIN_PASSWORD: "${DD_ADMIN_PASS}"
      DD_ADMIN_MAIL: "scorpyarin@gmail.com"
      DD_ADMIN_FIRST_NAME: "Yarin"
      DD_ADMIN_LAST_NAME: "Scorp10N"
      DD_INITIALIZE: "true"
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:8000/api/v2/ -o /dev/null || exit 1"]
      interval: 15s
      timeout: 5s
      retries: 10
      start_period: 60s

  celerybeat:
    image: defectdojo/defectdojo-django:latest
    entrypoint: ["/entrypoint-celery-beat.sh"]
    depends_on:
      - postgres
      - redis
    environment:
      DD_DATABASE_URL: "postgresql://defectdojo:defectdojo@postgres:5432/defectdojo"
      DD_CELERY_BROKER_URL: "redis://redis:6379/0"
      DD_SECRET_KEY: "local-dev-only-change-for-vps"

  celeryworker:
    image: defectdojo/defectdojo-django:latest
    entrypoint: ["/entrypoint-celery-worker.sh"]
    depends_on:
      - postgres
      - redis
    environment:
      DD_DATABASE_URL: "postgresql://defectdojo:defectdojo@postgres:5432/defectdojo"
      DD_CELERY_BROKER_URL: "redis://redis:6379/0"
      DD_SECRET_KEY: "local-dev-only-change-for-vps"

  redis:
    image: redis:7-alpine

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: defectdojo
      POSTGRES_USER: defectdojo
      POSTGRES_PASSWORD: defectdojo
    volumes:
      - dd-postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U defectdojo"]
      interval: 5s
      timeout: 3s
      retries: 10

volumes:
  dd-postgres-data:
```

- [ ] **Step 3: Write `.env.example`**

Write to `/home/yarin/Projects/devsecops/platform/.env.example`:
```bash
# Shape-only template — actual values live in security-data/secrets.enc.yaml (SOPS-encrypted)
# Never populate this file with real values. Use setup-sops.sh instead.
DD_ADMIN_PASS=
GH_PAT=
DEFECTDOJO_API_KEY=
```

- [ ] **Step 4: Validate YAML syntax**

```bash
python3 -c "import yaml; yaml.safe_load(open('/home/yarin/Projects/devsecops/platform/docker-compose.yml'))" && echo "YAML OK"
```

Expected: `YAML OK`

- [ ] **Step 5: Commit**

```bash
cd /home/yarin/Projects/devsecops
git add platform/docker-compose.yml platform/.env.example
git commit -m "feat(platform): add DefectDojo docker-compose stack"
```

---

## Task 4: Write `platform/bootstrap.sh`

**Files:**
- Create: `/home/yarin/Projects/devsecops/platform/bootstrap.sh`

Run as: `sops exec-env ../security-data/secrets.enc.yaml './platform/bootstrap.sh'`

This script:
1. Waits for DefectDojo to be healthy
2. Fetches the admin API token (JIT, in memory only)
3. Creates a Product in DD for each repo in `repo-map.yml`
4. Discovers OWASP ASVS and OWASP Top 10 regulation IDs and links them to each product
5. Updates `DEFECTDOJO_API_KEY` in `secrets.enc.yaml` via a RAM-only decrypt/re-encrypt cycle
6. Commits `.sops.yaml` + `secrets.enc.yaml` to `security-data`

- [ ] **Step 1: Write `bootstrap.sh`**

Write to `/home/yarin/Projects/devsecops/platform/bootstrap.sh`:
```bash
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
  if curl -sf "${DD_URL}/api/v2/" -o /dev/null 2>&1; then
    info "DefectDojo is up."
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
```

- [ ] **Step 2: Make executable**

```bash
chmod +x /home/yarin/Projects/devsecops/platform/bootstrap.sh
```

- [ ] **Step 3: Syntax check**

```bash
bash -n /home/yarin/Projects/devsecops/platform/bootstrap.sh && echo "SYNTAX OK"
```

Expected: `SYNTAX OK`

- [ ] **Step 4: Commit**

```bash
cd /home/yarin/Projects/devsecops
git add platform/bootstrap.sh
git commit -m "feat(platform): add DefectDojo bootstrap script (products + OWASP regulations)"
```

---

## Task 5: Write `scripts/lib/dd-api.sh`

**Files:**
- Create: `/home/yarin/Projects/devsecops/scripts/lib/dd-api.sh`

Shared functions sourced by both `scan-all.sh` and `import-ci-artifacts.sh`. Requires `DEFECTDOJO_API_KEY` in env (provided by `sops exec-env`).

- [ ] **Step 1: Create the lib directory and write `dd-api.sh`**

```bash
mkdir -p /home/yarin/Projects/devsecops/scripts/lib
```

Write to `/home/yarin/Projects/devsecops/scripts/lib/dd-api.sh`:
```bash
#!/usr/bin/env bash
# dd-api.sh — shared DefectDojo API helpers
# Source this file; do not execute directly.
# Requires: DEFECTDOJO_API_KEY in environment, jq, curl

DD_URL="${DD_URL:-http://localhost:8080}"

# dd_import_scan <product_name> <scan_type> <file_path> <engagement_name>
# POSTs a findings file to DefectDojo /api/v2/import-scan/
# Returns the HTTP response body (JSON).
dd_import_scan() {
  local product_name="$1"
  local scan_type="$2"
  local file_path="$3"
  local engagement_name="$4"

  [[ -f "${file_path}" ]] || { echo "[dd-api] SKIP: file not found: ${file_path}" >&2; return 0; }

  local response
  response=$(curl -sf -X POST \
    "${DD_URL}/api/v2/import-scan/" \
    -H "Authorization: Token ${DEFECTDOJO_API_KEY}" \
    -F "scan_type=${scan_type}" \
    -F "file=@${file_path}" \
    -F "product_name=${product_name}" \
    -F "engagement_name=${engagement_name}" \
    -F "auto_create_context=true" \
    -F "close_old_findings=true" \
    -F "push_to_jira=false") || {
      echo "[dd-api] ERROR: import-scan failed for ${product_name} / ${scan_type}" >&2
      return 1
    }

  local count
  count=$(echo "${response}" | jq -r '.test // "?" | tostring')
  echo "[dd-api] Imported ${scan_type} for ${product_name} (test_id=${count})"
}

# dd_get_product_id <product_name>
# Returns the numeric DD product ID for the given product name, or empty string.
dd_get_product_id() {
  local product_name="$1"
  curl -sf "${DD_URL}/api/v2/products/?name=${product_name}" \
    -H "Authorization: Token ${DEFECTDOJO_API_KEY}" \
    | jq -r '.results[0].id // empty'
}

# dd_posture_snapshot <output_file>
# Exports a summary of all active findings to <output_file> as JSON.
dd_posture_snapshot() {
  local output_file="$1"
  local tmp_dir
  tmp_dir=$(dirname "${output_file}")
  mkdir -p "${tmp_dir}"

  curl -sf "${DD_URL}/api/v2/findings/?active=true&limit=1000" \
    -H "Authorization: Token ${DEFECTDOJO_API_KEY}" \
    | jq '{
        generated_at: now | todate,
        total_active: (.count),
        by_severity: (
          .results
          | group_by(.severity)
          | map({(.[0].severity): length})
          | add // {}
        ),
        by_product: (
          .results
          | group_by(.test_object.engagement.product.name // "unknown")
          | map({(.[0].test_object.engagement.product.name // "unknown"): length})
          | add // {}
        ),
        critical_findings: [
          .results[]
          | select(.severity == "Critical")
          | {title: .title, product: .test_object.engagement.product.name, cve: .cve}
        ]
      }' > "${output_file}"

  echo "[dd-api] Posture snapshot written to ${output_file}"
}

# dd_save_and_archive <src_file> <findings_base_dir> <repo_slug> <tool_name>
# Copies src_file to findings/<repo_slug>/latest/<tool_name>.<ext>
# and archives to findings/<repo_slug>/history/YYYY-MM-DD/<tool_name>.<ext>
dd_save_and_archive() {
  local src_file="$1"
  local findings_base="$2"
  local repo_slug="$3"
  local tool_name="$4"
  local ext="${src_file##*.}"
  local today
  today=$(date +%Y-%m-%d)

  local latest_dir="${findings_base}/${repo_slug}/latest"
  local history_dir="${findings_base}/${repo_slug}/history/${today}"
  mkdir -p "${latest_dir}" "${history_dir}"

  cp "${src_file}" "${latest_dir}/${tool_name}.${ext}"
  cp "${src_file}" "${history_dir}/${tool_name}.${ext}"
  echo "[dd-api] Saved ${tool_name}.${ext} for ${repo_slug}"
}
```

- [ ] **Step 2: Syntax check**

```bash
bash -n /home/yarin/Projects/devsecops/scripts/lib/dd-api.sh && echo "SYNTAX OK"
```

Expected: `SYNTAX OK`

- [ ] **Step 3: Commit**

```bash
cd /home/yarin/Projects/devsecops
git add scripts/lib/dd-api.sh
git commit -m "feat(scripts): add shared DefectDojo API helper library"
```

---

## Task 6: Write `scripts/scan-all.sh` (Path A)

**Files:**
- Create: `/home/yarin/Projects/devsecops/scripts/scan-all.sh`

Run as: `sops exec-env ../security-data/secrets.enc.yaml './scripts/scan-all.sh'`

Requires `DEFECTDOJO_API_KEY` and `GH_PAT` in env. Clones each repo listed in `repo-map.yml`, runs applicable tools, imports to DD, saves findings, and commits a posture snapshot.

- [ ] **Step 1: Write `scan-all.sh`**

Write to `/home/yarin/Projects/devsecops/scripts/scan-all.sh`:
```bash
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
  git commit -m "chore(findings): scan run ${TODAY}" && git push origin main

info ""
info "Scan complete. Open http://localhost:8080 to review findings."
```

- [ ] **Step 2: Make executable and syntax check**

```bash
chmod +x /home/yarin/Projects/devsecops/scripts/scan-all.sh
bash -n /home/yarin/Projects/devsecops/scripts/scan-all.sh && echo "SYNTAX OK"
```

Expected: `SYNTAX OK`

- [ ] **Step 3: Commit**

```bash
cd /home/yarin/Projects/devsecops
git add scripts/scan-all.sh
git commit -m "feat(scripts): add on-demand scan-all script (Path A)"
```

---

## Task 7: Write `scripts/import-ci-artifacts.sh` (Path B)

**Files:**
- Create: `/home/yarin/Projects/devsecops/scripts/import-ci-artifacts.sh`

Run as: `sops exec-env ../security-data/secrets.enc.yaml './scripts/import-ci-artifacts.sh'`

Downloads the latest successful Security workflow run artifacts from GitHub Actions for each repo in `repo-map.yml` and imports them into DefectDojo.

- [ ] **Step 1: Write `import-ci-artifacts.sh`**

Write to `/home/yarin/Projects/devsecops/scripts/import-ci-artifacts.sh`:
```bash
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
    *trivy* | *.sarif)              echo "Trivy Scan" ;;
    *pip-audit* | *pip_audit*)      echo "pip-audit Scan" ;;
    *govulncheck*)                  echo "govulncheck Scanner" ;;
    *npm-audit* | *npm_audit*)      echo "NPM Audit Scan" ;;
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
  git commit -m "chore(findings): ci artifact import ${TODAY}" && git push origin main

info ""
info "Import complete. Open http://localhost:8080 to review findings."
```

- [ ] **Step 2: Make executable and syntax check**

```bash
chmod +x /home/yarin/Projects/devsecops/scripts/import-ci-artifacts.sh
bash -n /home/yarin/Projects/devsecops/scripts/import-ci-artifacts.sh && echo "SYNTAX OK"
```

Expected: `SYNTAX OK`

- [ ] **Step 3: Commit**

```bash
cd /home/yarin/Projects/devsecops
git add scripts/import-ci-artifacts.sh
git commit -m "feat(scripts): add CI artifact import script (Path B)"
```

---

## Task 8: Commit setup-sops.sh and push all devsecops changes

**Files:**
- Modify: `/home/yarin/Projects/devsecops/scripts/setup-sops.sh` (already written in Task 2, needs to be committed)

- [ ] **Step 1: Commit remaining uncommitted files**

```bash
cd /home/yarin/Projects/devsecops
git add scripts/setup-sops.sh
git commit -m "feat(scripts): add SOPS+age secrets bootstrap script"
```

- [ ] **Step 2: Push all commits to GitHub**

```bash
cd /home/yarin/Projects/devsecops
git push origin main
```

Expected: all commits pushed. Verify:
```bash
git log --oneline -6
```

Expected output (most recent first):
```
feat(scripts): add CI artifact import script (Path B)
feat(scripts): add on-demand scan-all script (Path A)
feat(scripts): add shared DefectDojo API helper library
feat(platform): add DefectDojo bootstrap script (products + OWASP regulations)
feat(scripts): add SOPS+age secrets bootstrap script
feat(platform): add DefectDojo docker-compose stack
```

---

## Task 9: End-to-end bootstrap and verification

This task runs the full sequence for the first time and verifies each step.

- [ ] **Step 1: Run `setup-sops.sh`**

```bash
cd /home/yarin/Projects/devsecops
./scripts/setup-sops.sh
```

Expected prompts:
```
[setup-sops] Generated new age key at /home/yarin/.config/sops/age/keys.txt
[setup-sops] Age public key: age1...
Enter secrets (input is hidden)...
DD_ADMIN_PASS: (type your chosen password, hidden)
GH_PAT: (paste your GitHub PAT, hidden)
[setup-sops] Encrypted secrets written to ../security-data/secrets.enc.yaml
```

- [ ] **Step 2: Verify `secrets.enc.yaml` is encrypted (not plaintext)**

```bash
head -5 /home/yarin/Projects/security-data/secrets.enc.yaml
```

Expected: SOPS header lines starting with `DD_ADMIN_PASS: ENC[AES256_GCM,...` — NOT plaintext values.

- [ ] **Step 3: Verify `sops exec-env` can decrypt JIT**

```bash
cd /home/yarin/Projects/devsecops
sops exec-env ../security-data/secrets.enc.yaml 'echo "GH_PAT length: ${#GH_PAT}"'
```

Expected: `GH_PAT length: <number>` (non-zero). The value never appears in the shell.

- [ ] **Step 4: Start DefectDojo**

```bash
cd /home/yarin/Projects/devsecops
sops exec-env ../security-data/secrets.enc.yaml \
  'docker compose -f platform/docker-compose.yml up -d'
```

Expected: Docker pulls images (first run takes ~2-3 minutes), then:
```
✔ Container platform-postgres-1     Started
✔ Container platform-redis-1        Started
✔ Container platform-uwsgi-1        Started
✔ Container platform-celerybeat-1   Started
✔ Container platform-celeryworker-1 Started
✔ Container platform-nginx-1        Started
```

- [ ] **Step 5: Wait for DefectDojo to initialize (allow 90–120 seconds)**

```bash
for i in $(seq 1 24); do
  if curl -sf http://localhost:8080/api/v2/ -o /dev/null 2>&1; then
    echo "DefectDojo is ready"; break
  fi
  echo "Waiting... (${i}/24)"
  sleep 5
done
```

Expected: `DefectDojo is ready` within 2 minutes.

- [ ] **Step 6: Run `bootstrap.sh`**

```bash
cd /home/yarin/Projects/devsecops
sops exec-env ../security-data/secrets.enc.yaml './platform/bootstrap.sh'
```

Expected output (abbreviated):
```
[bootstrap] DefectDojo is up.
[bootstrap] Token obtained.
[bootstrap] Created product type 'GitHub Repo' (id=1)
[bootstrap] Looking up OWASP regulation IDs ...
[bootstrap] Created product 'resumeforge' (id=1)
[bootstrap]   Linked regulations [...] to 'resumeforge'
[bootstrap] Created product 'resumeforge-cloud' (id=2)
[bootstrap] Created product 'devsecops' (id=3)
[bootstrap] DEFECTDOJO_API_KEY updated in .../secrets.enc.yaml
[bootstrap] Bootstrap complete. Dashboard: http://localhost:8080
```

- [ ] **Step 7: Verify `DEFECTDOJO_API_KEY` is now populated**

```bash
cd /home/yarin/Projects/devsecops
sops exec-env ../security-data/secrets.enc.yaml \
  'echo "API key length: ${#DEFECTDOJO_API_KEY}"'
```

Expected: `API key length: 40` (DefectDojo API keys are 40 chars).

- [ ] **Step 8: Run Path B (CI artifact import)**

```bash
cd /home/yarin/Projects/devsecops
sops exec-env ../security-data/secrets.enc.yaml './scripts/import-ci-artifacts.sh'
```

Expected: imports artifacts from `resumeforge` and `resumeforge-cloud` Security workflow runs, commits findings to `security-data`.

- [ ] **Step 9: Verify findings appear in DefectDojo**

```bash
cd /home/yarin/Projects/devsecops
sops exec-env ../security-data/secrets.enc.yaml \
  'curl -s "http://localhost:8080/api/v2/findings/?active=true" \
    -H "Authorization: Token ${DEFECTDOJO_API_KEY}" | jq "{total: .count, products: [.results[].test_object.engagement.product.name] | unique}"'
```

Expected: JSON showing `total` > 0 and `products` containing `["devsecops", "resumeforge", "resumeforge-cloud"]` (some subset).

- [ ] **Step 10: Open dashboard and verify**

Navigate to `http://localhost:8080` in a browser.
Login: `admin` / `<your DD_ADMIN_PASS>`

Verify:
- Products tab shows `resumeforge`, `resumeforge-cloud`, `devsecops`
- At least one product has findings
- Product detail → Compliance section shows OWASP ASVS and OWASP Top 10 listed

- [ ] **Step 11: Verify posture snapshot committed to security-data**

```bash
ls /home/yarin/Projects/security-data/posture/
git -C /home/yarin/Projects/security-data log --oneline posture/
```

Expected: `snapshot-YYYY-MM-DD.json` present, committed.

---

## Verification Summary

| Check | Command | Expected |
|---|---|---|
| age key exists | `ls ~/.config/sops/age/keys.txt` | File present |
| secrets encrypted | `head -3 security-data/secrets.enc.yaml` | `ENC[AES256_GCM` prefix |
| JIT access works | `sops exec-env ... 'echo ${#DEFECTDOJO_API_KEY}'` | `40` |
| DD healthy | `curl -sf http://localhost:8080/api/v2/ -o /dev/null && echo OK` | `OK` |
| Products exist | `curl -s .../api/v2/products/ -H "Authorization: Token ..."` | 3 products |
| Findings imported | `curl -s .../api/v2/findings/?active=true -H ...` | `count > 0` |
| Posture snapshot | `ls security-data/posture/` | `snapshot-YYYY-MM-DD.json` |
| Git history | `git -C security-data log --oneline` | ≥2 commits |
