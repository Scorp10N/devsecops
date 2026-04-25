# DefectDojo Security Dashboard — Design Spec

**Date:** 2026-04-25
**Status:** Approved
**Scope:** Add DefectDojo as a local security dashboard to `Scorp10N/devsecops`, backed by a new private `Scorp10N/security-data` repo as the GitOps state store.

---

## Problem

Security findings from TruffleHog, CodeQL, Trivy, Semgrep, pip-audit, and govulncheck are scattered across individual GitHub Actions runs with no unified view, no OWASP compliance mapping, no posture history, and no way to query across repos.

## Goal

A private, local-first security dashboard (DefectDojo) that:
- Aggregates findings from all Scorp10N repos into one queryable interface
- Maps findings to OWASP ASVS Level 1 and OWASP Top 10
- Tracks posture over time via git-committed snapshots
- Uses SOPS + age for JIT secret access — no secrets ever touch disk

---

## Platform Decision

**DefectDojo** — OSS vulnerability management platform (Django + PostgreSQL + Celery + Redis + nginx). Chosen over DIY (script + Postgres + Metabase) and ArcherySec because it provides SARIF import, OWASP ASVS mapping, deduplication, and a query/filter UI with zero custom code.

Deployment: local Docker Compose. Always-on VPS option deferred until validated locally.

---

## Secrets Management

**SOPS + age** (both already installed via Homebrew).

- Age private key: `~/.config/sops/age/keys.txt` — never committed anywhere
- Encrypted secrets: `security-data/secrets.enc.yaml` — SOPS-encrypted, committed to private repo
- JIT access pattern: `sops exec-env secrets.enc.yaml '<command>'` — secrets injected into subprocess env only, gone when subprocess exits, never appear in parent shell, never written to disk
- Bootstrap: `scripts/setup-sops.sh` prompts interactively, writes age key to `~/.config/sops/age/keys.txt`, generates `secrets.enc.yaml` via `sops` — no intermediate plaintext file

Secrets stored: `DEFECTDOJO_API_KEY`, `DD_ADMIN_PASS`, `GH_PAT` (fine-grained PAT: read access on all Scorp10N repos).

---

## Repo Structure

### `Scorp10N/devsecops` (public) — tooling only

```
platform/
  docker-compose.yml          ← DefectDojo stack (6 services)
  .env.example                ← shape only: DEFECTDOJO_API_KEY=, GH_PAT=, DD_ADMIN_PASS=
  bootstrap.sh                ← one-time: create DD products + link ASVS L1 + Top10 per repo
scripts/
  setup-sops.sh               ← generate age key, populate secrets.enc.yaml interactively
  scan-all.sh                 ← on-demand: clone all repos → run tools → push to DD → commit findings
  import-ci-artifacts.sh      ← pull latest CI SARIF via gh run download → import to DD
configs/
  semgrep.yml                 ← (existing)
  trufflehog.toml             ← (existing)
  trivy-ignore.txt            ← (existing)
  .pre-commit-config.yaml     ← (existing)
```

### `Scorp10N/security-data` (private) — state store

```
.sops.yaml                    ← SOPS config: age public key, encrypted file glob patterns
secrets.enc.yaml              ← SOPS-encrypted secrets (DEFECTDOJO_API_KEY, GH_PAT, DD_ADMIN_PASS)
repo-map.yml                  ← repo list + per-repo scan profiles (plain text, not sensitive)
findings/
  <repo-name>/
    latest/                   ← latest SARIF/JSON per tool (overwritten each run)
    history/YYYY-MM-DD/       ← timestamped archive
posture/
  snapshot-YYYY-MM-DD.json    ← DD API summary export committed after each scan run
```

---

## `repo-map.yml` Format

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

Adding a new repo to the platform = one PR adding an entry to this file.

---

## Conventions

Scripts assume `devsecops` and `security-data` are cloned as siblings under the same parent:
```
~/Projects/
  devsecops/       ← public repo, scripts run from here
  security-data/   ← private repo, referenced as ../security-data/
```

All `sops exec-env` calls use `../security-data/secrets.enc.yaml` as the path.

---

## DefectDojo Scan Type Mapping

| Tool | Output format | DD `scan_type` value |
|---|---|---|
| TruffleHog | JSON | `Trufflehog Scan` |
| Semgrep | JSON | `Semgrep JSON Report` |
| Trivy (filesystem) | SARIF | `Trivy Scan` |
| pip-audit | JSON | `pip-audit Scan` |
| govulncheck | JSON | `govulncheck Scanner` |
| npm audit | JSON | `NPM Audit Scan` |
| CodeQL (CI artifact) | SARIF | `SARIF` |

---

## Data Flow

### Path A — On-demand scan (`scan-all.sh`)

```
sops exec-env ../security-data/secrets.enc.yaml './scripts/scan-all.sh'
  → clone/pull each repo from ../security-data/repo-map.yml into /tmp/scans/<repo>/
  → per repo, run applicable tools:
      has_python  → pip-audit --format json
      has_go      → govulncheck -json ./...
      has_node    → npm audit --json
      always      → trufflehog git file://<path> --only-verified --json
      always      → semgrep --config configs/semgrep.yml --json
      has_containers → trivy fs --format sarif
  → POST /api/v2/import-scan/ per tool per repo (scan_type mapped per tool)
  → save output to security-data/findings/<repo>/latest/<tool>.{sarif,json}
  → archive to security-data/findings/<repo>/history/YYYY-MM-DD/
  → GET /api/v2/findings/?product=<id> → security-data/posture/snapshot-YYYY-MM-DD.json
  → git commit + push security-data
  → rm -rf /tmp/scans/
```

### Path B — CI artifact import (`import-ci-artifacts.sh`)

```
sops exec-env ../security-data/secrets.enc.yaml './scripts/import-ci-artifacts.sh'
  → for each repo in ../security-data/repo-map.yml:
      gh run list --repo <repo> --workflow=Security --status=success --limit=1
      gh run download <run-id> --repo <repo> --dir /tmp/artifacts/<repo>/
      POST /api/v2/import-scan/ per artifact file
      cp artifacts → security-data/findings/<repo>/latest/
  → git commit + push security-data
  → rm -rf /tmp/artifacts/
```

### DefectDojo Models

| Concept | Maps To |
|---|---|
| Repo | DD Product |
| Scan run | DD Engagement (dated) |
| Tool finding | DD Finding (deduplicated across runs) |
| OWASP ASVS L1 | Linked Regulation per Product |
| OWASP Top 10 | Linked Regulation per Product |

---

## OWASP Mapping

ASVS Level 1 controls covered by existing tools:

| ASVS Chapter | Tool |
|---|---|
| V2 — Authentication / Secrets | TruffleHog |
| V5 — Validation / Injection | Semgrep (Path A), CodeQL (Path B — CI only) |
| V10 — Malicious Code / Dependencies | pip-audit, govulncheck, npm audit |
| V13 — API | Semgrep custom rules (Path A), CodeQL (Path B — CI only) |
| V14 — Configuration / Containers | Trivy |

CodeQL findings enter only via Path B (CI artifact import) — CodeQL does not run locally in Path A.

OWASP Top 10 mapped automatically by DefectDojo's built-in CWE → Top10 cross-reference.

---

## Bootstrap Sequence (first-time setup)

1. `scripts/setup-sops.sh` — generate age key, seed `secrets.enc.yaml` interactively
2. `gh repo create Scorp10N/security-data --private` + clone locally
3. Commit `repo-map.yml` and `.sops.yaml` and `secrets.enc.yaml` to `security-data`
4. `cd platform && docker compose up -d` — start DefectDojo
5. `platform/bootstrap.sh` — create Products + link ASVS L1 + Top10 (reads `repo-map.yml`, calls DD API)
6. `scripts/import-ci-artifacts.sh` — initial population from existing CI runs
7. Verify dashboard at `http://localhost:8080`

---

## Posture History

After every scan run (both paths), a posture snapshot is committed to `security-data/posture/`. This gives a `git log`-diffable history of your security posture:

```bash
git -C security-data log --oneline posture/
git -C security-data diff HEAD~1 posture/snapshot-2026-04-25.json
```

---

## Out of Scope

- Always-on VPS deployment (deferred — evaluate after local validation)
- CI-push integration (DefectDojo not publicly accessible in local mode; use Path B instead)
- Automated scheduled scans (run scripts manually or via cron; no cron config in this spec)
- DefectDojo user management beyond the single admin account
