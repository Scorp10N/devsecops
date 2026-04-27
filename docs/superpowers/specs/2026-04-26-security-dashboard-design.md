# Security Dashboard — Design Spec

**Date:** 2026-04-26
**Status:** Approved for implementation

---

## Context

The current security platform uses DefectDojo (6 Docker containers, local-only) as its findings store and dashboard. It has three problems:

1. **Noise over signal** — 1036 active findings, all `Info` severity, all historical Go stdlib CVEs already fixed in Go 1.25. Zero actionable findings.
2. **Overbuilt infrastructure** — 6 containers running 24/7 for a solo developer with 2 repos.
3. **No native PR integration** — DefectDojo has no awareness of GitHub PRs or branch protection.

This design replaces DefectDojo with:
- **GitHub Security tab** for `resumeforge` (public repo, free, native PR integration)
- **SvelteKit SPA on GitHub Pages** for cross-repo historical dashboard, auth-gated via GitHub PAT
- **Event-driven collection** baked into `security-all.yml` (no systemd timer, no manual imports)

---

## Architecture

```
push / PR to resumeforge (public)
  → security-all.yml runs
  → SARIF uploaded to GitHub Security tab   ← new
  → collect job runs last
      → normalizes artifacts
      → commits to security-data (private)  ← replaces DD import

push / PR to resumeforge-cloud (private)
  → security-all.yml runs
  → collect job runs last
      → normalizes artifacts
      → commits to security-data (private)

security-data (private)
  → findings/<repo>/latest/normalized.json
  → posture/snapshot-YYYY-MM-DD.json

devsecops/dashboard/ (SvelteKit, static)
  → GitHub Pages (public URL)
  → user enters GitHub PAT (sessionStorage)
  → reads security-data via GitHub Contents API
  → shows posture overview + per-tool drilldown
```

**DefectDojo:** containers stopped, systemd timer and service removed.

---

## Component 1 — GitHub Security Tab (resumeforge only)

Add `upload-sarif` steps to `security-all.yml` after Trivy and Semgrep scans. CodeQL already uploads automatically.

**Changes to `security-all.yml`:**

- After Trivy engine + web scans: upload `trivy-engine.sarif` and `trivy-web.sarif` via `github/codeql-action/upload-sarif@v3`
- After Semgrep scan: upload `semgrep.sarif` via `github/codeql-action/upload-sarif@v3`
- Both gated: Trivy behind `inputs.has_containers`, Semgrep already push-only on main
- Requires `security-events: write` permission — already present in the workflow

**Result:** resumeforge's Security tab shows Trivy CVEs and Semgrep SAST findings inline on PRs. No cost, no infrastructure.

**Not applied to resumeforge-cloud:** private repo on free plan — GitHub Advanced Security required. CI gates (`pip-audit`, `TruffleHog`) remain the enforcement mechanism.

---

## Component 2 — Event-Driven Collection Job

A `collect` job added as the final job in `security-all.yml`. Fires on every successful Security run on `main`. No systemd timer. No separate trigger workflow in consuming repos.

**Job definition (in `security-all.yml`):**

```yaml
collect:
  name: Collect findings → security-data
  runs-on: ubuntu-latest
  needs: [secrets, deps, containers, sast-python, sast-go, sast-javascript, semgrep]
  if: always() && github.ref == 'refs/heads/main' && github.event_name == 'push'
  steps:
    - uses: actions/checkout@...
    - name: Download scan artifacts
      run: gh run download ${{ github.run_id }} --dir findings-raw/
      env:
        GH_TOKEN: ${{ github.token }}
    - name: Normalize findings
      run: python3 scripts/normalize-findings.py findings-raw/ ${{ github.repository }}
    - name: Commit to security-data
      env:
        SECURITY_DATA_PAT: ${{ secrets.SECURITY_DATA_PAT }}
      run: |
        git clone https://x-access-token:${SECURITY_DATA_PAT}@github.com/Scorp10N/security-data.git sd
        cp -r normalized/. sd/findings/
        python3 scripts/update-posture.py sd/findings/ > sd/posture/snapshot-$(date +%Y-%m-%d).json
        cd sd
        git config user.email "ci@scorp10n.github"
        git config user.name "Security Bot"
        git add findings/ posture/
        git diff --cached --quiet || git commit -m "findings: ${{ github.repository }} run ${{ github.run_id }}"
        git push
```

**`needs: always()`** — runs even if some scan jobs were skipped (e.g. has_go: false). Uses `always()` + checks each artifact directory exists before normalizing.

**New script:** `scripts/normalize-findings.py` — reads raw tool outputs (trufflehog.json, pip-audit.json, govulncheck.json, trivy-*.sarif, semgrep.sarif) and writes a single `normalized.json` per repo with a common schema:

```json
{
  "repo": "Scorp10N/resumeforge",
  "run_id": 12345,
  "scanned_at": "2026-04-26T19:00:00Z",
  "findings": [
    {
      "tool": "trivy",
      "id": "CVE-2026-33750",
      "title": "brace-expansion ReDoS",
      "severity": "medium",
      "package": "brace-expansion",
      "version": "2.0.1",
      "fix_version": "2.0.3",
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-33750"
    }
  ],
  "summary": {
    "critical": 0, "high": 0, "medium": 1, "low": 3, "info": 0
  }
}
```

Severity is normalised from each tool's native scale to `critical / high / medium / low / info`.

---

## Component 3 — security-data Protections (All Three Mitigations)

### Mitigation 1 — Block force pushes (branch protection)
```bash
gh api --method PUT repos/Scorp10N/security-data/branches/main/protection \
  --input - << 'JSON'
{
  "required_status_checks": null,
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```
Prevents the PAT from rewriting or deleting history. All writes are auditable commits.

### Mitigation 2 — File path ruleset (protect `posture/`)
A GitHub Ruleset on `security-data/main` that blocks human direct pushes touching `posture/**` — they must go through a PR. GitHub Actions is granted a bypass so the `collect` job can still write posture snapshots via CI. This limits blast radius: a compromised PAT used outside CI cannot tamper with the posture history directly.

```bash
gh api --method POST repos/Scorp10N/security-data/rulesets \
  --input - << 'JSON'
{
  "name": "protect-posture-path",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [
    {
      "actor_id": 2,
      "actor_type": "Integration",
      "bypass_mode": "always"
    }
  ],
  "conditions": {
    "ref_name": { "include": ["refs/heads/main"], "exclude": [] }
  },
  "rules": [
    {
      "type": "file_path_restriction",
      "parameters": {
        "restricted_file_paths": ["posture/**"]
      }
    }
  ]
}
JSON
```

`actor_id: 2` is the GitHub Actions integration. The bypass means CI writes to `posture/` freely; a human pushing directly to main touching `posture/` is rejected.

### Mitigation 3 — Code gate
`normalize-findings.py` and the collect job only call `git add` / `git commit` / `git push`. No `git rm`, no Contents API DELETE endpoint, no `git push --force`. The script is the only code path that touches security-data via CI.

---

## Component 4 — SvelteKit Dashboard

**Location:** `devsecops/dashboard/` — SvelteKit app with `@sveltejs/adapter-static`

**Deployment:** GitHub Actions workflow builds and deploys to GitHub Pages on every push to `devsecops/main` that touches `dashboard/**`.

**Auth:** On first load, the user is prompted to enter a GitHub fine-grained PAT with `Contents: read` on `security-data`. Token is stored in `sessionStorage` (cleared on tab close, never sent to any server). All data fetching uses the GitHub Contents API directly from the browser.

**Layout:**

```
┌─────────────────────────────────────────────────┐
│  Security Posture — Scorp10N                    │
│                                                 │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐           │
│  │Critical │ │  High   │ │ Medium  │  ...       │
│  │    0    │ │    0    │ │    1    │            │
│  └─────────┘ └─────────┘ └─────────┘           │
│                                                 │
│  Findings over 30 days  [sparkline chart]       │
│                                                 │
│  Last scanned: resumeforge 4 min ago            │
│               resumeforge-cloud 2 hr ago        │
├─────────────────────────────────────────────────┤
│  resumeforge           resumeforge-cloud        │
│                                                 │
│  [Trivy]  1 medium     [pip-audit]  0           │
│  [Semgrep] 0           [TruffleHog] 0           │
│  [pip-audit] 0                                  │
│  [TruffleHog] 0                                 │
│  [Govulncheck] 0                                │
└─────────────────────────────────────────────────┘
```

**Data fetching:**
- `GET /repos/Scorp10N/security-data/contents/posture/` — list snapshots for trend data
- `GET /repos/Scorp10N/security-data/contents/findings/{repo}/latest/normalized.json` — per-repo current findings
- All responses cached in `sessionStorage` for 5 minutes to avoid rate limits

**Tech stack:** SvelteKit 5, static adapter, TailwindCSS, no additional dependencies for charts (CSS-only sparklines for simplicity).

---

## Component 5 — SECURITY_DATA_PAT

**Two tokens:**

### CI token (stored as repo secret)
| Setting | Value |
|---|---|
| Name | `SECURITY_DATA_PAT` |
| Type | Fine-grained PAT |
| Expiry | 1 year |
| Repository access | `resumeforge`, `resumeforge-cloud`, `security-data` |
| Contents | Read + Write (`security-data` only) |
| Actions | Read (`resumeforge`, `resumeforge-cloud`) |
| Metadata | Read (all, mandatory) |

Set in: `resumeforge` repo secrets, `resumeforge-cloud` repo secrets.

### Dashboard token (personal, browser-only)
| Setting | Value |
|---|---|
| Type | Fine-grained PAT |
| Expiry | 90 days (recommended) |
| Repository access | `security-data` only |
| Contents | Read |
| Metadata | Read |

Entered once in the dashboard UI, stored in `sessionStorage`.

---

## Component 6 — DefectDojo Shutdown

```bash
# Stop containers
cd /home/yarin/Projects/devsecops/platform
docker compose down

# Disable systemd timer
systemctl --user disable --now dd-import.timer
systemctl --user disable --now dd-import.service

# Remove unit files
rm ~/.config/systemd/user/dd-import.{timer,service}
systemctl --user daemon-reload
```

Scripts kept as archive: `import-ci-artifacts.sh`, `auto-import.sh`, `lib/dd-api.sh` moved to `scripts/archive/`. The `collect-findings.sh` and `normalize-findings.py` replace them.

---

## Files Changed / Created

| File | Repo | Action |
|---|---|---|
| `.github/workflows/security-all.yml` | `devsecops` | Add `upload-sarif` steps + `collect` job |
| `scripts/normalize-findings.py` | `devsecops` | New — normalizes raw tool outputs to common schema |
| `scripts/update-posture.py` | `devsecops` | New — regenerates posture snapshot from normalized findings |
| `scripts/archive/` | `devsecops` | Move old DD scripts here |
| `dashboard/` | `devsecops` | New — SvelteKit static SPA |
| `.github/workflows/deploy-dashboard.yml` | `devsecops` | New — builds + deploys dashboard to GitHub Pages |
| `platform/docker-compose.yml` | `devsecops` | No change (containers just stopped, not removed) |
| `~/.config/systemd/user/dd-import.*` | local | Deleted |

---

## Verification

1. **SARIF uploads appear in Security tab:**
   Push a commit to `resumeforge` → open Security tab → confirm Trivy and Semgrep findings appear under Code Scanning.

2. **Collect job runs end-to-end:**
   Push to `resumeforge/main` → watch Security workflow → confirm `collect` job succeeds → check `security-data` for new commit to `findings/resumeforge/latest/normalized.json`.

3. **security-data protections hold:**
   - Attempt `git push --force` to `security-data/main` → rejected
   - Attempt direct push touching `posture/**` → rejected by ruleset
   - Confirm all CI writes land in `findings/` cleanly

4. **Dashboard loads and displays data:**
   Open `https://scorp10n.github.io/devsecops` → enter read PAT → confirm posture summary renders → confirm per-tool cards show correct finding counts → confirm trend sparkline shows last 30 days.

5. **DefectDojo is gone:**
   `docker ps` → no `platform-*` containers running.
   `systemctl --user list-timers` → no `dd-import` timer.
