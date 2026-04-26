# Security Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace DefectDojo with GitHub Security tab (resumeforge) + private SvelteKit dashboard on GitHub Pages reading from security-data, driven by event-based CI collection.

**Architecture:** A `collect` job is appended to `security-all.yml`; it normalises scan artifacts and commits them to the private `security-data` repo after every successful push to main. A SvelteKit static SPA deployed on GitHub Pages fetches that data via the GitHub Contents API using a PAT the user enters once.

**Tech Stack:** Python 3.12 (normalization scripts), SvelteKit 5 + Svelte 5 runes + TailwindCSS (dashboard), `@sveltejs/adapter-static` (GitHub Pages), GitHub Actions (collect + deploy), `gh` CLI, `git`.

---

## File Map

| File | Repo | Purpose |
|---|---|---|
| `scripts/normalize_findings.py` | devsecops | Parse 5 raw tool formats → `normalized.json` |
| `scripts/update_posture.py` | devsecops | Aggregate normalized files → posture snapshot |
| `scripts/tests/test_normalize.py` | devsecops | Unit tests for normalization |
| `scripts/tests/test_posture.py` | devsecops | Unit tests for posture aggregation |
| `scripts/tests/fixtures/` | devsecops | Minimal sample tool outputs |
| `scripts/archive/` | devsecops | Moved DD scripts (import-ci-artifacts.sh, auto-import.sh, lib/dd-api.sh) |
| `.github/workflows/security-all.yml` | devsecops | Add upload-sarif steps + collect job |
| `.github/workflows/deploy-dashboard.yml` | devsecops | Build + deploy dashboard to GitHub Pages |
| `dashboard/package.json` | devsecops | SvelteKit app dependencies |
| `dashboard/svelte.config.js` | devsecops | Static adapter + base path |
| `dashboard/vite.config.ts` | devsecops | Vite config |
| `dashboard/tailwind.config.js` | devsecops | TailwindCSS config |
| `dashboard/src/app.html` | devsecops | HTML shell |
| `dashboard/src/lib/types.ts` | devsecops | Shared TypeScript types (contract between collect and dashboard) |
| `dashboard/src/lib/auth.ts` | devsecops | PAT sessionStorage helpers |
| `dashboard/src/lib/github.ts` | devsecops | GitHub Contents API client with 5-min cache |
| `dashboard/src/lib/components/TokenGate.svelte` | devsecops | PAT entry UI |
| `dashboard/src/lib/components/PostureOverview.svelte` | devsecops | Severity counts + 30-day trend |
| `dashboard/src/lib/components/ToolDrilldown.svelte` | devsecops | Per-tool finding cards |
| `dashboard/src/routes/+page.svelte` | devsecops | Root page — orchestrates all components |

---

## Task 1: Shut down DefectDojo and archive DD scripts

**Files:**
- Delete: `~/.config/systemd/user/dd-import.timer`
- Delete: `~/.config/systemd/user/dd-import.service`
- Create: `scripts/archive/` (move DD scripts here)

- [ ] **Step 1: Stop containers and disable timer**

```bash
cd /home/yarin/Projects/devsecops/platform
docker compose down

systemctl --user disable --now dd-import.timer
systemctl --user disable --now dd-import.service 2>/dev/null || true
rm ~/.config/systemd/user/dd-import.timer
rm ~/.config/systemd/user/dd-import.service
systemctl --user daemon-reload
```

Expected: `docker compose down` prints container names stopping. `systemctl` confirms units removed.

- [ ] **Step 2: Archive DD scripts**

```bash
mkdir -p /home/yarin/Projects/devsecops/scripts/archive
mv /home/yarin/Projects/devsecops/scripts/import-ci-artifacts.sh scripts/archive/
mv /home/yarin/Projects/devsecops/scripts/auto-import.sh scripts/archive/
mv /home/yarin/Projects/devsecops/scripts/lib/dd-api.sh scripts/archive/
```

- [ ] **Step 3: Verify nothing is running**

```bash
docker ps --format "{{.Names}}" | grep platform || echo "DefectDojo: stopped"
systemctl --user list-timers 2>/dev/null | grep dd-import || echo "Timer: removed"
```

Expected: both lines print the "stopped/removed" message.

- [ ] **Step 4: Commit**

```bash
cd /home/yarin/Projects/devsecops
git add scripts/
git commit -m "chore: shut down DefectDojo, archive DD import scripts"
```

---

## Task 2: Harden security-data repo

**Files:** No local files — all `gh api` calls.

- [ ] **Step 1: Block force pushes and deletions on security-data/main**

```bash
gh api --method PUT repos/Scorp10N/security-data/branches/main/protection \
  --input - << 'JSON'
{
  "required_status_checks": null,
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": false
}
JSON
```

Expected: JSON response containing `"url": "https://api.github.com/repos/Scorp10N/security-data/branches/main/protection"`.

- [ ] **Step 2: Add file-path ruleset protecting posture/ from direct human pushes**

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

Expected: JSON response with `"id"` field and `"enforcement": "active"`. `actor_id: 2` is the GitHub Actions integration — CI can write to `posture/`, humans cannot push directly.

- [ ] **Step 3: Verify protections**

```bash
gh api repos/Scorp10N/security-data/branches/main/protection \
  --jq '{force_push: .allow_force_pushes.enabled, deletions: .allow_deletions.enabled}'

gh api repos/Scorp10N/security-data/rulesets \
  --jq '.[].name'
```

Expected:
```json
{"force_push": false, "deletions": false}
"protect-posture-path"
```

---

## Task 3: Create and configure SECURITY_DATA_PAT

**Files:** No local files — GitHub UI + `gh secret set`.

- [ ] **Step 1: Create fine-grained PAT (GitHub UI)**

Navigate to `https://github.com/settings/personal-access-tokens/new` and configure:

| Field | Value |
|---|---|
| Token name | `SECURITY_DATA_PAT` |
| Expiration | 1 year |
| Repository access | `resumeforge`, `resumeforge-cloud`, `security-data` |
| Contents | Read and Write |
| Actions | Read |
| Metadata | Read (mandatory) |

Copy the token value.

- [ ] **Step 2: Set secret in resumeforge**

```bash
gh secret set SECURITY_DATA_PAT --repo Scorp10N/resumeforge
# Paste token when prompted, then Ctrl+D
```

Expected: `✓ Set Actions secret SECURITY_DATA_PAT for Scorp10N/resumeforge`

- [ ] **Step 3: Set secret in resumeforge-cloud**

```bash
gh secret set SECURITY_DATA_PAT --repo Scorp10N/resumeforge-cloud
# Paste same token, then Ctrl+D
```

Expected: `✓ Set Actions secret SECURITY_DATA_PAT for Scorp10N/resumeforge-cloud`

- [ ] **Step 4: Verify secrets exist (names only — values are masked)**

```bash
gh secret list --repo Scorp10N/resumeforge | grep SECURITY_DATA_PAT
gh secret list --repo Scorp10N/resumeforge-cloud | grep SECURITY_DATA_PAT
```

Expected: one line per command showing `SECURITY_DATA_PAT`.

---

## Task 4: Write normalization script (TDD)

**Files:**
- Create: `scripts/tests/fixtures/trufflehog_empty.json`
- Create: `scripts/tests/fixtures/pip_audit_with_vuln.json`
- Create: `scripts/tests/fixtures/govulncheck_with_trace.ndjson`
- Create: `scripts/tests/fixtures/trivy.sarif`
- Create: `scripts/tests/test_normalize.py`
- Create: `scripts/normalize_findings.py`

- [ ] **Step 1: Create test fixtures**

```bash
mkdir -p /home/yarin/Projects/devsecops/scripts/tests/fixtures
```

Write `scripts/tests/fixtures/trufflehog_empty.json`:
```json
[]
```

Write `scripts/tests/fixtures/pip_audit_with_vuln.json`:
```json
{
  "dependencies": [
    {
      "name": "aiohttp",
      "version": "3.9.0",
      "vulns": [
        {
          "id": "GHSA-5m98-qgg9-wh84",
          "fix_versions": ["3.9.4"],
          "description": "aiohttp open redirect vulnerability"
        }
      ]
    },
    {
      "name": "requests",
      "version": "2.31.0",
      "vulns": []
    }
  ]
}
```

Write `scripts/tests/fixtures/govulncheck_with_trace.ndjson`:
```
{"config": {"protocol_version": "v1.0.0", "scanner_name": "govulncheck"}}
{"finding": {"osv": "GO-2024-0001", "module_path": "golang.org/x/net", "module_version": "v0.17.0", "trace": [{"function": "net/http.Get"}]}}
{"finding": {"osv": "GO-2021-0067", "module_path": "stdlib", "module_version": "go1.16.0", "trace": []}}
```

Write `scripts/tests/fixtures/trivy.sarif`:
```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Trivy",
          "rules": [
            {
              "id": "CVE-2026-33750",
              "shortDescription": {"text": "brace-expansion ReDoS"},
              "helpUri": "https://nvd.nist.gov/vuln/detail/CVE-2026-33750"
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "CVE-2026-33750",
          "level": "warning",
          "message": {"text": "Package brace-expansion 2.0.1 is vulnerable"}
        }
      ]
    }
  ]
}
```

- [ ] **Step 2: Write failing tests**

Write `scripts/tests/test_normalize.py`:
```python
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from normalize_findings import (
    parse_trufflehog,
    parse_pip_audit,
    parse_govulncheck,
    parse_sarif,
    summarise,
    normalize,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_trufflehog_empty():
    findings = parse_trufflehog(FIXTURES / "trufflehog_empty.json")
    assert findings == []


def test_parse_pip_audit_with_vuln():
    findings = parse_pip_audit(FIXTURES / "pip_audit_with_vuln.json")
    assert len(findings) == 1
    assert findings[0]["id"] == "GHSA-5m98-qgg9-wh84"
    assert findings[0]["tool"] == "pip-audit"
    assert findings[0]["package"] == "aiohttp"
    assert findings[0]["version"] == "3.9.0"
    assert findings[0]["fix_version"] == "3.9.4"
    assert findings[0]["severity"] == "high"


def test_parse_govulncheck_only_includes_traced():
    findings = parse_govulncheck(FIXTURES / "govulncheck_with_trace.ndjson")
    # GO-2024-0001 has a trace, GO-2021-0067 does not — only the traced one is included
    assert len(findings) == 1
    assert findings[0]["id"] == "GO-2024-0001"
    assert findings[0]["tool"] == "govulncheck"
    assert findings[0]["severity"] == "info"


def test_parse_sarif_trivy():
    findings = parse_sarif(FIXTURES / "trivy.sarif", "trivy")
    assert len(findings) == 1
    assert findings[0]["id"] == "CVE-2026-33750"
    assert findings[0]["tool"] == "trivy"
    assert findings[0]["severity"] == "medium"  # level=warning → medium
    assert findings[0]["title"] == "brace-expansion ReDoS"


def test_summarise():
    findings = [
        {"severity": "critical"},
        {"severity": "high"},
        {"severity": "high"},
        {"severity": "medium"},
    ]
    s = summarise(findings)
    assert s == {"critical": 1, "high": 2, "medium": 1, "low": 0, "info": 0}


def test_normalize_integration(tmp_path):
    # Copy fixtures into a tmp artifacts dir
    import shutil
    shutil.copy(FIXTURES / "trufflehog_empty.json", tmp_path / "trufflehog.json")
    shutil.copy(FIXTURES / "pip_audit_with_vuln.json", tmp_path / "pip-audit.json")
    shutil.copy(FIXTURES / "trivy.sarif", tmp_path / "trivy-engine.sarif")

    result = normalize(str(tmp_path), "Scorp10N/resumeforge", 12345)

    assert result["repo"] == "Scorp10N/resumeforge"
    assert result["run_id"] == 12345
    assert "scanned_at" in result
    assert len(result["findings"]) == 2  # 1 pip-audit + 1 trivy (trufflehog empty)
    assert result["summary"]["high"] == 1
    assert result["summary"]["medium"] == 1
```

- [ ] **Step 3: Run failing tests**

```bash
cd /home/yarin/Projects/devsecops
python3 -m pytest scripts/tests/test_normalize.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError: No module named 'normalize_findings'` — confirms tests are wired.

- [ ] **Step 4: Write `scripts/normalize_findings.py`**

```python
#!/usr/bin/env python3
"""
normalize_findings.py — normalize raw CI scan artifacts to a common schema.

Usage: python3 normalize_findings.py <artifacts_dir> <repo> <run_id>
Output: normalized/<repo_slug>/normalized.json
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def severity_from_sarif_level(level: str) -> str:
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(
        level, "info"
    )


def parse_trufflehog(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    return [
        {
            "tool": "trufflehog",
            "id": item.get("DetectorName", "unknown"),
            "title": f"Verified secret: {item.get('DetectorName', 'unknown')}",
            "severity": "critical",
            "package": None,
            "version": None,
            "fix_version": None,
            "url": None,
            "description": str(item.get("Raw", ""))[:200],
        }
        for item in data
    ]


def parse_pip_audit(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    findings = []
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            fix_versions = vuln.get("fix_versions", [])
            findings.append(
                {
                    "tool": "pip-audit",
                    "id": vuln["id"],
                    "title": f"{dep['name']} {dep['version']}: {vuln['id']}",
                    "severity": "high",
                    "package": dep["name"],
                    "version": dep["version"],
                    "fix_version": fix_versions[0] if fix_versions else None,
                    "url": f"https://osv.dev/vulnerability/{vuln['id']}",
                    "description": vuln.get("description", "")[:200],
                }
            )
    return findings


def parse_govulncheck(path: Path) -> list[dict]:
    findings = []
    seen: set[str] = set()
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "finding" not in obj:
            continue
        finding = obj["finding"]
        osv_id = finding.get("osv", "")
        if not osv_id or osv_id in seen:
            continue
        # Only include findings with an actual call trace — untrace means the
        # vulnerable code path is never called in this binary
        if not finding.get("trace"):
            continue
        seen.add(osv_id)
        findings.append(
            {
                "tool": "govulncheck",
                "id": osv_id,
                "title": osv_id,
                "severity": "info",
                "package": finding.get("module_path"),
                "version": finding.get("module_version"),
                "fix_version": None,
                "url": f"https://pkg.go.dev/vuln/{osv_id}",
                "description": "",
            }
        )
    return findings


def parse_sarif(path: Path, tool_name: str) -> list[dict]:
    data = json.loads(path.read_text())
    findings = []
    for run in data.get("runs", []):
        rules = {
            r["id"]: r
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule = rules.get(rule_id, {})
            severity = severity_from_sarif_level(result.get("level", "warning"))
            findings.append(
                {
                    "tool": tool_name,
                    "id": rule_id,
                    "title": rule.get("shortDescription", {}).get("text", rule_id),
                    "severity": severity,
                    "package": None,
                    "version": None,
                    "fix_version": None,
                    "url": rule.get("helpUri"),
                    "description": result.get("message", {}).get("text", "")[:200],
                }
            )
    return findings


def summarise(findings: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in counts:
            counts[sev] += 1
    return counts


def normalize(artifacts_dir: str, repo: str, run_id: int) -> dict:
    base = Path(artifacts_dir)
    findings: list[dict] = []

    parsers = [
        ("**/trufflehog.json", parse_trufflehog),
        ("**/pip-audit.json", parse_pip_audit),
        ("**/govulncheck.json", parse_govulncheck),
    ]
    for pattern, parser in parsers:
        for path in base.glob(pattern):
            findings.extend(parser(path))

    for path in base.glob("**/*.sarif"):
        tool = "semgrep" if "semgrep" in path.name else "trivy"
        findings.extend(parse_sarif(path, tool))

    return {
        "repo": repo,
        "run_id": run_id,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "summary": summarise(findings),
    }


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(
            "Usage: normalize_findings.py <artifacts_dir> <repo> <run_id>",
            file=sys.stderr,
        )
        sys.exit(1)
    result = normalize(sys.argv[1], sys.argv[2], int(sys.argv[3]))
    out_dir = Path("normalized") / sys.argv[2].split("/")[-1]
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "normalized.json"
    out_file.write_text(json.dumps(result, indent=2))
    print(f"Written {len(result['findings'])} findings to {out_file}")
```

- [ ] **Step 5: Run tests — expect pass**

```bash
cd /home/yarin/Projects/devsecops
python3 -m pytest scripts/tests/test_normalize.py -v
```

Expected: `6 passed`.

- [ ] **Step 6: Commit**

```bash
git add scripts/normalize_findings.py scripts/tests/
git commit -m "feat: add findings normalization script with tests"
```

---

## Task 5: Write posture update script (TDD)

**Files:**
- Create: `scripts/tests/test_posture.py`
- Create: `scripts/update_posture.py`

- [ ] **Step 1: Write failing tests**

Write `scripts/tests/test_posture.py`:
```python
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from update_posture import update_posture


def test_update_posture_aggregates_repos(tmp_path):
    # Create two fake normalized.json files
    repo_a = tmp_path / "resumeforge" / "latest"
    repo_a.mkdir(parents=True)
    (repo_a / "normalized.json").write_text(json.dumps({
        "repo": "Scorp10N/resumeforge",
        "run_id": 1,
        "scanned_at": "2026-04-26T10:00:00+00:00",
        "findings": [],
        "summary": {"critical": 0, "high": 1, "medium": 2, "low": 0, "info": 0},
    }))

    repo_b = tmp_path / "resumeforge-cloud" / "latest"
    repo_b.mkdir(parents=True)
    (repo_b / "normalized.json").write_text(json.dumps({
        "repo": "Scorp10N/resumeforge-cloud",
        "run_id": 2,
        "scanned_at": "2026-04-26T11:00:00+00:00",
        "findings": [],
        "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
    }))

    result = update_posture(str(tmp_path))

    assert result["total"]["high"] == 1
    assert result["total"]["critical"] == 1
    assert result["total"]["medium"] == 2
    assert "Scorp10N/resumeforge" in result["by_repo"]
    assert "Scorp10N/resumeforge-cloud" in result["by_repo"]
    assert result["last_scanned"]["Scorp10N/resumeforge"] == "2026-04-26T10:00:00+00:00"


def test_update_posture_empty_findings_dir(tmp_path):
    result = update_posture(str(tmp_path))
    assert result["total"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    assert result["by_repo"] == {}
```

- [ ] **Step 2: Run — expect fail**

```bash
python3 -m pytest scripts/tests/test_posture.py -v 2>&1 | head -10
```

Expected: `ModuleNotFoundError: No module named 'update_posture'`

- [ ] **Step 3: Write `scripts/update_posture.py`**

```python
#!/usr/bin/env python3
"""
update_posture.py — generate posture snapshot from all normalized findings.

Usage: python3 update_posture.py <findings_base_dir>
Prints JSON to stdout.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def update_posture(findings_base: str) -> dict:
    base = Path(findings_base)
    total: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_repo: dict[str, dict] = {}
    last_scanned: dict[str, str] = {}

    for norm_file in base.glob("*/latest/normalized.json"):
        data = json.loads(norm_file.read_text())
        repo = data["repo"]
        summary = data.get("summary", {})
        by_repo[repo] = summary
        last_scanned[repo] = data.get("scanned_at", "")
        for sev, count in summary.items():
            if sev in total:
                total[sev] += count

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": total,
        "by_repo": by_repo,
        "last_scanned": last_scanned,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: update_posture.py <findings_base_dir>", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(update_posture(sys.argv[1]), indent=2))
```

- [ ] **Step 4: Run — expect pass**

```bash
python3 -m pytest scripts/tests/test_posture.py -v
```

Expected: `2 passed`.

- [ ] **Step 5: Commit**

```bash
git add scripts/update_posture.py scripts/tests/test_posture.py
git commit -m "feat: add posture update script with tests"
```

---

## Task 6: Add SARIF upload to GitHub Security tab

**Files:**
- Modify: `.github/workflows/security-all.yml` (heredoc — Edit hook blocks this path)

- [ ] **Step 1: Add upload-sarif steps after Trivy scans and Semgrep scan**

The two changes needed in `security-all.yml`:

After the "Scan web image" step in the `containers` job, add:
```yaml
      - name: Upload Trivy results to GitHub Security tab
        if: ${{ always() && inputs.has_containers }}
        uses: github/codeql-action/upload-sarif@ce64ddcb0d8d890d2df4a9d1c04ff297367dea2a  # v3.35.2
        with:
          sarif_file: .
          category: trivy
```

After the "Run Semgrep" step in the `semgrep` job, add:
```yaml
      - name: Upload Semgrep results to GitHub Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@ce64ddcb0d8d890d2df4a9d1c04ff297367dea2a  # v3.35.2
        with:
          sarif_file: semgrep.sarif
          category: semgrep
```

Both jobs already have `permissions: security-events: write` inherited from the workflow context. Apply using a heredoc:

```bash
# Read the current file, make the two insertions, write back via heredoc
# See full file content in .github/workflows/security-all.yml
# Use cat > with the complete updated content
```

- [ ] **Step 2: Validate YAML**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/security-all.yml'))" && echo "YAML OK"
```

Expected: `YAML OK`

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/security-all.yml
git commit -m "feat: upload Trivy and Semgrep SARIF to GitHub Security tab"
```

---

## Task 7: Add collect job to security-all.yml

**Files:**
- Modify: `.github/workflows/security-all.yml` (heredoc)

- [ ] **Step 1: Append the collect job via heredoc**

Append this job to the end of `.github/workflows/security-all.yml` (before the final newline):

```yaml
  # ── 6. Collect findings → security-data ──────────────────────────────────
  collect:
    name: Collect findings → security-data
    runs-on: ubuntu-latest
    needs: [secrets, deps, containers, sast-python, sast-go, sast-javascript, semgrep]
    if: always() && github.ref == 'refs/heads/main' && github.event_name == 'push'
    steps:
      - name: Checkout devsecops (for normalization scripts)
        uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4
        with:
          repository: Scorp10N/devsecops
          path: devsecops

      - name: Download scan artifacts
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh run download ${{ github.run_id }} \
            --repo ${{ github.repository }} \
            --dir findings-raw/ 2>/dev/null || true

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Normalize findings
        run: |
          python3 devsecops/scripts/normalize_findings.py \
            findings-raw/ \
            "${{ github.repository }}" \
            "${{ github.run_id }}"

      - name: Clone security-data and update findings
        env:
          SECURITY_DATA_PAT: ${{ secrets.SECURITY_DATA_PAT }}
        run: |
          REPO_SLUG="${{ github.repository }}"
          REPO_SLUG="${REPO_SLUG#*/}"
          TODAY=$(date +%Y-%m-%d)

          git clone \
            https://x-access-token:${SECURITY_DATA_PAT}@github.com/Scorp10N/security-data.git \
            sd

          mkdir -p sd/findings/${REPO_SLUG}/latest
          cp normalized/${REPO_SLUG}/normalized.json sd/findings/${REPO_SLUG}/latest/

          python3 devsecops/scripts/update_posture.py sd/findings/ \
            > sd/posture/snapshot-${TODAY}.json

          # snapshot-latest.json is the canonical "current" pointer for the dashboard
          cp sd/posture/snapshot-${TODAY}.json sd/posture/snapshot-latest.json

          cd sd
          git config user.email "ci@scorp10n.github"
          git config user.name "Security Bot"
          git add findings/ posture/
          git diff --cached --quiet \
            || git commit -m "findings: ${{ github.repository }} run ${{ github.run_id }}"
          git push
```

Apply via heredoc (full file rewrite) since Edit hook blocks `.github/workflows/` paths.

- [ ] **Step 2: Validate YAML**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/security-all.yml'))" && echo "YAML OK"
```

Expected: `YAML OK`

- [ ] **Step 3: Commit and push to devsecops — triggers first collect run on next resumeforge push**

```bash
git add .github/workflows/security-all.yml
git commit -m "feat: add collect job — event-driven findings ingestion to security-data"
git push origin main
```

- [ ] **Step 4: Trigger a test run on resumeforge**

```bash
cd /home/yarin/Projects/resumeforge
git commit --allow-empty -m "ci: test collect job end-to-end"
git push origin main
```

- [ ] **Step 5: Watch the collect job**

```bash
RUN=$(gh run list --repo Scorp10N/resumeforge --workflow=Security --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch $RUN --repo Scorp10N/resumeforge --exit-status
```

Expected: all jobs including `Collect findings → security-data` show green.

- [ ] **Step 6: Verify security-data was updated**

```bash
gh api repos/Scorp10N/security-data/commits \
  --jq '.[0] | "\(.commit.message) — \(.commit.author.date)"'
```

Expected: `findings: Scorp10N/resumeforge run XXXXX — 2026-04-26T...`

---

## Task 8: Scaffold SvelteKit dashboard

**Files:**
- Create: `dashboard/package.json`
- Create: `dashboard/svelte.config.js`
- Create: `dashboard/vite.config.ts`
- Create: `dashboard/tailwind.config.js`
- Create: `dashboard/postcss.config.js`
- Create: `dashboard/tsconfig.json`
- Create: `dashboard/src/app.html`
- Create: `dashboard/src/routes/+page.svelte` (placeholder)

- [ ] **Step 1: Scaffold the SvelteKit app**

```bash
cd /home/yarin/Projects/devsecops
npm create svelte@latest dashboard -- --template skeleton --types ts --no-prettier --no-eslint --no-playwright --no-vitest
cd dashboard
npm install
npm install -D @sveltejs/adapter-static tailwindcss postcss autoprefixer
npx tailwindcss init -p
```

- [ ] **Step 2: Configure static adapter and GitHub Pages base path**

Write `dashboard/svelte.config.js`:
```javascript
import adapter from '@sveltejs/adapter-static';

export default {
  kit: {
    adapter: adapter({
      pages: 'build',
      assets: 'build',
      fallback: '404.html',
      precompress: false,
    }),
    paths: {
      base: process.env.NODE_ENV === 'production' ? '/devsecops' : '',
    },
  },
};
```

Write `dashboard/vite.config.ts`:
```typescript
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit()],
});
```

- [ ] **Step 3: Configure TailwindCSS**

Write `dashboard/tailwind.config.js`:
```javascript
export default {
  content: ['./src/**/*.{html,js,svelte,ts}'],
  theme: {
    extend: {},
  },
  plugins: [],
};
```

Write `dashboard/src/app.html`:
```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <link rel="icon" href="%sveltekit.assets%/favicon.png" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    %sveltekit.head%
  </head>
  <body data-sveltekit-preload-data="hover">
    <div style="display: contents">%sveltekit.body%</div>
  </body>
</html>
```

Add Tailwind directives — write `dashboard/src/app.css`:
```css
@tailwind base;
@tailwind components;
@tailwind utilities;
```

- [ ] **Step 4: Create placeholder page to verify build works**

Write `dashboard/src/routes/+page.svelte`:
```svelte
<script lang="ts">
  import '../app.css';
</script>

<main class="p-8">
  <h1 class="text-2xl font-bold">Security Dashboard</h1>
  <p class="text-gray-500 mt-2">Loading...</p>
</main>
```

- [ ] **Step 5: Verify build succeeds**

```bash
cd /home/yarin/Projects/devsecops/dashboard
npm run build 2>&1 | tail -5
```

Expected: `✓ built in ...ms` with no errors.

- [ ] **Step 6: Commit**

```bash
cd /home/yarin/Projects/devsecops
git add dashboard/
git commit -m "feat: scaffold SvelteKit dashboard with static adapter"
```

---

## Task 9: Implement TypeScript types, auth and GitHub API client

**Files:**
- Create: `dashboard/src/lib/types.ts`
- Create: `dashboard/src/lib/auth.ts`
- Create: `dashboard/src/lib/github.ts`

- [ ] **Step 1: Write `dashboard/src/lib/types.ts`**

```typescript
export interface Finding {
  tool: string;
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  package: string | null;
  version: string | null;
  fix_version: string | null;
  url: string | null;
  description: string;
}

export interface Summary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface NormalizedFindings {
  repo: string;
  run_id: number;
  scanned_at: string;
  findings: Finding[];
  summary: Summary;
}

export interface PostureSnapshot {
  generated_at: string;
  total: Summary;
  by_repo: Record<string, Summary>;
  last_scanned: Record<string, string>;
}
```

- [ ] **Step 2: Write `dashboard/src/lib/auth.ts`**

```typescript
const KEY = 'github_pat';

export function getToken(): string | null {
  if (typeof sessionStorage === 'undefined') return null;
  return sessionStorage.getItem(KEY);
}

export function setToken(token: string): void {
  sessionStorage.setItem(KEY, token);
}

export function clearToken(): void {
  sessionStorage.removeItem(KEY);
}
```

- [ ] **Step 3: Write `dashboard/src/lib/github.ts`**

```typescript
import type { NormalizedFindings, PostureSnapshot } from './types';

const REPO = 'Scorp10N/security-data';
const API = 'https://api.github.com';
const CACHE_TTL_MS = 5 * 60 * 1000;

function cacheKey(path: string): string {
  return `gh:${path}`;
}

function cacheGet<T>(path: string): T | null {
  const raw = sessionStorage.getItem(cacheKey(path));
  if (!raw) return null;
  const { data, ts } = JSON.parse(raw) as { data: T; ts: number };
  if (Date.now() - ts > CACHE_TTL_MS) {
    sessionStorage.removeItem(cacheKey(path));
    return null;
  }
  return data;
}

function cacheSet<T>(path: string, data: T): void {
  sessionStorage.setItem(cacheKey(path), JSON.stringify({ data, ts: Date.now() }));
}

async function ghFetch<T>(token: string, path: string, raw = true): Promise<T> {
  const cached = cacheGet<T>(path);
  if (cached) return cached;

  const res = await fetch(`${API}/repos/${REPO}/contents/${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: raw
        ? 'application/vnd.github.raw+json'
        : 'application/vnd.github+json',
    },
  });

  if (res.status === 401 || res.status === 403) throw new Error('auth');
  if (res.status === 404) throw new Error('not_found');
  if (!res.ok) throw new Error(`github_${res.status}`);

  const data = raw ? await res.json() : await res.json();
  cacheSet(path, data);
  return data as T;
}

export async function fetchPosture(token: string): Promise<PostureSnapshot> {
  return ghFetch<PostureSnapshot>(token, 'posture/snapshot-latest.json');
}

export async function fetchFindings(
  token: string,
  repoSlug: string
): Promise<NormalizedFindings> {
  return ghFetch<NormalizedFindings>(
    token,
    `findings/${repoSlug}/latest/normalized.json`
  );
}

export async function fetchPostureHistory(
  token: string
): Promise<PostureSnapshot[]> {
  // List files in posture/
  const entries = await ghFetch<Array<{ name: string }>>(
    token,
    'posture',
    false
  );
  const snapshots = entries
    .map((e) => e.name)
    .filter((n) => n.startsWith('snapshot-') && n.endsWith('.json') && n !== 'snapshot-latest.json')
    .sort()
    .slice(-30);

  return Promise.all(
    snapshots.map((name) =>
      ghFetch<PostureSnapshot>(token, `posture/${name}`)
    )
  );
}
```

- [ ] **Step 4: Type-check**

```bash
cd /home/yarin/Projects/devsecops/dashboard
npm run check 2>&1 | tail -10
```

Expected: `0 errors` (or only warnings).

- [ ] **Step 5: Commit**

```bash
cd /home/yarin/Projects/devsecops
git add dashboard/src/lib/
git commit -m "feat: add types, PAT auth and GitHub API client"
```

---

## Task 10: Implement TokenGate and PostureOverview components

**Files:**
- Create: `dashboard/src/lib/components/TokenGate.svelte`
- Create: `dashboard/src/lib/components/PostureOverview.svelte`

- [ ] **Step 1: Write `dashboard/src/lib/components/TokenGate.svelte`**

```svelte
<script lang="ts">
  let { onToken }: { onToken: (token: string) => void } = $props();
  let input = $state('');
  let error = $state('');

  function submit() {
    const t = input.trim();
    if (!t) { error = 'Enter a GitHub PAT'; return; }
    error = '';
    onToken(t);
  }
</script>

<div class="flex items-center justify-center min-h-screen bg-gray-50">
  <div class="bg-white rounded-lg shadow p-8 w-full max-w-sm">
    <h1 class="text-xl font-bold mb-1">Security Dashboard</h1>
    <p class="text-sm text-gray-500 mb-6">
      Enter a GitHub fine-grained PAT with <strong>Contents: read</strong>
      access to <code>security-data</code>.
    </p>

    <label class="block text-sm font-medium text-gray-700 mb-1" for="pat">
      GitHub PAT
    </label>
    <input
      id="pat"
      type="password"
      bind:value={input}
      onkeydown={(e) => e.key === 'Enter' && submit()}
      placeholder="github_pat_..."
      class="w-full border border-gray-300 rounded px-3 py-2 text-sm mb-3
             focus:outline-none focus:ring-2 focus:ring-blue-500"
    />

    {#if error}
      <p class="text-red-600 text-sm mb-3">{error}</p>
    {/if}

    <button
      onclick={submit}
      class="w-full bg-blue-600 text-white rounded px-4 py-2 text-sm font-medium
             hover:bg-blue-700 transition-colors"
    >
      Sign in
    </button>

    <p class="text-xs text-gray-400 mt-4">
      Token is stored in <code>sessionStorage</code> only — never sent to any server.
    </p>
  </div>
</div>
```

- [ ] **Step 2: Write `dashboard/src/lib/components/PostureOverview.svelte`**

```svelte
<script lang="ts">
  import type { PostureSnapshot } from '$lib/types';

  let {
    posture,
    history,
  }: {
    posture: PostureSnapshot;
    history: PostureSnapshot[];
  } = $props();

  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
  const COLORS: Record<string, string> = {
    critical: 'bg-red-100 text-red-800 border-red-200',
    high: 'bg-orange-100 text-orange-800 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    low: 'bg-blue-100 text-blue-800 border-blue-200',
    info: 'bg-gray-100 text-gray-600 border-gray-200',
  };

  // Build sparkline SVG path from history totals
  const sparkline = $derived(() => {
    if (history.length < 2) return '';
    const points = history.map((s) => {
      const t = s.total;
      return t.critical * 10 + t.high * 3 + t.medium;
    });
    const max = Math.max(...points, 1);
    const w = 200, h = 40;
    const coords = points.map((v, i) => {
      const x = (i / (points.length - 1)) * w;
      const y = h - (v / max) * h;
      return `${x},${y}`;
    });
    return `M ${coords.join(' L ')}`;
  });

  function ago(iso: string): string {
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  }
</script>

<div class="space-y-6">
  <!-- Severity counts -->
  <div class="grid grid-cols-5 gap-3">
    {#each SEVERITIES as sev}
      <div class="border rounded-lg p-4 text-center {COLORS[sev]}">
        <div class="text-2xl font-bold">{posture.total[sev] ?? 0}</div>
        <div class="text-xs mt-1 capitalize">{sev}</div>
      </div>
    {/each}
  </div>

  <!-- Trend sparkline -->
  {#if history.length >= 2}
    <div class="border rounded-lg p-4">
      <p class="text-xs text-gray-500 mb-2">Weighted findings — last {history.length} scans</p>
      <svg viewBox="0 0 200 40" class="w-full h-10">
        <path d={sparkline()} fill="none" stroke="#3b82f6" stroke-width="1.5" />
      </svg>
    </div>
  {/if}

  <!-- Last scanned -->
  <div class="text-sm text-gray-500 space-y-1">
    {#each Object.entries(posture.last_scanned) as [repo, ts]}
      <div>
        <span class="font-medium text-gray-700">{repo.split('/')[1]}</span>
        — last scanned {ago(ts)}
      </div>
    {/each}
  </div>
</div>
```

- [ ] **Step 3: Type-check**

```bash
cd /home/yarin/Projects/devsecops/dashboard && npm run check 2>&1 | tail -5
```

Expected: `0 errors`.

- [ ] **Step 4: Commit**

```bash
cd /home/yarin/Projects/devsecops
git add dashboard/src/lib/components/TokenGate.svelte dashboard/src/lib/components/PostureOverview.svelte
git commit -m "feat: add TokenGate and PostureOverview components"
```

---

## Task 11: Implement ToolDrilldown component and wire up main page

**Files:**
- Create: `dashboard/src/lib/components/ToolDrilldown.svelte`
- Modify: `dashboard/src/routes/+page.svelte`

- [ ] **Step 1: Write `dashboard/src/lib/components/ToolDrilldown.svelte`**

```svelte
<script lang="ts">
  import type { NormalizedFindings } from '$lib/types';

  let {
    findings,
    repos,
  }: {
    findings: Record<string, NormalizedFindings>;
    repos: string[];
  } = $props();

  const TOOLS = ['trivy', 'pip-audit', 'govulncheck', 'trufflehog', 'semgrep'];
  const SEVERITY_DOT: Record<string, string> = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-yellow-400',
    low: 'bg-blue-400',
    info: 'bg-gray-300',
  };

  function findingsByTool(repoFindings: NormalizedFindings, tool: string) {
    return repoFindings.findings.filter((f) => f.tool === tool);
  }
</script>

<div class="space-y-8">
  {#each repos as repo}
    {@const repoFindings = findings[repo]}
    <div>
      <h2 class="text-lg font-semibold mb-3">{repo}</h2>

      {#if !repoFindings}
        <p class="text-sm text-gray-400">No scan data yet.</p>
      {:else}
        <div class="grid grid-cols-1 gap-3">
          {#each TOOLS as tool}
            {@const toolFindings = findingsByTool(repoFindings, tool)}
            <div class="border rounded-lg p-4">
              <div class="flex justify-between items-center mb-2">
                <span class="text-sm font-medium capitalize">{tool}</span>
                <span class="text-sm text-gray-500">
                  {toolFindings.length} finding{toolFindings.length !== 1 ? 's' : ''}
                </span>
              </div>

              {#if toolFindings.length === 0}
                <p class="text-xs text-green-600">✓ Clean</p>
              {:else}
                <ul class="space-y-1">
                  {#each toolFindings as f}
                    <li class="flex items-start gap-2 text-xs">
                      <span
                        class="mt-1 w-2 h-2 rounded-full flex-shrink-0 {SEVERITY_DOT[f.severity] ?? 'bg-gray-300'}"
                      ></span>
                      <span class="flex-1">
                        {#if f.url}
                          <a
                            href={f.url}
                            target="_blank"
                            rel="noreferrer"
                            class="text-blue-600 hover:underline">{f.title}</a
                          >
                        {:else}
                          {f.title}
                        {/if}
                        {#if f.package}
                          <span class="text-gray-400"> — {f.package} {f.version ?? ''}</span>
                        {/if}
                        {#if f.fix_version}
                          <span class="text-green-600"> → fix: {f.fix_version}</span>
                        {/if}
                      </span>
                    </li>
                  {/each}
                </ul>
              {/if}
            </div>
          {/each}
        </div>
      {/if}
    </div>
  {/each}
</div>
```

- [ ] **Step 2: Write the full `dashboard/src/routes/+page.svelte`**

```svelte
<script lang="ts">
  import { onMount } from 'svelte';
  import '../app.css';
  import { getToken, setToken, clearToken } from '$lib/auth';
  import { fetchPosture, fetchFindings, fetchPostureHistory } from '$lib/github';
  import TokenGate from '$lib/components/TokenGate.svelte';
  import PostureOverview from '$lib/components/PostureOverview.svelte';
  import ToolDrilldown from '$lib/components/ToolDrilldown.svelte';
  import type { NormalizedFindings, PostureSnapshot } from '$lib/types';

  const REPOS = ['resumeforge', 'resumeforge-cloud'];

  let token = $state<string | null>(null);
  let posture = $state<PostureSnapshot | null>(null);
  let findings = $state<Record<string, NormalizedFindings>>({});
  let history = $state<PostureSnapshot[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(false);

  onMount(() => {
    token = getToken();
    if (token) loadData(token);
  });

  async function loadData(pat: string) {
    loading = true;
    error = null;
    try {
      posture = await fetchPosture(pat);

      const findingsMap: Record<string, NormalizedFindings> = {};
      for (const repo of REPOS) {
        try {
          findingsMap[repo] = await fetchFindings(pat, repo);
        } catch (e) {
          if (e instanceof Error && e.message === 'auth') throw e;
          // repo not yet scanned — skip silently
        }
      }
      findings = findingsMap;
      history = await fetchPostureHistory(pat);
    } catch (e) {
      if (e instanceof Error && e.message === 'auth') {
        clearToken();
        token = null;
        error = 'Token invalid or expired — please sign in again.';
      } else {
        error = e instanceof Error ? e.message : 'Unknown error loading data.';
      }
    } finally {
      loading = false;
    }
  }

  function handleToken(pat: string) {
    setToken(pat);
    token = pat;
    loadData(pat);
  }

  function handleSignOut() {
    clearToken();
    token = null;
    posture = null;
    findings = {};
    history = [];
    error = null;
  }
</script>

<svelte:head>
  <title>Security Dashboard — Scorp10N</title>
</svelte:head>

{#if !token}
  <TokenGate onToken={handleToken} />
{:else if loading}
  <div class="flex items-center justify-center min-h-screen">
    <p class="text-gray-400 text-sm">Loading security data...</p>
  </div>
{:else}
  <div class="max-w-4xl mx-auto px-6 py-10">
    <div class="flex justify-between items-center mb-8">
      <div>
        <h1 class="text-2xl font-bold">Security Posture</h1>
        <p class="text-sm text-gray-400">Scorp10N</p>
      </div>
      <button
        onclick={handleSignOut}
        class="text-sm text-gray-400 hover:text-gray-600 underline"
      >
        Sign out
      </button>
    </div>

    {#if error}
      <div class="bg-red-50 border border-red-200 rounded p-4 mb-6 text-sm text-red-700">
        {error}
      </div>
    {/if}

    {#if posture}
      <section class="mb-10">
        <PostureOverview {posture} {history} />
      </section>

      <section>
        <h2 class="text-lg font-semibold mb-4">Findings by tool</h2>
        <ToolDrilldown {findings} {repos}={REPOS} />
      </section>
    {/if}
  </div>
{/if}
```

- [ ] **Step 3: Type-check**

```bash
cd /home/yarin/Projects/devsecops/dashboard && npm run check 2>&1 | tail -5
```

Expected: `0 errors`.

- [ ] **Step 4: Build**

```bash
npm run build 2>&1 | tail -5
```

Expected: `✓ built in ...ms`

- [ ] **Step 5: Commit**

```bash
cd /home/yarin/Projects/devsecops
git add dashboard/
git commit -m "feat: wire up dashboard — TokenGate, PostureOverview, ToolDrilldown"
```

---

## Task 12: Deploy dashboard to GitHub Pages

**Files:**
- Create: `.github/workflows/deploy-dashboard.yml` (heredoc)
- Create: `dashboard/.nojekyll`

- [ ] **Step 1: Enable GitHub Pages on devsecops repo**

```bash
gh api --method POST repos/Scorp10N/devsecops/pages \
  --input - << 'JSON'
{
  "build_type": "workflow"
}
JSON
```

Expected: `{"url": "https://scorp10n.github.io/devsecops", ...}` or a 409 if already configured (that's fine).

- [ ] **Step 2: Add `.nojekyll` to prevent Jekyll processing**

```bash
touch /home/yarin/Projects/devsecops/dashboard/.nojekyll
```

- [ ] **Step 3: Create deploy workflow via heredoc**

```bash
cat > /home/yarin/Projects/devsecops/.github/workflows/deploy-dashboard.yml << 'YAML'
name: Deploy dashboard to GitHub Pages

on:
  push:
    branches: [main]
    paths:
      - 'dashboard/**'
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages
  cancel-in-progress: false

jobs:
  build:
    name: Build dashboard
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4

      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020  # v4.4.0
        with:
          node-version: '20'
          cache: npm
          cache-dependency-path: dashboard/package-lock.json

      - name: Install dependencies
        run: cd dashboard && npm ci

      - name: Build
        run: cd dashboard && npm run build
        env:
          NODE_ENV: production

      - name: Copy .nojekyll
        run: cp dashboard/.nojekyll dashboard/build/.nojekyll

      - uses: actions/upload-pages-artifact@v3
        with:
          path: dashboard/build

  deploy:
    name: Deploy to GitHub Pages
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - uses: actions/deploy-pages@v4
        id: deployment
YAML
```

- [ ] **Step 4: Validate YAML**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/deploy-dashboard.yml'))" && echo "YAML OK"
```

Expected: `YAML OK`

- [ ] **Step 5: Commit and push — triggers first deploy**

```bash
cd /home/yarin/Projects/devsecops
git add .github/workflows/deploy-dashboard.yml dashboard/.nojekyll
git commit -m "feat: deploy SvelteKit dashboard to GitHub Pages"
git push origin main
```

- [ ] **Step 6: Watch deploy**

```bash
RUN=$(gh run list --repo Scorp10N/devsecops --workflow="Deploy dashboard to GitHub Pages" --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch $RUN --repo Scorp10N/devsecops --exit-status
```

Expected: both `build` and `deploy` jobs green.

- [ ] **Step 7: Verify dashboard is live**

```bash
curl -sI https://scorp10n.github.io/devsecops/ | head -5
```

Expected: `HTTP/2 200`

---

## Verification Checklist

- [ ] `docker ps` shows no `platform-*` containers
- [ ] `systemctl --user list-timers` shows no `dd-import` timer
- [ ] `gh api repos/Scorp10N/security-data/branches/main/protection --jq '.allow_force_pushes.enabled'` → `false`
- [ ] Push a commit to `resumeforge/main` → Security workflow completes → `Collect findings → security-data` job green → new commit appears in `security-data`
- [ ] Open `https://scorp10n.github.io/devsecops/` → TokenGate shown → enter read PAT → posture overview loads → per-tool cards show correct counts
- [ ] Push a commit to `resumeforge-cloud/main` → same collect flow → `resumeforge-cloud` card appears in dashboard
- [ ] `resumeforge` Security tab → Code Scanning → Trivy and Semgrep findings visible
