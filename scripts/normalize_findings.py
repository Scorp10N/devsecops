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
