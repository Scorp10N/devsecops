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
