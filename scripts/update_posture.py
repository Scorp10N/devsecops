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
