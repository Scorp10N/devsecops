import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from update_posture import update_posture


def test_update_posture_aggregates_repos(tmp_path):
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
