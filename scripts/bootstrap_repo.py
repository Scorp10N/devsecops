#!/usr/bin/env python3
"""
Bootstrap a repo to a devsecops preset.

Usage:
  python3 scripts/bootstrap_repo.py --repo Scorp10N/my-repo --type container --lifecycle experimental
  python3 scripts/bootstrap_repo.py --repo Scorp10N/my-repo --type container --lifecycle experimental --dry-run
  python3 scripts/bootstrap_repo.py --wizard
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

DEVSECOPS_DIR = Path(__file__).parent.parent
PRESETS_DIR = DEVSECOPS_DIR / "presets"
DEFAULT_PROJECTS_DIR = Path.home() / "Projects"


# ── Preset loading ────────────────────────────────────────────────────────

def load_preset(type_: str, lifecycle: str) -> dict:
    """Load preset YAML, resolving extends chain recursively."""
    preset_file = PRESETS_DIR / f"{type_}-{lifecycle}.yml"
    if not preset_file.exists():
        sys.exit(f"ERROR: No preset file found: {preset_file}\n"
                 f"Available: {[p.name for p in PRESETS_DIR.glob('*.yml')]}")
    preset = yaml.safe_load(preset_file.read_text())
    if not preset.get("extends"):
        return preset
    parent_name = preset["extends"]
    # "container-experimental" → type=container, lifecycle=experimental
    parts = parent_name.rsplit("-", 1)
    parent = load_preset(parts[0], parts[1])
    # Merge: parent base, child overrides scalars
    merged = {**parent, **preset}
    # Merge workflow lists: child overrides by name
    parent_wf = {w["name"]: w for w in parent.get("workflows", [])}
    for wf in preset.get("workflows", []):
        parent_wf[wf["name"]] = wf
    merged["workflows"] = list(parent_wf.values())
    # Merge makefile_targets: deduplicate, preserving order
    seen, targets = set(), []
    for t in parent.get("makefile_targets", []) + preset.get("makefile_targets", []):
        if t not in seen:
            targets.append(t)
            seen.add(t)
    merged["makefile_targets"] = targets
    return merged


# ── Workflow templates ────────────────────────────────────────────────────

DEVSECOPS_SHA = subprocess.check_output(
    ["git", "rev-parse", "HEAD"], cwd=DEVSECOPS_DIR, text=True
).strip()


def workflow_security_containers(cron: str) -> str:
    return f"""name: Security

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: "{cron}"
  workflow_dispatch:

jobs:
  security:
    uses: Scorp10N/devsecops/.github/workflows/security-containers.yml@{DEVSECOPS_SHA}
    with:
      images: '["tailscale/tailscale:latest", "nginx:alpine"]'
    secrets: inherit
"""


def workflow_check_key_expiry(cron: str) -> str:
    return f"""name: Check Tailscale key expiry

on:
  schedule:
    - cron: "{cron}"
  workflow_dispatch:

jobs:
  check:
    name: Check auth key expiry
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4

      - name: Check key expiry
        id: check
        env:
          TS_API_TOKEN: ${{{{ secrets.TS_API_TOKEN }}}}
        run: |
          python3 - <<'PYEOF'
          import os, json
          from urllib.request import Request, urlopen
          from datetime import datetime, timezone
          token = os.environ["TS_API_TOKEN"]
          req = Request("https://api.tailscale.com/api/v2/tailnet/-/keys",
                        headers={{"Authorization": f"Bearer {{token}}"}})
          with urlopen(req) as r:
              keys = json.load(r)["keys"]
          now = datetime.now(timezone.utc)
          expiring = []
          for k in keys:
              if not k.get("expires"):
                  continue
              exp = datetime.fromisoformat(k["expires"].replace("Z", "+00:00"))
              days = (exp - now).days
              print(f"Key {{k['id']}} expires in {{days}} days")
              if days <= 14:
                  expiring.append((k["id"], k.get("description", ""), days, k["expires"]))
          if expiring:
              body = "## Tailscale auth key expiry warning\\n\\n"
              for kid, desc, days, exp in expiring:
                  body += f"- `{{kid}}` ({{desc}}): **{{days}} days** (expires {{exp}})\\n"
              body += "\\nRun `./start.sh` to mint a fresh key.\\n"
              with open(os.environ["GITHUB_OUTPUT"], "a") as f:
                  f.write("expiring=true\\n")
                  f.write(f"body<<EOF\\n{{body}}\\nEOF\\n")
          else:
              with open(os.environ["GITHUB_OUTPUT"], "a") as f:
                  f.write("expiring=false\\n")
          PYEOF

      - name: Open issue if expiring soon
        if: steps.check.outputs.expiring == 'true'
        env:
          GH_TOKEN: ${{{{ secrets.GITHUB_TOKEN }}}}
        run: |
          gh issue create \\
            --title "Tailscale auth key expiring soon" \\
            --body "${{{{ steps.check.outputs.body }}}}" \\
            --label "maintenance" || true
"""


def workflow_update_image_pins(cron: str) -> str:
    return f"""name: Pin container images

on:
  schedule:
    - cron: "{cron}"
  workflow_dispatch:

jobs:
  pin:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4
      - name: Update pins
        run: make pin-images
      - name: Open PR if changed
        env:
          GH_TOKEN: ${{{{ secrets.GITHUB_TOKEN }}}}
        run: |
          git diff --quiet docker-compose.yml && exit 0
          git config user.email "actions@github.com"
          git config user.name "GitHub Actions"
          BRANCH="chore/pin-images-$(date +%Y%m%d)"
          git checkout -b "$BRANCH"
          git add docker-compose.yml
          git commit -m "chore: update container image digest pins $(date +%Y-%m-%d)"
          git push origin "$BRANCH"
          gh pr create --title "chore: update container image pins $(date +%Y-%m-%d)" \\
            --body "Automated digest update." --base main --head "$BRANCH"
"""


WORKFLOW_TEMPLATES = {
    "security-containers.yml": workflow_security_containers,
    "check-key-expiry.yml": workflow_check_key_expiry,
    "update-image-pins.yml": workflow_update_image_pins,
}


# ── Makefile generation ───────────────────────────────────────────────────

MAKEFILE_TARGETS = {
    "start":       ".PHONY: start\nstart:\n\t./start.sh\n",
    "stop":        ".PHONY: stop\nstop:\n\tdocker compose down\n",
    "logs":        ".PHONY: logs\nlogs:\n\tdocker compose logs -f\n",
    "status":      ".PHONY: status\nstatus:\n\tdocker compose exec tailscale tailscale funnel status\n",
    "scan":        ".PHONY: scan\nscan:\n\t@for img in tailscale/tailscale:latest nginx:alpine; do \\\n\t\ttrivy image $$img; \\\n\tdone\n",
    "pin-images":  ".PHONY: pin-images\npin-images:\n\t@TAILSCALE_DIGEST=$$(docker buildx imagetools inspect tailscale/tailscale:latest \\\n\t  --format '{{json .Manifest}}' | python3 -c \"import sys,json; print(json.load(sys.stdin)['digest'])\"); \\\n\tNGINX_DIGEST=$$(docker buildx imagetools inspect nginx:alpine \\\n\t  --format '{{json .Manifest}}' | python3 -c \"import sys,json; print(json.load(sys.stdin)['digest'])\"); \\\n\tsed -i \"s|tailscale/tailscale:latest@sha256:[a-f0-9]*|tailscale/tailscale:latest@$$TAILSCALE_DIGEST|\" docker-compose.yml; \\\n\tsed -i \"s|nginx:alpine@sha256:[a-f0-9]*|nginx:alpine@$$NGINX_DIGEST|\" docker-compose.yml; \\\n\techo \"Pinned tailscale@$$TAILSCALE_DIGEST nginx@$$NGINX_DIGEST\"\n",
    "sync-resume": ".PHONY: sync-resume\nsync-resume:\n\tgh api repos/Scorp10N/resume/contents/index.html \\\n\t  | python3 -c \"import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['content']).decode())\" \\\n\t  > resume/index.html\n\t@echo 'Review: git diff resume/index.html'\n",
}


def generate_makefile(targets: list) -> str:
    lines = [".PHONY: " + " ".join(targets), ""]
    for t in targets:
        if t not in MAKEFILE_TARGETS:
            print(f"  WARNING: no template for Makefile target '{t}', skipping")
            continue
        lines.append(MAKEFILE_TARGETS[t])
    return "\n".join(lines)


# ── Core applier ──────────────────────────────────────────────────────────

def apply(repo: str, preset: dict, repo_dir: Path, dry_run: bool) -> list:
    """Apply preset to repo_dir. Returns list of change dicts."""
    changes = []

    # 1. Inject workflow files
    wf_dir = repo_dir / ".github" / "workflows"
    for wf in preset.get("workflows", []):
        template_fn = WORKFLOW_TEMPLATES.get(wf["template"])
        if not template_fn:
            print(f"  WARNING: unknown template '{wf['template']}', skipping")
            continue
        content = template_fn(wf.get("cron", "0 6 * * 1"))
        dest = wf_dir / f"{wf['name']}.yml"
        if dest.exists() and dest.read_text() == content:
            changes.append({"file": str(dest.relative_to(repo_dir)), "action": "unchanged"})
        else:
            action = "updated" if dest.exists() else "created"
            if not dry_run:
                wf_dir.mkdir(parents=True, exist_ok=True)
                dest.write_text(content)
            changes.append({"file": str(dest.relative_to(repo_dir)), "action": action})

    # 2. Inject Makefile targets (preserve custom targets)
    makefile_path = repo_dir / "Makefile"
    new_targets = preset.get("makefile_targets", [])
    if makefile_path.exists():
        existing = makefile_path.read_text()
        missing = [t for t in new_targets if f"\n{t}:" not in existing and not existing.startswith(f"{t}:")]
        if missing:
            addition = "\n" + generate_makefile(missing)
            if not dry_run:
                makefile_path.write_text(existing + addition)
            changes.append({"file": "Makefile", "action": "updated", "targets_added": missing})
        else:
            changes.append({"file": "Makefile", "action": "unchanged"})
    else:
        content = generate_makefile(new_targets)
        if not dry_run:
            makefile_path.write_text(content)
        changes.append({"file": "Makefile", "action": "created"})

    # 3. Write .devkeys.yml (namespace declaration)
    devkeys_path = repo_dir / ".devkeys.yml"
    repo_slug = repo.split("/")[-1]
    devkeys_content = f"namespace: {repo_slug}\nshared_access: []\n"
    if not devkeys_path.exists():
        if not dry_run:
            devkeys_path.write_text(devkeys_content)
        changes.append({"file": ".devkeys.yml", "action": "created"})

    # 4. Write .bootstrap.yml lock file
    lock = {
        "preset": preset["preset"],
        "devsecops_ref": DEVSECOPS_SHA,
        "applied_at": datetime.now(timezone.utc).isoformat(),
    }
    lock_path = repo_dir / ".bootstrap.yml"
    if not dry_run:
        lock_path.write_text(yaml.dump(lock, default_flow_style=False))
    changes.append({"file": ".bootstrap.yml", "action": "written"})

    return changes


def seed_secrets(repo: str, preset: dict, dry_run: bool) -> tuple:
    """Seed GitHub Secrets. Try devkeys first, fall back to manual prompt."""
    seeded, skipped = [], []
    for s in preset.get("secrets", []):
        name = s["name"]
        devkeys_key = s.get("devkeys_key", name)
        required = s.get("required", True)

        try:
            result = subprocess.run(
                ["devkeys", "get", devkeys_key, "--reveal"],
                capture_output=True, text=True
            )
            devkeys_ok = result.returncode == 0 and result.stdout.strip()
            value = result.stdout.strip() if devkeys_ok else ""
        except FileNotFoundError:
            devkeys_ok = False
            value = ""
        if devkeys_ok:
            if not dry_run:
                subprocess.run(
                    ["gh", "secret", "set", name, "-R", repo],
                    input=value, text=True, check=True
                )
            seeded.append(name)
        elif required:
            if not dry_run:
                print(f"\n  Secret '{name}' not found in devkeys.")
                print(f"  Run: gh secret set {name} -R {repo}")
            skipped.append(name)
        else:
            skipped.append(name)
    return seeded, skipped


def _get_or_clone(org_repo: str, projects_dir: Path, tmpdir: Path) -> Path:
    """Return path to a local clone, reusing ~/Projects/<repo> if available."""
    repo_slug = org_repo.split("/")[-1]
    local = projects_dir / repo_slug
    if local.is_dir() and (local / ".git").is_dir():
        subprocess.run(["git", "pull", "--ff-only"], cwd=local, check=True)
        return local
    cloned = tmpdir / repo_slug
    subprocess.run(["gh", "repo", "clone", org_repo, str(cloned)], check=True)
    return cloned


def register_repo(repo: str, type_: str, lifecycle: str, dry_run: bool,
                  projects_dir: Path = DEFAULT_PROJECTS_DIR):
    """Open PRs to repo-audit and security-data to register the repo."""
    repo_slug = repo.split("/")[-1]

    audit_entry = f"""id: {repo_slug}
full_name: {repo}
visibility: private
status: active
kind: Component
type: {type_}
lifecycle: {lifecycle}
owner: user:yarin
domain: infrastructure
description: ""
source_of_truth: implementation
integrations:
  copilot: not_applicable
  github_actions: active
  mission_control: not_applicable
  backstage: later
  cartography: later
documentation:
  readme: present
  roadmap: not_applicable
  architecture: not_applicable
  runbook: not_applicable
  security: not_applicable
  owner_notes: not_applicable
  docs_owner: repo-local
"""

    if dry_run:
        print(f"  [dry-run] Would open PR to repo-audit: repos/{repo_slug}.yml")
        print(f"  [dry-run] Would add {repo} to security-data/repo-map.yml")
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # ── repo-audit ────────────────────────────────────────────────────
        audit_dir = _get_or_clone("Scorp10N/repo-audit", projects_dir, tmp)
        entry_file = audit_dir / "repos" / f"{repo_slug}.yml"
        if not entry_file.exists():
            branch = f"feat/register-{repo_slug}"
            subprocess.run(["git", "checkout", "-b", branch], cwd=audit_dir, check=True)
            entry_file.write_text(audit_entry)
            subprocess.run(["git", "add", str(entry_file)], cwd=audit_dir, check=True)
            subprocess.run(["git", "commit", "-m", f"feat: register {repo_slug}"],
                           cwd=audit_dir, check=True)
            subprocess.run(["git", "push", "origin", branch], cwd=audit_dir, check=True)
            subprocess.run([
                "gh", "pr", "create",
                "--title", f"feat: register {repo_slug}",
                "--body", "Auto-generated by bootstrap applier.",
                "--base", "main", "--head", branch,
                "-R", "Scorp10N/repo-audit"
            ], cwd=audit_dir, check=True)
            print(f"  Opened PR in Scorp10N/repo-audit")
        else:
            print(f"  {repo_slug} already registered in repo-audit, skipping PR")

        # ── security-data ─────────────────────────────────────────────────
        sd_dir = _get_or_clone("Scorp10N/security-data", projects_dir, tmp)
        repo_map_path = sd_dir / "repo-map.yml"
        repo_map = yaml.safe_load(repo_map_path.read_text())
        names = [r["name"] for r in repo_map.get("repos", [])]
        if repo not in names:
            sd_branch = f"feat/add-{repo_slug}"
            subprocess.run(["git", "checkout", "-b", sd_branch], cwd=sd_dir, check=True)
            repo_map.setdefault("repos", []).append({
                "name": repo,
                "has_python": False,
                "has_go": False,
                "has_node": False,
                "has_containers": True,
            })
            repo_map_path.write_text(yaml.dump(repo_map, default_flow_style=False))
            findings_dir = sd_dir / "findings" / repo_slug / "latest"
            findings_dir.mkdir(parents=True, exist_ok=True)
            (findings_dir / ".gitkeep").touch()
            subprocess.run(["git", "add", "."], cwd=sd_dir, check=True)
            subprocess.run(["git", "commit", "-m", f"feat: add {repo_slug} to repo-map"],
                           cwd=sd_dir, check=True)
            subprocess.run(["git", "push", "origin", sd_branch], cwd=sd_dir, check=True)
            subprocess.run([
                "gh", "pr", "create",
                "--title", f"feat: add {repo_slug} to security posture tracking",
                "--body", "Auto-generated by bootstrap applier.",
                "--base", "main", "--head", sd_branch,
                "-R", "Scorp10N/security-data"
            ], cwd=sd_dir, check=True)
            print(f"  Opened PR in Scorp10N/security-data")
        else:
            print(f"  {repo} already in security-data/repo-map.yml, skipping PR")


# ── CLI ───────────────────────────────────────────────────────────────────

def wizard_mode():
    """Interactive TUI wizard using rich prompts."""
    try:
        from rich.prompt import Prompt
        from rich.console import Console
        console = Console()
    except ImportError:
        sys.exit("ERROR: 'rich' not installed. Run: pip install rich")

    console.print("\n[bold cyan]Bootstrap Repo Wizard[/bold cyan]\n")
    repo = Prompt.ask("Repository (e.g. Scorp10N/my-repo)")
    type_ = Prompt.ask("Type", choices=["container", "service", "library", "platform"],
                       default="container")
    lifecycle = Prompt.ask("Lifecycle", choices=["experimental", "production"],
                           default="experimental")
    dry_run = Prompt.ask("Dry run?", choices=["yes", "no"], default="no") == "yes"
    return repo, type_, lifecycle, dry_run


def main():
    parser = argparse.ArgumentParser(description="Bootstrap a repo to a devsecops preset")
    parser.add_argument("--repo", help="Full repo name e.g. Scorp10N/my-repo")
    parser.add_argument("--type", dest="type_", help="Preset type")
    parser.add_argument("--lifecycle", help="Lifecycle stage")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--output", choices=["human", "json"], default="human")
    parser.add_argument("--wizard", action="store_true")
    parser.add_argument("--projects-dir", type=Path, default=DEFAULT_PROJECTS_DIR,
                        help="Directory containing locally-cloned repos (default: ~/Projects)")
    args = parser.parse_args()

    if args.wizard:
        repo, type_, lifecycle, dry_run = wizard_mode()
    elif not (args.repo and args.type_ and args.lifecycle):
        parser.error("--repo, --type, and --lifecycle are required (or use --wizard)")
    else:
        repo, type_, lifecycle, dry_run = args.repo, args.type_, args.lifecycle, args.dry_run

    print(f"\nBootstrapping {repo} with preset {type_}-{lifecycle}"
          + (" [DRY RUN]" if dry_run else ""))
    preset = load_preset(type_, lifecycle)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        repo_dir = _get_or_clone(repo, args.projects_dir, tmp) if not dry_run \
            else tmp / repo.split("/")[-1]
        if dry_run:
            repo_dir.mkdir()

        changes = apply(repo, preset, repo_dir, dry_run)
        seeded, skipped = seed_secrets(repo, preset, dry_run)
        register_repo(repo, type_, lifecycle, dry_run, args.projects_dir)

        if not dry_run:
            subprocess.run(["git", "config", "user.email", "ci@scorp10n.github"],
                           cwd=repo_dir, check=True)
            subprocess.run(["git", "config", "user.name", "Bootstrap Bot"],
                           cwd=repo_dir, check=True)
            subprocess.run(["git", "add", "-A"], cwd=repo_dir, check=True)
            result = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=repo_dir)
            if result.returncode != 0:
                subprocess.run([
                    "git", "commit", "-m",
                    f"chore: apply bootstrap preset {type_}-{lifecycle} @ {DEVSECOPS_SHA[:8]}"
                ], cwd=repo_dir, check=True)
                subprocess.run(["git", "push"], cwd=repo_dir, check=True)

    result = {
        "repo": repo,
        "preset": f"{type_}-{lifecycle}",
        "status": "dry-run" if dry_run else "applied",
        "changes": changes,
        "secrets_seeded": seeded,
        "secrets_skipped": skipped,
    }

    if args.output == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"\nResult: {result['status']}")
        for c in changes:
            icon = "✓" if c["action"] == "unchanged" else "+"
            print(f"  {icon} {c['file']} [{c['action']}]")
        if seeded:
            print(f"  Secrets seeded: {', '.join(seeded)}")
        if skipped:
            print(f"  Secrets skipped (set manually): {', '.join(skipped)}")


if __name__ == "__main__":
    main()
