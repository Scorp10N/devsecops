# Scorp10N Security Platform

Reusable GitHub Actions security workflows and config templates for all Scorp10N repositories.

## Repo Layout

```
.github/workflows/
  security-all.yml          ← reusable workflow (5 jobs) — call with one line per repo
  sync-configs.yml          ← GitOps: auto-PR config changes to consuming repos
configs/
  semgrep.yml               ← custom SAST rules (project-specific patterns)
  trufflehog.toml           ← TruffleHog scan config + exclusion paths
  trivy-ignore.txt          ← CVE allowlist (unfixed or accepted risk, documented)
  .pre-commit-config.yaml   ← canonical pre-commit hooks (synced to each repo root)
```

## Calling the Reusable Workflow

Add this to `.github/workflows/security.yml` in any consuming repo:

```yaml
name: Security
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'
jobs:
  security:
    uses: Scorp10N/devsecops/.github/workflows/security-all.yml@main
    with:
      engine_dockerfile: "./engine"
      web_dockerfile: "./web"
      web_build_args: "VITE_ENGINE_URL=http://localhost:8080"
      go_version: "1.22"
      node_version: "20"
      has_go: true
      has_node: true
      has_containers: true
      codeql_languages: '["python","go","javascript-typescript"]'
    secrets: inherit
```

## Level A — Active Now

- CI-gated PRs: all status checks must pass before merge
- No direct push to `main` (all changes via PR)
- CODEOWNERS: @Scorp10N required on all changes
- Dependabot: weekly PRs for pip / gomod / npm / github-actions
- Pre-commit: ruff, file hygiene, TruffleHog, detect-private-key
- Security scans: TruffleHog · pip-audit · govulncheck · npm audit · Trivy · CodeQL · Semgrep

## Level B — When Team Grows (copy-paste ready)

Require signed commits:
```bash
gh api --method PATCH repos/Scorp10N/resumeforge/branches/main/protection \
  -f required_signatures=true
```

Enable GitHub native secret scanning push protection (free for public repos):
```bash
gh api --method PATCH repos/Scorp10N/resumeforge \
  -f security_and_analysis.secret_scanning_push_protection.status=enabled
```

Enable Dependabot security auto-fix PRs:
```bash
gh api --method PUT repos/Scorp10N/resumeforge/vulnerability-alerts
gh api --method PUT repos/Scorp10N/resumeforge/automated-security-fixes
```

Require 1 reviewer on PRs:
```bash
gh api --method PATCH repos/Scorp10N/resumeforge/branches/main/protection \
  --input - <<'JSON'
{"required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": true, "require_code_owner_reviews": true}}
JSON
```

## Level C — When Team > 2

Enforce admins (no bypass):
```bash
gh api --method PATCH repos/Scorp10N/resumeforge/branches/main/protection \
  -f enforce_admins=true
```

Require 2 reviewers:
```bash
gh api --method PATCH repos/Scorp10N/resumeforge/branches/main/protection \
  -f required_pull_request_reviews.required_approving_review_count=2
```

Add SLSA provenance to releases — see https://slsa.dev/spec/v1.0/ and `slsa-framework/slsa-github-generator`.

## Adding a New Repository

1. Add `.github/workflows/security.yml` calling `security-all.yml@main` (template above)
2. Add `.github/dependabot.yml` for the repo's package ecosystems
3. Add `.github/CODEOWNERS`
4. Copy `configs/.pre-commit-config.yaml` to the repo root; run `pre-commit install`
5. Add the repo to `matrix.repo` in `sync-configs.yml` and commit
6. Wait for the first workflow run to succeed (check names appear in GitHub Checks tab)
7. Run the `gh api` branch protection command from this README

## Required Secrets

| Secret | Location | Purpose |
|--------|----------|---------|
| `SYNC_PAT` | `devsecops` repo secrets | Fine-grained PAT: Contents+PRs write on consuming repos |
| `GITHUB_TOKEN` | Auto-provided by Actions | CodeQL SARIF upload, Trivy |
