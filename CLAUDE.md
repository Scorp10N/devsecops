# devsecops — Claude Notes

## CI Credentials

Cross-repo automation uses the `devsecops-automator` GitHub App (App ID: 3767249).

| Secret | Purpose |
|--------|---------|
| `DEVSECOPS_APP_ID` | App numeric ID — not sensitive |
| `DEVSECOPS_APP_PRIVATE_KEY` | App private key — mints short-lived tokens per run |

Installed on: `security-data`, `resumeforge`, `resumeforge-cloud`.

Token lifetime: ≤1 hour per run. No stored long-lived credential.

**To rotate the key:**
1. GitHub → Settings → Developer settings → GitHub Apps → devsecops-automator → Private keys → Generate a private key
2. `gh secret set DEVSECOPS_APP_PRIVATE_KEY --body "$(cat new-key.pem)" -R Scorp10N/devsecops`
3. Delete the old key from the GitHub App settings page
4. `rm new-key.pem`
