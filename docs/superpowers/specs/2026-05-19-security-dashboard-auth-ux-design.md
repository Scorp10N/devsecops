# Security Dashboard — Auth UX & Feature Polish Design

**Date:** 2026-05-19
**Status:** Approved for implementation
**Branch:** `feature/security-dashboard` (continues existing work)

---

## Context

The existing `feature/security-dashboard` branch implements a SvelteKit SPA on GitHub Pages that reads `security-data` (private repo) via GitHub Contents API. Auth is a fine-grained PAT pasted manually into `TokenGate.svelte` and stored in `sessionStorage`.

This spec adds four improvements to the existing dashboard without changing the deployment model or auth strategy.

### Auth strategy decision record

**Chosen: Option A — Fine-grained PAT + UX polish**

The dashboard has one user (the repo owner). Fine-grained PATs can be scoped to `contents:read` on `security-data` only — the narrowest possible credential. The only real friction is generating the PAT; this spec eliminates that friction with a pre-filled creation link.

**Rejected: Option B — GitHub Device Flow OAuth**
Classic OAuth tokens require `repo` scope (read+write all repos). No narrower classic OAuth scope exists for private repo reads. Blast radius is worse than the current PAT approach, not better.

**Deferred: Option C — GitHub App + token vending backend**
Correct architecture for multi-user or strict expiry requirements. Three concrete shapes evaluated:
- **C1:** Tiny FastAPI service, Tailscale peer-only. Best for keeping GitHub Pages.
- **C2:** One endpoint added to yantra-admin FastAPI, dashboard moves off GitHub Pages. Best reuse of existing infra, Google OAuth gates access.
- **C3:** Cloudflare Worker, private key in Cloudflare secrets, Cloudflare Access for auth. Zero self-hosted infra.

**Migration path:** `auth.ts` exports a stable `getToken(): Promise<string | null>` interface. Migrating to Option C requires replacing only this module — the rest of the app is unchanged.

---

## Scope

Four features added to `dashboard/`:

1. **Auth UX polish** — pre-filled PAT creation link, auto-validate on paste, signed-in status chip
2. **Per-repo trend lines** — inline sparkline per repo row in PostureOverview
3. **Finding detail accordion** — expand-in-place description for each finding in ToolDrilldown
4. **Alert/notification banner** — localStorage baseline, banner for new critical/high findings since last dismissal

No backend. No new GitHub App. No OAuth flow. Static adapter, GitHub Pages.

---

## File Map

| File | Change |
|------|--------|
| `dashboard/src/lib/auth.ts` | Add `validateToken(token)` — calls GitHub API to verify PAT works |
| `dashboard/src/lib/components/TokenGate.svelte` | Rewrite: pre-filled link, paste→auto-validate, cleaner copy |
| `dashboard/src/lib/components/PostureOverview.svelte` | Add per-repo inline sparklines from `history[].by_repo` |
| `dashboard/src/lib/components/ToolDrilldown.svelte` | Add accordion state; expand `description` on click |
| `dashboard/src/lib/components/AlertBanner.svelte` | New: localStorage baseline, new-findings banner with dismiss |
| `dashboard/src/routes/+page.svelte` | Wire AlertBanner; pass signed-in state to header chip |

---

## Feature 1: Auth UX Polish

### TokenGate rewrite

**Current:** blank password input + "Sign in" button + terse note about sessionStorage.

**New behaviour:**

1. **Pre-filled PAT creation link** — a button that opens:
   ```
   https://github.com/settings/personal-access-tokens/new?description=security-dashboard&repositories=security-data
   ```
   Opens in a new tab. Copy below: "Select **Contents: Read-only**, then paste the token here."

2. **Auto-validate on paste** — on `input` event (paste or type), if the value looks like a GitHub PAT (`github_pat_` prefix or `ghp_` prefix, length > 20), call `validateToken()`. Show a spinner inline. On success: call `onToken()`. On failure: show inline error "Token invalid or doesn't have access to `security-data`."

3. **Signed-in status chip** — once authenticated, a small chip appears in the top-right of the main layout: `● Signed in  Sign out`. Clicking Sign out calls `clearToken()` and returns to the gate.

### `auth.ts` addition

```typescript
export async function validateToken(token: string): Promise<boolean> {
  const res = await fetch(
    'https://api.github.com/repos/Scorp10N/security-data/contents/posture/snapshot-latest.json',
    { headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github.raw+json' } }
  );
  return res.ok;
}
```

Called on paste before `setToken()`. Never stores an invalid token.

---

## Feature 2: Per-Repo Trend Lines

### Data

`history: PostureSnapshot[]` is already fetched. Each snapshot has `by_repo: Record<string, Summary>`. The per-repo sparkline score uses the same formula as the existing global sparkline:

```
score = critical × 10 + high × 3 + medium
```

### Layout

In `PostureOverview.svelte`, each repo row becomes a three-column flex:

```
[repo name]    [severity pills]    [sparkline 80×24px]
```

Sparkline is an inline `<svg>` path derived from `history.map(s => s.by_repo[repo])`. If a snapshot has no data for a repo (repo added mid-history), treat as score 0 for that point. Minimum 2 points to draw a line; otherwise omit the SVG.

Color: red (`#dc2626`) if latest score > 0, green (`#16a34a`) if score = 0.

---

## Feature 3: Finding Detail Accordion

### Data

`Finding.description: string` exists in the type and is populated by `normalize_findings.py` but never displayed.

### Behaviour

In `ToolDrilldown.svelte`, each finding `<li>` becomes clickable. Click toggles `expanded` state (per-finding `Set<string>` keyed by `f.id`). When expanded, a detail block appears below the title row:

```
[severity dot]  [title]  [package@version → fix_version]     ▼
  Description text here, wrapping to multiple lines.
  [→ Advisory link if f.url exists]
```

When collapsed:
```
[severity dot]  [title]  [package@version → fix_version]     ▶
```

Accordion uses CSS `max-height` transition for smooth open/close.

---

## Feature 4: Alert/Notification Banner

### Baseline

On each successful data load, compare current `posture.total` against a localStorage baseline keyed `security-dashboard:baseline`:

```typescript
interface Baseline {
  critical: number;
  high: number;
  snapshot_date: string; // posture.generated_at
}
```

### Banner logic

Show `AlertBanner` if:
- `posture.total.critical > baseline.critical` OR `posture.total.high > baseline.high`
- AND baseline exists (no banner on first ever load — set baseline silently instead)

Banner content:
```
⚠ New findings since [baseline.snapshot_date]:
  +N critical  +M high
[Dismiss]
```

Dismiss: updates `localStorage` baseline to current counts + current `generated_at`. Banner disappears.

First load (no baseline): silently write current counts as baseline. No banner shown.

### `AlertBanner.svelte` props

```typescript
let {
  current,   // Summary
  baseline,  // Baseline | null
  onDismiss, // () => void
}: { current: Summary; baseline: Baseline | null; onDismiss: () => void } = $props();
```

---

## Error Handling

| Scenario | Behaviour |
|----------|-----------|
| PAT paste — invalid token | Inline error below input, token not stored |
| PAT paste — network error during validate | Show "Could not verify — check connection", allow manual submit |
| Data load — auth error (token revoked) | Clear token, return to TokenGate with message "Token expired or revoked" |
| Data load — 404 on snapshot | Show "No posture data yet — run the aggregation workflow" |
| Data load — network error | Show error banner, keep stale data visible if available |
| history fetch fails | PostureOverview renders without sparklines (graceful degrade) |

---

## Option C Backlog (deferred)

When a second user is added or token expiry becomes a requirement, migrate to Option C by:

1. Creating a GitHub App (`devsecops-automator` already exists — add `contents:read` installation on `security-data`)
2. Adding a token vending endpoint (C1: Tailscale FastAPI, C2: yantra-admin, or C3: Cloudflare Worker)
3. Replacing `auth.ts` `getToken()` to call the endpoint instead of sessionStorage
4. Removing `TokenGate.svelte` and `validateToken()`

No other files change. The `getToken(): Promise<string | null>` interface is the migration seam.

**Recommended shape when needed:** C2 (yantra-admin endpoint) — zero new infra, Google OAuth already in place, token scope narrows to `contents:read` with 1-hour expiry.

---

## Testing

Manual test checklist (no automated E2E — SPA reads private repo, requires live PAT):

- [ ] Open dashboard with no token → TokenGate shown
- [ ] Click PAT creation link → opens GitHub in new tab with description + repo pre-filled
- [ ] Paste valid PAT → spinner shown → auto-redirects to dashboard
- [ ] Paste invalid PAT → inline error, token not stored
- [ ] Paste valid PAT with wrong permissions → inline error "doesn't have access to security-data"
- [ ] Signed-in chip visible → click Sign out → TokenGate shown
- [ ] PostureOverview shows per-repo sparklines (one per repo, color matches posture)
- [ ] Repo with no history → sparkline absent, counts still shown
- [ ] Click finding row → accordion expands with description
- [ ] Click again → collapses
- [ ] New critical/high since baseline → banner appears on load
- [ ] Dismiss banner → banner gone → re-load → banner still gone
- [ ] First ever load (no localStorage) → no banner, baseline written silently
