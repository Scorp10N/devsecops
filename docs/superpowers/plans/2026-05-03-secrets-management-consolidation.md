# Secrets Management Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consolidate scattered sops/age/TPM setup documentation into a single canonical guide, sync dotfiles, trim project CLAUDE.md files to lean references, and create an auto-loading Claude Code skill for secrets management.

**Architecture:** One canonical doc in devsecops drives everything else. The dotfiles template stays in sync so fresh machines get the right PATH and env vars. Project CLAUDE.md files shrink to a pointer. A Claude Code skill auto-loads conventions and runs a health check whenever a project uses sops.

**Tech Stack:** sops v3.12.2, age v1.3.1, age-plugin-tpm v1.0.1, tpm2-abrmd, Claude Code skills (markdown), bash

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `devsecops/docs/sops-age-tpm.md` | Create | Canonical full setup guide |
| `dotfiles/linux/bashrc` | Modify | Add `~/go/bin` to PATH + `SOPS_AGE_KEY_FILE` |
| `MyLocalLLM/CLAUDE.md` | Modify | Replace verbose first-time setup with 2-line reference |
| `security-data/CLAUDE.md` | Modify | Replace verbose first-time setup with 2-line reference |
| `~/.claude/skills/secrets-management.md` | Create | Auto-loading skill: conventions + health check |

---

### Task 1: Create canonical sops-age-tpm guide

**Files:**
- Create: `devsecops/docs/sops-age-tpm.md`

- [ ] **Step 1: Create the guide**

Write `devsecops/docs/sops-age-tpm.md` with this exact content:

```markdown
# sops + age + TPM Setup Guide

Canonical reference for encrypting project secrets with SOPS, age, and a TPM-backed identity.
The private key lives inside the TPM chip and is never written to disk.

## Stack

| Tool | Version | Source |
|------|---------|--------|
| sops | v3.12.2 | `brew install sops` |
| age | v1.3.1 | `brew install age` |
| age-plugin-tpm | v1.0.1 | `go install github.com/foxboron/age-plugin-tpm/cmd/age-plugin-tpm@latest` |
| tpm2-abrmd | distro pkg | `sudo dnf install tpm2-abrmd tpm2-tools` |

## Prerequisites

```bash
# Install TPM userspace tools
sudo dnf install tpm2-abrmd tpm2-tools

# Enable resource manager daemon
sudo systemctl enable --now tpm2-abrmd

# Add yourself to the tss group — requires FULL REBOOT (not just re-login)
sudo usermod -aG tss $USER
sudo reboot
```

After reboot, verify: `groups | grep tss`

## Install age-plugin-tpm

```bash
go install github.com/foxboron/age-plugin-tpm/cmd/age-plugin-tpm@latest
ln -sf ~/go/bin/age-plugin-tpm ~/go/bin/age-plugin-tag
```

`~/go/bin` must be in PATH — see Shell Config below.

## Generate TPM Identity

```bash
mkdir -p ~/.config/sops/age
~/go/bin/age-plugin-tpm --generate --tpm-recipient \
  -o ~/.config/sops/age/tpm-identity.txt
```

Note the `age1tpm1...` recipient line — you'll need it for `.sops.yaml`.

```bash
grep Recipient ~/.config/sops/age/tpm-identity.txt
```

## Configure .sops.yaml

```yaml
creation_rules:
  - age: age1tpm1<your-public-key-here>
```

## Encrypt / Re-encrypt Secrets

First time encrypting a file:
```bash
sops --encrypt --age age1tpm1<your-key> secrets.yaml > secrets.enc.yaml
```

Adding a new recipient to an existing file:
```bash
# 1. Add the new age1tpm1... key to .sops.yaml
# 2. Re-encrypt:
sops updatekeys secrets.enc.yaml
```

## Shell Config

Add to `~/.bashrc` (or sync via dotfiles):

```bash
export PATH="$HOME/.local/npm/bin:$HOME/go/bin:$PATH"
export SOPS_AGE_KEY_FILE="$HOME/.config/sops/age/tpm-identity.txt"
```

## Daily Use

```bash
# Decrypt to stdout
sops --decrypt secrets.enc.yaml

# Edit in-place (decrypts → $EDITOR → re-encrypts on save)
sops secrets.enc.yaml
```

## Threat Model

| Threat | Mitigated? |
|--------|-----------|
| File theft / backup exposure | ✓ No key file to steal — identity handle is useless alone |
| Disk forensics | ✓ Key material sealed in TPM chip |
| Privilege escalation reading key file | ✓ No plaintext key file |
| Malware running as your user | ✗ TPM is transparent to your session |
| Physical TPM extraction | ✗ Very sophisticated attack |

The TPM key is bound to this machine. To migrate to a new machine, generate a new identity,
add it as a recipient, re-encrypt, then remove the old recipient.
```

- [ ] **Step 2: Verify the file renders cleanly**

```bash
wc -l ~/Projects/devsecops/docs/sops-age-tpm.md
# Should be > 80 lines
head -5 ~/Projects/devsecops/docs/sops-age-tpm.md
# Should print "# sops + age + TPM Setup Guide"
```

- [ ] **Step 3: Commit**

```bash
cd ~/Projects/devsecops
git add docs/sops-age-tpm.md
git commit -m "docs: add canonical sops + age + TPM setup guide"
```

---

### Task 2: Update dotfiles bashrc template

**Files:**
- Modify: `dotfiles/linux/bashrc`

The template currently has:
```bash
export PATH="$HOME/.local/npm/bin:$PATH"
```

It is missing `$HOME/go/bin` in PATH and the `SOPS_AGE_KEY_FILE` export.

- [ ] **Step 1: Verify current state**

```bash
grep -n "go/bin\|SOPS_AGE" ~/Projects/dotfiles/linux/bashrc
# Expected: no output (both lines are absent)
```

- [ ] **Step 2: Update the PATH line and add SOPS_AGE_KEY_FILE**

In `dotfiles/linux/bashrc`, replace:
```bash
export PATH="$HOME/.local/npm/bin:$PATH"
```
with:
```bash
export PATH="$HOME/.local/npm/bin:$HOME/go/bin:$PATH"
export SOPS_AGE_KEY_FILE="$HOME/.config/sops/age/tpm-identity.txt"
```

- [ ] **Step 3: Verify**

```bash
grep -n "go/bin\|SOPS_AGE" ~/Projects/dotfiles/linux/bashrc
# Expected:
# <line>:export PATH="$HOME/.local/npm/bin:$HOME/go/bin:$PATH"
# <line>:export SOPS_AGE_KEY_FILE="$HOME/.config/sops/age/tpm-identity.txt"
```

- [ ] **Step 4: Smoke test — source as fresh shell**

```bash
bash --norc --noprofile -c '
  source ~/Projects/dotfiles/linux/bashrc 2>/dev/null || true
  echo "SOPS_AGE_KEY_FILE=$SOPS_AGE_KEY_FILE"
'
# Expected: SOPS_AGE_KEY_FILE=/home/yarin/.config/sops/age/tpm-identity.txt
```

Note: the brew shellenv line may fail in a bare shell — that's fine, focus on the two exports.

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/dotfiles
git add linux/bashrc
git commit -m "feat: add go/bin to PATH and SOPS_AGE_KEY_FILE to bashrc template"
```

---

### Task 3: Trim MyLocalLLM/CLAUDE.md first-time setup block

**Files:**
- Modify: `MyLocalLLM/CLAUDE.md`

The "First-time setup on a new machine" section (lines ~85-108) contains a verbose shell script. Replace it with a 2-line pointer to the canonical guide.

- [ ] **Step 1: Locate the section**

```bash
grep -n "First-time setup" ~/Projects/MyLocalLLM/CLAUDE.md
```

- [ ] **Step 2: Replace the first-time setup block**

In `MyLocalLLM/CLAUDE.md`, find and replace the entire block from `### First-time setup on a new machine` through the closing ` ``` ` of the sops updatekeys step.

Replace with:
```markdown
### Setup

See: `~/Projects/devsecops/docs/sops-age-tpm.md`
```

- [ ] **Step 3: Verify the section is gone and reference is present**

```bash
grep -n "brew install\|dnf install tpm2\|age-plugin-tpm --generate\|First-time setup" ~/Projects/MyLocalLLM/CLAUDE.md
# Expected: no output

grep -n "sops-age-tpm.md" ~/Projects/MyLocalLLM/CLAUDE.md
# Expected: one line with the reference
```

- [ ] **Step 4: Confirm the Secrets Management section still reads cleanly**

```bash
grep -A 20 "## Secrets Management" ~/Projects/MyLocalLLM/CLAUDE.md
# Should show: How it works block + ### Setup + reference line
```

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/MyLocalLLM
git add CLAUDE.md
git commit -m "docs: replace verbose sops setup with reference to canonical guide"
```

---

### Task 4: Trim security-data/CLAUDE.md first-time setup block

**Files:**
- Modify: `security-data/CLAUDE.md`

Same pattern as Task 3 — the `### First-time setup on a new machine` block should become a 2-line pointer.

- [ ] **Step 1: Locate the section**

```bash
grep -n "First-time setup" ~/Projects/security-data/CLAUDE.md
```

- [ ] **Step 2: Replace the first-time setup block**

In `security-data/CLAUDE.md`, find and replace the entire block from `### First-time setup on a new machine` through the closing ` ``` ` of the sops updatekeys step.

Replace with:
```markdown
### Setup

See: `~/Projects/devsecops/docs/sops-age-tpm.md`
```

- [ ] **Step 3: Verify**

```bash
grep -n "brew install\|dnf install tpm2\|age-plugin-tpm --generate\|First-time setup" ~/Projects/security-data/CLAUDE.md
# Expected: no output

grep -n "sops-age-tpm.md" ~/Projects/security-data/CLAUDE.md
# Expected: one line with the reference
```

- [ ] **Step 4: Commit**

```bash
cd ~/Projects/security-data
git add CLAUDE.md
git commit -m "docs: replace verbose sops setup with reference to canonical guide"
```

---

### Task 5: Create secrets-management Claude Code skill

**Files:**
- Create: `~/.claude/skills/secrets-management.md`

- [ ] **Step 1: Create the skill file**

Write `~/.claude/skills/secrets-management.md` with this exact content:

```markdown
---
name: secrets-management
description: Auto-loads when a project uses sops/age. Injects conventions into context and runs a TPM health check.
triggers:
  - file: secrets.enc.yaml
  - file: .sops.yaml
  - keyword: secrets
  - keyword: sops
  - keyword: age key
  - keyword: encrypt
  - keyword: decrypt
---

# Secrets Management Conventions

This project uses **sops + age + TPM** for secret encryption.

## Stack

- sops v3.12.2 — encrypts/decrypts `secrets.enc.yaml`
- age v1.3.1 (linuxbrew) — encryption backend
- age-plugin-tpm v1.0.1 — TPM-backed identity; private key sealed in TPM chip
- Identity file: `~/.config/sops/age/tpm-identity.txt` (handle only, not the key)
- Recipient format: `age1tpm1...`
- Shell env: `SOPS_AGE_KEY_FILE="$HOME/.config/sops/age/tpm-identity.txt"` in `~/.bashrc`

## Rules

1. Use `age1tpm1...` as the recipient in `.sops.yaml` — never plaintext age keys.
2. When adding a recipient to an existing file: update `.sops.yaml`, then run `sops updatekeys <file>`.
3. Reference `~/Projects/devsecops/docs/sops-age-tpm.md` in any new project setup docs.
4. Never suggest storing the private key material on disk — the TPM identity file holds only a handle.

## Health Check

Run and report the result of each check. Mark ✓ if passing, ✗ + remediation hint if failing.

```bash
# 1. TPM identity file exists
ls ~/.config/sops/age/tpm-identity.txt

# 2. SOPS_AGE_KEY_FILE is set
[ -n "$SOPS_AGE_KEY_FILE" ] && echo "set: $SOPS_AGE_KEY_FILE" || echo "UNSET"

# 3. tpm2-abrmd is running
systemctl is-active tpm2-abrmd

# 4. sops can decrypt a known file
sops --decrypt ~/Projects/MyLocalLLM/secrets.enc.yaml > /dev/null && echo "ok"
```

### Remediation hints

| Check | Failure | Fix |
|-------|---------|-----|
| Identity file | `No such file` | Run `age-plugin-tpm --generate --tpm-recipient -o ~/.config/sops/age/tpm-identity.txt` |
| SOPS_AGE_KEY_FILE | `UNSET` | Add `export SOPS_AGE_KEY_FILE="$HOME/.config/sops/age/tpm-identity.txt"` to `~/.bashrc` and source it |
| tpm2-abrmd | `inactive` | Run `sudo systemctl start tpm2-abrmd`; if not installed: `sudo dnf install tpm2-abrmd && sudo systemctl enable --now tpm2-abrmd` |
| sops decrypt | error | Check that `.sops.yaml` contains your `age1tpm1...` recipient; run `sops updatekeys secrets.enc.yaml` if keys changed |
```

- [ ] **Step 2: Verify the file is present and well-formed**

```bash
ls -la ~/.claude/skills/secrets-management.md
head -10 ~/.claude/skills/secrets-management.md
# Should start with ---  and name: secrets-management
```

- [ ] **Step 3: Run the health check manually to confirm all 4 checks pass**

```bash
ls ~/.config/sops/age/tpm-identity.txt && echo "✓ identity file"
[ -n "$SOPS_AGE_KEY_FILE" ] && echo "✓ SOPS_AGE_KEY_FILE=$SOPS_AGE_KEY_FILE" || echo "✗ SOPS_AGE_KEY_FILE unset"
systemctl is-active tpm2-abrmd && echo "✓ tpm2-abrmd" || echo "✗ tpm2-abrmd not active"
sops --decrypt ~/Projects/MyLocalLLM/secrets.enc.yaml > /dev/null && echo "✓ sops decrypt" || echo "✗ sops decrypt failed"
```

Expected output:
```
/home/yarin/.config/sops/age/tpm-identity.txt
✓ identity file
✓ SOPS_AGE_KEY_FILE=/home/yarin/.config/sops/age/tpm-identity.txt
active
✓ tpm2-abrmd
✓ sops decrypt
```

- [ ] **Step 4: No commit needed** — skills live in `~/.claude/` which is outside git repos.

---

## Verification Checklist

After all 5 tasks complete:

```bash
# 1. Canonical guide exists
ls ~/Projects/devsecops/docs/sops-age-tpm.md

# 2. dotfiles template has both lines
grep "go/bin" ~/Projects/dotfiles/linux/bashrc
grep "SOPS_AGE_KEY_FILE" ~/Projects/dotfiles/linux/bashrc

# 3. Project CLAUDE.md files no longer contain setup scripts
grep -r "age-plugin-tpm --generate" ~/Projects/MyLocalLLM/CLAUDE.md ~/Projects/security-data/CLAUDE.md
# Expected: no output

# 4. Both CLAUDE.md files reference the canonical guide
grep -r "sops-age-tpm.md" ~/Projects/MyLocalLLM/CLAUDE.md ~/Projects/security-data/CLAUDE.md
# Expected: one match per file

# 5. Skill file is in place
ls ~/.claude/skills/secrets-management.md

# 6. sops still decrypts both secret files
sops --decrypt ~/Projects/MyLocalLLM/secrets.enc.yaml | head -3
sops --decrypt ~/Projects/security-data/secrets.enc.yaml | head -3
```
