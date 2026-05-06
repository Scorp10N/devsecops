# Secrets Management Consolidation Design

**Date:** 2026-05-03
**Status:** Approved

## Context

After migrating from a plaintext age key (`~/.config/sops/age/keys.txt`) to a TPM-backed
key (`~/.config/sops/age/tpm-identity.txt`), the setup documentation is scattered across
individual project CLAUDE.md files and not reflected in dotfiles. The goal is a single
canonical guide in devsecops, a lean reference in each project, a synced dotfiles template,
and a Claude Code skill that auto-loads secrets conventions and runs a health check whenever
a project uses sops.

---

## Current Secrets Stack

- **sops** v3.12.2 — encrypts/decrypts `secrets.enc.yaml` files
- **age** v1.3.1 (linuxbrew) — encryption backend
- **age-plugin-tpm** v1.0.1 — TPM-backed age identity; private key sealed in TPM chip
- **tpm2-abrmd** — TPM resource manager daemon (systemd service)
- **Identity file:** `~/.config/sops/age/tpm-identity.txt` (handle only, not the key)
- **Recipient format:** `age1tpm1...`
- **Shell env:** `SOPS_AGE_KEY_FILE="$HOME/.config/sops/age/tpm-identity.txt"` in `~/.bashrc`
- **Binaries:** `~/go/bin/age-plugin-tpm`, `~/go/bin/age-plugin-tag` (symlink)

---

## Components

### 1. Canonical Setup Guide — `devsecops/docs/sops-age-tpm.md`

Full setup guide covering:
- Prerequisites: `tpm2-abrmd`, `tpm2-tools`, `tss` group membership, reboot requirement
- Installing `age-plugin-tpm` via Go + `age-plugin-tag` symlink
- Generating TPM identity with `--tpm-recipient` flag
- Updating `.sops.yaml` and running `sops updatekeys`
- Shell config (`SOPS_AGE_KEY_FILE`, `~/go/bin` in PATH)
- Threat model summary

### 2. Dotfiles Sync — `dotfiles/linux/bashrc`

Add two lines currently missing from the template:
```bash
export PATH="$HOME/.local/npm/bin:$HOME/go/bin:$PATH"
export SOPS_AGE_KEY_FILE="$HOME/.config/sops/age/tpm-identity.txt"
```

### 3. CLAUDE.md Trimming — MyLocalLLM + security-data

Replace the verbose first-time setup block in both files with:
```
### Setup
See: `~/Projects/devsecops/docs/sops-age-tpm.md`
```

### 4. Secrets Management Skill — `~/.claude/skills/secrets-management.md`

A Claude Code skill that auto-loads when secrets-related context is detected.

**Trigger conditions:**
- Project contains `secrets.enc.yaml` or `.sops.yaml`
- Task involves words: "secrets", "sops", "age key", "encrypt", "decrypt"
- Project `CLAUDE.md` references `sops-age-tpm.md`

**On load — two actions:**

**Conventions block** (always):
- Reminds Claude of the full stack: sops + age + TPM identity path + recipient format
- Instructs Claude to use `sops updatekeys` when adding recipients to existing files
- Instructs Claude to reference `devsecops/docs/sops-age-tpm.md` in new project setup docs

**Health check** (runs and reports):
```bash
# 1. TPM identity file exists
ls ~/.config/sops/age/tpm-identity.txt

# 2. SOPS_AGE_KEY_FILE is set
echo $SOPS_AGE_KEY_FILE

# 3. tpm2-abrmd is running
systemctl is-active tpm2-abrmd

# 4. sops can decrypt a known file
sops --decrypt ~/Projects/MyLocalLLM/secrets.enc.yaml > /dev/null
```

Reports: ✓ healthy / ✗ broken with remediation hint per check.

---

## Data Flow

```
New project needs secrets
  → Claude detects .sops.yaml or "secrets" keyword
    → secrets-management skill auto-loads
      → conventions loaded into context
      → health check runs, reports status
        → Claude uses age1tpm1... recipient in .sops.yaml
        → Claude references devsecops guide in project CLAUDE.md
```

---

## Files Modified

| File | Action |
|------|--------|
| `devsecops/docs/sops-age-tpm.md` | Create |
| `dotfiles/linux/bashrc` | Update — add go/bin PATH + SOPS_AGE_KEY_FILE |
| `MyLocalLLM/CLAUDE.md` | Update — trim setup block to reference |
| `security-data/CLAUDE.md` | Update — trim setup block to reference |
| `~/.claude/skills/secrets-management.md` | Create |

---

## Verification

```bash
# 1. Skill loads correctly
# Open a project with secrets.enc.yaml and check Claude context includes secrets conventions

# 2. Health check passes
# All 4 checks return ✓

# 3. dotfiles install works on a fresh shell
source ~/Projects/dotfiles/linux/bashrc
echo $SOPS_AGE_KEY_FILE   # should print ~/.config/sops/age/tpm-identity.txt
which age-plugin-tpm      # should resolve to ~/go/bin/age-plugin-tpm

# 4. sops still decrypts
sops --decrypt ~/Projects/MyLocalLLM/secrets.enc.yaml | head -3
sops --decrypt ~/Projects/security-data/secrets.enc.yaml | head -3
```
