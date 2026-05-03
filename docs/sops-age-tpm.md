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
