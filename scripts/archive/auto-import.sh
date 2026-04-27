#!/usr/bin/env bash
# auto-import.sh — called by systemd timer; safe to run unattended
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/home/yarin/.local/share/dd-import"
LOG="${LOG_DIR}/dd-import-$(date +%Y-%m-%d).log"
mkdir -p "${LOG_DIR}"

if ! docker ps --filter "name=platform-uwsgi" --filter "status=running" --format "{{.Names}}" 2>/dev/null | grep -q platform-uwsgi; then
  echo "$(date -Is) [skip] DefectDojo not running" >> "${LOG}"
  exit 0
fi

echo "$(date -Is) [start] import-ci-artifacts" >> "${LOG}"
cd "${SCRIPT_DIR}/.."
sops exec-env ../security-data/secrets.enc.yaml './scripts/import-ci-artifacts.sh' >> "${LOG}" 2>&1
echo "$(date -Is) [done]" >> "${LOG}"
