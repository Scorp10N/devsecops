#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
pip install pyyaml rich --quiet 2>/dev/null || true
exec python3 "$SCRIPT_DIR/bootstrap_repo.py" "$@"
