#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_BIN="${ROOT_DIR}/.venv/bin/repo-skeptic"

if [ -x "${VENV_BIN}" ]; then
  exec "${VENV_BIN}" snapshot-scan "$@"
fi

export PYTHONPATH="${ROOT_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}"
exec python3 -m repo_skeptic.cli snapshot-scan "$@"
