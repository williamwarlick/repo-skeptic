#!/usr/bin/env bash
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="${SKILL_DIR}${PYTHONPATH:+:${PYTHONPATH}}"
exec python3 -m repo_skeptic.cli snapshot-scan "$@"
