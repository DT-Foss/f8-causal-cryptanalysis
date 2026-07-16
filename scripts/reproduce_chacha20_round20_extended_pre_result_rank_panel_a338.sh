#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
exec "$PYTHON" research/experiments/chacha20_round20_extended_pre_result_rank_panel_a338.py "$@"
