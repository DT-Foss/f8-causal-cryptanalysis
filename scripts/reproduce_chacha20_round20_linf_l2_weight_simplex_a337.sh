#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
exec "$PYTHON" research/experiments/chacha20_round20_linf_l2_weight_simplex_a337.py "$@"
