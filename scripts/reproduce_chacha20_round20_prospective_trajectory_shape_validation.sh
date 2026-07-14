#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"

exec "$PYTHON" \
  "$ROOT/research/experiments/chacha20_round20_prospective_trajectory_shape_validation.py" \
  --run "$@"
