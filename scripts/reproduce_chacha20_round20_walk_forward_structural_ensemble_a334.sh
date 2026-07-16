#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"

if [[ ! -x "$PYTHON" ]]; then
  echo "Python environment not found: $PYTHON" >&2
  exit 2
fi

exec "$PYTHON" \
  "$ROOT/research/experiments/chacha20_round20_walk_forward_structural_ensemble_a334.py" \
  "$@"
