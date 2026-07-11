#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
  .venv/bin/python -m pip install -r requirements.txt
  .venv/bin/python -m pip install -e .
fi

export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
mkdir -p research/results/v1

.venv/bin/python research/experiments/shake_native_window_solver.py \
  --window-bits 32 \
  --stream-packs 4194304 \
  --checkpoint research/results/v1/shake_native_window32_solver_v1.checkpoint.json \
  --output research/results/v1/shake_native_window32_solver_v1.json \
  --causal-output research/results/v1/shake_native_window32_solver_v1.causal

.venv/bin/pytest -q tests/test_shake_native_window_solver.py
.venv/bin/python scripts/validate_causal_artifacts.py >/dev/null

.venv/bin/python scripts/write_hash_manifest.py \
  --output research/results/v1/SHAKE_NATIVE_EXTENDED_SHA256SUMS \
  research/experiments/shake_bitsliced_native.c \
  research/experiments/shake_native_window_solver.py \
  research/results/v1/shake_native_window32_solver_v1.json \
  research/results/v1/shake_native_window32_solver_v1.causal

echo "SHAKE128/256 32-coordinate native full-round consistency reproduced."
