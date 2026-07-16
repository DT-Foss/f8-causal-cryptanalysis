#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RUNNER="$ROOT/research/experiments/chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439.py"
IMPLEMENTATION="$ROOT/research/configs/chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439_implementation_v1.json"

cd "$ROOT"

if [[ ! -f "$IMPLEMENTATION" ]]; then
  "$PYTHON" "$RUNNER" --freeze-implementation
fi

IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"

if [[ ! -f "$ROOT/research/results/v1/chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439_v1.json" ]]; then
  "$PYTHON" "$RUNNER" \
    --build-result \
    --expected-implementation-sha256 "$IMPLEMENTATION_SHA256"
fi

"$PYTHON" -m pytest -q \
  tests/test_chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439.py
"$PYTHON" "$RUNNER" --analyze
