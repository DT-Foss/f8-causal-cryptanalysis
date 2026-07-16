#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
RUNNER="research/experiments/chacha20_round20_w50_direct12_transfer_diversity_schedule_a400.py"
IMPLEMENTATION="research/configs/chacha20_round20_w50_direct12_transfer_diversity_schedule_a400_implementation_v1.json"
RESULT="research/results/v1/chacha20_round20_w50_direct12_transfer_diversity_schedule_a400_v1.json"

if [[ ! -f "$IMPLEMENTATION" ]]; then
  "$PYTHON" "$RUNNER" --freeze-implementation
fi

IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"

if [[ ! -f "$RESULT" ]]; then
  "$PYTHON" "$RUNNER" --materialize \
    --expected-implementation-sha256 "$IMPLEMENTATION_SHA256"
fi

"$PYTHON" "$RUNNER" --analyze
"$PYTHON" -m pytest -q tests/test_chacha20_round20_w50_direct12_transfer_diversity_schedule_a400.py
