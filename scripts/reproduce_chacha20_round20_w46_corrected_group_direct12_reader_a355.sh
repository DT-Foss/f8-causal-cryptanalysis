#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUNNER="research/experiments/chacha20_round20_w46_corrected_group_direct12_reader_a355.py"
IMPLEMENTATION="research/configs/chacha20_round20_w46_corrected_group_direct12_reader_a355_implementation_v1.json"

.venv/bin/python -m pytest -q \
  tests/test_chacha20_round20_w46_corrected_group_direct12_reader_a355.py

if [[ ! -f "$IMPLEMENTATION" ]]; then
  .venv/bin/python "$RUNNER" --freeze-implementation
fi

IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
if [[ -f "research/results/v1/chacha20_round20_w46_corrected_group_direct12_reader_a355_v1.json" ]]; then
  .venv/bin/python "$RUNNER" --analyze
else
  .venv/bin/python "$RUNNER" \
    --measure \
    --expected-implementation-sha256 "$IMPLEMENTATION_SHA256"
fi
