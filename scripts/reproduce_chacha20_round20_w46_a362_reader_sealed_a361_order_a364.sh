#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUNNER="research/experiments/chacha20_round20_w46_a362_reader_sealed_a361_order_a364.py"
IMPLEMENTATION="research/configs/chacha20_round20_w46_a362_reader_sealed_a361_order_a364_implementation_v1.json"
A363_RESULT="research/results/v1/chacha20_round20_w46_polarity_invariant_validation_a363_v1.json"
ORDER="research/results/v1/chacha20_round20_w46_a362_reader_sealed_a361_order_a364_v1.json"

.venv/bin/python -m pytest -q \
  tests/test_chacha20_round20_w46_a362_reader_sealed_a361_order_a364.py

if [[ ! -f "$IMPLEMENTATION" ]]; then
  .venv/bin/python "$RUNNER" --freeze-implementation
fi

if [[ -f "$A363_RESULT" && ! -f "$ORDER" ]]; then
  IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
  A363_RESULT_SHA256="$(shasum -a 256 "$A363_RESULT" | awk '{print $1}')"
  .venv/bin/python "$RUNNER" \
    --freeze-order \
    --expected-implementation-sha256 "$IMPLEMENTATION_SHA256" \
    --expected-a363-result-sha256 "$A363_RESULT_SHA256"
else
  .venv/bin/python "$RUNNER" --analyze
fi
