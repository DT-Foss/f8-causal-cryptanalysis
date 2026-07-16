#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUNNER="research/experiments/chacha20_round20_w46_a367_reader_portfolio_sealed_a361_order_a368.py"
IMPLEMENTATION="research/configs/chacha20_round20_w46_a367_reader_portfolio_sealed_a361_order_a368_implementation_v1.json"
ORDER="research/results/v1/chacha20_round20_w46_a367_reader_portfolio_sealed_a361_order_a368_v1.json"
A367_RESULT="research/results/v1/chacha20_round20_w46_cross_corpus_invariant_validation_a367_v1.json"

.venv/bin/python -m pytest -q \
  tests/test_chacha20_round20_w46_a367_reader_portfolio_sealed_a361_order_a368.py

if [[ ! -f "$IMPLEMENTATION" ]]; then
  .venv/bin/python "$RUNNER" --freeze-implementation
fi

if [[ -f "$A367_RESULT" && ! -f "$ORDER" ]]; then
  IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
  A367_RESULT_SHA256="$(shasum -a 256 "$A367_RESULT" | awk '{print $1}')"
  .venv/bin/python "$RUNNER" \
    --freeze-order \
    --expected-implementation-sha256 "$IMPLEMENTATION_SHA256" \
    --expected-a367-result-sha256 "$A367_RESULT_SHA256"
else
  .venv/bin/python "$RUNNER" --analyze
fi
