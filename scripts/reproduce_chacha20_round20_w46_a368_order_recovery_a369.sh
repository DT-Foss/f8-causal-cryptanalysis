#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUNNER="research/experiments/chacha20_round20_w46_a368_order_recovery_a369.py"
IMPLEMENTATION="research/configs/chacha20_round20_w46_a368_order_recovery_a369_implementation_v1.json"
ORDER="research/results/v1/chacha20_round20_w46_a367_reader_portfolio_sealed_a361_order_a368_v1.json"
RESULT="research/results/v1/chacha20_round20_w46_a368_order_recovery_a369_v1.json"
QUALIFICATION="research/results/v1/chacha20_round20_w46_eight_slab_grouped_engine_a324_qualification_v1.json"

.venv/bin/python -m pytest -q \
  tests/test_chacha20_round20_w46_a368_order_recovery_a369.py

if [[ ! -f "$IMPLEMENTATION" ]]; then
  .venv/bin/python "$RUNNER" --freeze-implementation
fi

if [[ -f "$ORDER" && ! -f "$RESULT" ]]; then
  IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
  ORDER_SHA256="$(shasum -a 256 "$ORDER" | awk '{print $1}')"
  QUALIFICATION_SHA256="$(shasum -a 256 "$QUALIFICATION" | awk '{print $1}')"
  caffeinate -dimsu nice -n 5 .venv/bin/python "$RUNNER" \
    --recover \
    --expected-implementation-sha256 "$IMPLEMENTATION_SHA256" \
    --expected-order-sha256 "$ORDER_SHA256" \
    --expected-a324-qualification-sha256 "$QUALIFICATION_SHA256"
else
  .venv/bin/python "$RUNNER" --analyze
fi
