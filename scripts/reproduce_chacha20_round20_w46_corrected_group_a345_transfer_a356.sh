#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUNNER="research/experiments/chacha20_round20_w46_corrected_group_a345_transfer_a356.py"
IMPLEMENTATION="research/configs/chacha20_round20_w46_corrected_group_a345_transfer_a356_implementation_v1.json"
MEASUREMENT="research/results/v1/chacha20_round20_w46_corrected_group_a345_transfer_a356_measurement_v1.json"
A355_RESULT="research/results/v1/chacha20_round20_w46_corrected_group_direct12_reader_a355_v1.json"
ORDER="research/results/v1/chacha20_round20_w46_corrected_group_a345_transfer_a356_order_v1.json"

.venv/bin/python -m pytest -q \
  tests/test_chacha20_round20_w46_corrected_group_a345_transfer_a356.py

if [[ ! -f "$IMPLEMENTATION" ]]; then
  .venv/bin/python "$RUNNER" --freeze-implementation
fi
IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"

if [[ ! -f "$MEASUREMENT" ]]; then
  .venv/bin/python "$RUNNER" \
    --measure-unlabeled \
    --expected-implementation-sha256 "$IMPLEMENTATION_SHA256"
fi

if [[ -f "$A355_RESULT" && ! -f "$ORDER" ]]; then
  MEASUREMENT_SHA256="$(shasum -a 256 "$MEASUREMENT" | awk '{print $1}')"
  A355_RESULT_SHA256="$(shasum -a 256 "$A355_RESULT" | awk '{print $1}')"
  .venv/bin/python "$RUNNER" \
    --freeze-order \
    --expected-implementation-sha256 "$IMPLEMENTATION_SHA256" \
    --expected-measurement-sha256 "$MEASUREMENT_SHA256" \
    --expected-a355-result-sha256 "$A355_RESULT_SHA256"
fi

.venv/bin/python "$RUNNER" --analyze
