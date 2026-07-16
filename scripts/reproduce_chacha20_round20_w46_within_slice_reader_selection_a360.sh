#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUNNER="research/experiments/chacha20_round20_w46_within_slice_reader_selection_a360.py"
IMPLEMENTATION="research/configs/chacha20_round20_w46_within_slice_reader_selection_a360_implementation_v1.json"
SELECTION="research/results/v1/chacha20_round20_w46_within_slice_reader_selection_a360_frozen_v1.json"
RESULT="research/results/v1/chacha20_round20_w46_within_slice_reader_selection_a360_v1.json"
PREPARED="research/results/v1/chacha20_round20_w46_corrected_knownkey_slice_corpus_a359_prepared_v1.json"

.venv/bin/python -m pytest -q \
  tests/test_chacha20_round20_w46_within_slice_reader_selection_a360.py

if [[ ! -f "$IMPLEMENTATION" ]]; then
  .venv/bin/python "$RUNNER" --freeze-implementation
fi

IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
PREPARED_SHA256="$(shasum -a 256 "$PREPARED" | awk '{print $1}')"
if [[ ! -f "$SELECTION" ]]; then
  .venv/bin/python "$RUNNER" \
    --freeze-selection \
    --expected-implementation-sha256 "$IMPLEMENTATION_SHA256" \
    --expected-prepared-sha256 "$PREPARED_SHA256"
fi

SELECTION_SHA256="$(shasum -a 256 "$SELECTION" | awk '{print $1}')"
if [[ -f "$RESULT" ]]; then
  .venv/bin/python "$RUNNER" --analyze
else
  .venv/bin/python "$RUNNER" \
    --validate-holdout \
    --expected-selection-sha256 "$SELECTION_SHA256"
fi
