#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUNNER="research/experiments/chacha20_round20_w46_cross_corpus_invariant_validation_a367.py"
IMPLEMENTATION="research/configs/chacha20_round20_w46_cross_corpus_invariant_validation_a367_implementation_v1.json"
PREPARED="research/results/v1/chacha20_round20_w46_cross_corpus_invariant_validation_a367_prepared_v1.json"
RESULT="research/results/v1/chacha20_round20_w46_cross_corpus_invariant_validation_a367_v1.json"

.venv/bin/python -m pytest -q \
  tests/test_chacha20_round20_w46_cross_corpus_invariant_validation_a367.py

if [[ ! -f "$IMPLEMENTATION" ]]; then
  .venv/bin/python "$RUNNER" --freeze-implementation
fi

IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
if [[ ! -f "$PREPARED" ]]; then
  .venv/bin/python "$RUNNER" \
    --prepare \
    --expected-implementation-sha256 "$IMPLEMENTATION_SHA256"
fi

PREPARED_SHA256="$(shasum -a 256 "$PREPARED" | awk '{print $1}')"
if [[ ! -f "$RESULT" ]]; then
  .venv/bin/python "$RUNNER" \
    --measure-and-validate \
    --expected-prepared-sha256 "$PREPARED_SHA256"
else
  .venv/bin/python "$RUNNER" --analyze
fi
