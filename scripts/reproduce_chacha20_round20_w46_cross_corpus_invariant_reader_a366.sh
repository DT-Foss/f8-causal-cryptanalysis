#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUNNER="research/experiments/chacha20_round20_w46_cross_corpus_invariant_reader_a366.py"
IMPLEMENTATION="research/configs/chacha20_round20_w46_cross_corpus_invariant_reader_a366_implementation_v1.json"
RESULT="research/results/v1/chacha20_round20_w46_cross_corpus_invariant_reader_a366_v1.json"

.venv/bin/python -m pytest -q \
  tests/test_chacha20_round20_w46_cross_corpus_invariant_reader_a366.py

if [[ ! -f "$IMPLEMENTATION" ]]; then
  .venv/bin/python "$RUNNER" --freeze-implementation
fi

IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
if [[ ! -f "$RESULT" ]]; then
  .venv/bin/python "$RUNNER" \
    --select \
    --expected-implementation-sha256 "$IMPLEMENTATION_SHA256"
else
  .venv/bin/python "$RUNNER" --analyze
fi
