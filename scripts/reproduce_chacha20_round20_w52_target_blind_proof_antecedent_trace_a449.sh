#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

RUNNER="research/experiments/chacha20_round20_w52_target_blind_proof_antecedent_trace_a449.py"
IMPLEMENTATION="research/configs/chacha20_round20_w52_target_blind_proof_antecedent_trace_a449_implementation_v1.json"

if [ ! -f "$IMPLEMENTATION" ]; then
  .venv/bin/python "$RUNNER" --freeze-implementation
fi

IMPLEMENTATION_SHA256=$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')
.venv/bin/python "$RUNNER" --measure --expected-implementation-sha256 "$IMPLEMENTATION_SHA256"
.venv/bin/python "$RUNNER" --build-result --expected-implementation-sha256 "$IMPLEMENTATION_SHA256"
.venv/bin/python -m pytest -q \
  tests/test_chacha20_fresh_clause_antecedents.py \
  tests/test_proof_antecedent_features.py \
  tests/test_chacha20_round20_w52_target_blind_proof_antecedent_trace_a449.py
.venv/bin/python "$RUNNER" --analyze
