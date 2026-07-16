#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
SLICE_WORKERS="${SLICE_WORKERS:-8}"
RUNNER="research/experiments/chacha20_round20_w50_knownkey_direct12_learning_a401.py"
IMPLEMENTATION="research/configs/chacha20_round20_w50_knownkey_direct12_learning_a401_implementation_v1.json"
PROTOCOL="research/configs/chacha20_round20_w50_knownkey_direct12_learning_a401_public_corpus_v1.json"
SELECTION="research/configs/chacha20_round20_w50_knownkey_direct12_learning_a401_selection_v1.json"
RESULT="research/results/v1/chacha20_round20_w50_knownkey_direct12_learning_a401_v1.json"
TEST="tests/test_chacha20_round20_w50_knownkey_direct12_learning_a401.py"

if [[ ! -f "$IMPLEMENTATION" ]]; then
  "$PYTHON" "$RUNNER" --freeze-implementation
fi

IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
PROTOCOL_SHA256="$(shasum -a 256 "$PROTOCOL" | awk '{print $1}')"

if [[ ! -f "$SELECTION" ]]; then
  "$PYTHON" "$RUNNER" --measure-all \
    --expected-protocol-sha256 "$PROTOCOL_SHA256" \
    --slice-workers "$SLICE_WORKERS"
  "$PYTHON" "$RUNNER" --freeze-selection \
    --expected-implementation-sha256 "$IMPLEMENTATION_SHA256"
fi

SELECTION_SHA256="$(shasum -a 256 "$SELECTION" | awk '{print $1}')"

if [[ ! -f "$RESULT" ]]; then
  "$PYTHON" "$RUNNER" --evaluate-holdout \
    --expected-selection-sha256 "$SELECTION_SHA256"
fi

"$PYTHON" "$RUNNER" --analyze
"$PYTHON" -m pytest -q "$TEST"
