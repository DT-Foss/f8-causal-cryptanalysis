#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
RUNNER="research/experiments/chacha20_round20_w50_knownkey_nested_prototype_reader_a410.py"
IMPLEMENTATION="research/configs/chacha20_round20_w50_knownkey_nested_prototype_reader_a410_implementation_v1.json"
A401_RESULT="research/results/v1/chacha20_round20_w50_knownkey_direct12_learning_a401_v1.json"
A401_SELECTION="research/configs/chacha20_round20_w50_knownkey_direct12_learning_a401_selection_v1.json"
A408_RESULT="research/results/v1/chacha20_round20_w50_knownkey_nested_fisher_reader_a408_v1.json"
RESULT="research/results/v1/chacha20_round20_w50_knownkey_nested_prototype_reader_a410_v1.json"
TEST="tests/test_chacha20_round20_w50_knownkey_nested_prototype_reader_a410.py"

if [[ ! -f "$IMPLEMENTATION" ]]; then
  "$PYTHON" "$RUNNER" --freeze-implementation
fi

if [[ -f "$A401_RESULT" && -f "$A401_SELECTION" && -f "$A408_RESULT" && ! -f "$RESULT" ]]; then
  IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
  A401_RESULT_SHA256="$(shasum -a 256 "$A401_RESULT" | awk '{print $1}')"
  A401_SELECTION_SHA256="$(shasum -a 256 "$A401_SELECTION" | awk '{print $1}')"
  A408_RESULT_SHA256="$(shasum -a 256 "$A408_RESULT" | awk '{print $1}')"
  "$PYTHON" "$RUNNER" --materialize \
    --expected-implementation-sha256 "$IMPLEMENTATION_SHA256" \
    --expected-a401-result-sha256 "$A401_RESULT_SHA256" \
    --expected-a401-selection-sha256 "$A401_SELECTION_SHA256" \
    --expected-a408-result-sha256 "$A408_RESULT_SHA256"
fi

"$PYTHON" "$RUNNER" --analyze
"$PYTHON" -m pytest -q "$TEST"
