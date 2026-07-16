#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ $# -ne 1 || ! "$1" =~ ^[0-9]+$ ]]; then
  printf 'usage: %s A401_MEASUREMENT_PID\n' "$0" >&2
  exit 2
fi

PYTHON="${PYTHON:-.venv/bin/python}"
MEASUREMENT_PID="$1"
A401_RUNNER="research/experiments/chacha20_round20_w50_knownkey_direct12_learning_a401.py"
A401_IMPLEMENTATION="research/configs/chacha20_round20_w50_knownkey_direct12_learning_a401_implementation_v1.json"
A401_SELECTION="research/configs/chacha20_round20_w50_knownkey_direct12_learning_a401_selection_v1.json"
A401_PROGRESS="research/results/v1/chacha20_round20_w50_knownkey_direct12_learning_a401_progress_v1.json"
A401_RESULT="research/results/v1/chacha20_round20_w50_knownkey_direct12_learning_a401_v1.json"
A402_RUNNER="research/experiments/chacha20_round20_w50_knownkey_fullfit_production_reader_a402.py"
A402_IMPLEMENTATION="research/configs/chacha20_round20_w50_knownkey_fullfit_production_reader_a402_implementation_v1.json"
A402_RESULT="research/results/v1/chacha20_round20_w50_knownkey_fullfit_production_reader_a402_v1.json"

while kill -0 "$MEASUREMENT_PID" 2>/dev/null; do
  sleep 20
done

MEASUREMENT_STATUS="$($PYTHON -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$A401_PROGRESS")"
COMPLETED_TARGETS="$($PYTHON -c 'import json,sys; print(json.load(open(sys.argv[1]))["completed_targets"])' "$A401_PROGRESS")"
if [[ "$MEASUREMENT_STATUS" != "measurement_complete" || "$COMPLETED_TARGETS" != "16" ]]; then
  printf 'A401 measurement ended without the complete 16-target gate: status=%s targets=%s\n' \
    "$MEASUREMENT_STATUS" "$COMPLETED_TARGETS" >&2
  exit 1
fi

A401_IMPLEMENTATION_SHA256="$(shasum -a 256 "$A401_IMPLEMENTATION" | awk '{print $1}')"
if [[ ! -f "$A401_SELECTION" ]]; then
  "$PYTHON" "$A401_RUNNER" --freeze-selection \
    --expected-implementation-sha256 "$A401_IMPLEMENTATION_SHA256"
fi

A401_SELECTION_SHA256="$(shasum -a 256 "$A401_SELECTION" | awk '{print $1}')"
if [[ ! -f "$A401_RESULT" ]]; then
  "$PYTHON" "$A401_RUNNER" --evaluate-holdout \
    --expected-selection-sha256 "$A401_SELECTION_SHA256"
fi

A401_RESULT_SHA256="$(shasum -a 256 "$A401_RESULT" | awk '{print $1}')"
A402_IMPLEMENTATION_SHA256="$(shasum -a 256 "$A402_IMPLEMENTATION" | awk '{print $1}')"
if [[ ! -f "$A402_RESULT" ]]; then
  "$PYTHON" "$A402_RUNNER" --materialize \
    --expected-implementation-sha256 "$A402_IMPLEMENTATION_SHA256" \
    --expected-a401-result-sha256 "$A401_RESULT_SHA256" \
    --expected-a401-selection-sha256 "$A401_SELECTION_SHA256"
fi

"$PYTHON" "$A401_RUNNER" --analyze
"$PYTHON" "$A402_RUNNER" --analyze
"$PYTHON" -m pytest -q \
  tests/test_chacha20_round20_w50_knownkey_direct12_learning_a401.py \
  tests/test_chacha20_round20_w50_knownkey_fullfit_production_reader_a402.py
