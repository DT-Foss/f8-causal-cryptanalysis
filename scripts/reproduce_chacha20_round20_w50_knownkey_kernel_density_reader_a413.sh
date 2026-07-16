#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
RUNNER="research/experiments/chacha20_round20_w50_knownkey_kernel_density_reader_a413.py"
IMPLEMENTATION="research/configs/chacha20_round20_w50_knownkey_kernel_density_reader_a413_implementation_v1.json"
MODEL="research/configs/chacha20_round20_w50_knownkey_kernel_density_reader_a413_model_v1.json"
RESULT="research/results/v1/chacha20_round20_w50_knownkey_kernel_density_reader_a413_v1.json"
TEST="tests/test_chacha20_round20_w50_knownkey_kernel_density_reader_a413.py"

MODE="${1:---analyze}"
if [[ "$MODE" != "--analyze" && "$MODE" != "--train" && "$MODE" != "--evaluate" && "$MODE" != "--run" ]]; then
  printf 'usage: %s [--analyze|--train|--evaluate|--run]\n' "$0" >&2
  exit 2
fi

if [[ ! -f "$IMPLEMENTATION" ]]; then
  "$PYTHON" "$RUNNER" --freeze-implementation
fi

IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
if [[ "$MODE" == "--train" || "$MODE" == "--run" ]]; then
  if [[ ! -f "$MODEL" ]]; then
    "$PYTHON" "$RUNNER" --freeze-model \
      --expected-implementation-sha256 "$IMPLEMENTATION_SHA256"
  fi
fi

if [[ "$MODE" == "--evaluate" || "$MODE" == "--run" ]]; then
  if [[ ! -f "$MODEL" ]]; then
    printf 'A413 fixed model is absent; run --train first\n' >&2
    exit 2
  fi
  if [[ ! -f "$RESULT" ]]; then
    MODEL_SHA256="$(shasum -a 256 "$MODEL" | awk '{print $1}')"
    "$PYTHON" "$RUNNER" --evaluate-external \
      --expected-implementation-sha256 "$IMPLEMENTATION_SHA256" \
      --expected-model-sha256 "$MODEL_SHA256"
  fi
fi

"$PYTHON" "$RUNNER" --analyze
"$PYTHON" -m pytest -q "$TEST"
