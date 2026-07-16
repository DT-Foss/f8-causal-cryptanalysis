#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
RUNNER="research/experiments/chacha20_round20_w50_xor_landscape_portfolio_a415.py"
TRAINING="research/results/v1/chacha20_round20_w50_xor_landscape_portfolio_a415_training_v1.json"
IMPLEMENTATION="research/configs/chacha20_round20_w50_xor_landscape_portfolio_a415_implementation_v1.json"
MODEL="research/configs/chacha20_round20_w50_xor_landscape_portfolio_a415_model_v1.json"
RESULT="research/results/v1/chacha20_round20_w50_xor_landscape_portfolio_a415_v1.json"
TEST="tests/test_chacha20_round20_w50_xor_landscape_portfolio_a415.py"

MODE="${1:---analyze}"
if [[ "$MODE" != "--analyze" && "$MODE" != "--train" && "$MODE" != "--fit" && "$MODE" != "--evaluate" && "$MODE" != "--run" ]]; then
  printf 'usage: %s [--analyze|--train|--fit|--evaluate|--run]\n' "$0" >&2
  exit 2
fi

if [[ "$MODE" == "--train" || "$MODE" == "--fit" || "$MODE" == "--run" ]]; then
  if [[ ! -f "$TRAINING" ]]; then
    "$PYTHON" "$RUNNER" --materialize-training
  fi
fi

if [[ -f "$TRAINING" && ! -f "$IMPLEMENTATION" ]]; then
  TRAINING_SHA256="$(shasum -a 256 "$TRAINING" | awk '{print $1}')"
  "$PYTHON" "$RUNNER" --freeze-implementation \
    --expected-training-sha256 "$TRAINING_SHA256"
fi

if [[ "$MODE" == "--fit" || "$MODE" == "--run" ]]; then
  if [[ ! -f "$IMPLEMENTATION" ]]; then
    printf 'A415 implementation is absent; run --train first\n' >&2
    exit 2
  fi
  if [[ ! -f "$MODEL" ]]; then
    IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
    "$PYTHON" "$RUNNER" --freeze-model \
      --expected-implementation-sha256 "$IMPLEMENTATION_SHA256"
  fi
fi

if [[ "$MODE" == "--evaluate" || "$MODE" == "--run" ]]; then
  if [[ ! -f "$IMPLEMENTATION" || ! -f "$MODEL" ]]; then
    printf 'A415 fixed model is absent; run --fit first\n' >&2
    exit 2
  fi
  if [[ ! -f "$RESULT" ]]; then
    IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
    MODEL_SHA256="$(shasum -a 256 "$MODEL" | awk '{print $1}')"
    "$PYTHON" "$RUNNER" --evaluate-external \
      --expected-implementation-sha256 "$IMPLEMENTATION_SHA256" \
      --expected-model-sha256 "$MODEL_SHA256"
  fi
fi

"$PYTHON" "$RUNNER" --analyze
"$PYTHON" -m pytest -q "$TEST"
