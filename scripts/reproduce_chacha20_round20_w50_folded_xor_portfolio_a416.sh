#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
RUNNER="research/experiments/chacha20_round20_w50_folded_xor_portfolio_a416.py"
IMPLEMENTATION="research/configs/chacha20_round20_w50_folded_xor_portfolio_a416_implementation_v1.json"
MODEL="research/configs/chacha20_round20_w50_folded_xor_portfolio_a416_model_v1.json"
RESULT="research/results/v1/chacha20_round20_w50_folded_xor_portfolio_a416_v1.json"
TEST="tests/test_chacha20_round20_w50_folded_xor_portfolio_a416.py"

MODE="${1:---analyze}"
if [[ "$MODE" != "--analyze" && "$MODE" != "--fit" && "$MODE" != "--evaluate" && "$MODE" != "--run" ]]; then
  printf 'usage: %s [--analyze|--fit|--evaluate|--run]\n' "$0" >&2
  exit 2
fi

if [[ ! -f "$IMPLEMENTATION" ]]; then
  "$PYTHON" "$RUNNER" --freeze-implementation
fi

if [[ "$MODE" == "--fit" || "$MODE" == "--run" ]]; then
  if [[ ! -f "$MODEL" ]]; then
    IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
    "$PYTHON" "$RUNNER" --freeze-model \
      --expected-implementation-sha256 "$IMPLEMENTATION_SHA256"
  fi
fi

if [[ "$MODE" == "--evaluate" || "$MODE" == "--run" ]]; then
  if [[ ! -f "$MODEL" ]]; then
    printf 'A416 fixed model is absent; run --fit first\n' >&2
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
