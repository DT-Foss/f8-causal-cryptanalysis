#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
RUNNER="research/experiments/chacha20_round20_w50_knownkey_parallel_portfolio_a414.py"
IMPLEMENTATION="research/configs/chacha20_round20_w50_knownkey_parallel_portfolio_a414_implementation_v1.json"
PORTFOLIO="research/configs/chacha20_round20_w50_knownkey_parallel_portfolio_a414_model_v1.json"
RESULT="research/results/v1/chacha20_round20_w50_knownkey_parallel_portfolio_a414_v1.json"
TEST="tests/test_chacha20_round20_w50_knownkey_parallel_portfolio_a414.py"

MODE="${1:---analyze}"
if [[ "$MODE" != "--analyze" && "$MODE" != "--fit" && "$MODE" != "--evaluate" && "$MODE" != "--run" ]]; then
  printf 'usage: %s [--analyze|--fit|--evaluate|--run]\n' "$0" >&2
  exit 2
fi

if [[ ! -f "$IMPLEMENTATION" ]]; then
  "$PYTHON" "$RUNNER" --freeze-implementation
fi

IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
if [[ "$MODE" == "--fit" || "$MODE" == "--run" ]]; then
  if [[ ! -f "$PORTFOLIO" ]]; then
    "$PYTHON" "$RUNNER" --freeze-portfolio \
      --expected-implementation-sha256 "$IMPLEMENTATION_SHA256"
  fi
fi

if [[ "$MODE" == "--evaluate" || "$MODE" == "--run" ]]; then
  if [[ ! -f "$PORTFOLIO" ]]; then
    printf 'A414 fixed portfolio is absent; run --fit first\n' >&2
    exit 2
  fi
  if [[ ! -f "$RESULT" ]]; then
    PORTFOLIO_SHA256="$(shasum -a 256 "$PORTFOLIO" | awk '{print $1}')"
    "$PYTHON" "$RUNNER" --evaluate-external \
      --expected-implementation-sha256 "$IMPLEMENTATION_SHA256" \
      --expected-portfolio-sha256 "$PORTFOLIO_SHA256"
  fi
fi

"$PYTHON" "$RUNNER" --analyze
"$PYTHON" -m pytest -q "$TEST"
