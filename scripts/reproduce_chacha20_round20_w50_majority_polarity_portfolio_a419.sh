#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
RUNNER="research/experiments/chacha20_round20_w50_majority_polarity_portfolio_a419.py"
TEST="tests/test_chacha20_round20_w50_majority_polarity_portfolio_a419.py"
IMPLEMENTATION="research/configs/chacha20_round20_w50_majority_polarity_portfolio_a419_implementation_v1.json"
MODEL="research/configs/chacha20_round20_w50_majority_polarity_portfolio_a419_model_v1.json"

run_tests() {
  PYTHONWARNINGS=error "$PYTHON" -m pytest -q "$TEST"
}

case "${1:---analyze}" in
  --freeze-implementation)
    run_tests
    "$PYTHON" "$RUNNER" --freeze-implementation
    ;;
  --freeze-model)
    run_tests
    [[ -f "$IMPLEMENTATION" ]]
    implementation_sha256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
    "$PYTHON" "$RUNNER" \
      --freeze-model \
      --expected-implementation-sha256 "$implementation_sha256"
    ;;
  --evaluate)
    run_tests
    [[ -f "$IMPLEMENTATION" && -f "$MODEL" ]]
    implementation_sha256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
    model_sha256="$(shasum -a 256 "$MODEL" | awk '{print $1}')"
    "$PYTHON" "$RUNNER" \
      --evaluate-external \
      --expected-implementation-sha256 "$implementation_sha256" \
      --expected-model-sha256 "$model_sha256"
    run_tests
    "$PYTHON" "$RUNNER" --analyze
    ;;
  --analyze)
    run_tests
    "$PYTHON" "$RUNNER" --analyze
    ;;
  *)
    printf 'usage: %s [--freeze-implementation|--freeze-model|--evaluate|--analyze]\n' "$0" >&2
    exit 2
    ;;
esac
