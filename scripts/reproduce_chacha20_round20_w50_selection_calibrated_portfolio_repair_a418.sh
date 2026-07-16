#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
RUNNER="research/experiments/chacha20_round20_w50_selection_calibrated_portfolio_repair_a418.py"
TEST="tests/test_chacha20_round20_w50_selection_calibrated_portfolio_repair_a418.py"
IMPLEMENTATION="research/configs/chacha20_round20_w50_selection_calibrated_portfolio_repair_a418_implementation_v1.json"

run_tests() {
  PYTHONWARNINGS=error "$PYTHON" -m pytest -q "$TEST"
}

case "${1:---analyze}" in
  --freeze-implementation)
    run_tests
    "$PYTHON" "$RUNNER" --freeze-implementation
    ;;
  --evaluate)
    run_tests
    [[ -f "$IMPLEMENTATION" ]]
    implementation_sha256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
    "$PYTHON" "$RUNNER" \
      --evaluate-external \
      --expected-implementation-sha256 "$implementation_sha256"
    run_tests
    "$PYTHON" "$RUNNER" --analyze
    ;;
  --analyze)
    run_tests
    "$PYTHON" "$RUNNER" --analyze
    ;;
  *)
    printf 'usage: %s [--freeze-implementation|--evaluate|--analyze]\n' "$0" >&2
    exit 2
    ;;
esac
