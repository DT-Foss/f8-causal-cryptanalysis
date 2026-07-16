#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
RUNNER="research/experiments/chacha20_round20_w50_selection_calibrated_portfolio_a417.py"
IMPLEMENTATION="research/configs/chacha20_round20_w50_selection_calibrated_portfolio_a417_implementation_v1.json"
LIBRARY="research/configs/chacha20_round20_w50_selection_calibrated_portfolio_a417_library_v1.json"
SELECTION="research/configs/chacha20_round20_w50_selection_calibrated_portfolio_a417_selection_v1.json"
RESULT="research/results/v1/chacha20_round20_w50_selection_calibrated_portfolio_a417_v1.json"
TEST="tests/test_chacha20_round20_w50_selection_calibrated_portfolio_a417.py"

MODE="${1:---analyze}"
if [[ "$MODE" != "--analyze" && "$MODE" != "--fit" && "$MODE" != "--select" && "$MODE" != "--evaluate" && "$MODE" != "--run" ]]; then
  printf 'usage: %s [--analyze|--fit|--select|--evaluate|--run]\n' "$0" >&2
  exit 2
fi

if [[ ! -f "$IMPLEMENTATION" ]]; then
  "$PYTHON" "$RUNNER" --freeze-implementation
fi

IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"

if [[ "$MODE" == "--fit" || "$MODE" == "--select" || "$MODE" == "--run" ]]; then
  if [[ ! -f "$LIBRARY" ]]; then
    "$PYTHON" "$RUNNER" --freeze-library \
      --expected-implementation-sha256 "$IMPLEMENTATION_SHA256"
  fi
fi

if [[ -f "$LIBRARY" ]]; then
  LIBRARY_SHA256="$(shasum -a 256 "$LIBRARY" | awk '{print $1}')"
else
  LIBRARY_SHA256=""
fi

if [[ "$MODE" == "--select" || "$MODE" == "--run" ]]; then
  if [[ ! -f "$SELECTION" ]]; then
    "$PYTHON" "$RUNNER" --select \
      --expected-implementation-sha256 "$IMPLEMENTATION_SHA256" \
      --expected-library-sha256 "$LIBRARY_SHA256"
  fi
fi

if [[ -f "$SELECTION" ]]; then
  SELECTION_SHA256="$(shasum -a 256 "$SELECTION" | awk '{print $1}')"
else
  SELECTION_SHA256=""
fi

if [[ "$MODE" == "--evaluate" || "$MODE" == "--run" ]]; then
  if [[ -z "$LIBRARY_SHA256" || -z "$SELECTION_SHA256" ]]; then
    printf 'A417 library and selection must exist before evaluation\n' >&2
    exit 2
  fi
  if [[ ! -f "$RESULT" ]]; then
    "$PYTHON" "$RUNNER" --evaluate-external \
      --expected-implementation-sha256 "$IMPLEMENTATION_SHA256" \
      --expected-library-sha256 "$LIBRARY_SHA256" \
      --expected-selection-sha256 "$SELECTION_SHA256"
  fi
fi

"$PYTHON" "$RUNNER" --analyze
"$PYTHON" -m pytest -q "$TEST"
