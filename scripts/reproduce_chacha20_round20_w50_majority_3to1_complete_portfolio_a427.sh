#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
RUNNER="research/experiments/chacha20_round20_w50_majority_3to1_complete_portfolio_a427.py"
TEST="tests/test_chacha20_round20_w50_majority_3to1_complete_portfolio_a427.py"
IMPLEMENTATION="research/configs/chacha20_round20_w50_majority_3to1_complete_portfolio_a427_implementation_v1.json"
MODEL="research/configs/chacha20_round20_w50_majority_3to1_complete_portfolio_a427_model_v1.json"

case "${1:---analyze}" in
  --test)
    "$PYTHON" -m pytest -q "$TEST"
    ;;
  --freeze-implementation)
    "$PYTHON" "$RUNNER" --freeze-implementation
    ;;
  --freeze-model)
    implementation_sha256="${2:-$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')}"
    "$PYTHON" "$RUNNER" --freeze-model \
      --expected-implementation-sha256 "$implementation_sha256"
    ;;
  --evaluate)
    implementation_sha256="${2:-$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')}"
    model_sha256="${3:-$(shasum -a 256 "$MODEL" | awk '{print $1}')}"
    "$PYTHON" "$RUNNER" --evaluate \
      --expected-implementation-sha256 "$implementation_sha256" \
      --expected-model-sha256 "$model_sha256"
    ;;
  --analyze)
    "$PYTHON" "$RUNNER" --analyze
    ;;
  *)
    echo "usage: $0 [--test|--freeze-implementation|--freeze-model [implementation_sha256]|--evaluate [implementation_sha256 model_sha256]|--analyze]" >&2
    exit 2
    ;;
esac
