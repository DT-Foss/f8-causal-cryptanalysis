#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
RUNNER="research/experiments/chacha20_round20_w50_fresh_hybrid_reader_a412.py"
IMPLEMENTATION="research/configs/chacha20_round20_w50_fresh_hybrid_reader_a412_implementation_v1.json"
PROTOCOL="research/configs/chacha20_round20_w50_fresh_hybrid_reader_a412_public_corpus_v1.json"
SELECTION="research/configs/chacha20_round20_w50_fresh_hybrid_reader_a412_selection_v1.json"
RESULT="research/results/v1/chacha20_round20_w50_fresh_hybrid_reader_a412_v1.json"
TEST="tests/test_chacha20_round20_w50_fresh_hybrid_reader_a412.py"

MODE="${1:---analyze}"
if [[ "$MODE" != "--analyze" && "$MODE" != "--run" ]]; then
  printf 'usage: %s [--analyze|--run] [SLICE_WORKERS]\n' "$0" >&2
  exit 2
fi
SLICE_WORKERS="${2:-8}"
if [[ ! "$SLICE_WORKERS" =~ ^[0-9]+$ ]] || (( SLICE_WORKERS < 1 || SLICE_WORKERS > 10 )); then
  printf 'SLICE_WORKERS must lie in 1..10\n' >&2
  exit 2
fi

if [[ ! -f "$IMPLEMENTATION" ]]; then
  "$PYTHON" "$RUNNER" --freeze-implementation
fi

if [[ "$MODE" == "--run" ]]; then
  IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
  PROTOCOL_SHA256="$(shasum -a 256 "$PROTOCOL" | awk '{print $1}')"
  "$PYTHON" "$RUNNER" --measure \
    --expected-protocol-sha256 "$PROTOCOL_SHA256" \
    --slice-workers "$SLICE_WORKERS"
  if [[ ! -f "$SELECTION" ]]; then
    "$PYTHON" "$RUNNER" --freeze-selection \
      --expected-implementation-sha256 "$IMPLEMENTATION_SHA256"
  fi
  if [[ ! -f "$RESULT" ]]; then
    SELECTION_SHA256="$(shasum -a 256 "$SELECTION" | awk '{print $1}')"
    "$PYTHON" "$RUNNER" --materialize \
      --expected-implementation-sha256 "$IMPLEMENTATION_SHA256" \
      --expected-selection-sha256 "$SELECTION_SHA256"
  fi
fi

"$PYTHON" "$RUNNER" --analyze
"$PYTHON" -m pytest -q "$TEST"
