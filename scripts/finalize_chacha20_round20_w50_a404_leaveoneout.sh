#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MEASUREMENT_PID="${1:-72138}"
PYTHON="${PYTHON:-.venv/bin/python}"
A401_SELECTION="research/configs/chacha20_round20_w50_knownkey_direct12_learning_a401_selection_v1.json"
A401_RESULT="research/results/v1/chacha20_round20_w50_knownkey_direct12_learning_a401_v1.json"
A404_IMPLEMENTATION="research/configs/chacha20_round20_w50_knownkey_leaveoneout_reader_a404_implementation_v1.json"
A404_RESULT="research/results/v1/chacha20_round20_w50_knownkey_leaveoneout_reader_a404_v1.json"
A404_REPRO="scripts/reproduce_chacha20_round20_w50_knownkey_leaveoneout_reader_a404.sh"
EXPECTED_IMPLEMENTATION_SHA256="4a60f4704397d4f3978756a91194efd16f3561c636aedb8ed3a078cba4e4def9"

while kill -0 "$MEASUREMENT_PID" 2>/dev/null; do
  sleep 15
done

while [[ ! -f "$A401_SELECTION" || ! -f "$A401_RESULT" ]]; do
  sleep 5
done

ACTUAL_IMPLEMENTATION_SHA256="$(shasum -a 256 "$A404_IMPLEMENTATION" | awk '{print $1}')"
if [[ "$ACTUAL_IMPLEMENTATION_SHA256" != "$EXPECTED_IMPLEMENTATION_SHA256" ]]; then
  printf 'A404 implementation hash differs: %s\n' "$ACTUAL_IMPLEMENTATION_SHA256" >&2
  exit 1
fi

if [[ ! -f "$A404_RESULT" ]]; then
  "$A404_REPRO"
fi

"$PYTHON" research/experiments/chacha20_round20_w50_knownkey_leaveoneout_reader_a404.py --analyze
