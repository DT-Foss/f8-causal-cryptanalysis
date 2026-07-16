#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MEASUREMENT_PID="${1:-72138}"
A401_SELECTION="research/configs/chacha20_round20_w50_knownkey_direct12_learning_a401_selection_v1.json"
A401_RESULT="research/results/v1/chacha20_round20_w50_knownkey_direct12_learning_a401_v1.json"
A408_RESULT="research/results/v1/chacha20_round20_w50_knownkey_nested_fisher_reader_a408_v1.json"
A410_IMPLEMENTATION="research/configs/chacha20_round20_w50_knownkey_nested_prototype_reader_a410_implementation_v1.json"
A410_RESULT="research/results/v1/chacha20_round20_w50_knownkey_nested_prototype_reader_a410_v1.json"
A410_REPRO="scripts/reproduce_chacha20_round20_w50_knownkey_nested_prototype_reader_a410.sh"
EXPECTED_IMPLEMENTATION_SHA256="20e0dae438201a1a34716c3a24082468e4c57ae1b4dce92dd63eb8ecf131cba2"

while kill -0 "$MEASUREMENT_PID" 2>/dev/null; do
  sleep 15
done

while [[ ! -f "$A401_SELECTION" || ! -f "$A401_RESULT" || ! -f "$A408_RESULT" ]]; do
  sleep 5
done

ACTUAL_IMPLEMENTATION_SHA256="$(shasum -a 256 "$A410_IMPLEMENTATION" | awk '{print $1}')"
if [[ "$ACTUAL_IMPLEMENTATION_SHA256" != "$EXPECTED_IMPLEMENTATION_SHA256" ]]; then
  printf 'A410 implementation hash differs: %s\n' "$ACTUAL_IMPLEMENTATION_SHA256" >&2
  exit 1
fi

if [[ ! -f "$A410_RESULT" ]]; then
  "$A410_REPRO"
fi
