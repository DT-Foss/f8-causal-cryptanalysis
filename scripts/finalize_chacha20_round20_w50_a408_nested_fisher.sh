#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MEASUREMENT_PID="${1:-72138}"
A401_SELECTION="research/configs/chacha20_round20_w50_knownkey_direct12_learning_a401_selection_v1.json"
A401_RESULT="research/results/v1/chacha20_round20_w50_knownkey_direct12_learning_a401_v1.json"
A406_RESULT="research/results/v1/chacha20_round20_w50_knownkey_weighted_reader_a406_v1.json"
A408_IMPLEMENTATION="research/configs/chacha20_round20_w50_knownkey_nested_fisher_reader_a408_implementation_v1.json"
A408_RESULT="research/results/v1/chacha20_round20_w50_knownkey_nested_fisher_reader_a408_v1.json"
A408_REPRO="scripts/reproduce_chacha20_round20_w50_knownkey_nested_fisher_reader_a408.sh"
EXPECTED_IMPLEMENTATION_SHA256="999ac2e2ffa9536d977e93932bc197451d0307e516060f8bae8d0df70dce9e5c"

while kill -0 "$MEASUREMENT_PID" 2>/dev/null; do
  sleep 15
done

while [[ ! -f "$A401_SELECTION" || ! -f "$A401_RESULT" || ! -f "$A406_RESULT" ]]; do
  sleep 5
done

ACTUAL_IMPLEMENTATION_SHA256="$(shasum -a 256 "$A408_IMPLEMENTATION" | awk '{print $1}')"
if [[ "$ACTUAL_IMPLEMENTATION_SHA256" != "$EXPECTED_IMPLEMENTATION_SHA256" ]]; then
  printf 'A408 implementation hash differs: %s\n' "$ACTUAL_IMPLEMENTATION_SHA256" >&2
  exit 1
fi

if [[ ! -f "$A408_RESULT" ]]; then
  "$A408_REPRO"
fi
