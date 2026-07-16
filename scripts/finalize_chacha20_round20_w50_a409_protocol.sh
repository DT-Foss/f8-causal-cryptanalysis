#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MEASUREMENT_PID="${1:-72138}"
A402_RESULT="research/results/v1/chacha20_round20_w50_knownkey_fullfit_production_reader_a402_v1.json"
A404_RESULT="research/results/v1/chacha20_round20_w50_knownkey_leaveoneout_reader_a404_v1.json"
A406_RESULT="research/results/v1/chacha20_round20_w50_knownkey_weighted_reader_a406_v1.json"
A408_RESULT="research/results/v1/chacha20_round20_w50_knownkey_nested_fisher_reader_a408_v1.json"
A409_IMPLEMENTATION="research/configs/chacha20_round20_w50_nested_fisher_recovery_a409_implementation_v1.json"
A409_PROTOCOL="research/configs/chacha20_round20_w50_nested_fisher_recovery_a409_v1.json"
A409_REPRO="scripts/reproduce_chacha20_round20_w50_nested_fisher_recovery_a409.sh"
EXPECTED_IMPLEMENTATION_SHA256="43ec9b73498e129c202b25af318ba10dd8f1de80a8b3a6122f3d3537cdca2325"

while kill -0 "$MEASUREMENT_PID" 2>/dev/null; do
  sleep 15
done

while [[ ! -f "$A402_RESULT" || ! -f "$A404_RESULT" || ! -f "$A406_RESULT" || ! -f "$A408_RESULT" ]]; do
  sleep 5
done

ACTUAL_IMPLEMENTATION_SHA256="$(shasum -a 256 "$A409_IMPLEMENTATION" | awk '{print $1}')"
if [[ "$ACTUAL_IMPLEMENTATION_SHA256" != "$EXPECTED_IMPLEMENTATION_SHA256" ]]; then
  printf 'A409 implementation hash differs: %s\n' "$ACTUAL_IMPLEMENTATION_SHA256" >&2
  exit 1
fi

QUALIFIED="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["comparison"]["qualified"]).lower())' "$A408_RESULT")"
if [[ "$QUALIFIED" == "true" && ! -f "$A409_PROTOCOL" ]]; then
  "$A409_REPRO"
fi
