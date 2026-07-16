#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

A402_RESULT="research/results/v1/chacha20_round20_w50_knownkey_fullfit_production_reader_a402_v1.json"
A404_RESULT="research/results/v1/chacha20_round20_w50_knownkey_leaveoneout_reader_a404_v1.json"
A406_RESULT="research/results/v1/chacha20_round20_w50_knownkey_weighted_reader_a406_v1.json"
A408_RESULT="research/results/v1/chacha20_round20_w50_knownkey_nested_fisher_reader_a408_v1.json"
A410_RESULT="research/results/v1/chacha20_round20_w50_knownkey_nested_prototype_reader_a410_v1.json"
A411_IMPLEMENTATION="research/configs/chacha20_round20_w50_nested_prototype_recovery_a411_implementation_v1.json"
A411_PROTOCOL="research/configs/chacha20_round20_w50_nested_prototype_recovery_a411_v1.json"
A411_REPRO="scripts/reproduce_chacha20_round20_w50_nested_prototype_recovery_a411.sh"
EXPECTED_IMPLEMENTATION_SHA256="580ac8d1b0f13870337b925b2d9d73c5414f1b19ed90d145cae41a643f971ed4"

while [[ ! -f "$A402_RESULT" || ! -f "$A404_RESULT" || ! -f "$A406_RESULT" || ! -f "$A408_RESULT" || ! -f "$A410_RESULT" ]]; do
  sleep 5
done

ACTUAL_IMPLEMENTATION_SHA256="$(shasum -a 256 "$A411_IMPLEMENTATION" | awk '{print $1}')"
if [[ "$ACTUAL_IMPLEMENTATION_SHA256" != "$EXPECTED_IMPLEMENTATION_SHA256" ]]; then
  printf 'A411 implementation hash differs: %s\n' "$ACTUAL_IMPLEMENTATION_SHA256" >&2
  exit 1
fi

QUALIFIED="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["comparison"]["qualified"]).lower())' "$A410_RESULT")"
if [[ "$QUALIFIED" == "true" && ! -f "$A411_PROTOCOL" ]]; then
  "$A411_REPRO"
fi
