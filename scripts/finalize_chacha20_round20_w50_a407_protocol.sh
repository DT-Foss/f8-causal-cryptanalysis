#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MEASUREMENT_PID="${1:-72138}"
A402_RESULT="research/results/v1/chacha20_round20_w50_knownkey_fullfit_production_reader_a402_v1.json"
A404_RESULT="research/results/v1/chacha20_round20_w50_knownkey_leaveoneout_reader_a404_v1.json"
A406_RESULT="research/results/v1/chacha20_round20_w50_knownkey_weighted_reader_a406_v1.json"
A407_IMPLEMENTATION="research/configs/chacha20_round20_w50_weighted_reader_recovery_a407_implementation_v1.json"
A407_PROTOCOL="research/configs/chacha20_round20_w50_weighted_reader_recovery_a407_v1.json"
A407_REPRO="scripts/reproduce_chacha20_round20_w50_weighted_reader_recovery_a407.sh"
EXPECTED_IMPLEMENTATION_SHA256="fab95bd0b48c73915f22395d15ebfebd2d5a70a63dffd306e15c5a9ec7b9cdd2"

while kill -0 "$MEASUREMENT_PID" 2>/dev/null; do
  sleep 15
done

while [[ ! -f "$A402_RESULT" || ! -f "$A404_RESULT" || ! -f "$A406_RESULT" ]]; do
  sleep 5
done

ACTUAL_IMPLEMENTATION_SHA256="$(shasum -a 256 "$A407_IMPLEMENTATION" | awk '{print $1}')"
if [[ "$ACTUAL_IMPLEMENTATION_SHA256" != "$EXPECTED_IMPLEMENTATION_SHA256" ]]; then
  printf 'A407 implementation hash differs: %s\n' "$ACTUAL_IMPLEMENTATION_SHA256" >&2
  exit 1
fi

QUALIFIED="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["leaveoneout"]["qualified"]).lower())' "$A406_RESULT")"
if [[ "$QUALIFIED" == "true" && ! -f "$A407_PROTOCOL" ]]; then
  "$A407_REPRO"
fi
