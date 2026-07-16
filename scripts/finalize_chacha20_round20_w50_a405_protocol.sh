#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MEASUREMENT_PID="${1:-72138}"
A402_RESULT="research/results/v1/chacha20_round20_w50_knownkey_fullfit_production_reader_a402_v1.json"
A404_RESULT="research/results/v1/chacha20_round20_w50_knownkey_leaveoneout_reader_a404_v1.json"
A405_IMPLEMENTATION="research/configs/chacha20_round20_w50_leaveoneout_reader_recovery_a405_implementation_v1.json"
A405_PROTOCOL="research/configs/chacha20_round20_w50_leaveoneout_reader_recovery_a405_v1.json"
A405_REPRO="scripts/reproduce_chacha20_round20_w50_leaveoneout_reader_recovery_a405.sh"
EXPECTED_IMPLEMENTATION_SHA256="150c0ef629493b5923cdd3a51dbe44560fa619c4d76a2c0eacc4bb8299e42c62"

while kill -0 "$MEASUREMENT_PID" 2>/dev/null; do
  sleep 15
done

while [[ ! -f "$A402_RESULT" || ! -f "$A404_RESULT" ]]; do
  sleep 5
done

ACTUAL_IMPLEMENTATION_SHA256="$(shasum -a 256 "$A405_IMPLEMENTATION" | awk '{print $1}')"
if [[ "$ACTUAL_IMPLEMENTATION_SHA256" != "$EXPECTED_IMPLEMENTATION_SHA256" ]]; then
  printf 'A405 implementation hash differs: %s\n' "$ACTUAL_IMPLEMENTATION_SHA256" >&2
  exit 1
fi

QUALIFIED="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["leaveoneout"]["qualified"]).lower())' "$A404_RESULT")"
if [[ "$QUALIFIED" == "true" && ! -f "$A405_PROTOCOL" ]]; then
  "$A405_REPRO"
fi
