#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
RUNNER="research/experiments/chacha20_round20_w50_leaveoneout_reader_recovery_a405.py"
IMPLEMENTATION="research/configs/chacha20_round20_w50_leaveoneout_reader_recovery_a405_implementation_v1.json"
PROTOCOL="research/configs/chacha20_round20_w50_leaveoneout_reader_recovery_a405_v1.json"
A402_RESULT="research/results/v1/chacha20_round20_w50_knownkey_fullfit_production_reader_a402_v1.json"
A404_RESULT="research/results/v1/chacha20_round20_w50_knownkey_leaveoneout_reader_a404_v1.json"
TEST="tests/test_chacha20_round20_w50_leaveoneout_reader_recovery_a405.py"

RECOVER=false
if [[ "${1:-}" == "--recover" ]]; then
  RECOVER=true
elif [[ $# -ne 0 ]]; then
  printf 'usage: %s [--recover]\n' "$0" >&2
  exit 2
fi

if [[ ! -f "$IMPLEMENTATION" ]]; then
  "$PYTHON" "$RUNNER" --freeze-implementation
fi

if [[ -f "$A402_RESULT" && -f "$A404_RESULT" && ! -f "$PROTOCOL" ]]; then
  QUALIFIED="$($PYTHON -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["leaveoneout"]["qualified"]).lower())' "$A404_RESULT")"
  if [[ "$QUALIFIED" == "true" ]]; then
    IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
    A402_RESULT_SHA256="$(shasum -a 256 "$A402_RESULT" | awk '{print $1}')"
    A404_RESULT_SHA256="$(shasum -a 256 "$A404_RESULT" | awk '{print $1}')"
    "$PYTHON" "$RUNNER" --freeze-protocol \
      --expected-implementation-sha256 "$IMPLEMENTATION_SHA256" \
      --expected-a404-result-sha256 "$A404_RESULT_SHA256" \
      --expected-a402-result-sha256 "$A402_RESULT_SHA256"
  fi
fi

if [[ "$RECOVER" == "true" ]]; then
  if [[ ! -f "$PROTOCOL" ]]; then
    printf 'A405 recovery requires an out-of-fold-qualified A404 result and frozen protocol\n' >&2
    exit 1
  fi
  EXECUTION_ENABLED="$($PYTHON -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["execution_enabled"]).lower())' "$PROTOCOL")"
  if [[ "$EXECUTION_ENABLED" != "true" ]]; then
    printf 'A405 protocol is equivalence-only because its order is identical to A402\n' >&2
    exit 1
  fi
  PROTOCOL_SHA256="$(shasum -a 256 "$PROTOCOL" | awk '{print $1}')"
  "$PYTHON" "$RUNNER" --recover --expected-protocol-sha256 "$PROTOCOL_SHA256"
fi

"$PYTHON" "$RUNNER" --analyze
"$PYTHON" -m pytest -q "$TEST"
