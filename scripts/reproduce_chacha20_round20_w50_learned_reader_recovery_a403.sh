#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
RUNNER="research/experiments/chacha20_round20_w50_learned_reader_recovery_a403.py"
IMPLEMENTATION="research/configs/chacha20_round20_w50_learned_reader_recovery_a403_implementation_v1.json"
PROTOCOL="research/configs/chacha20_round20_w50_learned_reader_recovery_a403_v1.json"
A402_RESULT="research/results/v1/chacha20_round20_w50_knownkey_fullfit_production_reader_a402_v1.json"
TEST="tests/test_chacha20_round20_w50_learned_reader_recovery_a403.py"

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

if [[ -f "$A402_RESULT" ]]; then
  QUALIFIED="$($PYTHON -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["qualification"]["qualified"]).lower())' "$A402_RESULT")"
  if [[ "$QUALIFIED" == "true" && ! -f "$PROTOCOL" ]]; then
    IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
    A402_RESULT_SHA256="$(shasum -a 256 "$A402_RESULT" | awk '{print $1}')"
    "$PYTHON" "$RUNNER" --freeze-protocol \
      --expected-implementation-sha256 "$IMPLEMENTATION_SHA256" \
      --expected-a402-result-sha256 "$A402_RESULT_SHA256"
  fi
fi

if [[ "$RECOVER" == "true" ]]; then
  if [[ ! -f "$PROTOCOL" ]]; then
    printf 'A403 recovery requires a heldout-qualified A402 result and frozen protocol\n' >&2
    exit 1
  fi
  PROTOCOL_SHA256="$(shasum -a 256 "$PROTOCOL" | awk '{print $1}')"
  "$PYTHON" "$RUNNER" --recover --expected-protocol-sha256 "$PROTOCOL_SHA256"
fi

"$PYTHON" "$RUNNER" --analyze
"$PYTHON" -m pytest -q "$TEST"
