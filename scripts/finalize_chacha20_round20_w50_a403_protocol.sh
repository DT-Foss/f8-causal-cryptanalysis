#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ $# -ne 1 || ! "$1" =~ ^[0-9]+$ ]]; then
  printf 'usage: %s A401_A402_FINALIZER_PID\n' "$0" >&2
  exit 2
fi

FINALIZER_PID="$1"
A402_RESULT="research/results/v1/chacha20_round20_w50_knownkey_fullfit_production_reader_a402_v1.json"

while [[ ! -f "$A402_RESULT" ]] && kill -0 "$FINALIZER_PID" 2>/dev/null; do
  sleep 20
done

if [[ ! -f "$A402_RESULT" ]]; then
  printf 'A401/A402 finalizer ended without an A402 result\n' >&2
  exit 1
fi

scripts/reproduce_chacha20_round20_w50_learned_reader_recovery_a403.sh
