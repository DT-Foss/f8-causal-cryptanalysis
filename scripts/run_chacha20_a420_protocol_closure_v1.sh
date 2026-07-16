#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LOG="research/logs/chacha20_a420_protocol_closure_v1.log"
IMPLEMENTATION="research/configs/chacha20_round20_w50_external_reader_shared_stop_recovery_a420_implementation_v1.json"
PROTOCOL="research/configs/chacha20_round20_w50_external_reader_shared_stop_recovery_a420_v1.json"
A418_RESULT="research/results/v1/chacha20_round20_w50_selection_calibrated_portfolio_repair_a418_v1.json"
A419_RESULT="research/results/v1/chacha20_round20_w50_majority_polarity_portfolio_a419_v1.json"
POLL_SECONDS="${POLL_SECONDS:-20}"

mkdir -p "$(dirname "$LOG")"

stamp() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

record() {
  printf '%s %s\n' "$(stamp)" "$*" | tee -a "$LOG"
}

on_exit() {
  local status="$?"
  record "A420 protocol closure exit status=$status"
}

trap on_exit EXIT
trap 'record "A420 protocol closure received signal"; exit 130' INT TERM HUP

record "A420 protocol closure start poll_seconds=$POLL_SECONDS"
while [[ ! -f "$IMPLEMENTATION" ]] || [[ ! -f "$A418_RESULT" ]] || [[ ! -f "$A419_RESULT" ]]; do
  a418=no
  a419=no
  [[ -f "$A418_RESULT" ]] && a418=yes
  [[ -f "$A419_RESULT" ]] && a419=yes
  record "waiting for immutable source results A418=$a418 A419=$a419"
  sleep "$POLL_SECONDS"
done

if [[ ! -f "$PROTOCOL" ]]; then
  record "freezing A420 protocol from the prospectively declared external selection rule"
  scripts/reproduce_chacha20_round20_w50_external_reader_shared_stop_recovery_a420.sh \
    --freeze-protocol >>"$LOG" 2>&1
fi

protocol_sha256="$(shasum -a 256 "$PROTOCOL" | awk '{print $1}')"
selected_source="$(.venv/bin/python -c 'import json,sys; print(json.load(open(sys.argv[1]))["selected_source_attempt_id"])' "$PROTOCOL")"
record "A420 protocol frozen sha256=$protocol_sha256 selected_source=$selected_source"
