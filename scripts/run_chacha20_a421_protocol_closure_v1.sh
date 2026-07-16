#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LOG="research/logs/chacha20_a421_protocol_closure_v1.log"
IMPLEMENTATION="research/configs/chacha20_round20_w51_external_reader_shared_stop_recovery_a421_implementation_v1.json"
A420_PROTOCOL="research/configs/chacha20_round20_w50_external_reader_shared_stop_recovery_a420_v1.json"
A420_RESULT="research/results/v1/chacha20_round20_w50_external_reader_shared_stop_recovery_a420_v1.json"
PROTOCOL="research/configs/chacha20_round20_w51_external_reader_shared_stop_recovery_a421_v1.json"
POLL_SECONDS="${POLL_SECONDS:-10}"

mkdir -p "$(dirname "$LOG")"

stamp() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
record() { printf '%s %s\n' "$(stamp)" "$*" | tee -a "$LOG"; }
on_exit() { local status="$?"; record "A421 protocol closure exit status=$status"; }
trap on_exit EXIT
trap 'record "A421 protocol closure received signal"; exit 130' INT TERM HUP

record "A421 protocol closure start poll_seconds=$POLL_SECONDS"
while [[ ! -f "$IMPLEMENTATION" ]] || [[ ! -f "$A420_PROTOCOL" ]]; do
  record "waiting for frozen A420 protocol"
  sleep "$POLL_SECONDS"
done

if [[ -f "$A420_RESULT" ]] && [[ ! -f "$PROTOCOL" ]]; then
  record "A420 result preceded A421 fresh challenge; refusing retrospective materialization"
  exit 1
fi

if [[ ! -f "$PROTOCOL" ]]; then
  record "materializing fresh W51 challenge against the already frozen A420 schedule"
  scripts/reproduce_chacha20_round20_w51_external_reader_shared_stop_recovery_a421.sh \
    --materialize-protocol >>"$LOG" 2>&1
fi

protocol_sha256="$(shasum -a 256 "$PROTOCOL" | awk '{print $1}')"
challenge_sha256="$(.venv/bin/python -c 'import json,sys; print(json.load(open(sys.argv[1]))["public_challenge_sha256"])' "$PROTOCOL")"
record "A421 protocol frozen sha256=$protocol_sha256 public_challenge_sha256=$challenge_sha256"
