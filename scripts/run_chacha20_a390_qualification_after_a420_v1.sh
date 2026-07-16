#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LOG="research/logs/chacha20_a390_qualification_after_a420_v1.log"
A420_RESULT="research/results/v1/chacha20_round20_w50_external_reader_shared_stop_recovery_a420_v1.json"
A421_PROTOCOL="research/configs/chacha20_round20_w51_external_reader_shared_stop_recovery_a421_v1.json"
A390_PROTOCOL="research/configs/chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_v1.json"
A390_QUALIFICATION="research/results/v1/chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_qualification_v1.json"
POLL_SECONDS="${POLL_SECONDS:-20}"
MAX_ACTIVE="${MAX_ACTIVE:-8}"

mkdir -p "$(dirname "$LOG")"

stamp() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
record() { printf '%s %s\n' "$(stamp)" "$*" | tee -a "$LOG"; }
on_exit() { local status="$?"; record "A390 qualification supervisor exit status=$status"; }
trap on_exit EXIT
trap 'record "A390 qualification supervisor received signal"; exit 130' INT TERM HUP

active_recoveries() {
  ps -axo command | awk '
    ($1 ~ /(^|\/)Python$/ || $1 ~ /(^|\/)python([0-9.]*)?$/) &&
    /research\/experiments\/chacha20/ &&
    (/--recover([[:space:]]|$)/ || /--recover-worker([[:space:]]|$)/) { count += 1 }
    END { print count + 0 }
  '
}

record "A390 qualification supervisor start"
while [[ ! -f "$A420_RESULT" ]] || [[ ! -f "$A421_PROTOCOL" ]]; do
  record "waiting for A420 result and pre-result A421 protocol"
  sleep "$POLL_SECONDS"
done

while pgrep -f 'scripts/run_chacha20_a420_recovery_slot_queue_v1.sh' >/dev/null 2>&1; do
  record "waiting for A420 launch arbitration to close"
  sleep "$POLL_SECONDS"
done

while (( $(active_recoveries) >= MAX_ACTIVE )); do
  record "waiting for one free exact-recovery slot active=$(active_recoveries)/$MAX_ACTIVE"
  sleep "$POLL_SECONDS"
done

if [[ ! -f "$A390_QUALIFICATION" ]]; then
  protocol_sha256="$(shasum -a 256 "$A390_PROTOCOL" | awk '{print $1}')"
  record "starting target-free complete 2^39 W51 engine qualification protocol_sha256=$protocol_sha256"
  PYTHONWARNINGS=error .venv/bin/python -m pytest -q \
    tests/test_chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390.py \
    >>"$LOG" 2>&1
  scripts/reproduce_chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390.sh \
    --qualify --expected-protocol-sha256 "$protocol_sha256" >>"$LOG" 2>&1
fi

qualification_sha256="$(shasum -a 256 "$A390_QUALIFICATION" | awk '{print $1}')"
record "A390 exact W51 qualification complete sha256=$qualification_sha256"
