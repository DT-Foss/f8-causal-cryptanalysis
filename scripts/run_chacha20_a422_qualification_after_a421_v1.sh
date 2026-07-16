#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LOG="research/logs/chacha20_a422_qualification_after_a421_v1.log"
A421_RESULT="research/results/v1/chacha20_round20_w51_external_reader_shared_stop_recovery_a421_v1.json"
A390_QUALIFICATION="research/results/v1/chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_qualification_v1.json"
A422_PROTOCOL="research/configs/chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422_v1.json"
A422_QUALIFICATION="research/results/v1/chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422_qualification_v1.json"
POLL_SECONDS="${POLL_SECONDS:-20}"
MAX_ACTIVE="${MAX_ACTIVE:-8}"

mkdir -p "$(dirname "$LOG")"

stamp() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
record() { printf '%s %s\n' "$(stamp)" "$*" | tee -a "$LOG"; }
on_exit() { local status="$?"; record "A422 qualification supervisor exit status=$status"; }
trap on_exit EXIT
trap 'record "A422 qualification supervisor received signal"; exit 130' INT TERM HUP

active_recoveries() {
  ps -axo command | awk '
    ($1 ~ /(^|\/)Python$/ || $1 ~ /(^|\/)python([0-9.]*)?$/) &&
    /research\/experiments\/chacha20/ &&
    (/--recover([[:space:]]|$)/ || /--recover-worker([[:space:]]|$)/) { count += 1 }
    END { print count + 0 }
  '
}

record "A422 qualification supervisor start"
while [[ ! -f "$A421_RESULT" ]] || [[ ! -f "$A390_QUALIFICATION" ]]; do
  record "waiting for A421 terminal result and exact A390 source qualification"
  sleep "$POLL_SECONDS"
done

while pgrep -f 'scripts/run_chacha20_a421_recovery_slot_queue_v1.sh' >/dev/null 2>&1; do
  record "waiting for A421 launch arbitration to close"
  sleep "$POLL_SECONDS"
done

while (( $(active_recoveries) >= MAX_ACTIVE )); do
  record "waiting for one free exact-recovery slot active=$(active_recoveries)/$MAX_ACTIVE"
  sleep "$POLL_SECONDS"
done

if [[ ! -f "$A422_QUALIFICATION" ]]; then
  record "starting target-free complete 2^40 W52 engine qualification"
  scripts/reproduce_chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422.sh \
    --qualify >>"$LOG" 2>&1
fi

qualification_sha256="$(shasum -a 256 "$A422_QUALIFICATION" | awk '{print $1}')"
record "A422 exact W52 qualification complete sha256=$qualification_sha256"
