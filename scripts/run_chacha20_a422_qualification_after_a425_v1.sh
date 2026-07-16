#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LOG="research/logs/chacha20_a422_qualification_after_a425_v1.log"
A425_RESULT="research/results/v1/chacha20_round20_w51_a416_fresh_shared_stop_recovery_a425_v1.json"
A390_QUALIFICATION="research/results/v1/chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_qualification_v1.json"
A422_PROTOCOL="research/configs/chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422_v1.json"
A422_QUALIFICATION="research/results/v1/chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422_qualification_v1.json"
POLL_SECONDS="${POLL_SECONDS:-20}"

mkdir -p "$(dirname "$LOG")"

stamp() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
record() { printf '%s %s\n' "$(stamp)" "$*" | tee -a "$LOG"; }
on_exit() { local status="$?"; record "A422-after-A425 qualification supervisor exit status=$status"; }
trap on_exit EXIT
trap 'record "A422-after-A425 qualification supervisor received signal"; exit 130' INT TERM HUP

active_recoveries() {
  ps -axo command | awk '
    ($1 ~ /(^|\/)Python$/ || $1 ~ /(^|\/)python([0-9.]*)?$/) &&
    /research\/experiments\/chacha20/ &&
    (/--recover([[:space:]]|$)/ || /--recover-worker([[:space:]]|$)/) { count += 1 }
    END { print count + 0 }
  '
}

record "A422-after-A425 qualification supervisor start"
while [[ ! -f "$A425_RESULT" ]] || [[ ! -f "$A390_QUALIFICATION" ]]; do
  record "waiting for A425 terminal recovery and A390 exact qualification"
  sleep "$POLL_SECONDS"
done

while (( $(active_recoveries) > 0 )) \
  || pgrep -f '[r]un_chacha20_a425_recovery_slot_queue_v1.sh' >/dev/null 2>&1; do
  record "waiting for A425 recovery processes to close active=$(active_recoveries)"
  sleep "$POLL_SECONDS"
done

if [[ ! -f "$A422_QUALIFICATION" ]]; then
  record "starting target-free complete 2^40 W52 engine qualification"
  scripts/reproduce_chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422.sh \
    --qualify >>"$LOG" 2>&1
fi

qualification_sha256="$(shasum -a 256 "$A422_QUALIFICATION" | awk '{print $1}')"
record "A422 exact W52 qualification complete sha256=$qualification_sha256"
