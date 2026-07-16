#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MAX_ACTIVE="${MAX_ACTIVE:-8}"
POLL_SECONDS="${POLL_SECONDS:-20}"
LAUNCH_SETTLE_SECONDS="${LAUNCH_SETTLE_SECONDS:-5}"
QUEUE_LOG="research/logs/chacha20_a421_recovery_slot_queue_v1.log"
PROTOCOL="research/configs/chacha20_round20_w51_external_reader_shared_stop_recovery_a421_v1.json"
QUALIFICATION="research/results/v1/chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_qualification_v1.json"
A420_RESULT="research/results/v1/chacha20_round20_w50_external_reader_shared_stop_recovery_a420_v1.json"
STOP="research/results/v1/chacha20_round20_w51_external_reader_shared_stop_recovery_a421_confirmed_stop_v1.json"
RESULT="research/results/v1/chacha20_round20_w51_external_reader_shared_stop_recovery_a421_v1.json"

mkdir -p "$(dirname "$QUEUE_LOG")"

stamp() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
record() { printf '%s %s\n' "$(stamp)" "$*" | tee -a "$QUEUE_LOG"; }
on_exit() { local status="$?"; record "A421 recovery queue exit status=$status"; }
trap on_exit EXIT
trap 'record "A421 recovery queue received signal"; exit 130' INT TERM HUP

active_recoveries() {
  ps -axo command | awk '
    ($1 ~ /(^|\/)Python$/ || $1 ~ /(^|\/)python([0-9.]*)?$/) &&
    /research\/experiments\/chacha20/ &&
    (/--recover([[:space:]]|$)/ || /--recover-worker([[:space:]]|$)/) { count += 1 }
    END { print count + 0 }
  '
}

worker_progress() {
  local worker="$1"
  local path="research/results/v1/chacha20_round20_w51_external_reader_shared_stop_recovery_a421_worker_${worker}_progress_v1.json"
  if [[ ! -f "$path" ]]; then printf 'absent\n'; return; fi
  .venv/bin/python -c 'import json,sys; print(json.load(open(sys.argv[1])).get("status", "unknown"))' "$path"
}

worker_active() {
  local worker="$1"
  pgrep -f "chacha20_round20_w51_external_reader_shared_stop_recovery_a421[^ ]* .*--recover-worker ${worker}([[:space:]]|$)" >/dev/null 2>&1
}

launch_worker() {
  local worker="$1"
  local log="research/logs/chacha20_round20_w51_a421_worker_${worker}_recovery.log"
  record "launch A421 worker=$worker"
  caffeinate -dimsu nice -n 10 \
    scripts/reproduce_chacha20_round20_w51_external_reader_shared_stop_recovery_a421.sh \
    --recover-worker "$worker" >>"$log" 2>&1 &
}

record "A421 recovery queue start max_active=$MAX_ACTIVE"
while [[ ! -f "$PROTOCOL" ]] || [[ ! -f "$QUALIFICATION" ]] || [[ ! -f "$A420_RESULT" ]]; do
  record "waiting for A421 protocol, A390 qualification and A420 terminal result"
  sleep "$POLL_SECONDS"
done

while pgrep -f 'scripts/run_chacha20_a420_recovery_slot_queue_v1.sh' >/dev/null 2>&1 \
  || pgrep -f 'chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390.py --qualify' >/dev/null 2>&1; do
  record "waiting for prior launch or qualification process to close"
  sleep "$POLL_SECONDS"
done

protocol_sha256="$(shasum -a 256 "$PROTOCOL" | awk '{print $1}')"
qualification_sha256="$(shasum -a 256 "$QUALIFICATION" | awk '{print $1}')"
record "A421 prerequisites observed protocol_sha256=$protocol_sha256 qualification_sha256=$qualification_sha256"

while [[ ! -f "$RESULT" ]]; do
  launched=no
  for worker in 0 1 2 3 4 5 6 7; do
    [[ -f "$RESULT" ]] && break
    status="$(worker_progress "$worker")"
    case "$status" in
      worker_exhausted|peer_confirmed)
        continue
        ;;
    esac
    if worker_active "$worker"; then continue; fi
    active="$(active_recoveries)"
    if (( active >= MAX_ACTIVE )); then break; fi
    if [[ -f "$STOP" && "$status" == absent ]]; then
      continue
    fi
    launch_worker "$worker"
    launched=yes
    sleep "$LAUNCH_SETTLE_SECONDS"
  done

  if [[ "$launched" == no ]]; then
    exhausted=0
    for worker in 0 1 2 3 4 5 6 7; do
      [[ "$(worker_progress "$worker")" == worker_exhausted ]] && exhausted=$((exhausted + 1))
    done
    if (( exhausted == 8 )); then
      record "all eight A421 schedules exhausted without a confirmed model"
      exit 1
    fi
    sleep "$POLL_SECONDS"
  fi
done

result_sha256="$(shasum -a 256 "$RESULT" | awk '{print $1}')"
record "A421 result complete sha256=$result_sha256"
