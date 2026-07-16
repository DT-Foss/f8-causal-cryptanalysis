#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MAX_ACTIVE="${MAX_ACTIVE:-8}"
POLL_SECONDS="${POLL_SECONDS:-20}"
LAUNCH_SETTLE_SECONDS="${LAUNCH_SETTLE_SECONDS:-3}"
QUEUE_LOG="research/logs/chacha20_a429_recovery_after_a426_v1.log"
PROTOCOL="research/configs/chacha20_round20_w50_a428_global_wavefront_recovery_a429_v1.json"
EXPECTED_PROTOCOL_SHA256="12038e91c7f4aa48eea7d7b13bd3b092b1d29a1ed16eca3e6a42a85fe194d8a6"
A426_RESULT="research/results/v1/chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_v1.json"
RESULT="research/results/v1/chacha20_round20_w50_a428_global_wavefront_recovery_a429_v1.json"
RUNNER="research/experiments/chacha20_round20_w50_a428_global_wavefront_recovery_a429.py"
WORKERS=(polarity c123 c035 c100 c153 c091 c049 c144)

mkdir -p "$(dirname "$QUEUE_LOG")"

stamp() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
record() { printf '%s %s\n' "$(stamp)" "$*" | tee -a "$QUEUE_LOG"; }
on_exit() { local status="$?"; record "A429 recovery supervisor exit status=$status"; }
trap on_exit EXIT
trap 'record "A429 recovery supervisor received signal"; exit 130' INT TERM HUP

active_recoveries() {
  ps -axo command | awk '
    ($1 ~ /(^|\/)Python$/ || $1 ~ /(^|\/)python([0-9.]*)?$/) &&
    /research\/experiments\/chacha20/ &&
    (/--recover([[:space:]]|$)/ || /--recover-worker([[:space:]]|$)/) { count += 1 }
    END { print count + 0 }
  '
}

prior_supervisor_active() {
  pgrep -f '[r]un_chacha20_recovery_slot_queue_v1.sh' >/dev/null 2>&1 \
    || pgrep -f '[r]un_chacha20_a420_recovery_slot_queue_v1.sh' >/dev/null 2>&1 \
    || pgrep -f '[r]un_chacha20_a390_qualification_after_a420_v1.sh' >/dev/null 2>&1 \
    || pgrep -f '[r]un_chacha20_a421_recovery_slot_queue_v1.sh' >/dev/null 2>&1 \
    || pgrep -f '[r]un_chacha20_a422_qualification_after_a421_v1.sh' >/dev/null 2>&1 \
    || pgrep -f '[r]un_chacha20_a423_recovery_slot_queue_v1.sh' >/dev/null 2>&1 \
    || pgrep -f '[r]un_chacha20_a424_recovery_slot_queue_v1.sh' >/dev/null 2>&1 \
    || pgrep -f '[r]un_chacha20_a390_qualification_after_a424_v1.sh' >/dev/null 2>&1 \
    || pgrep -f '[r]un_chacha20_a425_recovery_slot_queue_v1.sh' >/dev/null 2>&1 \
    || pgrep -f '[r]un_chacha20_a422_qualification_after_a425_v1.sh' >/dev/null 2>&1 \
    || pgrep -f '[r]un_chacha20_a426_recovery_slot_queue_v1.sh' >/dev/null 2>&1
}

progress_path() {
  local worker="$1"
  printf 'research/results/v1/chacha20_round20_w50_a428_global_wavefront_recovery_a429_%s_progress_v1.json\n' "$worker"
}

worker_status() {
  local path
  path="$(progress_path "$1")"
  if [[ ! -f "$path" ]]; then
    printf 'absent\n'
    return
  fi
  .venv/bin/python -c \
    'import json,sys; print(json.load(open(sys.argv[1])).get("status", "unknown"))' \
    "$path"
}

worker_active() {
  local worker="$1"
  pgrep -f "chacha20_round20_w50_a428_global_wavefront_recovery_a429.py --recover-worker ${worker}([[:space:]]|$)" \
    >/dev/null 2>&1
}

launch_worker() {
  local worker="$1"
  local log="research/logs/chacha20_round20_w50_a429_worker_${worker}_recovery.log"
  record "launch A429 worker=$worker protocol_sha256=$EXPECTED_PROTOCOL_SHA256"
  caffeinate -dimsu nice -n 10 \
    .venv/bin/python "$RUNNER" \
    --recover-worker "$worker" \
    --expected-protocol-sha256 "$EXPECTED_PROTOCOL_SHA256" \
    >>"$log" 2>&1 &
}

record "A429 recovery supervisor start max_active=$MAX_ACTIVE"

while [[ ! -f "$PROTOCOL" ]] || [[ ! -f "$A426_RESULT" ]]; do
  record "waiting for frozen A429 protocol and terminal A426 result"
  sleep "$POLL_SECONDS"
done

protocol_sha256="$(shasum -a 256 "$PROTOCOL" | awk '{print $1}')"
if [[ "$protocol_sha256" != "$EXPECTED_PROTOCOL_SHA256" ]]; then
  record "A429 protocol hash mismatch expected=$EXPECTED_PROTOCOL_SHA256 observed=$protocol_sha256"
  exit 1
fi

while prior_supervisor_active || (( $(active_recoveries) > 0 )); do
  record "waiting without interference for prior supervisors and recoveries to close active=$(active_recoveries)"
  sleep "$POLL_SECONDS"
done

record "exclusive eight-slot A429 launch window acquired"
while [[ ! -f "$RESULT" ]]; do
  launched=no
  for worker in "${WORKERS[@]}"; do
    [[ -f "$RESULT" ]] && break
    status="$(worker_status "$worker")"
    case "$status" in
      worker_exhausted|peer_confirmed)
        continue
        ;;
    esac
    if worker_active "$worker"; then
      continue
    fi
    active="$(active_recoveries)"
    if (( active >= MAX_ACTIVE )); then
      break
    fi
    launch_worker "$worker"
    launched=yes
    sleep "$LAUNCH_SETTLE_SECONDS"
  done

  if [[ "$launched" == no ]]; then
    exhausted=0
    for worker in "${WORKERS[@]}"; do
      [[ "$(worker_status "$worker")" == worker_exhausted ]] && exhausted=$((exhausted + 1))
    done
    if (( exhausted == ${#WORKERS[@]} )); then
      record "all eight A429 schedules exhausted without a confirmed model"
      exit 1
    fi
    sleep "$POLL_SECONDS"
  fi
done

result_sha256="$(shasum -a 256 "$RESULT" | awk '{print $1}')"
record "A429 result complete sha256=$result_sha256"
