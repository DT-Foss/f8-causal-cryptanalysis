#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MAX_ACTIVE="${MAX_ACTIVE:-8}"
POLL_SECONDS="${POLL_SECONDS:-20}"
LAUNCH_SETTLE_SECONDS="${LAUNCH_SETTLE_SECONDS:-3}"
QUEUE_LOG="research/logs/chacha20_a431_recovery_after_a429_v1.log"
PROTOCOL="research/configs/chacha20_round20_w51_a430_direct12_recovery_a431_v1.json"
EXPECTED_PROTOCOL_SHA256="3bf82d76d6ed0346a336711b011106df8a4b493c27a7b2e5b6c9eb8706c5da00"
QUALIFICATION="research/results/v1/chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_qualification_v1.json"
A429_RESULT="research/results/v1/chacha20_round20_w50_a428_global_wavefront_recovery_a429_v1.json"
RESULT="research/results/v1/chacha20_round20_w51_a430_direct12_recovery_a431_v1.json"
RUNNER="research/experiments/chacha20_round20_w51_a430_direct12_recovery_a431.py"
WORKERS=(
  direct_wave_0
  direct_wave_1
  direct_wave_2
  direct_wave_3
  direct_wave_4
  direct_wave_5
  direct_wave_6
  direct_wave_7
)

mkdir -p "$(dirname "$QUEUE_LOG")"

stamp() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
record() { printf '%s %s\n' "$(stamp)" "$*" | tee -a "$QUEUE_LOG"; }
on_exit() { local status="$?"; record "A431 recovery supervisor exit status=$status"; }
trap on_exit EXIT
trap 'record "A431 recovery supervisor received signal"; exit 130' INT TERM HUP

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
    || pgrep -f '[r]un_chacha20_a426_recovery_slot_queue_v1.sh' >/dev/null 2>&1 \
    || pgrep -f '[r]un_chacha20_a429_recovery_after_a426_v1.sh' >/dev/null 2>&1
}

progress_path() {
  local worker="$1"
  local index="${worker##*_}"
  printf 'research/results/v1/chacha20_round20_w51_a430_direct12_recovery_a431_worker_%s_progress_v1.json\n' "$index"
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
  pgrep -f "chacha20_round20_w51_a430_direct12_recovery_a431.py --recover-worker ${worker}([[:space:]]|$)" \
    >/dev/null 2>&1
}

launch_worker() {
  local worker="$1"
  local qualification_sha256="$2"
  local log="research/logs/chacha20_round20_w51_a431_worker_${worker}_recovery.log"
  record "launch A431 worker=$worker protocol_sha256=$EXPECTED_PROTOCOL_SHA256 qualification_sha256=$qualification_sha256"
  caffeinate -dimsu nice -n 10 \
    .venv/bin/python "$RUNNER" \
    --recover-worker "$worker" \
    --expected-protocol-sha256 "$EXPECTED_PROTOCOL_SHA256" \
    --expected-a390-qualification-sha256 "$qualification_sha256" \
    >>"$log" 2>&1 &
}

record "A431 recovery supervisor start max_active=$MAX_ACTIVE"

while [[ ! -f "$PROTOCOL" ]] || [[ ! -f "$QUALIFICATION" ]] || [[ ! -f "$A429_RESULT" ]]; do
  record "waiting for frozen A431 protocol, A390 qualification and terminal A429 result"
  sleep "$POLL_SECONDS"
done

protocol_sha256="$(shasum -a 256 "$PROTOCOL" | awk '{print $1}')"
if [[ "$protocol_sha256" != "$EXPECTED_PROTOCOL_SHA256" ]]; then
  record "A431 protocol hash mismatch expected=$EXPECTED_PROTOCOL_SHA256 observed=$protocol_sha256"
  exit 1
fi
qualification_sha256="$(shasum -a 256 "$QUALIFICATION" | awk '{print $1}')"

while prior_supervisor_active || (( $(active_recoveries) > 0 )); do
  record "waiting without interference for prior supervisors and recoveries to close active=$(active_recoveries)"
  sleep "$POLL_SECONDS"
done

record "exclusive eight-slot A431 launch window acquired qualification_sha256=$qualification_sha256"
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
    launch_worker "$worker" "$qualification_sha256"
    launched=yes
    sleep "$LAUNCH_SETTLE_SECONDS"
  done

  if [[ "$launched" == no ]]; then
    exhausted=0
    for worker in "${WORKERS[@]}"; do
      [[ "$(worker_status "$worker")" == worker_exhausted ]] && exhausted=$((exhausted + 1))
    done
    if (( exhausted == ${#WORKERS[@]} )); then
      record "all eight A431 schedules exhausted without a confirmed model"
      exit 1
    fi
    sleep "$POLL_SECONDS"
  fi
done

result_sha256="$(shasum -a 256 "$RESULT" | awk '{print $1}')"
record "A431 result complete sha256=$result_sha256"
