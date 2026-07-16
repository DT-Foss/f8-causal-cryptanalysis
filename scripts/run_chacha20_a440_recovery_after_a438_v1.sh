#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MAX_ACTIVE="${MAX_ACTIVE:-8}"
POLL_SECONDS="${POLL_SECONDS:-20}"
LAUNCH_SETTLE_SECONDS="${LAUNCH_SETTLE_SECONDS:-3}"
QUEUE_LOG="research/logs/chacha20_a440_recovery_after_a438_v1.log"
A422_QUALIFICATION="research/results/v1/chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422_qualification_v1.json"
A434_PROTOCOL="research/configs/chacha20_round20_w52_dual_axis_square_wavefront_a434_v1.json"
A434_QUALIFICATION="research/results/v1/chacha20_round20_w52_dual_axis_square_wavefront_a434_qualification_v1.json"
A434_RUNNER="research/experiments/chacha20_round20_w52_dual_axis_square_wavefront_a434.py"
A438_RESULT="research/results/v1/chacha20_round20_w52_calibration_balanced_wavefront_recovery_a438_v1.json"
A443_RESULT="research/results/v1/chacha20_round20_w52_borda_meta_reader_wavefront_recovery_a443_v1.json"
A440_PROTOCOL="research/configs/chacha20_round20_w52_wide_consensus_wavefront_recovery_a440_v1.json"
EXPECTED_A440_PROTOCOL_SHA256="b69fe063628857748258d91b5985161ae6957773fc1100f8230dc6504b91be26"
A440_RESULT="research/results/v1/chacha20_round20_w52_wide_consensus_wavefront_recovery_a440_v1.json"
A440_RUNNER="research/experiments/chacha20_round20_w52_wide_consensus_wavefront_recovery_a440.py"
WORKERS=(0 1 2 3 4 5 6 7)

mkdir -p "$(dirname "$QUEUE_LOG")"

stamp() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
record() { printf '%s %s\n' "$(stamp)" "$*" | tee -a "$QUEUE_LOG"; }
on_exit() { local status="$?"; record "A440 supervisor exit status=$status"; }
trap on_exit EXIT
trap 'record "A440 supervisor received signal"; exit 130' INT TERM HUP

active_recoveries() {
  ps -axo command | awk '
    ($1 ~ /(^|\/)Python$/ || $1 ~ /(^|\/)python([0-9.]*)?$/) &&
    /research\/experiments\/chacha20/ &&
    (/--recover([[:space:]]|$)/ || /--recover-worker([[:space:]]|$)/) { count += 1 }
    END { print count + 0 }
  '
}

a438_supervisor_active() {
  pgrep -f '[r]un_chacha20_a438_recovery_after_a431_v1.sh' >/dev/null 2>&1
}

a438_progress_path() {
  local worker="$1"
  printf 'research/results/v1/chacha20_round20_w52_calibration_balanced_wavefront_recovery_a438_worker_%s_progress_v1.json\n' "$worker"
}

a438_terminal() {
  if [[ -f "$A438_RESULT" ]]; then
    return 0
  fi
  local exhausted=0
  local worker
  for worker in "${WORKERS[@]}"; do
    local path
    path="$(a438_progress_path "$worker")"
    if [[ -f "$path" ]] && [[ "$(.venv/bin/python -c 'import json,sys; print(json.load(open(sys.argv[1])).get("status", "unknown"))' "$path")" == worker_exhausted ]]; then
      exhausted=$((exhausted + 1))
    fi
  done
  (( exhausted == ${#WORKERS[@]} ))
}

a443_supervisor_active() {
  pgrep -f '[r]un_chacha20_a443_recovery_after_a438_v1.sh' >/dev/null 2>&1
}

a443_progress_path() {
  local worker="$1"
  printf 'research/results/v1/chacha20_round20_w52_borda_meta_reader_wavefront_recovery_a443_worker_%s_progress_v1.json\n' "$worker"
}

a443_terminal() {
  if [[ -f "$A443_RESULT" ]]; then
    return 0
  fi
  local exhausted=0
  local worker
  for worker in "${WORKERS[@]}"; do
    local path
    path="$(a443_progress_path "$worker")"
    if [[ -f "$path" ]] && [[ "$(.venv/bin/python -c 'import json,sys; print(json.load(open(sys.argv[1])).get("status", "unknown"))' "$path")" == worker_exhausted ]]; then
      exhausted=$((exhausted + 1))
    fi
  done
  (( exhausted == ${#WORKERS[@]} ))
}

progress_path() {
  local worker="$1"
  printf 'research/results/v1/chacha20_round20_w52_wide_consensus_wavefront_recovery_a440_worker_%s_progress_v1.json\n' "$worker"
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
  pgrep -f "chacha20_round20_w52_wide_consensus_wavefront_recovery_a440.py --recover-worker ${worker}([[:space:]]|$)" \
    >/dev/null 2>&1
}

launch_worker() {
  local worker="$1"
  local qualification_sha256="$2"
  local log="research/logs/chacha20_round20_w52_a440_worker_${worker}_recovery.log"
  record "launch A440 worker=$worker protocol_sha256=$EXPECTED_A440_PROTOCOL_SHA256 qualification_sha256=$qualification_sha256"
  caffeinate -dimsu nice -n 10 \
    .venv/bin/python "$A440_RUNNER" \
    --recover-worker "$worker" \
    --expected-protocol-sha256 "$EXPECTED_A440_PROTOCOL_SHA256" \
    --expected-a434-qualification-sha256 "$qualification_sha256" \
    >>"$log" 2>&1 &
}

record "A440 supervisor start max_active=$MAX_ACTIVE"

observed_protocol_sha256="$(shasum -a 256 "$A440_PROTOCOL" | awk '{print $1}')"
if [[ "$observed_protocol_sha256" != "$EXPECTED_A440_PROTOCOL_SHA256" ]]; then
  record "A440 protocol hash mismatch expected=$EXPECTED_A440_PROTOCOL_SHA256 observed=$observed_protocol_sha256"
  exit 1
fi

while ! a438_terminal; do
  record "waiting for terminal A438 result or complete eight-worker exhaustion"
  sleep "$POLL_SECONDS"
done

while a438_supervisor_active || (( $(active_recoveries) > 0 )); do
  record "A438 terminal observed; waiting for its supervisor and workers to close active=$(active_recoveries)"
  sleep "$POLL_SECONDS"
done

while ! a443_terminal; do
  record "A438 terminal observed; waiting for higher-priority orthogonal A443 result or complete exhaustion"
  sleep "$POLL_SECONDS"
done

while a443_supervisor_active || (( $(active_recoveries) > 0 )); do
  record "A443 terminal observed; waiting for its supervisor and workers to close active=$(active_recoveries)"
  sleep "$POLL_SECONDS"
done

if [[ ! -f "$A422_QUALIFICATION" ]]; then
  record "A422 qualification absent after A438 terminal; waiting"
  while [[ ! -f "$A422_QUALIFICATION" ]]; do
    sleep "$POLL_SECONDS"
  done
fi

if [[ ! -f "$A434_QUALIFICATION" ]]; then
  a434_protocol_sha256="$(shasum -a 256 "$A434_PROTOCOL" | awk '{print $1}')"
  a422_qualification_sha256="$(shasum -a 256 "$A422_QUALIFICATION" | awk '{print $1}')"
  record "qualify A434 protocol_sha256=$a434_protocol_sha256 A422_qualification_sha256=$a422_qualification_sha256"
  .venv/bin/python "$A434_RUNNER" \
    --qualify \
    --expected-protocol-sha256 "$a434_protocol_sha256" \
    --expected-a422-qualification-sha256 "$a422_qualification_sha256" \
    >>"$QUEUE_LOG" 2>&1
fi

qualification_sha256="$(shasum -a 256 "$A434_QUALIFICATION" | awk '{print $1}')"
.venv/bin/python "$A440_RUNNER" --analyze >/dev/null
record "exclusive eight-slot A440 launch window acquired qualification_sha256=$qualification_sha256"

while [[ ! -f "$A440_RESULT" ]]; do
  launched=no
  for worker in "${WORKERS[@]}"; do
    [[ -f "$A440_RESULT" ]] && break
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
      record "all eight A440 schedules exhausted without a confirmed model"
      exit 1
    fi
    sleep "$POLL_SECONDS"
  fi
done

result_sha256="$(shasum -a 256 "$A440_RESULT" | awk '{print $1}')"
record "A440 result complete sha256=$result_sha256"
