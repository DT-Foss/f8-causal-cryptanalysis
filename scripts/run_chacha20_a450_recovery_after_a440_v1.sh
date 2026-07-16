#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MAX_ACTIVE="${MAX_ACTIVE:-8}"
POLL_SECONDS="${POLL_SECONDS:-20}"
LAUNCH_SETTLE_SECONDS="${LAUNCH_SETTLE_SECONDS:-3}"
QUEUE_LOG="research/logs/chacha20_a450_recovery_after_a440_v1.log"
A434_QUALIFICATION="research/results/v1/chacha20_round20_w52_dual_axis_square_wavefront_a434_qualification_v1.json"
A440_RESULT="research/results/v1/chacha20_round20_w52_wide_consensus_wavefront_recovery_a440_v1.json"
A450_PROTOCOL="research/configs/chacha20_round20_w52_proof_antecedent_wavefront_recovery_a450_v1.json"
EXPECTED_A450_PROTOCOL_SHA256="88a06dcfb5d0a4a49c2ee98071a4f4f36c6cd6f497528cf61e3d0a07bd0edd5e"
A450_RESULT="research/results/v1/chacha20_round20_w52_proof_antecedent_wavefront_recovery_a450_v1.json"
A450_RUNNER="research/experiments/chacha20_round20_w52_proof_antecedent_wavefront_recovery_a450.py"
WORKERS=(0 1 2 3 4 5 6 7)

mkdir -p "$(dirname "$QUEUE_LOG")"

stamp() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
record() { printf '%s %s\n' "$(stamp)" "$*" | tee -a "$QUEUE_LOG"; }
on_exit() { local status="$?"; record "A450 supervisor exit status=$status"; }
trap on_exit EXIT
trap 'record "A450 supervisor received signal"; exit 130' INT TERM HUP

active_recoveries() {
  ps -axo command | awk '
    ($1 ~ /(^|\/)Python$/ || $1 ~ /(^|\/)python([0-9.]*)?$/) &&
    /research\/experiments\/chacha20/ &&
    (/--recover([[:space:]]|$)/ || /--recover-worker([[:space:]]|$)/) { count += 1 }
    END { print count + 0 }
  '
}

a440_supervisor_active() {
  pgrep -f '[r]un_chacha20_a440_recovery_after_a438_v1.sh' >/dev/null 2>&1
}

a440_progress_path() {
  printf 'research/results/v1/chacha20_round20_w52_wide_consensus_wavefront_recovery_a440_worker_%s_progress_v1.json\n' "$1"
}

a440_closed_terminal() {
  [[ -f "$A440_RESULT" ]] && return 0
  local exhausted=0
  local worker
  for worker in "${WORKERS[@]}"; do
    local path
    path="$(a440_progress_path "$worker")"
    if [[ -f "$path" ]] && [[ "$(.venv/bin/python -c 'import json,sys; print(json.load(open(sys.argv[1])).get("status", "unknown"))' "$path")" == worker_exhausted ]]; then
      exhausted=$((exhausted + 1))
    fi
  done
  (( exhausted == ${#WORKERS[@]} ))
}

progress_path() {
  printf 'research/results/v1/chacha20_round20_w52_proof_antecedent_wavefront_recovery_a450_worker_%s_progress_v1.json\n' "$1"
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
  pgrep -f "chacha20_round20_w52_proof_antecedent_wavefront_recovery_a450.py --recover-worker ${worker}([[:space:]]|$)" \
    >/dev/null 2>&1
}

launch_worker() {
  local worker="$1"
  local qualification_sha256="$2"
  local log="research/logs/chacha20_round20_w52_a450_worker_${worker}_recovery.log"
  record "launch A450 worker=$worker protocol_sha256=$EXPECTED_A450_PROTOCOL_SHA256 qualification_sha256=$qualification_sha256"
  caffeinate -dimsu nice -n 10 \
    .venv/bin/python "$A450_RUNNER" \
    --recover-worker "$worker" \
    --expected-protocol-sha256 "$EXPECTED_A450_PROTOCOL_SHA256" \
    --expected-a434-qualification-sha256 "$qualification_sha256" \
    >>"$log" 2>&1 &
}

record "A450 supervisor start max_active=$MAX_ACTIVE"

observed_protocol_sha256="$(shasum -a 256 "$A450_PROTOCOL" | awk '{print $1}')"
if [[ "$observed_protocol_sha256" != "$EXPECTED_A450_PROTOCOL_SHA256" ]]; then
  record "A450 protocol hash mismatch expected=$EXPECTED_A450_PROTOCOL_SHA256 observed=$observed_protocol_sha256"
  exit 1
fi

observed_a440_supervisor=no
while true; do
  if a440_supervisor_active; then
    observed_a440_supervisor=yes
    record "waiting for exclusive predecessor A440 supervisor to close"
    sleep "$POLL_SECONDS"
    continue
  fi
  active="$(active_recoveries)"
  if (( active > 0 )); then
    record "A440 supervisor closed or not yet active; waiting for all recovery workers active=$active"
    sleep "$POLL_SECONDS"
    continue
  fi
  if a440_closed_terminal; then
    break
  fi
  if [[ "$observed_a440_supervisor" == yes ]]; then
    record "A440 supervisor closed without a terminal result or complete exhaustion"
    exit 1
  fi
  record "waiting for A440 supervisor or an already-closed terminal A440 state"
  sleep "$POLL_SECONDS"
done

while [[ ! -f "$A434_QUALIFICATION" ]]; do
  record "waiting for A434 target-free qualification"
  sleep "$POLL_SECONDS"
done

qualification_sha256="$(shasum -a 256 "$A434_QUALIFICATION" | awk '{print $1}')"
.venv/bin/python "$A450_RUNNER" --analyze >/dev/null
record "exclusive eight-slot A450 launch window acquired qualification_sha256=$qualification_sha256"

while [[ ! -f "$A450_RESULT" ]]; do
  launched=no
  for worker in "${WORKERS[@]}"; do
    [[ -f "$A450_RESULT" ]] && break
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
      record "all eight A450 schedules exhausted without a confirmed model"
      exit 1
    fi
    sleep "$POLL_SECONDS"
  fi
done

result_sha256="$(shasum -a 256 "$A450_RESULT" | awk '{print $1}')"
record "A450 result complete sha256=$result_sha256"
