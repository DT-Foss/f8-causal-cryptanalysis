#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MAX_ACTIVE="${MAX_ACTIVE:-8}"
POLL_SECONDS="${POLL_SECONDS:-20}"
LAUNCH_SETTLE_SECONDS="${LAUNCH_SETTLE_SECONDS:-3}"
QUEUE_LOG="research/logs/chacha20_a452_recovery_after_a450_v1.log"
A434_QUALIFICATION="research/results/v1/chacha20_round20_w52_dual_axis_square_wavefront_a434_qualification_v1.json"
A450_RESULT="research/results/v1/chacha20_round20_w52_proof_antecedent_wavefront_recovery_a450_v1.json"
A452_PROTOCOL="research/configs/chacha20_round20_w52_deduplicated_reader_portfolio_recovery_a452_v1.json"
EXPECTED_A452_PROTOCOL_SHA256="fa55a09ff90574f50a08704592f30ccfec4bc6e1071a82d4f2721ea920cf4cfb"
A452_RESULT="research/results/v1/chacha20_round20_w52_deduplicated_reader_portfolio_recovery_a452_v1.json"
A452_RUNNER="research/experiments/chacha20_round20_w52_deduplicated_reader_portfolio_recovery_a452.py"
WORKERS=(0 1 2 3 4 5 6 7)

mkdir -p "$(dirname "$QUEUE_LOG")"

stamp() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
record() { printf '%s %s\n' "$(stamp)" "$*" | tee -a "$QUEUE_LOG"; }
on_exit() { local status="$?"; record "A452 supervisor exit status=$status"; }
trap on_exit EXIT
trap 'record "A452 supervisor received signal"; exit 130' INT TERM HUP

active_recoveries() {
  ps -axo command | awk '
    ($1 ~ /(^|\/)Python$/ || $1 ~ /(^|\/)python([0-9.]*)?$/) &&
    /research\/experiments\/chacha20/ &&
    (/--recover([[:space:]]|$)/ || /--recover-worker([[:space:]]|$)/) { count += 1 }
    END { print count + 0 }
  '
}

a450_supervisor_active() {
  pgrep -f '[r]un_chacha20_a450_recovery_after_a440_v1.sh' >/dev/null 2>&1
}

a450_progress_path() {
  printf 'research/results/v1/chacha20_round20_w52_proof_antecedent_wavefront_recovery_a450_worker_%s_progress_v1.json\n' "$1"
}

a450_closed_terminal() {
  [[ -f "$A450_RESULT" ]] && return 0
  local exhausted=0
  local worker
  for worker in "${WORKERS[@]}"; do
    local path
    path="$(a450_progress_path "$worker")"
    if [[ -f "$path" ]] && [[ "$(.venv/bin/python -c 'import json,sys; print(json.load(open(sys.argv[1])).get("status", "unknown"))' "$path")" == worker_exhausted ]]; then
      exhausted=$((exhausted + 1))
    fi
  done
  (( exhausted == ${#WORKERS[@]} ))
}

progress_path() {
  printf 'research/results/v1/chacha20_round20_w52_deduplicated_reader_portfolio_recovery_a452_worker_%s_progress_v1.json\n' "$1"
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
  pgrep -f "chacha20_round20_w52_deduplicated_reader_portfolio_recovery_a452.py --recover-worker ${worker}([[:space:]]|$)" \
    >/dev/null 2>&1
}

launch_worker() {
  local worker="$1"
  local qualification_sha256="$2"
  local log="research/logs/chacha20_round20_w52_a452_worker_${worker}_recovery.log"
  record "launch A452 worker=$worker protocol_sha256=$EXPECTED_A452_PROTOCOL_SHA256 qualification_sha256=$qualification_sha256"
  caffeinate -dimsu nice -n 10 \
    .venv/bin/python "$A452_RUNNER" \
    --recover-worker "$worker" \
    --expected-protocol-sha256 "$EXPECTED_A452_PROTOCOL_SHA256" \
    --expected-a434-qualification-sha256 "$qualification_sha256" \
    >>"$log" 2>&1 &
}

record "A452 supervisor start max_active=$MAX_ACTIVE"

observed_protocol_sha256="$(shasum -a 256 "$A452_PROTOCOL" | awk '{print $1}')"
if [[ "$observed_protocol_sha256" != "$EXPECTED_A452_PROTOCOL_SHA256" ]]; then
  record "A452 protocol hash mismatch expected=$EXPECTED_A452_PROTOCOL_SHA256 observed=$observed_protocol_sha256"
  exit 1
fi

observed_a450_supervisor=no
while true; do
  if a450_supervisor_active; then
    observed_a450_supervisor=yes
    record "waiting for exclusive predecessor A450 supervisor to close"
    sleep "$POLL_SECONDS"
    continue
  fi
  active="$(active_recoveries)"
  if (( active > 0 )); then
    record "A450 supervisor closed or not yet active; waiting for all recovery workers active=$active"
    sleep "$POLL_SECONDS"
    continue
  fi
  if a450_closed_terminal; then
    break
  fi
  if [[ "$observed_a450_supervisor" == yes ]]; then
    record "A450 supervisor closed without a terminal result or complete exhaustion"
    exit 1
  fi
  record "waiting for A450 supervisor or an already-closed terminal A450 state"
  sleep "$POLL_SECONDS"
done

while [[ ! -f "$A434_QUALIFICATION" ]]; do
  record "waiting for A434 target-free qualification"
  sleep "$POLL_SECONDS"
done

qualification_sha256="$(shasum -a 256 "$A434_QUALIFICATION" | awk '{print $1}')"
.venv/bin/python "$A452_RUNNER" --analyze >/dev/null
record "exclusive eight-slot A452 launch window acquired qualification_sha256=$qualification_sha256"

while [[ ! -f "$A452_RESULT" ]]; do
  launched=no
  for worker in "${WORKERS[@]}"; do
    [[ -f "$A452_RESULT" ]] && break
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
      record "all eight A452 streams exhausted without a confirmed model"
      exit 1
    fi
    sleep "$POLL_SECONDS"
  fi
done

result_sha256="$(shasum -a 256 "$A452_RESULT" | awk '{print $1}')"
record "A452 result complete sha256=$result_sha256"
