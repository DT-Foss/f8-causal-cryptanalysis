#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MAX_ACTIVE="${MAX_ACTIVE:-8}"
POLL_SECONDS="${POLL_SECONDS:-20}"
LAUNCH_SETTLE_SECONDS="${LAUNCH_SETTLE_SECONDS:-3}"
QUEUE_LOG="research/logs/chacha20_a455_recovery_after_a452_v1.log"
A434_QUALIFICATION="research/results/v1/chacha20_round20_w52_dual_axis_square_wavefront_a434_qualification_v1.json"
A452_RESULT="research/results/v1/chacha20_round20_w52_deduplicated_reader_portfolio_recovery_a452_v1.json"
A455_PROTOCOL="research/configs/chacha20_round20_w52_no_refit_weighted_reader_portfolio_recovery_a455_v1.json"
EXPECTED_A455_PROTOCOL_SHA256="4da384c21476aa8fb4e1045c1d8552254c63711e5ac87f77ab392c4e5b697113"
A455_RESULT="research/results/v1/chacha20_round20_w52_no_refit_weighted_reader_portfolio_recovery_a455_v1.json"
A455_RUNNER="research/experiments/chacha20_round20_w52_no_refit_weighted_reader_portfolio_recovery_a455.py"
WORKERS=(0 1 2 3 4 5 6 7)

mkdir -p "$(dirname "$QUEUE_LOG")"

stamp() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
record() { printf '%s %s\n' "$(stamp)" "$*" | tee -a "$QUEUE_LOG"; }
on_exit() { local status="$?"; record "A455 supervisor exit status=$status"; }
trap on_exit EXIT
trap 'record "A455 supervisor received signal"; exit 130' INT TERM HUP

active_recoveries() {
  ps -axo command | awk '
    ($1 ~ /(^|\/)Python$/ || $1 ~ /(^|\/)python([0-9.]*)?$/) &&
    /research\/experiments\/chacha20/ &&
    (/--recover([[:space:]]|$)/ || /--recover-worker([[:space:]]|$)/) { count += 1 }
    END { print count + 0 }
  '
}

a452_supervisor_active() {
  pgrep -f '[r]un_chacha20_a452_recovery_after_a450_v1.sh' >/dev/null 2>&1
}

progress_path() {
  printf 'research/results/v1/chacha20_round20_w52_no_refit_weighted_reader_portfolio_recovery_a455_worker_%s_progress_v1.json\n' "$1"
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
  pgrep -f "chacha20_round20_w52_no_refit_weighted_reader_portfolio_recovery_a455.py --recover-worker ${worker}([[:space:]]|$)" \
    >/dev/null 2>&1
}

launch_worker() {
  local worker="$1"
  local qualification_sha256="$2"
  local log="research/logs/chacha20_round20_w52_a455_worker_${worker}_recovery.log"
  record "launch A455 worker=$worker protocol_sha256=$EXPECTED_A455_PROTOCOL_SHA256 qualification_sha256=$qualification_sha256"
  caffeinate -dimsu nice -n 10 \
    .venv/bin/python "$A455_RUNNER" \
    --recover-worker "$worker" \
    --expected-protocol-sha256 "$EXPECTED_A455_PROTOCOL_SHA256" \
    --expected-a434-qualification-sha256 "$qualification_sha256" \
    >>"$log" 2>&1 &
}

record "A455 supervisor start max_active=$MAX_ACTIVE"

observed_protocol_sha256="$(shasum -a 256 "$A455_PROTOCOL" | awk '{print $1}')"
if [[ "$observed_protocol_sha256" != "$EXPECTED_A455_PROTOCOL_SHA256" ]]; then
  record "A455 protocol hash mismatch expected=$EXPECTED_A455_PROTOCOL_SHA256 observed=$observed_protocol_sha256"
  exit 1
fi

observed_a452_supervisor=no
while true; do
  if a452_supervisor_active; then
    observed_a452_supervisor=yes
    record "waiting for exclusive predecessor A452 supervisor to close"
    sleep "$POLL_SECONDS"
    continue
  fi
  active="$(active_recoveries)"
  if (( active > 0 )); then
    record "A452 supervisor closed or not yet active; waiting for all recovery workers active=$active"
    sleep "$POLL_SECONDS"
    continue
  fi
  if [[ -f "$A452_RESULT" ]]; then
    break
  fi
  if [[ "$observed_a452_supervisor" == yes ]]; then
    record "A452 supervisor closed without a terminal confirmed result"
    exit 1
  fi
  record "waiting for A452 supervisor or an already-closed terminal A452 result"
  sleep "$POLL_SECONDS"
done

while [[ ! -f "$A434_QUALIFICATION" ]]; do
  record "waiting for A434 target-free qualification"
  sleep "$POLL_SECONDS"
done

qualification_sha256="$(shasum -a 256 "$A434_QUALIFICATION" | awk '{print $1}')"
.venv/bin/python "$A455_RUNNER" --analyze >/dev/null
record "exclusive eight-slot A455 launch window acquired qualification_sha256=$qualification_sha256"

while [[ ! -f "$A455_RESULT" ]]; do
  launched=no
  for worker in "${WORKERS[@]}"; do
    [[ -f "$A455_RESULT" ]] && break
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
      record "all eight A455 streams exhausted without a confirmed model"
      exit 1
    fi
    sleep "$POLL_SECONDS"
  fi
done

result_sha256="$(shasum -a 256 "$A455_RESULT" | awk '{print $1}')"
record "A455 result complete sha256=$result_sha256"
