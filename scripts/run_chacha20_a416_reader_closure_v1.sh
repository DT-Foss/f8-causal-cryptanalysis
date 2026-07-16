#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LOG="research/logs/chacha20_a416_reader_closure_v1.log"
PROGRESS="research/results/v1/chacha20_round20_w50_fresh_hybrid_reader_a412_progress_v1.json"
A412_RESULT="research/results/v1/chacha20_round20_w50_fresh_hybrid_reader_a412_v1.json"
A415_RESULT="research/results/v1/chacha20_round20_w50_xor_landscape_portfolio_a415_v1.json"
A416_RESULT="research/results/v1/chacha20_round20_w50_folded_xor_portfolio_a416_v1.json"
POLL_SECONDS="${POLL_SECONDS:-30}"

mkdir -p "$(dirname "$LOG")"

timestamp() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

log() {
  printf '%s %s\n' "$(timestamp)" "$*" | tee -a "$LOG"
}

on_exit() {
  status=$?
  log "A416 closure supervisor exit status=$status"
}
trap on_exit EXIT
trap 'log "A416 closure supervisor received signal"; exit 130' INT TERM HUP

progress_complete() {
  [[ -f "$PROGRESS" ]] || return 1
  python3 - "$PROGRESS" <<'PY'
import json
import sys
from pathlib import Path

value = json.loads(Path(sys.argv[1]).read_bytes())
raise SystemExit(
    0
    if value.get("completed_targets") == 32
    and value.get("complete_direct12_cells") == 32 * 4096
    and value.get("selection_or_holdout_labels_opened") is False
    else 1
)
PY
}

log "A416 closure supervisor start poll_seconds=$POLL_SECONDS"
while ! progress_complete || [[ ! -f "$A412_RESULT" ]] || [[ ! -f "$A415_RESULT" ]] || pgrep -f 'chacha20_round20_w50_fresh_hybrid_reader_a412.py' >/dev/null; do
  if [[ -f "$PROGRESS" ]]; then
    completed="$(python3 - "$PROGRESS" <<'PY'
import json
import sys
from pathlib import Path

print(json.loads(Path(sys.argv[1]).read_bytes()).get("completed_targets", 0))
PY
)"
  else
    completed=0
  fi
  a415_present=no
  [[ -f "$A415_RESULT" ]] && a415_present=yes
  log "waiting for A412/A415 closure completed_targets=$completed/32 A415_result=$a415_present"
  sleep "$POLL_SECONDS"
done

log "A412 and A415 terminal closure observed"
if [[ ! -f "$A416_RESULT" ]]; then
  log "starting A416 external evaluation"
  scripts/reproduce_chacha20_round20_w50_folded_xor_portfolio_a416.sh --evaluate \
    >>"$LOG" 2>&1
fi
log "A416 external result present; closure complete"
