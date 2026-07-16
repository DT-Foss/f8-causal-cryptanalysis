#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RUNNER="research/experiments/chacha20_round20_w46_corrected_order_prospective_recovery_a358.py"
IMPLEMENTATION="research/configs/chacha20_round20_w46_corrected_order_prospective_recovery_a358_implementation_v1.json"
PROTOCOL="research/configs/chacha20_round20_w46_corrected_order_prospective_recovery_a358_v1.json"
RESULT="research/results/v1/chacha20_round20_w46_corrected_order_prospective_recovery_a358_v1.json"
QUALIFICATION_SHA256="996dcddfc5f9b9e91f7c77c01aa10747af8f291795dfa04d3e7eaf890047296a"

if [[ ! -f "$IMPLEMENTATION" ]]; then
  "$PYTHON" "$RUNNER" --freeze-implementation
fi
IMPLEMENTATION_SHA256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"

if [[ ! -f "$PROTOCOL" ]]; then
  "$PYTHON" "$RUNNER" --freeze-protocol \
    --expected-implementation-sha256 "$IMPLEMENTATION_SHA256"
fi
PROTOCOL_SHA256="$(shasum -a 256 "$PROTOCOL" | awk '{print $1}')"

if [[ "${RUN_RECOVERY:-0}" == "1" && ! -f "$RESULT" ]]; then
  "$PYTHON" "$RUNNER" --recover \
    --expected-protocol-sha256 "$PROTOCOL_SHA256" \
    --expected-a324-qualification-sha256 "$QUALIFICATION_SHA256"
fi

"$PYTHON" "$RUNNER" --analyze
"$PYTHON" -m pytest -q tests/test_chacha20_round20_w46_corrected_order_prospective_recovery_a358.py
