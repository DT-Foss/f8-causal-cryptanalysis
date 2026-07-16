#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

runner="research/experiments/chacha20_round20_w51_public_output_direct12_eight_worker_a430.py"
test_file="tests/test_chacha20_round20_w51_public_output_direct12_eight_worker_a430.py"
implementation="research/configs/chacha20_round20_w51_public_output_direct12_eight_worker_a430_implementation_v1.json"
preflight="research/results/v1/chacha20_round20_w51_public_output_direct12_eight_worker_a430_preflight_v1.json"
a425_protocol="research/configs/chacha20_round20_w51_a416_fresh_shared_stop_recovery_a425_v1.json"

ruff check "$runner" "$test_file"
.venv/bin/python -m py_compile "$runner" "$test_file"
.venv/bin/python -m pytest -q "$test_file"

if [[ ! -f "$implementation" ]]; then
  .venv/bin/python "$runner" --freeze-implementation
fi
implementation_sha256="$(shasum -a 256 "$implementation" | awk '{print $1}')"
a425_protocol_sha256="$(shasum -a 256 "$a425_protocol" | awk '{print $1}')"

if [[ ! -f "$preflight" ]]; then
  .venv/bin/python "$runner" \
    --preflight \
    --expected-implementation-sha256 "$implementation_sha256" \
    --expected-a425-protocol-sha256 "$a425_protocol_sha256"
fi
preflight_sha256="$(shasum -a 256 "$preflight" | awk '{print $1}')"

if [[ "${1:-}" == "--measure" ]]; then
  .venv/bin/python "$runner" \
    --measure \
    --expected-implementation-sha256 "$implementation_sha256" \
    --expected-preflight-sha256 "$preflight_sha256" \
    --expected-a425-protocol-sha256 "$a425_protocol_sha256"
else
  .venv/bin/python "$runner" --analyze
fi
