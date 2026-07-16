#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

runner="research/experiments/chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_assembly_v3.py"
test_file="tests/test_chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_assembly_v3.py"
implementation="research/configs/chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_assembly_v3_implementation_v1.json"

ruff check "$runner" "$test_file"
.venv/bin/python -m py_compile "$runner" "$test_file"
.venv/bin/python -m pytest -q "$test_file"

if [[ ! -f "$implementation" ]]; then
  .venv/bin/python "$runner" --freeze-assembly
fi
implementation_sha256="$(shasum -a 256 "$implementation" | awk '{print $1}')"

if [[ "${1:-}" == "--assemble" ]]; then
  .venv/bin/python "$runner" \
    --assemble \
    --expected-assembly-sha256 "$implementation_sha256"
else
  .venv/bin/python "$runner" --analyze
fi
