#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

runner="research/experiments/chacha20_round20_w52_dual_axis_square_wavefront_a434.py"
test_file="tests/test_chacha20_round20_w52_dual_axis_square_wavefront_a434.py"
implementation="research/configs/chacha20_round20_w52_dual_axis_square_wavefront_a434_implementation_v1.json"
protocol="research/configs/chacha20_round20_w52_dual_axis_square_wavefront_a434_v1.json"
a433_result="research/results/v1/chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_v2.json"
a422_qualification="research/results/v1/chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422_qualification_v1.json"

ruff check "$runner" "$test_file"
.venv/bin/python -m py_compile "$runner" "$test_file"
.venv/bin/python -m pytest -q "$test_file"

if [[ ! -f "$implementation" ]]; then
  .venv/bin/python "$runner" --freeze-implementation
fi
implementation_sha256="$(shasum -a 256 "$implementation" | awk '{print $1}')"

if [[ "${1:-}" == "--freeze-protocol" ]]; then
  a433_result_sha256="$(shasum -a 256 "$a433_result" | awk '{print $1}')"
  .venv/bin/python "$runner" \
    --freeze-protocol \
    --expected-implementation-sha256 "$implementation_sha256" \
    --expected-a433-result-sha256 "$a433_result_sha256"
elif [[ "${1:-}" == "--qualify" ]]; then
  protocol_sha256="$(shasum -a 256 "$protocol" | awk '{print $1}')"
  a422_qualification_sha256="$(shasum -a 256 "$a422_qualification" | awk '{print $1}')"
  .venv/bin/python "$runner" \
    --qualify \
    --expected-protocol-sha256 "$protocol_sha256" \
    --expected-a422-qualification-sha256 "$a422_qualification_sha256"
else
  .venv/bin/python "$runner" --analyze
fi
