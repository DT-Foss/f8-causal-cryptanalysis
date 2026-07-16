#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

ruff check \
  research/experiments/chacha20_round20_w51_a430_direct12_recovery_a431.py \
  tests/test_chacha20_round20_w51_a430_direct12_recovery_a431.py
.venv/bin/python -m py_compile \
  research/experiments/chacha20_round20_w51_a430_direct12_recovery_a431.py \
  tests/test_chacha20_round20_w51_a430_direct12_recovery_a431.py
.venv/bin/pytest -q tests/test_chacha20_round20_w51_a430_direct12_recovery_a431.py

if [[ ! -f research/configs/chacha20_round20_w51_a430_direct12_recovery_a431_implementation_v1.json ]]; then
  .venv/bin/python research/experiments/chacha20_round20_w51_a430_direct12_recovery_a431.py \
    --freeze-implementation
fi

implementation_sha256="$(sha256sum research/configs/chacha20_round20_w51_a430_direct12_recovery_a431_implementation_v1.json | awk '{print $1}')"
a430_result="research/results/v1/chacha20_round20_w51_public_output_direct12_eight_worker_a430_v1.json"
protocol="research/configs/chacha20_round20_w51_a430_direct12_recovery_a431_v1.json"

if [[ -f "$a430_result" && ! -f "$protocol" ]]; then
  a430_result_sha256="$(sha256sum "$a430_result" | awk '{print $1}')"
  .venv/bin/python research/experiments/chacha20_round20_w51_a430_direct12_recovery_a431.py \
    --freeze-protocol \
    --expected-implementation-sha256 "$implementation_sha256" \
    --expected-a430-result-sha256 "$a430_result_sha256"
fi

if [[ "$#" -gt 0 && "$1" == "--recover-worker" ]]; then
  worker="$2"
  qualification="research/results/v1/chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_qualification_v1.json"
  [[ -f "$protocol" ]] || { echo "A431 protocol is not frozen" >&2; exit 1; }
  [[ -f "$qualification" ]] || { echo "A390 qualification is unavailable" >&2; exit 1; }
  protocol_sha256="$(sha256sum "$protocol" | awk '{print $1}')"
  qualification_sha256="$(sha256sum "$qualification" | awk '{print $1}')"
  .venv/bin/python research/experiments/chacha20_round20_w51_a430_direct12_recovery_a431.py \
    --recover-worker "$worker" \
    --expected-protocol-sha256 "$protocol_sha256" \
    --expected-a390-qualification-sha256 "$qualification_sha256"
else
  .venv/bin/python research/experiments/chacha20_round20_w51_a430_direct12_recovery_a431.py \
    --analyze
fi
