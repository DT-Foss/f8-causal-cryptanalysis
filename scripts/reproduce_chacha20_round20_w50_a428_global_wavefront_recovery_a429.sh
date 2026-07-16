#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

ruff check \
  research/experiments/chacha20_round20_w50_a428_global_wavefront_recovery_a429.py \
  tests/test_chacha20_round20_w50_a428_global_wavefront_recovery_a429.py
.venv/bin/python -m py_compile \
  research/experiments/chacha20_round20_w50_a428_global_wavefront_recovery_a429.py \
  tests/test_chacha20_round20_w50_a428_global_wavefront_recovery_a429.py
.venv/bin/pytest -q tests/test_chacha20_round20_w50_a428_global_wavefront_recovery_a429.py

if [[ ! -f research/configs/chacha20_round20_w50_a428_global_wavefront_recovery_a429_implementation_v1.json ]]; then
  .venv/bin/python research/experiments/chacha20_round20_w50_a428_global_wavefront_recovery_a429.py --freeze-implementation
fi

implementation_sha256="$(sha256sum research/configs/chacha20_round20_w50_a428_global_wavefront_recovery_a429_implementation_v1.json | awk '{print $1}')"
if [[ ! -f research/configs/chacha20_round20_w50_a428_global_wavefront_recovery_a429_v1.json ]]; then
  .venv/bin/python research/experiments/chacha20_round20_w50_a428_global_wavefront_recovery_a429.py \
    --freeze-protocol \
    --expected-implementation-sha256 "$implementation_sha256"
fi

protocol_sha256="$(sha256sum research/configs/chacha20_round20_w50_a428_global_wavefront_recovery_a429_v1.json | awk '{print $1}')"

if [[ "${1:-}" == "--recover-worker" ]]; then
  worker="${2:?worker slug required}"
  .venv/bin/python research/experiments/chacha20_round20_w50_a428_global_wavefront_recovery_a429.py \
    --recover-worker "$worker" \
    --expected-protocol-sha256 "$protocol_sha256"
else
  .venv/bin/python research/experiments/chacha20_round20_w50_a428_global_wavefront_recovery_a429.py --analyze
fi
