#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

ruff check \
  research/experiments/chacha20_round20_w50_global_best_rank_wavefront_a428.py \
  tests/test_chacha20_round20_w50_global_best_rank_wavefront_a428.py
.venv/bin/python -m py_compile \
  research/experiments/chacha20_round20_w50_global_best_rank_wavefront_a428.py \
  tests/test_chacha20_round20_w50_global_best_rank_wavefront_a428.py
.venv/bin/pytest -q tests/test_chacha20_round20_w50_global_best_rank_wavefront_a428.py

if [[ ! -f research/configs/chacha20_round20_w50_global_best_rank_wavefront_a428_implementation_v1.json ]]; then
  .venv/bin/python research/experiments/chacha20_round20_w50_global_best_rank_wavefront_a428.py --freeze-implementation
fi

implementation_sha256="$(sha256sum research/configs/chacha20_round20_w50_global_best_rank_wavefront_a428_implementation_v1.json | awk '{print $1}')"
if [[ ! -f research/results/v1/chacha20_round20_w50_global_best_rank_wavefront_a428_v1.json ]]; then
  .venv/bin/python research/experiments/chacha20_round20_w50_global_best_rank_wavefront_a428.py \
    --measure \
    --expected-implementation-sha256 "$implementation_sha256"
fi

.venv/bin/python research/experiments/chacha20_round20_w50_global_best_rank_wavefront_a428.py
