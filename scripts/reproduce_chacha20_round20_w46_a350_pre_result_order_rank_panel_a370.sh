#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

.venv/bin/python -m pytest -q \
  tests/test_chacha20_round20_w46_a350_pre_result_order_rank_panel_a370.py

RESULT="research/results/v1/chacha20_round20_w46_a350_pre_result_order_rank_panel_a370_v1.json"
if [[ ! -f "$RESULT" ]]; then
  .venv/bin/python \
    research/experiments/chacha20_round20_w46_a350_pre_result_order_rank_panel_a370.py \
    --run
else
  .venv/bin/python \
    research/experiments/chacha20_round20_w46_a350_pre_result_order_rank_panel_a370.py \
    --analyze
fi
