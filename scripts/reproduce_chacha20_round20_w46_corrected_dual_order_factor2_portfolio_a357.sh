#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RUNNER="research/experiments/chacha20_round20_w46_corrected_dual_order_factor2_portfolio_a357.py"

if [[ -f research/results/v1/chacha20_round20_w46_corrected_dual_order_factor2_portfolio_a357_order_v1.json ]]; then
  "$PYTHON" "$RUNNER" --analyze
else
  "$PYTHON" "$RUNNER" --freeze
fi

"$PYTHON" -m pytest -q tests/test_chacha20_round20_w46_corrected_dual_order_factor2_portfolio_a357.py
