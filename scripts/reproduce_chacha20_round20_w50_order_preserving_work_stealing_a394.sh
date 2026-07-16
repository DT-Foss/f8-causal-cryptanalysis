#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

exec .venv/bin/python \
  research/experiments/chacha20_round20_w50_order_preserving_work_stealing_a394.py \
  "$@"
