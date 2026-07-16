#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

exec .venv/bin/python \
  research/experiments/chacha20_round20_w46_familywise_channel_portfolio_a341.py \
  "$@"
