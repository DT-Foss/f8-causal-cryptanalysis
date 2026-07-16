#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

exec .venv/bin/python \
  research/experiments/chacha20_round20_fresh_w48_pretarget_transfer_a372.py \
  "$@"
