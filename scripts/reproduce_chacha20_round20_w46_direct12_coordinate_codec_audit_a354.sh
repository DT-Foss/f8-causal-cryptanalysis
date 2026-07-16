#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

.venv/bin/python -m pytest -q \
  tests/test_chacha20_round20_w46_direct12_coordinate_codec_audit_a354.py

RESULT="research/results/v1/chacha20_round20_w46_direct12_coordinate_codec_audit_a354_v1.json"
if [[ -f "$RESULT" ]]; then
  .venv/bin/python \
    research/experiments/chacha20_round20_w46_direct12_coordinate_codec_audit_a354.py \
    --verify
else
  .venv/bin/python \
    research/experiments/chacha20_round20_w46_direct12_coordinate_codec_audit_a354.py \
    --audit
fi
