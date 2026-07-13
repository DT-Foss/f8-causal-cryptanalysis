#!/usr/bin/env bash
set -euo pipefail

PHASE2_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$PHASE2_DIR/../../../.." && pwd)"
cd "$ROOT"

PYTHONPATH=.:src python3 \
  research/pilots/chacha20_round20_partition_v1/phase2_split18_10s/runner.py \
  --analyze-only
PYTHONPATH=.:src python3 \
  research/pilots/chacha20_round20_partition_v1/phase2_split18_10s/runner.py
PYTHONPATH=.:src python3 -m pytest -q \
  research/pilots/chacha20_round20_partition_v1/phase2_split18_10s/test_phase2.py
