#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3}"
"$PYTHON" scripts/verify_hash_manifest.py \
  research/results/v1/ANCHOR_SHA256SUMS
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" -m compileall -q \
  provenance/fullround_anchors/f8/experiments \
  provenance/fullround_anchors/f8/reproduce.py

echo "anchor manifest: OK"
