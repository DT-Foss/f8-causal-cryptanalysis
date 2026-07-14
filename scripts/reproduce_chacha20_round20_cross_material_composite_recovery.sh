#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${PYTHON:-"$ROOT/.venv/bin/python"}
PROTOCOL_SHA256=8c82ff74661a74c453bd744d847d0d9c14bec869a956d8b9961d49f9df82bde7

cd "$ROOT"
exec "$PYTHON" \
  research/experiments/chacha20_round20_cross_material_composite_recovery.py \
  --expected-protocol-sha256 "$PROTOCOL_SHA256" \
  --run "$@"
