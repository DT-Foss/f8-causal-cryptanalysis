#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${PYTHON:-"$ROOT/.venv/bin/python"}
PROTOCOL_SHA256=28ab0b12e7f58b8e4096fd278d4f88991e7af3797f104202d84d3a70f7b85600

cd "$ROOT"
exec "$PYTHON" \
  research/experiments/chacha20_round20_selected_channel_target_measure.py \
  --expected-protocol-sha256 "$PROTOCOL_SHA256" \
  --run "$@"
