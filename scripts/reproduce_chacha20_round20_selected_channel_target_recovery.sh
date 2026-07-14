#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${PYTHON:-"$ROOT/.venv/bin/python"}
PROTOCOL_SHA256=70f2634adffb2aaec7fc029694a4422de80257f8a07ca71f8b8e7002181eabb4

cd "$ROOT"
exec "$PYTHON" \
  research/experiments/chacha20_round20_selected_channel_target_recovery.py \
  --expected-protocol-sha256 "$PROTOCOL_SHA256" \
  --run "$@"
