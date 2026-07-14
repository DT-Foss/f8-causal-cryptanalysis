#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${PYTHON:-"$ROOT/.venv/bin/python"}
PROTOCOL_SHA256=d6e753defe3eba1e9989e8e6f792a6e731d8371487788917db0d7cff518c75f9

cd "$ROOT"
exec "$PYTHON" \
  research/experiments/chacha20_round20_selected_channel_target_replication_measure.py \
  --expected-protocol-sha256 "$PROTOCOL_SHA256" \
  --run "$@"
