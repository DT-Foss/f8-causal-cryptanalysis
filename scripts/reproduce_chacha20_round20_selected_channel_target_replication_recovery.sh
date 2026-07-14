#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${PYTHON:-"$ROOT/.venv/bin/python"}
PROTOCOL_SHA256=b40a8d6da6a5ce3af80e6f34f0eae28f87f1eb22448985ee95e5382ae455b9e5

cd "$ROOT"
exec "$PYTHON" \
  research/experiments/chacha20_round20_selected_channel_target_replication_recovery.py \
  --expected-protocol-sha256 "$PROTOCOL_SHA256" \
  --run "$@"
