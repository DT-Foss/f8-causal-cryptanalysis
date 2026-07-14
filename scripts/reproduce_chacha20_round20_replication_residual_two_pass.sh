#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${PYTHON:-"$ROOT/.venv/bin/python"}
PROTOCOL_SHA256=1f7aa99d6b869287cb78bc9a3a321cf5d559c44137d554dc19b9435bb1f78b69

cd "$ROOT"
exec "$PYTHON" \
  research/experiments/chacha20_round20_replication_residual_two_pass.py \
  --expected-protocol-sha256 "$PROTOCOL_SHA256" \
  --run "$@"
