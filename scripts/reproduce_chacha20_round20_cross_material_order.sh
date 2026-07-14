#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${PYTHON:-"$ROOT/.venv/bin/python"}
MASTER_SHA256=256504ef394fbc4d5e1da2881f3de0c8a32af5908f454e58cf9711da733551b6
TARGET_SHA256=a2685c03c3fb486c25362e5e7ae99a001ae14b36a7d96595b0f66628c52b0b16
SYMBOLIC_SHA256=5443d4ef635d1b31001a99295be34fa0e4878f0496c570b58fed59efb60e1f75

cd "$ROOT"
exec "$PYTHON" \
  research/experiments/chacha20_round20_cross_material_measure.py \
  --expected-master-sha256 "$MASTER_SHA256" \
  --expected-target-sha256 "$TARGET_SHA256" \
  --expected-symbolic-sha256 "$SYMBOLIC_SHA256" \
  --run "$@"
