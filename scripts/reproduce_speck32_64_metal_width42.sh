#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

RUNNER="research/experiments/speck32_64_metal_width42_recovery.py"
TEST="tests/test_speck32_64_metal_width42_recovery.py"

python3 "$RUNNER" --analyze-only >/dev/null
python3 -m pytest -q "$TEST"

case "${1:-}" in
  "")
    ;;
  --run)
    python3 "$RUNNER" --resume
    ;;
  *)
    echo "usage: $0 [--run]" >&2
    exit 2
    ;;
esac
