#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

RUNNER="research/experiments/simon64_128_metal_width43_recovery.py"
TEST="tests/test_simon64_128_metal_width43_recovery.py"

python3 "$RUNNER" --analyze-only >/dev/null
python3 -m pytest -q "$TEST"

case "${1:-}" in
  "")
    ;;
  --run)
    python3 "$RUNNER" --execute-full-domain --resume
    ;;
  *)
    echo "usage: $0 [--run]" >&2
    echo "default: anchor analysis plus unit/KAT/Metal smoke only" >&2
    echo "--run: explicitly start/resume the qualified complete 2^43 execution" >&2
    exit 2
    ;;
esac
