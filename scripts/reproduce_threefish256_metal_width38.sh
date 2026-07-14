#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

PYTHON=${PYTHON:-python3}
if [ -x "$ROOT/.venv/bin/python" ]; then
    PYTHON="$ROOT/.venv/bin/python"
fi

RUNNER="research/experiments/threefish256_metal_width38_recovery.py"
TEST="tests/test_threefish256_metal_width38_recovery.py"
QUALIFICATION_TEST="tests/test_threefish256_metal_qualification.py"

"$PYTHON" "$RUNNER" --analyze-only >/dev/null
"$PYTHON" -m pytest -q "$TEST" "$QUALIFICATION_TEST"

case "${1:-}" in
  "")
    ;;
  --run)
    "$PYTHON" "$RUNNER" --resume
    ;;
  *)
    echo "usage: $0 [--run]" >&2
    exit 2
    ;;
esac
