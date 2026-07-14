#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
if [ -x "$ROOT/.venv/bin/python" ]; then
  PYTHON="$ROOT/.venv/bin/python"
else
  PYTHON="python3"
fi

RUNNER="research/experiments/chacha20_round20_fresh_nonlinear_poe.py"
TESTS="tests/test_fresh_candidate_nonlinear.py tests/test_chacha20_round20_fresh_nonlinear_poe.py"

"$PYTHON" "$RUNNER" >/dev/null
"$PYTHON" -m pytest -q $TESTS

case "${1:-}" in
  "")
    ;;
  --run)
    "$PYTHON" "$RUNNER" --run
    ;;
  *)
    echo "usage: $0 [--run]" >&2
    echo "default: frozen-protocol and nonlinear-reader tests only" >&2
    echo "--run: evaluate A250 on the twenty completed A242 calibration keys" >&2
    exit 2
    ;;
esac
