#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

PYTHON=${PYTHON:-.venv/bin/python}
RUNNER=research/experiments/chacha20_round20_fresh_clause_operation_reader.py
TESTS="tests/test_chacha20_operation_taps.py tests/test_chacha20_round20_fresh_clause_operation_reader.py"

"$PYTHON" -m pytest -q $TESTS
"$PYTHON" -m py_compile src/arx_carry_leak/chacha20_operation_taps.py "$RUNNER"
ruff check src/arx_carry_leak/chacha20_operation_taps.py "$RUNNER" $TESTS

if [ "${1:-}" = "--run" ]; then
  "$PYTHON" "$RUNNER" --run
else
  "$PYTHON" "$RUNNER"
fi
