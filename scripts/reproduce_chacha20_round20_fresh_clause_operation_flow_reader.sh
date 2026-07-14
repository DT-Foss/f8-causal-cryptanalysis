#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

RUNNER="research/experiments/chacha20_round20_fresh_clause_operation_flow_reader.py"
TESTS="tests/test_chacha20_operation_flow.py tests/test_chacha20_round20_operation_flow_preflight.py tests/test_chacha20_round20_fresh_clause_operation_flow_reader.py"

python3 -m pytest -q $TESTS
python3 -m py_compile \
  src/arx_carry_leak/chacha20_operation_flow.py \
  research/experiments/chacha20_round20_operation_flow_preflight.py \
  "$RUNNER"

case "${1:-}" in
  "")
    python3 "$RUNNER"
    ;;
  --run)
    test "$#" -eq 1
    python3 "$RUNNER" --run
    ;;
  *)
    echo "usage: $0 [--run]" >&2
    echo "default: frozen gates and tests only; --run executes A261 without new solver measurements" >&2
    exit 2
    ;;
esac
