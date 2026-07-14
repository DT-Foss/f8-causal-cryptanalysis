#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

RUNNER="research/experiments/chacha20_round20_fresh_clause_continuous_flow_reader.py"
TESTS="tests/test_chacha20_continuous_flow.py tests/test_chacha20_round20_fresh_clause_continuous_flow_reader.py"

python3 -m pytest -q $TESTS
python3 -m py_compile src/arx_carry_leak/chacha20_continuous_flow.py "$RUNNER"

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
    echo "default: frozen gates and synthetic tests only; --run reuses A251 measurements" >&2
    exit 2
    ;;
esac
