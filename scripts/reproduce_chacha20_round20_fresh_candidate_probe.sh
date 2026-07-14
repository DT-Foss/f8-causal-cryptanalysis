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

RUNNER="research/experiments/chacha20_round20_fresh_candidate_probe.py"
TESTS="tests/test_chacha20_fresh_multihorizon.py tests/test_chacha20_round20_fresh_candidate_probe.py"

"$PYTHON" "$RUNNER" --analyze-only >/dev/null
"$PYTHON" -m pytest -q $TESTS

case "${1:-}" in
  "")
    ;;
  --run)
    "$PYTHON" "$RUNNER" --run
    ;;
  *)
    echo "usage: $0 [--run]" >&2
    echo "default: frozen-protocol and unit/native-helper tests only" >&2
    echo "--run: execute or resume all twenty A242 validation keys" >&2
    exit 2
    ;;
esac
