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

RUNNER="research/experiments/chacha20_round20_fresh_clause_identity_reader.py"
TESTS="tests/test_chacha20_fresh_clause_identity.py tests/test_learned_clause_reader.py tests/test_chacha20_round20_fresh_clause_identity_reader.py"

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
    echo "default: frozen-protocol, native clause-capture, and reader tests only" >&2
    echo "--run: execute or resume all twenty A251 known-key clause-identity measurements" >&2
    exit 2
    ;;
esac
