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

RUNNER="research/experiments/chacha20_round20_fresh_clause_topology_reader.py"
TESTS="tests/test_cnf_semantic_topology.py tests/test_chacha20_round20_fresh_clause_topology_reader.py"

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
    echo "default: frozen-protocol and public-topology tests only" >&2
    echo "--run: project and evaluate the completed A251 corpus without new solver measurements" >&2
    exit 2
    ;;
esac
