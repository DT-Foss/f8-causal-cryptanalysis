#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
if [[ ! -x "$PYTHON" ]]; then
  echo "missing executable Python environment: $PYTHON" >&2
  echo "run ./scripts/bootstrap.sh or set PYTHON=/path/to/python" >&2
  exit 2
fi

export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1

"$PYTHON" scripts/verify_hash_manifest.py \
  research/results/v1/A223_A277_SHA256SUMS

"$PYTHON" - <<'PY'
from research.experiments.chacha20_ranked_until_sat import compile_helper

build = compile_helper()
expected = "daf36a6e15c9936068044d8ea77053bb72c5d868f738a18b218132bb716baff7"
if build["binary_sha256"] != expected:
    raise SystemExit("ranked CaDiCaL helper identity differs")
print("ranked CaDiCaL helper: OK")
PY

TEST_LIST="research/results/v1/A223_A277_TESTS.txt"
TESTS="$(sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' "$TEST_LIST")"
if [[ -z "$TESTS" ]]; then
  echo "empty focused test list: $TEST_LIST" >&2
  exit 2
fi

# Every path is repository-relative and contains no shell whitespace.
# shellcheck disable=SC2086
"$PYTHON" -m pytest -q $TESTS

CAUSAL_AUDIT="$(mktemp)"
trap 'rm -f "$CAUSAL_AUDIT"' EXIT
"$PYTHON" scripts/validate_causal_artifacts.py research/results/v1 > "$CAUSAL_AUDIT"
"$PYTHON" - "$CAUSAL_AUDIT" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    audit = json.load(handle)

validated = int(audit["validated"])
if validated < 389:
    raise SystemExit(f"expected at least 389 Causal artifacts, read {validated}")
print(f"causal artifacts: OK ({validated} validated)")
PY

echo "A223--A277 evidence tier: OK"
