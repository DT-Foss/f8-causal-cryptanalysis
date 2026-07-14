#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
PYTHON=${PYTHON:-"$ROOT/.venv/bin/python"}
RUFF=${RUFF:-ruff}

QUALIFICATION="research/experiments/salsa20_20_metal_qualification.py"
FACTORY="research/experiments/salsa20_20_metal_protocol_factory.py"
RUNNER="research/experiments/salsa20_20_metal_recovery.py"
NATIVE="research/experiments/salsa20_20_metal_native.swift"
TEST="tests/test_salsa20_20_record_factory.py"

case "${1:-}" in
  "")
    "$PYTHON" -m pytest -q "$TEST"
    "$PYTHON" -m py_compile \
      src/arx_carry_leak/salsa20_reference.py \
      "$QUALIFICATION" \
      "$FACTORY" \
      "$RUNNER"
    "$RUFF" check \
      src/arx_carry_leak/salsa20_reference.py \
      "$QUALIFICATION" \
      "$FACTORY" \
      "$RUNNER" \
      "$TEST"
    swiftc -typecheck \
      -framework Foundation \
      -framework CoreFoundation \
      -framework Metal \
      "$NATIVE"
    ;;
  --qualify)
    test "$#" -eq 1
    "$PYTHON" "$QUALIFICATION" --metal
    ;;
  --freeze-after-root-review)
    test "$#" -eq 1
    "$PYTHON" "$FACTORY" --root-review-acknowledged
    ;;
  --analyze)
    test "$#" -eq 3
    "$PYTHON" "$RUNNER" \
      --protocol "$2" \
      --expected-protocol-sha256 "$3" \
      --analyze-only
    ;;
  --run)
    test "$#" -eq 3
    "$PYTHON" "$RUNNER" \
      --protocol "$2" \
      --expected-protocol-sha256 "$3" \
      --execute-full-domain \
      --resume
    ;;
  *)
    echo "usage: $0 [--qualify|--freeze-after-root-review|--analyze PROTOCOL SHA256|--run PROTOCOL SHA256]" >&2
    echo "default: CPU/KAT/static/Swift typecheck tests only; never invokes Metal" >&2
    echo "--qualify: explicitly run bounded A263 pre-target Metal KATs and benchmark" >&2
    echo "--freeze-after-root-review: freeze the fresh A264 public relation" >&2
    echo "--run: explicitly start/resume the hash-gated complete A264 domain" >&2
    exit 2
    ;;
esac
