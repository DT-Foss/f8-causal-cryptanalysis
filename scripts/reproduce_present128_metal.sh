#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

if test -n "${PYTHON:-}"; then
  PYTHON_BIN=$PYTHON
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN=python
else
  PYTHON_BIN=python3
fi

QUALIFICATION="research/experiments/present128_metal_qualification.py"
FACTORY="research/experiments/present128_metal_protocol_factory.py"
RUNNER="research/experiments/present128_metal_recovery.py"
REFERENCE_TEST="tests/test_present128_reference.py"
FACTORY_TEST="tests/test_present128_record_factory_pre_metal.py"

case "${1:-}" in
  "")
    "$PYTHON_BIN" -m pytest -q "$REFERENCE_TEST" "$FACTORY_TEST"
    "$PYTHON_BIN" -m py_compile \
      src/arx_carry_leak/present128_reference.py \
      "$QUALIFICATION" \
      "$FACTORY" \
      "$RUNNER"
    swiftc -typecheck research/experiments/present128_metal_native.swift
    ;;
  --qualify)
    test "$#" -eq 1
    "$PYTHON_BIN" "$QUALIFICATION"
    ;;
  --freeze)
    test "$#" -eq 1
    "$PYTHON_BIN" "$FACTORY"
    ;;
  --analyze)
    test "$#" -eq 3
    "$PYTHON_BIN" "$RUNNER" \
      --protocol "$2" \
      --expected-protocol-sha256 "$3" \
      --analyze-only
    ;;
  --run)
    test "$#" -eq 3
    "$PYTHON_BIN" "$RUNNER" \
      --protocol "$2" \
      --expected-protocol-sha256 "$3" \
      --execute-full-domain \
      --resume
    ;;
  *)
    echo "usage: $0 [--qualify|--freeze|--analyze PROTOCOL SHA256|--run PROTOCOL SHA256]" >&2
    echo "default: CPU/reference/static/Reader tests only; never invokes Metal" >&2
    echo "--qualify: explicitly compile, validate, and benchmark P128Q1 on Metal" >&2
    echo "--freeze: freeze P128R1 at the width selected by retained P128Q1" >&2
    echo "--run: explicitly start/resume the hash-gated complete P128R1 domain" >&2
    exit 2
    ;;
esac
