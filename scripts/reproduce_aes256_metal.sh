#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

if test -n "${PYTHON:-}"; then
  PYTHON_BIN=$PYTHON
elif test -x "$ROOT/.venv/bin/python"; then
  PYTHON_BIN=$ROOT/.venv/bin/python
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN=python3
else
  PYTHON_BIN=python
fi

QUALIFICATION="research/experiments/aes256_metal_qualification.py"
FACTORY="research/experiments/aes256_metal_protocol_factory.py"
RUNNER="research/experiments/aes256_metal_recovery.py"
TEST="tests/test_aes256_record_factory_pre_metal.py"

case "${1:-}" in
  "")
    "$PYTHON_BIN" -m pytest -q "$TEST"
    "$PYTHON_BIN" -m py_compile \
      src/arx_carry_leak/aes256_reference.py \
      src/arx_carry_leak/aes256_independent.py \
      "$QUALIFICATION" "$FACTORY" "$RUNNER"
    swiftc -typecheck research/experiments/aes256_metal_native.swift
    ;;
  --qualify)
    test "$#" -ge 2
    OUTPUT=$2
    shift 2
    "$PYTHON_BIN" "$QUALIFICATION" --metal --output "$OUTPUT" "$@"
    ;;
  --freeze)
    test "$#" -eq 3
    "$PYTHON_BIN" "$FACTORY" \
      --freeze-challenge --review-acknowledged \
      --qualification "$2" --output "$3"
    ;;
  --analyze)
    test "$#" -eq 3
    "$PYTHON_BIN" "$RUNNER" \
      --protocol "$2" --expected-protocol-sha256 "$3" --analyze-only
    ;;
  --run)
    test "$#" -eq 3
    "$PYTHON_BIN" "$RUNNER" \
      --protocol "$2" --expected-protocol-sha256 "$3" \
      --execute-full-domain --resume
    ;;
  *)
    echo "usage: $0 [--qualify OUTPUT [ARGS...]|--freeze QUALIFICATION OUTPUT|--analyze PROTOCOL SHA256|--run PROTOCOL SHA256]" >&2
    echo "default: CPU/reference/static/Reader tests only; never invokes Metal" >&2
    echo "--qualify: explicitly execute capped AES256Q1 Metal qualification" >&2
    echo "--freeze: explicitly freeze fresh AES256R1 after retained AES256Q1" >&2
    echo "--run: explicitly start/resume the complete hash-gated residual domain" >&2
    exit 2
    ;;
esac
