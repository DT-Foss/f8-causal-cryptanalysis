#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

QUALIFICATION="research/experiments/rc5_32_12_16_metal_qualification.py"
FACTORY="research/experiments/rc5_32_12_16_metal_protocol_factory.py"
RUNNER="research/experiments/rc5_32_12_16_metal_recovery.py"
REFERENCE_TEST="tests/test_rc5_reference.py"
FACTORY_TEST="tests/test_rc5_32_12_16_record_factory_pre_metal.py"

case "${1:-}" in
  "")
    python3 -m pytest -q "$REFERENCE_TEST" "$FACTORY_TEST"
    python3 -m py_compile \
      src/arx_carry_leak/rc5_reference.py \
      "$QUALIFICATION" \
      "$FACTORY" \
      "$RUNNER"
    ;;
  --qualify)
    test "$#" -eq 1
    python3 "$QUALIFICATION"
    ;;
  --freeze)
    test "$#" -eq 1
    python3 "$FACTORY"
    ;;
  --analyze)
    test "$#" -eq 3
    python3 "$RUNNER" \
      --protocol "$2" \
      --expected-protocol-sha256 "$3" \
      --analyze-only
    ;;
  --run)
    test "$#" -eq 3
    python3 "$RUNNER" \
      --protocol "$2" \
      --expected-protocol-sha256 "$3" \
      --execute-full-domain \
      --resume
    ;;
  *)
    echo "usage: $0 [--qualify|--freeze|--analyze PROTOCOL SHA256|--run PROTOCOL SHA256]" >&2
    echo "default: CPU/reference/static/Reader tests only; never invokes Metal" >&2
    echo "--qualify: explicitly compile, validate, and benchmark A247 on Metal" >&2
    echo "--freeze: freeze A248 at the width selected by retained A247" >&2
    echo "--run: explicitly start/resume the hash-gated complete A248 domain" >&2
    exit 2
    ;;
esac
