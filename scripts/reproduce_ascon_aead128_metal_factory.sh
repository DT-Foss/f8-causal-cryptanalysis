#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

REFERENCE="src/arx_carry_leak/ascon_aead128_reference.py"
QUALIFICATION="research/experiments/ascon_aead128_metal_qualification.py"
FACTORY="research/experiments/ascon_aead128_metal_protocol_factory.py"
RUNNER="research/experiments/ascon_aead128_metal_recovery.py"
TEST="tests/test_ascon_aead128_record_factory.py"
DOTCAUSAL_SRC=${DOTCAUSAL_SRC:-/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src}

case "${1:-}" in
  "")
    python3 -m pytest -q "$TEST"
    python3 -m py_compile "$REFERENCE" "$QUALIFICATION" "$FACTORY" "$RUNNER"
    ruff check "$REFERENCE" "$QUALIFICATION" "$FACTORY" "$RUNNER" "$TEST"
    ;;
  --qualify)
    test "$#" -eq 1
    python3 "$QUALIFICATION"
    ;;
  --freeze-reviewed)
    test "$#" -eq 1
    python3 "$FACTORY" --acknowledge-root-review
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
      --dotcausal-src "$DOTCAUSAL_SRC" \
      --execute-full-domain \
      --resume
    ;;
  *)
    echo "usage: $0 [--qualify|--freeze-reviewed|--analyze PROTOCOL SHA256|--run PROTOCOL SHA256]" >&2
    echo "default: CPU/reference/factory tests plus py_compile and ruff; no Metal" >&2
    echo "--qualify: capped A255 KAT/mapping/benchmark only; never freezes A256" >&2
    echo "--freeze-reviewed: explicitly acknowledge root review and freeze fresh A256" >&2
    echo "--run: start/resume A256 and emit Reader-verified JSON/.causal/report/manifest" >&2
    exit 2
    ;;
esac
