#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
RUNNER="research/experiments/chacha20_round20_w51_a416_fresh_shared_stop_recovery_a425.py"
TEST="tests/test_chacha20_round20_w51_a416_fresh_shared_stop_recovery_a425.py"
IMPLEMENTATION="research/configs/chacha20_round20_w51_a416_fresh_shared_stop_recovery_a425_implementation_v1.json"
PROTOCOL="research/configs/chacha20_round20_w51_a416_fresh_shared_stop_recovery_a425_v1.json"
A416_RESULT="research/results/v1/chacha20_round20_w50_folded_xor_portfolio_a416_v1.json"
A390_QUALIFICATION="research/results/v1/chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_qualification_v1.json"

usage() {
  printf '%s\n' \
    "usage: $0 --analyze" \
    "       $0 --test" \
    "       $0 --freeze-implementation" \
    "       $0 --materialize-protocol" \
    "       $0 --recover-worker INDEX"
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

[[ $# -ge 1 ]] || { usage >&2; exit 2; }

case "$1" in
  --analyze)
    exec "$PYTHON" "$RUNNER" --analyze
    ;;
  --test)
    exec "$PYTHON" -m pytest -q "$TEST"
    ;;
  --freeze-implementation)
    "$PYTHON" -m pytest -q "$TEST"
    exec "$PYTHON" "$RUNNER" --freeze-implementation
    ;;
  --materialize-protocol)
    [[ -f "$IMPLEMENTATION" ]] || {
      printf '%s\n' "A425 implementation freeze is absent" >&2
      exit 1
    }
    exec "$PYTHON" "$RUNNER" \
      --materialize-protocol \
      --expected-implementation-sha256 "$(sha256_file "$IMPLEMENTATION")" \
      --expected-a416-result-sha256 "$(sha256_file "$A416_RESULT")"
    ;;
  --recover-worker)
    [[ $# -eq 2 ]] || { usage >&2; exit 2; }
    [[ -f "$PROTOCOL" ]] || {
      printf '%s\n' "A425 protocol is absent" >&2
      exit 1
    }
    [[ -f "$A390_QUALIFICATION" ]] || {
      printf '%s\n' "A390 qualification is absent" >&2
      exit 1
    }
    exec "$PYTHON" "$RUNNER" \
      --recover-worker "$2" \
      --expected-protocol-sha256 "$(sha256_file "$PROTOCOL")" \
      --expected-a390-qualification-sha256 "$(sha256_file "$A390_QUALIFICATION")"
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
