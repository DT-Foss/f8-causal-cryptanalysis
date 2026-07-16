#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
RUNNER="research/experiments/chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422.py"
TEST="tests/test_chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422.py"
PROTOCOL="research/configs/chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422_v1.json"
A390_QUALIFICATION="research/results/v1/chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_qualification_v1.json"

run_tests() {
  PYTHONWARNINGS=error "$PYTHON" -m pytest -q "$TEST"
}

case "${1:---analyze}" in
  --freeze)
    run_tests
    "$PYTHON" "$RUNNER" --freeze
    ;;
  --qualify)
    run_tests
    [[ -f "$PROTOCOL" && -f "$A390_QUALIFICATION" ]]
    protocol_sha256="$(shasum -a 256 "$PROTOCOL" | awk '{print $1}')"
    qualification_sha256="$(shasum -a 256 "$A390_QUALIFICATION" | awk '{print $1}')"
    "$PYTHON" "$RUNNER" \
      --qualify \
      --expected-protocol-sha256 "$protocol_sha256" \
      --expected-a390-qualification-sha256 "$qualification_sha256"
    ;;
  --analyze)
    run_tests
    "$PYTHON" "$RUNNER" --analyze
    ;;
  *)
    printf 'usage: %s [--freeze|--qualify|--analyze]\n' "$0" >&2
    exit 2
    ;;
esac
