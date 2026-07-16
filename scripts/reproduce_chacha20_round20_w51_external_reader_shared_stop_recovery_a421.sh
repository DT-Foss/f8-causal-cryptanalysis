#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
RUNNER="research/experiments/chacha20_round20_w51_external_reader_shared_stop_recovery_a421.py"
TEST="tests/test_chacha20_round20_w51_external_reader_shared_stop_recovery_a421.py"
IMPLEMENTATION="research/configs/chacha20_round20_w51_external_reader_shared_stop_recovery_a421_implementation_v1.json"
PROTOCOL="research/configs/chacha20_round20_w51_external_reader_shared_stop_recovery_a421_v1.json"
A390_QUALIFICATION="research/results/v1/chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_qualification_v1.json"
A420_PROTOCOL="research/configs/chacha20_round20_w50_external_reader_shared_stop_recovery_a420_v1.json"

run_tests() {
  PYTHONWARNINGS=error "$PYTHON" -m pytest -q "$TEST"
}

case "${1:---analyze}" in
  --freeze-implementation)
    run_tests
    "$PYTHON" "$RUNNER" --freeze-implementation
    ;;
  --materialize-protocol)
    run_tests
    [[ -f "$IMPLEMENTATION" && -f "$A420_PROTOCOL" ]]
    implementation_sha256="$(shasum -a 256 "$IMPLEMENTATION" | awk '{print $1}')"
    a420_protocol_sha256="$(shasum -a 256 "$A420_PROTOCOL" | awk '{print $1}')"
    "$PYTHON" "$RUNNER" \
      --materialize-protocol \
      --expected-implementation-sha256 "$implementation_sha256" \
      --expected-a420-protocol-sha256 "$a420_protocol_sha256"
    ;;
  --recover-worker)
    [[ $# -eq 2 ]]
    run_tests
    [[ -f "$PROTOCOL" && -f "$A390_QUALIFICATION" ]]
    protocol_sha256="$(shasum -a 256 "$PROTOCOL" | awk '{print $1}')"
    qualification_sha256="$(shasum -a 256 "$A390_QUALIFICATION" | awk '{print $1}')"
    "$PYTHON" "$RUNNER" \
      --recover-worker "$2" \
      --expected-protocol-sha256 "$protocol_sha256" \
      --expected-a390-qualification-sha256 "$qualification_sha256"
    ;;
  --analyze)
    run_tests
    "$PYTHON" "$RUNNER" --analyze
    ;;
  *)
    printf 'usage: %s [--freeze-implementation|--materialize-protocol|--recover-worker INDEX|--analyze]\n' "$0" >&2
    exit 2
    ;;
esac
