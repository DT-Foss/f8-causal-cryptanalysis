#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

runner="research/experiments/chacha20_round20_w52_dual_axis_square_wavefront_recovery_a435.py"
test_file="tests/test_chacha20_round20_w52_dual_axis_square_wavefront_recovery_a435.py"
implementation="research/configs/chacha20_round20_w52_dual_axis_square_wavefront_recovery_a435_implementation_v1.json"
protocol="research/configs/chacha20_round20_w52_dual_axis_square_wavefront_recovery_a435_v1.json"
qualification="research/results/v1/chacha20_round20_w52_dual_axis_square_wavefront_a434_qualification_v1.json"

ruff check "$runner" "$test_file"
.venv/bin/python -m py_compile "$runner" "$test_file"
.venv/bin/python -m pytest -q "$test_file"

case "${1:---analyze}" in
  --freeze-implementation)
    .venv/bin/python "$runner" --freeze-implementation
    ;;
  --freeze-protocol)
    implementation_sha256="$(shasum -a 256 "$implementation" | awk '{print $1}')"
    .venv/bin/python "$runner" \
      --freeze-protocol \
      --expected-implementation-sha256 "$implementation_sha256"
    ;;
  --recover-worker)
    worker="${2:?worker index 0 through 7 required}"
    protocol_sha256="$(shasum -a 256 "$protocol" | awk '{print $1}')"
    qualification_sha256="$(shasum -a 256 "$qualification" | awk '{print $1}')"
    .venv/bin/python "$runner" \
      --recover-worker "$worker" \
      --expected-protocol-sha256 "$protocol_sha256" \
      --expected-a434-qualification-sha256 "$qualification_sha256"
    ;;
  --analyze)
    .venv/bin/python "$runner" --analyze
    ;;
  *)
    printf 'usage: %s [--analyze|--freeze-implementation|--freeze-protocol|--recover-worker N]\n' "$0" >&2
    exit 2
    ;;
esac
