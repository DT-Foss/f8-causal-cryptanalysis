#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

runner="research/experiments/chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_v2.py"
test_file="tests/test_chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_v2.py"
implementation="research/configs/chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_implementation_v2.json"
protocol="research/configs/chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_v2.json"

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
  --assemble)
    protocol_sha256="$(shasum -a 256 "$protocol" | awk '{print $1}')"
    .venv/bin/python "$runner" \
      --assemble \
      --expected-protocol-sha256 "$protocol_sha256"
    ;;
  --analyze)
    .venv/bin/python "$runner"
    ;;
  *)
    printf 'usage: %s [--analyze|--freeze-implementation|--freeze-protocol|--assemble]\n' "$0" >&2
    exit 2
    ;;
esac
