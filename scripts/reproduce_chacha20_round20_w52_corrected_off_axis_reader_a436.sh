#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

runner="research/experiments/chacha20_round20_w52_corrected_off_axis_reader_a436.py"
test_file="tests/test_chacha20_round20_w52_corrected_off_axis_reader_a436.py"
implementation="research/configs/chacha20_round20_w52_corrected_off_axis_reader_a436_implementation_v1.json"

ruff check "$runner" "$test_file"
.venv/bin/python -m py_compile "$runner" "$test_file"
.venv/bin/python -m pytest -q "$test_file"

case "${1:---analyze}" in
  --freeze-implementation)
    .venv/bin/python "$runner" --freeze-implementation
    ;;
  --assemble)
    implementation_sha256="$(shasum -a 256 "$implementation" | awk '{print $1}')"
    .venv/bin/python "$runner" \
      --assemble \
      --expected-implementation-sha256 "$implementation_sha256"
    ;;
  --analyze)
    .venv/bin/python "$runner" --analyze
    ;;
  *)
    printf 'usage: %s [--analyze|--freeze-implementation|--assemble]\n' "$0" >&2
    exit 2
    ;;
esac
