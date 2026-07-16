#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

runner="research/experiments/chacha20_round20_w52_knownkey_meta_reader_transfer_a442.py"
test_file="tests/test_chacha20_round20_w52_knownkey_meta_reader_transfer_a442.py"
implementation="research/configs/chacha20_round20_w52_knownkey_meta_reader_transfer_a442_implementation_v1.json"

ruff check "$runner" "$test_file"
.venv/bin/python -m py_compile "$runner" "$test_file"
.venv/bin/python -m pytest -q "$test_file"

case "${1:---analyze}" in
  --freeze-implementation)
    .venv/bin/python "$runner" --freeze-implementation
    ;;
  --build-result)
    implementation_sha256="$(shasum -a 256 "$implementation" | awk '{print $1}')"
    exec nice -n 10 .venv/bin/python "$runner" \
      --build-result \
      --expected-implementation-sha256 "$implementation_sha256"
    ;;
  --analyze)
    .venv/bin/python "$runner" --analyze
    ;;
  *)
    printf 'usage: %s [--analyze|--freeze-implementation|--build-result]\n' "$0" >&2
    exit 2
    ;;
esac
