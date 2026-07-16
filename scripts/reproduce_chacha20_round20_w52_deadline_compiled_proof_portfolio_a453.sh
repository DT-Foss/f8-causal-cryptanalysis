#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

runner="research/experiments/chacha20_round20_w52_deadline_compiled_proof_portfolio_a453.py"
test_file="tests/test_chacha20_round20_w52_deadline_compiled_proof_portfolio_a453.py"
native_source="research/native/a453_deadline_compiler.cpp"
native_executable="research/bin/a453_deadline_compiler"
implementation="research/configs/chacha20_round20_w52_deadline_compiled_proof_portfolio_a453_implementation_v2.json"

ruff check "$runner" "$test_file"
.venv/bin/python -m py_compile "$runner" "$test_file"
"$native_executable" --self-test
.venv/bin/python -m pytest -q "$test_file"

case "${1:---analyze}" in
  --compile-native)
    clang++ -O3 -std=c++20 -Wall -Wextra -Wpedantic \
      "$native_source" -o "$native_executable"
    "$native_executable" --self-test
    ;;
  --freeze-implementation)
    .venv/bin/python "$runner" --freeze-implementation
    ;;
  --build)
    implementation_sha256="$(shasum -a 256 "$implementation" | awk '{print $1}')"
    .venv/bin/python "$runner" \
      --build \
      --expected-implementation-sha256 "$implementation_sha256"
    ;;
  --analyze)
    .venv/bin/python "$runner" --analyze
    ;;
  *)
    printf 'usage: %s [--analyze|--compile-native|--freeze-implementation|--build]\n' "$0" >&2
    exit 2
    ;;
esac
