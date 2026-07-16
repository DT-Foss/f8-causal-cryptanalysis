#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

runner="research/experiments/chacha20_round20_w52_no_refit_frequency_ray_portfolio_recovery_a457.py"
test_file="tests/test_chacha20_round20_w52_no_refit_frequency_ray_portfolio_recovery_a457.py"
implementation="research/configs/chacha20_round20_w52_no_refit_frequency_ray_portfolio_recovery_a457_implementation_v1.json"
protocol="research/configs/chacha20_round20_w52_no_refit_frequency_ray_portfolio_recovery_a457_v1.json"

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
    worker="${2:?worker index required}"
    qualification_sha256="${3:?A434 qualification SHA-256 required}"
    protocol_sha256="$(shasum -a 256 "$protocol" | awk '{print $1}')"
    exec nice -n 10 .venv/bin/python "$runner" \
      --recover-worker "$worker" \
      --expected-protocol-sha256 "$protocol_sha256" \
      --expected-a434-qualification-sha256 "$qualification_sha256"
    ;;
  --analyze)
    .venv/bin/python "$runner" --analyze
    ;;
  *)
    printf 'usage: %s [--analyze|--freeze-implementation|--freeze-protocol|--recover-worker WORKER A434_SHA256]\n' "$0" >&2
    exit 2
    ;;
esac

