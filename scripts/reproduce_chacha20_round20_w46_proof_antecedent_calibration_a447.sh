#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

runner="research/experiments/chacha20_round20_w46_proof_antecedent_calibration_a447.py"
runner_test="tests/test_chacha20_round20_w46_proof_antecedent_calibration_a447.py"
wrapper_test="tests/test_chacha20_fresh_clause_antecedents.py"
feature_test="tests/test_proof_antecedent_features.py"
implementation="research/configs/chacha20_round20_w46_proof_antecedent_calibration_a447_implementation_v1.json"

.venv/bin/python -m pytest -q "$wrapper_test" "$feature_test" "$runner_test"
.venv/bin/python "$runner" --analyze

case "${1:-}" in
  "")
    ;;
  --measure)
    if [[ ! -f "$implementation" ]]; then
      printf '%s\n' "A447 implementation must be frozen before measurement" >&2
      exit 2
    fi
    implementation_sha256="$(shasum -a 256 "$implementation" | awk '{print $1}')"
    .venv/bin/python "$runner" \
      --measure \
      --expected-implementation-sha256 "$implementation_sha256"
    ;;
  --build-result)
    if [[ ! -f "$implementation" ]]; then
      printf '%s\n' "A447 implementation must be frozen before result construction" >&2
      exit 2
    fi
    implementation_sha256="$(shasum -a 256 "$implementation" | awk '{print $1}')"
    .venv/bin/python "$runner" \
      --build-result \
      --expected-implementation-sha256 "$implementation_sha256"
    .venv/bin/python -m pytest -q "$wrapper_test" "$feature_test" "$runner_test"
    ;;
  *)
    printf '%s\n' "usage: $0 [--measure|--build-result]" >&2
    exit 2
    ;;
esac
