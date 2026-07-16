#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

runner="research/experiments/chacha20_round20_w52_assumption_cut_clause_provenance_reader_a446.py"
test_file="tests/test_chacha20_round20_w52_assumption_cut_clause_provenance_reader_a446.py"
provenance_test="tests/test_assumption_cut_provenance.py"
implementation="research/configs/chacha20_round20_w52_assumption_cut_clause_provenance_reader_a446_implementation_v1.json"

.venv/bin/python -m pytest -q "$provenance_test" "$test_file"
.venv/bin/python "$runner" --analyze

if [[ "${1:-}" == "--build-result" ]]; then
  if [[ ! -f "$implementation" ]]; then
    printf '%s\n' "A446 implementation must be frozen before result construction" >&2
    exit 2
  fi
  implementation_sha256="$(shasum -a 256 "$implementation" | awk '{print $1}')"
  .venv/bin/python "$runner" \
    --build-result \
    --expected-implementation-sha256 "$implementation_sha256"
  .venv/bin/python -m pytest -q "$provenance_test" "$test_file"
fi
