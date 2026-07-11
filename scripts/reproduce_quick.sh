#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
  .venv/bin/python -m pip install --upgrade pip
  .venv/bin/python -m pip install -r requirements.txt
  .venv/bin/python -m pip install -e .
fi

export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

.venv/bin/python -m arx_carry_leak verify-vectors
.venv/bin/pytest -q \
  tests/test_ciphers.py \
  tests/test_f8.py \
  tests/test_casi.py \
  tests/test_crypto_causal.py \
  tests/test_present_exact_mechanism.py \
  tests/test_sha2_fullround_feedforward.py \
  tests/test_shake_native_window_solver.py \
  tests/test_shake_boolean_cnf_reader.py \
  tests/test_shake_prefix_observability_frontier.py \
  tests/test_shake_affine_hull_frontier.py \
  tests/test_shake_algebraic_degree_frontier.py \
  tests/test_shake_boolean_influence_frontier.py
CAUSAL_AUDIT="$(mktemp)"
trap 'rm -f "$CAUSAL_AUDIT"' EXIT
.venv/bin/python scripts/validate_causal_artifacts.py > "$CAUSAL_AUDIT"
CAUSAL_COUNT="$(.venv/bin/python - "$CAUSAL_AUDIT" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle)["validated"])
PY
)"
echo "causal artifacts: OK ($CAUSAL_COUNT validated)"
.venv/bin/python scripts/verify_hash_manifest.py \
  provenance/SHA256SUMS \
  research/results/reproduction_v1/SHA256SUMS \
  research/results/v1/ANCHOR_SHA256SUMS \
  research/results/v1/CAUSAL_SHA256SUMS \
  research/results/v1/ATLAS_SHA256SUMS \
  research/results/v1/PQC_SHA256SUMS \
  research/results/v1/FULLROUND_TRANSFER_SHA256SUMS \
  research/results/v1/SHAKE_NATIVE_EXTENDED_SHA256SUMS \
  research/results/v1/SHAKE_SOLVER_FRONTIER_SHA256SUMS
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q src research/experiments tests

echo "quick evidence tier: OK"
