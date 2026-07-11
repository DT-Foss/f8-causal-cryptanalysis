#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
  .venv/bin/python -m pip install -r requirements.txt
  .venv/bin/python -m pip install -e .
fi

Z3_BIN="$(command -v z3 2>/dev/null || true)"
if [[ -z "$Z3_BIN" && -x /opt/homebrew/bin/z3 ]]; then
  Z3_BIN="/opt/homebrew/bin/z3"
fi
if [[ -z "$Z3_BIN" ]]; then
  echo "Z3 CLI 4.15.4 is required for the Boolean Reader reproduction." >&2
  exit 2
fi
Z3_VERSION="$($Z3_BIN -version)"
if [[ "$Z3_VERSION" != "Z3 version 4.15.4"* ]]; then
  echo "Expected Z3 CLI 4.15.4, found: $Z3_VERSION" >&2
  exit 2
fi

export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
mkdir -p research/results/v1

.venv/bin/python research/experiments/shake_prefix_observability_frontier.py \
  --window-bits 16 \
  --output research/results/v1/shake_prefix_observability_frontier_v1.json \
  --causal-output research/results/v1/shake_prefix_observability_frontier_v1.causal

.venv/bin/python research/experiments/shake_boolean_cnf_reader.py \
  --variants shake128 \
  --window-bits 4,8,12,16 \
  --output-lanes 21 \
  --timeout-seconds 120 \
  --branching-heuristic chb \
  --z3 "$Z3_BIN" \
  --output research/results/v1/shake_boolean_cnf_reader_v1.json \
  --causal-output research/results/v1/shake_boolean_cnf_reader_v1.causal

.venv/bin/python research/experiments/shake_affine_hull_frontier.py \
  --window-bits 16 \
  --output research/results/v1/shake_affine_hull_frontier_v1.json \
  --causal-output research/results/v1/shake_affine_hull_frontier_v1.causal

.venv/bin/python research/experiments/shake_algebraic_degree_frontier.py \
  --window-bits 16 \
  --rounds 0,1,2,3,4,5,6,8,12,24 \
  --output research/results/v1/shake_algebraic_degree_frontier_v1.json \
  --causal-output research/results/v1/shake_algebraic_degree_frontier_v1.causal

.venv/bin/python research/experiments/shake_boolean_influence_frontier.py \
  --window-bits 16 \
  --rounds 0,1,2,3,4,5,24 \
  --seeds 3 \
  --output research/results/v1/shake_boolean_influence_frontier_v1.json \
  --causal-output research/results/v1/shake_boolean_influence_frontier_v1.causal

.venv/bin/pytest -q \
  tests/test_shake_boolean_cnf_reader.py \
  tests/test_shake_prefix_observability_frontier.py \
  tests/test_shake_affine_hull_frontier.py \
  tests/test_shake_algebraic_degree_frontier.py \
  tests/test_shake_boolean_influence_frontier.py
.venv/bin/python scripts/validate_causal_artifacts.py >/dev/null

.venv/bin/python scripts/write_hash_manifest.py \
  --output research/results/v1/SHAKE_SOLVER_FRONTIER_SHA256SUMS \
  research/results/v1/shake_boolean_cnf_reader_v1.json \
  research/results/v1/shake_boolean_cnf_reader_v1.causal \
  research/results/v1/shake_prefix_observability_frontier_v1.json \
  research/results/v1/shake_prefix_observability_frontier_v1.causal \
  research/results/v1/shake_affine_hull_frontier_v1.json \
  research/results/v1/shake_affine_hull_frontier_v1.causal \
  research/results/v1/shake_algebraic_degree_frontier_v1.json \
  research/results/v1/shake_algebraic_degree_frontier_v1.causal \
  research/results/v1/shake_boolean_influence_frontier_v1.json \
  research/results/v1/shake_boolean_influence_frontier_v1.causal

echo "SHAKE Boolean, observability, affine-hull, ANF, and influence frontiers reproduced."
