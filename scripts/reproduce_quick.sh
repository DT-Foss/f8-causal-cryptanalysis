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
  tests/test_chacha20_vector256_fullround_replay.py \
  tests/test_chacha20_metal_fullround_replay.py \
  tests/test_chacha20_metal_width36_partial_key_recovery.py \
  tests/test_chacha20_metal_width38_partial_key_recovery.py \
  tests/test_chacha20_metal_width40_partial_key_recovery.py \
  tests/test_chacha20_smt_directional_round4_transfer.py \
  tests/test_chacha20_smt_directional_round5_transfer.py \
  tests/test_chacha20_smt_shared_key_multiblock_transfer.py \
  tests/test_chacha20_bitwuzla_round5_transfer.py \
  tests/test_chacha20_bitwuzla_round6_width20_transfer.py \
  tests/test_chacha20_bitwuzla_round7_width18_transfer.py \
  tests/test_chacha20_bitwuzla_round7_partition_transfer.py \
  tests/test_chacha20_bitwuzla_round7_width20_partition_transfer.py \
  tests/test_chacha20_bitwuzla_round8_width20_partition_transfer.py \
  tests/test_chacha20_bitwuzla_round9_width20_partition_transfer.py \
  tests/test_chacha20_bitwuzla_round10_width20_partition_transfer.py \
  tests/test_chacha20_bitwuzla_round10_split9_transfer.py \
  tests/test_chacha20_bitwuzla_round10_width12_refinement.py \
  tests/test_chacha20_bitwuzla_round10_b8_partition_transfer.py \
  tests/test_chacha20_formula_operator_atlas.py \
  tests/test_chacha20_formula_operator_atlas_figure.py \
  tests/test_chacha20_round10_public_geometry_partition.py \
  tests/test_chacha20_round10_public_geometry_partition_figure.py \
  tests/test_chacha20_phase_conjugacy_holdout.py \
  tests/test_chacha20_phase_conjugacy_holdout_figure.py \
  tests/test_chacha20_round10_b8_global_cse.py \
  tests/test_chacha20_round10_b8_global_cse_figure.py \
  tests/test_chacha20_round10_b8_lane_major.py \
  tests/test_chacha20_round10_b8_lane_major_figure.py \
  tests/test_chacha20_round10_external_cnf_reverse.py \
  tests/test_chacha20_a188_cnf_structural_ordering.py \
  tests/test_chacha20_round10_bidirectional_min_distance.py \
  tests/test_chacha20_round10_structural_order_archive.py \
  tests/test_chacha20_round10_structural_portfolio.py \
  tests/test_chacha20_round10_structural_portfolio_result.py \
  tests/test_chacha20_round10_bfs_far_long_budget.py \
  tests/test_chacha20_round10_bfs_far_width12_refinement.py \
  tests/test_chacha20_round10_incremental_sibling_learning.py \
  tests/test_chacha20_cnf_structural_figures.py \
  tests/test_chacha20_smt_round5_retained_figures.py \
  tests/test_shake_native_window_solver.py \
  tests/test_shake_boolean_cnf_reader.py \
  tests/test_shake_prefix_observability_frontier.py \
  tests/test_shake_affine_hull_frontier.py \
  tests/test_shake_algebraic_degree_frontier.py \
  tests/test_shake_boolean_influence_frontier.py \
  tests/test_shake_anf_compression_cascade.py \
  tests/test_shake_symbolic_anf_frontier.py \
  tests/test_shake_symbolic_r2_smt_reader.py \
  tests/test_shake_symbolic_r2_partition_reader.py \
  tests/test_shake_symbolic_split_frontier.py \
  tests/test_shake_symbolic_r1_scaling_reader.py \
  tests/test_shake_symbolic_r1_partition_scaling_reader.py \
  tests/test_shake_symbolic_r1_upper_partition_reader.py \
  tests/test_shake_symbolic_r1_structural_partition_reader.py \
  tests/test_shake256_symbolic_r1_scaling_reader.py
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
  research/results/v1/SHAKE_SOLVER_FRONTIER_SHA256SUMS \
  research/results/v1/A211_A220P_SHA256SUMS \
  research/results/v1/A220B_A222_INFRA_SHA256SUMS \
  research/results/v1/A223_A277_SHA256SUMS \
  research/results/v1/A278_A286_RECORDS_SHA256SUMS \
  research/results/v1/A287_A325_SHA256SUMS \
  research/results/v1/FULLROUND_RECOVERY_COMPLETENESS_SHA256SUMS
.venv/bin/python scripts/verify_a326_a458_frontier.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q src research/experiments tests

echo "quick evidence tier: OK"
