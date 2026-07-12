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
if [[ "$Z3_VERSION" != "Z3 version 4.15.4 "* ]]; then
  echo "Z3 CLI 4.15.4 is required; observed: $Z3_VERSION" >&2
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

.venv/bin/python research/experiments/shake_anf_compression_cascade.py \
  --window-bits 16 \
  --rounds 0,1,2,3,4,24 \
  --pack-rounds 2,3 \
  --cascade-rounds 2,3 \
  --output research/results/v1/shake_anf_compression_cascade_v1.json \
  --causal-output research/results/v1/shake_anf_compression_cascade_v1.causal \
  --pack-output research/results/v1/shake_anf_dictionary_v1.anfpack

.venv/bin/python research/experiments/shake_symbolic_anf_frontier.py \
  --window-bits 16,32,64,128,256,512 \
  --assignment-samples 8 \
  --output research/results/v1/shake_symbolic_anf_frontier_v1.json \
  --causal-output research/results/v1/shake_symbolic_anf_frontier_v1.causal

.venv/bin/python research/experiments/shake_symbolic_r2_smt_reader.py \
  --window-bits 4,8,12,16 \
  --timeout-seconds 120 \
  --z3 "$Z3_BIN" \
  --output research/results/v1/shake_symbolic_r2_smt_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r2_smt_reader_v1.causal

.venv/bin/python research/experiments/shake_symbolic_r2_partition_reader.py \
  --window-bits 16 \
  --partition-bits 4 \
  --timeout-seconds 60 \
  --max-workers 5 \
  --z3 "$Z3_BIN" \
  --output research/results/v1/shake_symbolic_r2_partition_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r2_partition_reader_v1.causal

.venv/bin/python research/experiments/shake_symbolic_split_frontier.py \
  --prefix-rounds 1,2,3 \
  --timeout-seconds 60 \
  --z3 "$Z3_BIN" \
  --output research/results/v1/shake_symbolic_split_frontier_v1.json \
  --causal-output research/results/v1/shake_symbolic_split_frontier_v1.causal

.venv/bin/python research/experiments/shake_symbolic_r1_scaling_reader.py \
  --window-bits 16,20,24 \
  --timeout-seconds 120 \
  --z3 "$Z3_BIN" \
  --output research/results/v1/shake_symbolic_r1_scaling_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_scaling_reader_v1.causal

.venv/bin/python research/experiments/shake_symbolic_r1_partition_scaling_reader.py \
  --z3 "$Z3_BIN" \
  --output research/results/v1/shake_symbolic_r1_partition_scaling_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_partition_scaling_reader_v1.causal

.venv/bin/python research/experiments/shake_symbolic_r1_upper_partition_reader.py \
  --z3 "$Z3_BIN" \
  --output research/results/v1/shake_symbolic_r1_upper_partition_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_upper_partition_reader_v1.causal

.venv/bin/python research/experiments/shake_symbolic_r1_structural_partition_reader.py \
  --z3 "$Z3_BIN" \
  --output research/results/v1/shake_symbolic_r1_structural_partition_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_structural_partition_reader_v1.causal

.venv/bin/python research/experiments/shake256_symbolic_r1_scaling_reader.py \
  --window-bits 16,20,24 \
  --timeout-seconds 120 \
  --z3 "$Z3_BIN" \
  --output research/results/v1/shake256_symbolic_r1_scaling_reader_v1.json \
  --causal-output research/results/v1/shake256_symbolic_r1_scaling_reader_v1.causal

.venv/bin/python research/experiments/shake_symbolic_r1_structural6_partition_reader.py \
  --z3 "$Z3_BIN" \
  --output research/results/v1/shake_symbolic_r1_structural6_partition_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_structural6_partition_reader_v1.causal

.venv/bin/python research/experiments/shake_symbolic_r1_z3_strategy_frontier.py \
  --z3 "$Z3_BIN" \
  --output research/results/v1/shake_symbolic_r1_z3_strategy_frontier_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_z3_strategy_frontier_v1.causal

.venv/bin/python research/experiments/shake_symbolic_r1_structural_depth_frontier.py \
  --z3 "$Z3_BIN" \
  --output research/results/v1/shake_symbolic_r1_structural_depth_frontier_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_structural_depth_frontier_v1.causal

.venv/bin/python research/experiments/shake_symbolic_r1_z3_structural6_partition_reader.py \
  --z3 "$Z3_BIN" \
  --output research/results/v1/shake_symbolic_r1_z3_structural6_partition_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_z3_structural6_partition_reader_v1.causal

.venv/bin/python research/experiments/shake_symbolic_r1_structural_k8_reader.py \
  --z3 "$Z3_BIN" \
  --output research/results/v1/shake_symbolic_r1_structural_k8_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_structural_k8_reader_v1.causal

.venv/bin/python research/experiments/shake_symbolic_r1_width24_depth_frontier.py \
  --z3 "$Z3_BIN" \
  --output research/results/v1/shake_symbolic_r1_width24_depth_frontier_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_width24_depth_frontier_v1.causal

.venv/bin/python research/experiments/shake_symbolic_r1_width24_vertex_cover_reader.py \
  --z3 "$Z3_BIN" \
  --output research/results/v1/shake_symbolic_r1_width24_vertex_cover_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_width24_vertex_cover_reader_v1.causal

# A152 is a publicly precommitted prospective run. The aggregate reproduction
# validates its retained artifacts; the exact fresh-run command and commit gate
# are documented in its dedicated report.
.venv/bin/python research/experiments/shake_symbolic_r1_affine_basis_reader.py
.venv/bin/python research/experiments/shake_symbolic_r2_pivot_basis_reader.py
.venv/bin/python research/experiments/shake_symbolic_r2_affine_gauge_reader.py
.venv/bin/python research/experiments/shake_symbolic_r2_order_weighted_gauge_reader.py
.venv/bin/python research/experiments/shake_a152_native_fullround_reader_transfer.py \
  --no-resume

# A156 contains four sequential 120-second solver executions. The aggregate
# gate rebuilds all four formulas byte-for-byte and validates the retained
# execution. A157--A159, A161, A163, A164, A166--A170 and A172--A176 do the
# same for shared-R2 encoders, weighted orders, fixed-rlimit replay,
# affine-gauge transfers, the nonrepeating factorial completion, signed-alias
# controls, fanout decomposition, order reversal, central transfers and exact
# alpha-renaming and declaration-order controls. Use their dedicated reports to
# repeat the long solver frontiers. A177's complete `2^32` native execution is
# likewise retained and hash-gated here; its dedicated report gives the
# checkpointable full-run command. A160/A162 are regenerated above; A171 is
# intentionally unused.
.venv/bin/pytest -q \
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
  tests/test_shake256_symbolic_r1_scaling_reader.py \
  tests/test_shake_symbolic_r1_structural6_partition_reader.py \
  tests/test_shake_symbolic_r1_z3_strategy_frontier.py \
  tests/test_shake_symbolic_r1_structural_depth_frontier.py \
  tests/test_shake_symbolic_r1_z3_structural6_partition_reader.py \
  tests/test_shake_symbolic_r1_structural_k8_reader.py \
  tests/test_shake_symbolic_r1_width24_depth_frontier.py \
  tests/test_shake_symbolic_r1_width24_vertex_cover_reader.py \
  tests/test_shake_symbolic_r1_width24_prospective_transfer.py \
  tests/test_shake_symbolic_r1_affine_basis_reader.py \
  tests/test_shake_symbolic_r2_pivot_basis_reader.py \
  tests/test_shake_symbolic_r1_systematic_encoder_frontier.py \
  tests/test_shake_symbolic_r2_shared_monomial_encoder_frontier.py \
  tests/test_shake_symbolic_r2_weighted_input_order_frontier.py \
  tests/test_shake_symbolic_r2_fixed_rlimit_order_frontier.py \
  tests/test_shake_symbolic_r2_affine_gauge_reader.py \
  tests/test_shake_symbolic_r2_affine_gauge_solver_frontier.py \
  tests/test_shake_symbolic_r2_order_weighted_gauge_reader.py \
  tests/test_shake_symbolic_r2_order_weighted_gauge_solver_frontier.py \
  tests/test_shake_symbolic_r2_four_gauge_factorial_completion.py \
  tests/test_shake_a152_native_fullround_reader_transfer.py \
  tests/test_shake_symbolic_r2_signed_alias_compiler_frontier.py \
  tests/test_shake_symbolic_r2_id_preserving_signed_alias_frontier.py \
  tests/test_shake_symbolic_r2_normalized_materialized_alias_frontier.py \
  tests/test_shake_symbolic_r2_alias_fanout_mobius_frontier.py \
  tests/test_shake_symbolic_r2_reversed_order_alias_polarity_frontier.py \
  tests/test_shake_symbolic_r2_adjacent_0_12_transfer_frontier.py \
  tests/test_shake_symbolic_r2_center_position_family_contrast.py \
  tests/test_shake_symbolic_r2_center_alias_partner_transfer.py \
  tests/test_shake_symbolic_r2_alpha_renamed_center_boundary.py \
  tests/test_shake_symbolic_r2_input_declaration_swap_boundary.py \
  tests/test_shake256_native_fullround_width32_prospective.py
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
  research/results/v1/shake_boolean_influence_frontier_v1.causal \
  research/results/v1/shake_anf_compression_cascade_v1.json \
  research/results/v1/shake_anf_compression_cascade_v1.causal \
  research/results/v1/shake_anf_dictionary_v1.anfpack \
  research/results/v1/shake_symbolic_anf_frontier_v1.json \
  research/results/v1/shake_symbolic_anf_frontier_v1.causal \
  research/results/v1/shake_symbolic_r2_smt_reader_v1.json \
  research/results/v1/shake_symbolic_r2_smt_reader_v1.causal \
  research/results/v1/shake_symbolic_r2_partition_reader_v1.json \
  research/results/v1/shake_symbolic_r2_partition_reader_v1.causal \
  research/results/v1/shake_symbolic_split_frontier_v1.json \
  research/results/v1/shake_symbolic_split_frontier_v1.causal \
  research/results/v1/shake_symbolic_r1_scaling_reader_v1.json \
  research/results/v1/shake_symbolic_r1_scaling_reader_v1.causal \
  research/results/v1/shake_symbolic_r1_partition_scaling_reader_v1.json \
  research/results/v1/shake_symbolic_r1_partition_scaling_reader_v1.causal \
  research/results/v1/shake_symbolic_r1_upper_partition_reader_v1.json \
  research/results/v1/shake_symbolic_r1_upper_partition_reader_v1.causal \
  research/results/v1/shake_symbolic_r1_structural_partition_reader_v1.json \
  research/results/v1/shake_symbolic_r1_structural_partition_reader_v1.causal \
  research/results/v1/shake256_symbolic_r1_scaling_reader_v1.json \
  research/results/v1/shake256_symbolic_r1_scaling_reader_v1.causal \
  research/results/v1/shake_symbolic_r1_structural6_partition_reader_v1.json \
  research/results/v1/shake_symbolic_r1_structural6_partition_reader_v1.causal \
  research/results/v1/shake_symbolic_r1_z3_strategy_frontier_v1.json \
  research/results/v1/shake_symbolic_r1_z3_strategy_frontier_v1.causal \
  research/results/v1/shake_symbolic_r1_structural_depth_frontier_v1.json \
  research/results/v1/shake_symbolic_r1_structural_depth_frontier_v1.causal \
  research/results/v1/shake_symbolic_r1_z3_structural6_partition_reader_v1.json \
  research/results/v1/shake_symbolic_r1_z3_structural6_partition_reader_v1.causal \
  research/results/v1/shake_symbolic_r1_structural_k8_reader_v1.json \
  research/results/v1/shake_symbolic_r1_structural_k8_reader_v1.causal \
  research/results/v1/shake_symbolic_r1_width24_depth_frontier_v1.json \
  research/results/v1/shake_symbolic_r1_width24_depth_frontier_v1.causal \
  research/results/v1/shake_symbolic_r1_width24_vertex_cover_reader_v1.json \
  research/results/v1/shake_symbolic_r1_width24_vertex_cover_reader_v1.causal \
  research/results/v1/shake_symbolic_r1_width24_prospective_transfer_v1.json \
  research/results/v1/shake_symbolic_r1_width24_prospective_transfer_v1.causal \
  research/results/v1/shake_symbolic_r1_affine_basis_reader_v1.json \
  research/results/v1/shake_symbolic_r1_affine_basis_reader_v1.causal \
  research/results/v1/shake_symbolic_r2_pivot_basis_reader_v1.json \
  research/results/v1/shake_symbolic_r2_pivot_basis_reader_v1.causal \
  research/results/v1/shake_symbolic_r1_systematic_encoder_frontier_v1.json \
  research/results/v1/shake_symbolic_r1_systematic_encoder_frontier_v1.causal \
  research/results/v1/shake_symbolic_r2_shared_monomial_encoder_frontier_v1.json \
  research/results/v1/shake_symbolic_r2_shared_monomial_encoder_frontier_v1.causal \
  research/results/v1/shake_symbolic_r2_weighted_input_order_frontier_v1.json \
  research/results/v1/shake_symbolic_r2_weighted_input_order_frontier_v1.causal \
  research/results/v1/shake_symbolic_r2_fixed_rlimit_order_frontier_v1.json \
  research/results/v1/shake_symbolic_r2_fixed_rlimit_order_frontier_v1.causal \
  research/results/v1/shake_symbolic_r2_affine_gauge_reader_v1.json \
  research/results/v1/shake_symbolic_r2_affine_gauge_reader_v1.causal \
  research/results/v1/shake_symbolic_r2_affine_gauge_solver_frontier_v1.json \
  research/results/v1/shake_symbolic_r2_affine_gauge_solver_frontier_v1.causal \
  research/results/v1/shake_symbolic_r2_order_weighted_gauge_reader_v1.json \
  research/results/v1/shake_symbolic_r2_order_weighted_gauge_reader_v1.causal \
  research/results/v1/shake_symbolic_r2_order_weighted_gauge_solver_frontier_v1.json \
  research/results/v1/shake_symbolic_r2_order_weighted_gauge_solver_frontier_v1.causal \
  research/configs/shake_symbolic_r2_four_gauge_factorial_completion_v1.json \
  research/results/v1/shake_symbolic_r2_four_gauge_factorial_completion_v1.json \
  research/results/v1/shake_symbolic_r2_four_gauge_factorial_completion_v1.causal \
  research/configs/shake_a152_native_fullround_reader_transfer_v1.json \
  research/results/v1/shake_a152_native_fullround_reader_transfer_v1.json \
  research/results/v1/shake_a152_native_fullround_reader_transfer_v1.causal \
  research/configs/shake_symbolic_r2_signed_alias_compiler_frontier_v1.json \
  research/results/v1/shake_symbolic_r2_signed_alias_compiler_frontier_v1.json \
  research/results/v1/shake_symbolic_r2_signed_alias_compiler_frontier_v1.causal \
  research/configs/shake_symbolic_r2_id_preserving_signed_alias_frontier_v1.json \
  research/results/v1/shake_symbolic_r2_id_preserving_signed_alias_frontier_v1.json \
  research/results/v1/shake_symbolic_r2_id_preserving_signed_alias_frontier_v1.causal \
  research/configs/shake_symbolic_r2_normalized_materialized_alias_frontier_v1.json \
  research/results/v1/shake_symbolic_r2_normalized_materialized_alias_frontier_v1.json \
  research/results/v1/shake_symbolic_r2_normalized_materialized_alias_frontier_v1.causal \
  research/configs/shake_symbolic_r2_alias_fanout_mobius_frontier_v1.json \
  research/results/v1/shake_symbolic_r2_alias_fanout_mobius_frontier_v1.json \
  research/results/v1/shake_symbolic_r2_alias_fanout_mobius_frontier_v1.causal \
  research/configs/shake_symbolic_r2_reversed_order_alias_polarity_frontier_v1.json \
  research/results/v1/shake_symbolic_r2_reversed_order_alias_polarity_frontier_v1.json \
  research/results/v1/shake_symbolic_r2_reversed_order_alias_polarity_frontier_v1.causal \
  research/configs/shake_symbolic_r2_adjacent_0_12_transfer_frontier_v1.json \
  research/results/v1/shake_symbolic_r2_adjacent_0_12_transfer_frontier_v1.json \
  research/results/v1/shake_symbolic_r2_adjacent_0_12_transfer_frontier_v1.causal \
  research/configs/shake_symbolic_r2_center_position_family_contrast_v1.json \
  research/results/v1/shake_symbolic_r2_center_position_family_contrast_v1.json \
  research/results/v1/shake_symbolic_r2_center_position_family_contrast_v1.causal \
  research/configs/shake_symbolic_r2_center_alias_partner_transfer_v1.json \
  research/results/v1/shake_symbolic_r2_center_alias_partner_transfer_v1.json \
  research/results/v1/shake_symbolic_r2_center_alias_partner_transfer_v1.causal \
  research/configs/shake_symbolic_r2_alpha_renamed_center_boundary_v1.json \
  research/results/v1/shake_symbolic_r2_alpha_renamed_center_boundary_v1.json \
  research/results/v1/shake_symbolic_r2_alpha_renamed_center_boundary_v1.causal \
  research/configs/shake_symbolic_r2_input_declaration_swap_boundary_v1.json \
  research/results/v1/shake_symbolic_r2_input_declaration_swap_boundary_v1.json \
  research/results/v1/shake_symbolic_r2_input_declaration_swap_boundary_v1.causal \
  research/configs/shake256_native_fullround_width32_prospective_v1.json \
  research/results/v1/shake256_native_fullround_width32_prospective_v1.json \
  research/results/v1/shake256_native_fullround_width32_prospective_v1.causal

echo "SHAKE Boolean, algebraic, symbolic-split, partition, strategy, prospective, affine-basis, gauge-factorial, native width-32 and alias-order Readers validated."
