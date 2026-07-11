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
  echo "Z3 CLI 4.15.4 is required for the symbolic Reader reproduction." >&2
  exit 2
fi
Z3_VERSION="$($Z3_BIN -version)"
if [[ "$Z3_VERSION" != "Z3 version 4.15.4"* ]]; then
  echo "Expected Z3 CLI 4.15.4, found: $Z3_VERSION" >&2
  exit 2
fi

export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
mkdir -p research/results/v1

.venv/bin/python research/experiments/present128_fullround_causal_f8.py \
  --output research/results/v1/present128_fullround_causal_f8_v1.json \
  --causal-output research/results/v1/present128_fullround_causal_f8_v1.causal

.venv/bin/python research/experiments/present128_fixedpoint_causal_mechanism.py \
  --output research/results/v1/present128_fixedpoint_causal_mechanism_v1.json \
  --causal-output research/results/v1/present128_fixedpoint_causal_mechanism_v1.causal

.venv/bin/python research/experiments/present_fullround_exact_mechanism.py \
  --output research/results/v1/present_fullround_exact_mechanism_v1.json \
  --causal-output research/results/v1/present_fullround_exact_mechanism_v1.causal

.venv/bin/python research/experiments/sha2_fullround_feedforward_causal.py \
  --variant sha256 \
  --output research/results/v1/sha256_fullround_feedforward_causal_v1.json \
  --causal-output research/results/v1/sha256_fullround_feedforward_causal_v1.causal

.venv/bin/python research/experiments/sha2_fullround_feedforward_causal.py \
  --variant sha512 \
  --output research/results/v1/sha512_fullround_feedforward_causal_v1.json \
  --causal-output research/results/v1/sha512_fullround_feedforward_causal_v1.causal

.venv/bin/python research/experiments/sha2_feedforward_carry_spectrum.py \
  --variant sha256 \
  --output research/results/v1/sha256_feedforward_carry_spectrum_v1.json \
  --causal-output research/results/v1/sha256_feedforward_carry_spectrum_v1.causal

.venv/bin/python research/experiments/sha2_feedforward_carry_spectrum.py \
  --variant sha512 \
  --output research/results/v1/sha512_feedforward_carry_spectrum_v1.json \
  --causal-output research/results/v1/sha512_feedforward_carry_spectrum_v1.causal

.venv/bin/python research/experiments/feal32x_fullround_distance2_causal.py \
  --output research/results/v1/feal32x_fullround_distance2_causal_v1.json \
  --causal-output research/results/v1/feal32x_fullround_distance2_causal_v1.causal

.venv/bin/python research/experiments/feal32x_fullround_reader_inverse.py \
  --output research/results/v1/feal32x_fullround_reader_inverse_v1.json \
  --causal-output research/results/v1/feal32x_fullround_reader_inverse_v1.causal

.venv/bin/python research/experiments/shacal2_fullround_cancellation_reader.py \
  --output research/results/v1/shacal2_fullround_cancellation_reader_v1.json \
  --causal-output research/results/v1/shacal2_fullround_cancellation_reader_v1.causal

.venv/bin/python research/experiments/sparkle_fullstep_causal.py \
  --output research/results/v1/sparkle_fullstep_causal_v1.json \
  --causal-output research/results/v1/sparkle_fullstep_causal_v1.causal

.venv/bin/python research/experiments/blake3_fullcompression_reader.py \
  --output research/results/v1/blake3_fullcompression_reader_v1.json \
  --causal-output research/results/v1/blake3_fullcompression_reader_v1.causal

.venv/bin/python research/experiments/blake3_output_borrow_spectrum.py \
  --output research/results/v1/blake3_output_borrow_spectrum_v1.json \
  --causal-output research/results/v1/blake3_output_borrow_spectrum_v1.causal

.venv/bin/python research/experiments/chacha20_fullround_feedforward_reader.py \
  --output research/results/v1/chacha20_fullround_feedforward_reader_v1.json \
  --causal-output research/results/v1/chacha20_fullround_feedforward_reader_v1.causal

.venv/bin/python research/experiments/chacha20_feedforward_xor_carry_spectrum.py \
  --output research/results/v1/chacha20_feedforward_xor_carry_spectrum_v1.json \
  --causal-output research/results/v1/chacha20_feedforward_xor_carry_spectrum_v1.causal

.venv/bin/python research/experiments/shake_fullround_rate_reader.py \
  --output research/results/v1/shake_fullround_rate_reader_v1.json \
  --causal-output research/results/v1/shake_fullround_rate_reader_v1.causal

.venv/bin/python research/experiments/shake_capacity_jacobian_reader.py \
  --output research/results/v1/shake_capacity_jacobian_reader_v1.json \
  --causal-output research/results/v1/shake_capacity_jacobian_reader_v1.causal

.venv/bin/python research/experiments/shake_capacity_window_inference.py \
  --output research/results/v1/shake_capacity_window_inference_v1.json \
  --causal-output research/results/v1/shake_capacity_window_inference_v1.causal

.venv/bin/python research/experiments/shake_bitsliced_window_solver.py \
  --output research/results/v1/shake_bitsliced_window_solver_v1.json \
  --causal-output research/results/v1/shake_bitsliced_window_solver_v1.causal

.venv/bin/python research/experiments/shake_native_window_solver.py \
  --window-bits 24,28 \
  --no-resume \
  --output research/results/v1/shake_native_window_solver_v1.json \
  --causal-output research/results/v1/shake_native_window_solver_v1.causal

.venv/bin/python research/experiments/shake_prefix_observability_frontier.py \
  --window-bits 16 \
  --output research/results/v1/shake_prefix_observability_frontier_v1.json \
  --causal-output research/results/v1/shake_prefix_observability_frontier_v1.causal

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

.venv/bin/pytest -q \
  tests/test_blake3_fullcompression_reader.py \
  tests/test_blake3_output_borrow_spectrum.py \
  tests/test_chacha20_fullround_feedforward_reader.py \
  tests/test_chacha20_feedforward_xor_carry_spectrum.py \
  tests/test_shake_fullround_rate_reader.py \
  tests/test_shake_capacity_jacobian_reader.py \
  tests/test_shake_capacity_window_inference.py \
  tests/test_shake_bitsliced_window_solver.py \
  tests/test_shake_native_window_solver.py \
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
  tests/test_feal32x_fullround_causal.py \
  tests/test_present_exact_mechanism.py \
  tests/test_shacal2_fullround_cancellation.py \
  tests/test_sparkle_fullstep_causal.py \
  tests/test_sha2_fullround_feedforward.py \
  tests/test_ciphers.py
.venv/bin/python scripts/validate_causal_artifacts.py >/dev/null

.venv/bin/python scripts/write_hash_manifest.py \
  --output research/results/v1/FULLROUND_TRANSFER_SHA256SUMS \
  research/results/v1/present128_fullround_causal_f8_v1.json \
  research/results/v1/present128_fullround_causal_f8_v1.causal \
  research/results/v1/present128_fixedpoint_causal_mechanism_v1.json \
  research/results/v1/present128_fixedpoint_causal_mechanism_v1.causal \
  research/results/v1/present_fullround_exact_mechanism_v1.json \
  research/results/v1/present_fullround_exact_mechanism_v1.causal \
  research/results/v1/sha256_fullround_feedforward_causal_v1.json \
  research/results/v1/sha256_fullround_feedforward_causal_v1.causal \
  research/results/v1/sha512_fullround_feedforward_causal_v1.json \
  research/results/v1/sha512_fullround_feedforward_causal_v1.causal \
  research/results/v1/sha256_feedforward_carry_spectrum_v1.json \
  research/results/v1/sha256_feedforward_carry_spectrum_v1.causal \
  research/results/v1/sha512_feedforward_carry_spectrum_v1.json \
  research/results/v1/sha512_feedforward_carry_spectrum_v1.causal \
  research/results/v1/feal32x_fullround_distance2_causal_v1.json \
  research/results/v1/feal32x_fullround_distance2_causal_v1.causal \
  research/results/v1/feal32x_fullround_reader_inverse_v1.json \
  research/results/v1/feal32x_fullround_reader_inverse_v1.causal \
  research/results/v1/shacal2_fullround_cancellation_reader_v1.json \
  research/results/v1/shacal2_fullround_cancellation_reader_v1.causal \
  research/results/v1/sparkle_fullstep_causal_v1.json \
  research/results/v1/sparkle_fullstep_causal_v1.causal \
  research/results/v1/blake3_fullcompression_reader_v1.json \
  research/results/v1/blake3_fullcompression_reader_v1.causal \
  research/results/v1/blake3_output_borrow_spectrum_v1.json \
  research/results/v1/blake3_output_borrow_spectrum_v1.causal \
  research/results/v1/chacha20_fullround_feedforward_reader_v1.json \
  research/results/v1/chacha20_fullround_feedforward_reader_v1.causal \
  research/results/v1/chacha20_feedforward_xor_carry_spectrum_v1.json \
  research/results/v1/chacha20_feedforward_xor_carry_spectrum_v1.causal \
  research/results/v1/shake_fullround_rate_reader_v1.json \
  research/results/v1/shake_fullround_rate_reader_v1.causal \
  research/results/v1/shake_capacity_jacobian_reader_v1.json \
  research/results/v1/shake_capacity_jacobian_reader_v1.causal \
  research/results/v1/shake_capacity_window_inference_v1.json \
  research/results/v1/shake_capacity_window_inference_v1.causal \
  research/results/v1/shake_bitsliced_window_solver_v1.json \
  research/results/v1/shake_bitsliced_window_solver_v1.causal \
  research/results/v1/shake_native_window_solver_v1.json \
  research/results/v1/shake_native_window_solver_v1.causal \
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
  research/results/v1/shake_symbolic_r1_scaling_reader_v1.causal

echo "PRESENT-128, SHA-2, FEAL-32X, SHACAL-2, SPARKLE, BLAKE3, ChaCha20 and SHAKE endpoint mechanisms reproduced."
