#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi
.venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt
.venv/bin/python -m pip install -e .

mkdir -p research/results/v1

.venv/bin/python -m pytest tests/test_pqc_output_control_suite.py -q

# Real ML-KEM, ML-DSA, and HQC operation controls.
.venv/bin/python research/experiments/pqc_output_control_suite.py \
  --operations 128 --seeds 2 --permutations 2 \
  --targets mlkem512 mlkem768 mlkem1024 mldsa44 mldsa65 mldsa87 hqc128 hqc192 hqc256 \
  --output research/results/v1/pqc_output_controls.json

# Hash-signature serialization boundary control; pqcrypto's API retains the
# SPHINCS+ name, so this is a family control rather than a FIPS conformance run.
.venv/bin/python research/experiments/pqc_output_control_suite.py \
  --operations 64 --seeds 2 --permutations 2 --targets sphincs128f \
  --output research/results/v1/sphincs128f_boundary_full.json

.venv/bin/python research/experiments/mlkem_ntt_trace_suite.py \
  --operations 1000 --permutations 5 --bvn-routes 16 \
  --output research/results/v1/mlkem_ntt_trace_field.json

.venv/bin/python research/experiments/mlkem_deterministic_io_f8.py \
  --operations 5000 --permutations 5 \
  --output research/results/v1/mlkem_deterministic_io_f8.json

.venv/bin/python research/experiments/mlkem_compression_control_suite.py \
  --operations 500 --seeds 3 \
  --output research/results/v1/mlkem_compression_controls.json

.venv/bin/python research/experiments/mlkem_mutation_profile_suite.py \
  --operations 128 \
  --output research/results/v1/mlkem_mutation_profile.json

# Balanced causal null: every public row is preserved exactly while globally
# routed bijections intervene only on output order. This prevents treating
# CASI/F8-O serialization effects as PQC-internal observations.
.venv/bin/python research/experiments/pqc_bvn_route_control_suite.py \
  --operations 128 --seeds 3 --routes 32 --max-rows 1200 \
  --targets mlkem512 mldsa44 \
  --output research/results/v1/pqc_bvn_route_controls_v1.json

.venv/bin/python scripts/write_hash_manifest.py \
  --output research/results/v1/PQC_SHA256SUMS \
  research/results/v1/pqc_output_controls.json \
  research/results/v1/sphincs128f_boundary_full.json \
  research/results/v1/mlkem_ntt_trace_field.json \
  research/results/v1/mlkem_deterministic_io_f8.json \
  research/results/v1/mlkem_compression_controls.json \
  research/results/v1/mlkem_mutation_profile.json \
  research/results/v1/pqc_bvn_route_controls_v1.json
