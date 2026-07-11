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

.venv/bin/python -m pytest \
  tests/test_crypto_causal.py \
  tests/test_causal_carry_intervention.py \
  tests/test_mlkem_causal_serialization.py \
  tests/test_compression_cascade_causal.py \
  tests/test_causal_information_compression.py -q

# Paper-scale mechanism intervention across all ten Speck variants, the SIMON
# no-addition control, and Threefish-256.
.venv/bin/python research/experiments/causal_carry_intervention_suite.py \
  --blocks 20000 --seeds 10 --round-pairs 8 --routes 16 \
  --output research/results/v1/causal_carry_intervention_paper_scale.json \
  --causal-output research/results/v1/causal_carry_intervention_paper_scale.causal

# Corrected ML-KEM causal control: same compressed values/bits/length under
# bijective serialization, plus uniform Z_q -> Compress_d rather than an
# artificial uniform output-alphabet control.
.venv/bin/python research/experiments/mlkem_causal_serialization_suite.py \
  --operations 500 --seeds 10 \
  --output research/results/v1/mlkem_causal_serialization_v2.json \
  --causal-output research/results/v1/mlkem_causal_serialization_v2.causal

.venv/bin/python research/experiments/compression_cascade_causal_suite.py \
  --blocks 5000 --seeds 10 \
  --output research/results/v1/compression_cascade_causal_v1.json \
  --causal-output research/results/v1/compression_cascade_causal_v1.causal

.venv/bin/python research/experiments/causal_information_compression_suite.py \
  --blocks 10000 --seeds 10 --routes 16 \
  --output research/results/v1/causal_information_compression_v1.json \
  --causal-output research/results/v1/causal_information_compression_v1.causal

.venv/bin/python scripts/write_hash_manifest.py \
  --output research/results/v1/CAUSAL_SHA256SUMS \
  research/results/v1/causal_carry_intervention_paper_scale.json \
  research/results/v1/causal_carry_intervention_paper_scale.causal \
  research/results/v1/mlkem_causal_serialization_v2.json \
  research/results/v1/mlkem_causal_serialization_v2.causal \
  research/results/v1/compression_cascade_causal_v1.json \
  research/results/v1/compression_cascade_causal_v1.causal \
  research/results/v1/causal_information_compression_v1.json \
  research/results/v1/causal_information_compression_v1.causal
