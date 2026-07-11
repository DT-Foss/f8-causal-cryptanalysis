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
.venv/bin/python -m pytest tests/test_atlas.py tests/test_crypto_causal.py -q

.venv/bin/python research/experiments/multi_cipher_causal_atlas.py \
  --rows 4000 --seeds 5 --permutations 8 --similarity-null-draws 999 \
  --output research/results/v1/multi_cipher_causal_atlas_v1.json \
  --causal-output research/results/v1/multi_cipher_causal_atlas_v1.causal \
  --figure-prefix research/results/v1/multi_cipher_causal_atlas_v1

.venv/bin/python research/experiments/multi_cipher_causal_atlas.py \
  --rows 10000 --seeds 10 --permutations 16 --similarity-null-draws 4999 \
  --targets random_bytes chacha_r1 chacha_r2 chacha_r3 aes_r1 aes_r2 \
  --output research/results/v1/multi_cipher_frontier_confirm_v1.json \
  --causal-output research/results/v1/multi_cipher_frontier_confirm_v1.causal \
  --figure-prefix research/results/v1/multi_cipher_frontier_confirm_v1

.venv/bin/python scripts/write_hash_manifest.py \
  --output research/results/v1/ATLAS_SHA256SUMS \
  research/results/v1/multi_cipher_causal_atlas_v1.json \
  research/results/v1/multi_cipher_causal_atlas_v1.causal \
  research/results/v1/multi_cipher_causal_atlas_v1_fingerprints.png \
  research/results/v1/multi_cipher_causal_atlas_v1_similarity.png \
  research/results/v1/multi_cipher_frontier_confirm_v1.json \
  research/results/v1/multi_cipher_frontier_confirm_v1.causal \
  research/results/v1/multi_cipher_frontier_confirm_v1_fingerprints.png \
  research/results/v1/multi_cipher_frontier_confirm_v1_similarity.png
