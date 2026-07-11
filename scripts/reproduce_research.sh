#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
  .venv/bin/python -m pip install -r requirements.txt
  .venv/bin/python -m pip install -e .
fi

mkdir -p research/results/v1

if [[ ! -f research/results/reproduction_v1/index.json ]]; then
  echo "Paper baseline is incomplete: run ./scripts/reproduce_papers.sh first." >&2
  exit 2
fi

REPRODUCED="$(jq -r '(.counts.by_status.reproduced // 0) + (.counts.by_status.reproduced_expected_failure // 0)' research/results/reproduction_v1/index.json)"
if [[ "$REPRODUCED" != "39" ]]; then
  echo "Paper baseline is incomplete: ${REPRODUCED}/39 legacy outcomes reproduced." >&2
  exit 2
fi

if [[ "$(jq -r '.exact_cipher_payload_match' research/results/reproduction_v1/nano_master_rebuild.json)" != "true" ]]; then
  echo "Nano master rebuild does not match the retained paper artifact." >&2
  exit 2
fi

.venv/bin/python research/experiments/reference_vector_audit.py \
  --output research/results/v1/reference_vectors.json

.venv/bin/python research/experiments/f8_fair_null_suite.py \
  --config research/configs/research_v1.json \
  --output research/results/v1/f8_fair_null.json

.venv/bin/python research/experiments/casi_calibration_suite.py \
  --config research/configs/research_v1.json \
  --output research/results/v1/casi_calibration.json

.venv/bin/python research/experiments/casi_input_model_suite.py \
  --output research/results/v1/casi_input_model.json

.venv/bin/python research/experiments/validate_research_results.py \
  --results research/results/v1 \
  --output research/results/v1/validation.json

.venv/bin/python scripts/write_hash_manifest.py \
  --output research/results/v1/SHA256SUMS \
  research/results/v1/*.json
