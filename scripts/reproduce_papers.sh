#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
  .venv/bin/python -m pip install -r requirements.txt
  .venv/bin/python -m pip install -e .
fi

PYTHONDONTWRITEBYTECODE=1 .venv/bin/python research/reproduction/build_manifest.py

# The 38 NumPy/SciPy legacy scripts use the pinned project environment.
F8_IDS=()
while IFS= read -r experiment_id; do
  F8_IDS+=("$experiment_id")
done < <(
  PYTHONDONTWRITEBYTECODE=1 .venv/bin/python \
    research/reproduction/run_legacy_reproduction.py --list \
    | cut -f1 \
    | grep -v 'gohr_comparison'
)
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python \
  research/reproduction/run_legacy_reproduction.py "${F8_IDS[@]}" --timeout 7200

# The archived neural comparison needs Torch. Use an explicitly selected Python
# so its executable and versions are retained in the run record.
TORCH_PYTHON="${TORCH_PYTHON:-python3}"
if "$TORCH_PYTHON" -c 'import torch' >/dev/null 2>&1; then
  PYTHONDONTWRITEBYTECODE=1 .venv/bin/python \
    research/reproduction/run_legacy_reproduction.py \
    provenance__original_f8_scripts__gohr_comparison \
    --python "$TORCH_PYTHON" --timeout 14400
else
  echo "Torch is required for the archived Gohr comparison." >&2
  echo "Set TORCH_PYTHON to a Python executable that can import torch." >&2
  exit 2
fi

PYTHONDONTWRITEBYTECODE=1 .venv/bin/python \
  research/reproduction/rebuild_nano_master.py \
  --output research/results/reproduction_v1/nano_master_rebuild.json
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python \
  research/reproduction/audit_nano_protocol.py \
  --output research/results/reproduction_v1/nano_protocol_audit.json
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python \
  research/reproduction/summarize_runs.py

.venv/bin/python scripts/write_hash_manifest.py \
  --output research/results/reproduction_v1/SHA256SUMS \
  --tree research/results/reproduction_v1
