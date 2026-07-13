#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-.venv/bin/python}"

PYTHONWARNINGS=error PYTHONPATH=src "$PYTHON" - <<'PY'
from hashlib import sha256
import json
from pathlib import Path

anchors = {
    "research/results/v1/chacha20_round20_multihorizon_preflight_v1.json":
        "f5cc99ac3dcf679023e1a32b91b5dae26d94837db08673f23f0f5cb787afd946",
    "research/configs/chacha20_round20_multihorizon_preflight_v1.json":
        "a1f544800f0f2349d6a74ceca041e212a624e74b5a0ade3975e233571eb3e474",
    "research/configs/chacha20_round20_factorial_trajectory_transfer_v1.json":
        "70df07cb4f4f22115e3aa63765de0fca0dd610607cc87356946a188f53fe5645",
    "research/experiments/chacha20_round20_public_core.py":
        "953e4478d369b2eb39657d4b6f718fa97a46cac1855b0364cce1bc4e4753f77f",
    "src/arx_carry_leak/factorial_trajectory.py":
        "df05913df5b5c589eed73c5ab877c2776cbdb78e68338677bd4a1577358c2916",
    "research/experiments/chacha20_round20_factorial_trajectory_read.py":
        "294e962e639b2058d3cf726949c05206e4ac14a4d663e1b482077f9c49ae8965",
    "tests/test_chacha20_round20_factorial_trajectory_read.py":
        "bc9b825f1de9a59ec30fe3fc6c999e699bb5b195a0466413a46cd462622d3d66",
}
for raw_path, expected in anchors.items():
    path = Path(raw_path)
    observed = sha256(path.read_bytes()).hexdigest()
    if observed != expected:
        raise SystemExit(f"hash mismatch: {path}: {observed} != {expected}")
payload = json.loads(Path(
    "research/results/v1/chacha20_round20_multihorizon_preflight_v1.json"
).read_bytes())
expected_measurement = "a43f530b72dad576db5623e3c23f8c3dcb3ce666c4159b29d74c9bb7294cfdc7"
if payload.get("measurement_sha256") != expected_measurement:
    raise SystemExit("A220P scientific measurement hash mismatch")
print(f"A220P/A220 anchors: {len(anchors)}/{len(anchors)} exact")
PY

PYTHONWARNINGS=error PYTHONPATH=src "$PYTHON" -m pytest -q \
  tests/test_chacha20_round10_global_incremental_cover.py \
  tests/test_chacha20_round20_global_incremental_transfer.py \
  tests/test_chacha20_solver_trajectory_formula_atlas.py \
  tests/test_chacha20_round20_causal_pcr_backprojection.py \
  tests/test_chacha20_round20_knownkey_atlas_helpers.py \
  tests/test_chacha20_round20_knownkey_propagation_atlas.py \
  tests/test_chacha20_round20_symbolic_template.py \
  tests/test_chacha20_round20_key_contrast_mobius_atlas.py \
  tests/test_chacha20_round20_multifrequency_group_readout.py \
  tests/test_chacha20_round20_multifrequency_selection_matched_null.py \
  tests/test_chacha20_round20_operator_diversity_audit.py \
  tests/test_chacha20_round20_knownkey_trajectory_atlas.py \
  tests/test_chacha20_round20_knownkey_trajectory_atlas_reveal.py \
  tests/test_chacha20_round20_ranked_target_recovery.py \
  tests/test_chacha20_round20_ranked_target_cross_confirmation.py \
  tests/test_chacha20_retained_multihorizon.py \
  tests/test_chacha20_round20_multihorizon_preflight.py \
  tests/test_chacha20_round20_public_core.py \
  tests/test_factorial_trajectory.py \
  tests/test_chacha20_round20_factorial_trajectory_read.py \
  tests/test_chacha20_round20_factorial_trajectory_protocol.py

echo "A211-A220P retained-evidence and protocol gates passed."
