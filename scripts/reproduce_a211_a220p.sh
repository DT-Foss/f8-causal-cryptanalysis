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
    "research/experiments/chacha20_round20_factorial_trajectory_collect.py":
        "5112a75ed09872dcc928f3ad42f669895c4f5bb5ec518f32edcd4f66328ed6d7",
    "tests/test_chacha20_round20_factorial_trajectory_collect.py":
        "511cd8c2d78cde72492391cffad821001fe579033c3d453ce8325c75a1423d91",
    "src/arx_carry_leak/factorial_holdout.py":
        "d2ab7a8f35a1160f7022f72cdd4ce3e18bb05b8ecd5a06136f8d2f9ea697c411",
    "tests/test_factorial_holdout.py":
        "73b1283c50e5eb9e843b8c9c1e473898738e331e050c6e7995884dfab1974e2d",
    "research/experiments/chacha20_round20_factorial_trajectory_holdout_collect.py":
        "66d8d97625975548b7d42d423653e79e7333d233093ac3d6a341808faf6f8010",
    "tests/test_chacha20_round20_factorial_trajectory_holdout_collect.py":
        "43b23caeeeab01d68e1bdafcb796eb88cb6537c45818200c05c7bd998f1603db",
    "research/experiments/chacha20_round20_factorial_trajectory_holdout_evaluate.py":
        "d3db06f9db83af2103b9761b0c6e7fdcfbd6752ac846e17829d49b5b2607eb5f",
    "tests/test_chacha20_round20_factorial_trajectory_holdout_evaluate.py":
        "24778441af01918737505013fc986b0f199381739d1b34bbcf283b27ebe2b9e6",
    "src/arx_carry_leak/factorial_target.py":
        "e072cdb2db1d3a0f639f9c3bf71c06d428d86140d3f2ac3e73b3809dba36e015",
    "tests/test_factorial_target.py":
        "e940da0845407f329288dbafb3d5332ff75f2875c945b98bf1368caa7e26400a",
    "src/arx_carry_leak/factorial_boundary.py":
        "8888b57c21cda56a746c938716f789c92957d5f443899cf477d035054709e7dc",
    "tests/test_factorial_boundary.py":
        "8c77f9b1bc587c5786abd7baf7856de48aa7a8e6478650569e8f9609a1d5d357",
    "research/experiments/chacha20_round20_factorial_boundary_route.py":
        "dd10dd48a37b158d005a0d42c3d4d0fbd59864a75fe2dd0e8d8e79f7e004536d",
    "tests/test_chacha20_round20_factorial_boundary_route.py":
        "356272aaf348442385b058d37da1af519e48becd1dff7824e361a419903eb982",
    "research/configs/chacha20_round20_factorial_boundary_router_v1.json":
        "e69cde426e264025aeadd209560b93ec4667ddc8e63faaf98f6459b281a343a5",
    "research/configs/chacha20_round20_factorial_eight_block_ensemble_v1.json":
        "e3ee7ccc583ee778ca832877cf27a0fa9ad5d7c1544429e3b0277b30aa0fab51",
    "research/experiments/chacha20_round20_factorial_eight_block_key_design.py":
        "633d56ade07ecb30e7c1182fd98f2ba415d1a3d2f90bfbbccbac9ce9791f780f",
    "tests/test_chacha20_round20_factorial_eight_block_key_design.py":
        "2e9fbe04650618cc069cafabcd796bfa05ca415edbf020ec2ab9f5407a4e6cb2",
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
  tests/test_factorial_holdout.py \
  tests/test_factorial_target.py \
  tests/test_chacha20_round20_factorial_trajectory_collect.py \
  tests/test_chacha20_round20_factorial_trajectory_holdout_collect.py \
  tests/test_chacha20_round20_factorial_trajectory_holdout_evaluate.py \
  tests/test_chacha20_round20_factorial_trajectory_read.py \
  tests/test_chacha20_round20_factorial_trajectory_protocol.py \
  tests/test_factorial_boundary.py \
  tests/test_chacha20_round20_factorial_boundary_route.py \
  tests/test_chacha20_round20_factorial_eight_block_key_design.py

"$PYTHON" scripts/verify_hash_manifest.py \
  research/results/v1/A220B_A222_INFRA_SHA256SUMS

echo "A211-A220P retained evidence and A220/A220B/A222 frozen-infrastructure gates passed."
