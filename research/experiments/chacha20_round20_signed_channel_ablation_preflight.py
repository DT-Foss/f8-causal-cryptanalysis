#!/usr/bin/env python3
"""Freeze A271's complete signed-channel family before any grouped outcome."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.trajectory_contribution import signed_semantic_groups  # noqa: E402

ATTEMPT_ID = "A271"
A268_PROTOCOL = (
    ROOT
    / "research/configs/chacha20_round20_prospective_trajectory_shape_validation_v1.json"
)
A268_PREFLIGHT = (
    ROOT
    / "research/provenance/chacha20_round20_a268_prospective_trajectory_shape_preflight_v1.json"
)
A268_RESULT = (
    ROOT
    / "research/results/v1/chacha20_round20_prospective_trajectory_shape_validation_v1.json"
)
A268_CAUSAL = A268_RESULT.with_suffix(".causal")
A268_RUNNER = Path(__file__).with_name(
    "chacha20_round20_prospective_trajectory_shape_validation.py"
)
A270_PROTOCOL = (
    ROOT / "research/configs/chacha20_round20_local_pairwise_intervention_v1.json"
)
A270_RESULT = (
    ROOT / "research/results/v1/chacha20_round20_local_pairwise_intervention_v1.json"
)
A270_CAUSAL = A270_RESULT.with_suffix(".causal")
SHAPE_SOURCE = ROOT / "src/arx_carry_leak/solver_trajectory_shape.py"
CONTRIBUTION_SOURCE = ROOT / "src/arx_carry_leak/trajectory_contribution.py"
CONTRIBUTION_TEST = ROOT / "tests/test_trajectory_contribution.py"
RUNNER = Path(__file__).with_name("chacha20_round20_signed_channel_ablation.py")
OUTPUT = ROOT / "research/configs/chacha20_round20_signed_channel_ablation_v1.json"

A268_PROTOCOL_SHA256 = "274cdc5b4e2ef0a4887e67d13106b17b6011d0917d473de158e72cbc55f14221"
A268_PREFLIGHT_SHA256 = "d8fdbb88254b40ea90812c29563baf8f82b693d5fa9980f28a116089abfa9a17"
A268_RESULT_SHA256 = "f49919a23234e4087523e0ba8a4abbdb19feedf0a685e49d61f5bbe603ee1849"
A268_CAUSAL_SHA256 = "2264a20e7ed790e3d8f9e99d204962880be5af17a7024e3e25e9e58ef39216bb"
A270_PROTOCOL_SHA256 = "6a5e416234a1d129c7532ffade36eac3bcdb8c35a1271f81e13807ce32e30f5e"
A270_RESULT_SHA256 = "8bf9e98335384a192c8974e150efa9553bf48b6cb5ecec1b661755b9f98df86f"
A270_CAUSAL_SHA256 = "34b85a2cb68432e3d50ae23ce15b80a33f774d16f31836640fcde8a7d44e2c57"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_sha256(value: Any) -> str:
    return _sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    )


def _atomic_json(path: Path, value: Any) -> None:
    raw = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
        .encode("ascii")
        + b"\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def build_protocol() -> dict[str, Any]:
    if OUTPUT.exists():
        raise FileExistsError(f"A271 protocol already exists: {OUTPUT}")
    fixed_hashes = {
        A268_PROTOCOL: A268_PROTOCOL_SHA256,
        A268_PREFLIGHT: A268_PREFLIGHT_SHA256,
        A268_RESULT: A268_RESULT_SHA256,
        A268_CAUSAL: A268_CAUSAL_SHA256,
        A270_PROTOCOL: A270_PROTOCOL_SHA256,
        A270_RESULT: A270_RESULT_SHA256,
        A270_CAUSAL: A270_CAUSAL_SHA256,
    }
    for path, expected in fixed_hashes.items():
        if _file_sha256(path) != expected:
            raise RuntimeError(f"A271 anchored predecessor differs: {path.name}")
    a268_preflight = json.loads(A268_PREFLIGHT.read_bytes())
    a268 = json.loads(A268_RESULT.read_bytes())
    a270 = json.loads(A270_RESULT.read_bytes())
    if (
        a268.get("evidence_stage")
        != "FULLROUND_R20_PROSPECTIVE_TRAJECTORY_SHAPE_BOUNDARY"
        or a268.get("retention_gate", {}).get("passed") is not False
        or a270.get("evidence_stage")
        != "FULLROUND_R20_LOCAL_PAIRWISE_INTERVENTION_BOUNDARY"
        or a270.get("retention_gate", {}).get("passed") is not False
        or a270.get("causal", {})
        .get("personal_semantic_readback", {})
        .get("next_gap", {})
        .get("expected_object_type")
        != "channel_signed_pairwise_ablation_without_model_refit"
    ):
        raise RuntimeError("A271 predecessor route differs")
    model = a268_preflight["frozen_model"]["model"]
    groups = signed_semantic_groups(model["feature_names"], model["coefficients"])
    group_rows = [
        {"name": name, "feature_indices": list(indices)}
        for name, indices in groups.items()
    ]
    nonzero = sum(float(value) != 0.0 for value in model["coefficients"])
    if len(group_rows) != 32 or sum(len(row["feature_indices"]) for row in group_rows) != nonzero:
        raise RuntimeError("A271 signed-channel geometry differs")
    anchors = {
        "A268_protocol_path": str(A268_PROTOCOL.relative_to(ROOT)),
        "A268_protocol_sha256": A268_PROTOCOL_SHA256,
        "A268_preflight_path": str(A268_PREFLIGHT.relative_to(ROOT)),
        "A268_preflight_sha256": A268_PREFLIGHT_SHA256,
        "A268_result_path": str(A268_RESULT.relative_to(ROOT)),
        "A268_result_sha256": A268_RESULT_SHA256,
        "A268_causal_path": str(A268_CAUSAL.relative_to(ROOT)),
        "A268_causal_sha256": A268_CAUSAL_SHA256,
        "A268_runner_path": str(A268_RUNNER.relative_to(ROOT)),
        "A268_runner_sha256": _file_sha256(A268_RUNNER),
        "A270_protocol_path": str(A270_PROTOCOL.relative_to(ROOT)),
        "A270_protocol_sha256": A270_PROTOCOL_SHA256,
        "A270_result_path": str(A270_RESULT.relative_to(ROOT)),
        "A270_result_sha256": A270_RESULT_SHA256,
        "A270_causal_path": str(A270_CAUSAL.relative_to(ROOT)),
        "A270_causal_sha256": A270_CAUSAL_SHA256,
        "shape_source_path": str(SHAPE_SOURCE.relative_to(ROOT)),
        "shape_source_sha256": _file_sha256(SHAPE_SOURCE),
        "contribution_source_path": str(CONTRIBUTION_SOURCE.relative_to(ROOT)),
        "contribution_source_sha256": _file_sha256(CONTRIBUTION_SOURCE),
        "contribution_test_path": str(CONTRIBUTION_TEST.relative_to(ROOT)),
        "contribution_test_sha256": _file_sha256(CONTRIBUTION_TEST),
        "runner_path": str(RUNNER.relative_to(ROOT)),
        "runner_sha256": _file_sha256(RUNNER),
    }
    return {
        "schema": "chacha20-round20-signed-channel-ablation-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_after_A270_boundary_before_any_signed_channel_contribution_score_rank_or_XOR_control",
        "anchors": anchors,
        "frozen_model": {
            "model_sha256": a268_preflight["frozen_model"]["model_sha256"],
            "feature_count": len(model["feature_names"]),
            "nonzero_coefficient_count": nonzero,
            "signed_semantic_groups": group_rows,
            "group_ledger_sha256": _canonical_sha256(group_rows),
        },
        "view_family": {
            "group_count": len(group_rows),
            "modes": ["direct_additive_contribution", "normalized_8cube_graph_laplacian"],
            "view_count": len(group_rows) * 2,
            "operator_family_selected_from_A268_or_A270_group_outcomes": False,
            "all_views_retained_for_familywise_control": True,
        },
        "controls": {
            "shared_XOR_offsets": 256,
            "per_view_statistic": "mean_log2_descending_midrank",
            "familywise_statistic": "maximum_bit_gain_across_all_64_frozen_views",
            "multiplicity_control": "exact_shared_XOR_max_statistic",
        },
        "retention_gate": {
            "maximum_exact_familywise_shared_xor_p": 0.05,
            "best_view_bit_gain_must_exceed_raw_A268_bit_gain": True,
            "minimum_positive_prefix_groups_for_best_view": 3,
            "next_if_passed": "prospective_disjoint_signed_channel_validation_without_refit",
            "next_if_not_passed": "ordered_clause_event_timing_reader_without_model_refit",
        },
        "information_boundary": {
            "A268_and_A270_outcomes_known_at_freeze": True,
            "frozen_A267_model_coefficients_known_at_freeze": True,
            "group_partition_uses_only_feature_names_and_coefficient_signs": True,
            "any_A268_grouped_contribution_computed_at_freeze": False,
            "any_signed_channel_rank_or_XOR_control_known_at_freeze": False,
            "model_refit_or_coefficient_update_permitted": False,
            "future_target_generated": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", action="store_true")
    args = parser.parse_args()
    if not args.freeze:
        print(json.dumps({"attempt_id": ATTEMPT_ID, "output": str(OUTPUT)}, indent=2))
        return
    protocol = build_protocol()
    _atomic_json(OUTPUT, protocol)
    print(
        json.dumps(
            {
                "output": str(OUTPUT),
                "protocol_sha256": _file_sha256(OUTPUT),
                "runner_sha256": protocol["anchors"]["runner_sha256"],
                "group_ledger_sha256": protocol["frozen_model"]["group_ledger_sha256"],
                "view_count": protocol["view_family"]["view_count"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
