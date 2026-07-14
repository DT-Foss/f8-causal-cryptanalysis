#!/usr/bin/env python3
"""Freeze A270's single local intervention before computing its outcome."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
ATTEMPT_ID = "A270"
A268_RESULT = (
    ROOT
    / "research/results/v1/chacha20_round20_prospective_trajectory_shape_validation_v1.json"
)
A268_CAUSAL = A268_RESULT.with_suffix(".causal")
A269_ROUTE = (
    ROOT / "research/provenance/chacha20_round20_a269_target_route_preflight_v1.json"
)
OPERATOR_SOURCE = ROOT / "src/arx_carry_leak/score_hypercube.py"
OPERATOR_TEST = ROOT / "tests/test_score_hypercube.py"
RUNNER = Path(__file__).with_name("chacha20_round20_local_pairwise_intervention.py")
OUTPUT = ROOT / "research/configs/chacha20_round20_local_pairwise_intervention_v1.json"

A268_RESULT_SHA256 = "f49919a23234e4087523e0ba8a4abbdb19feedf0a685e49d61f5bbe603ee1849"
A268_CAUSAL_SHA256 = "2264a20e7ed790e3d8f9e99d204962880be5af17a7024e3e25e9e58ef39216bb"
A269_ROUTE_SHA256 = "7dde8989c60c00add4f47e259968bf93b0e18c5e01a4e92a54638397e28b8f50"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def build_protocol() -> dict[str, Any]:
    if OUTPUT.exists():
        raise FileExistsError(f"A270 protocol already exists: {OUTPUT}")
    if _file_sha256(A268_RESULT) != A268_RESULT_SHA256:
        raise RuntimeError("A270 A268 result hash differs")
    if _file_sha256(A268_CAUSAL) != A268_CAUSAL_SHA256:
        raise RuntimeError("A270 A268 Causal hash differs")
    if _file_sha256(A269_ROUTE) != A269_ROUTE_SHA256:
        raise RuntimeError("A270 A269 route hash differs")
    a268 = json.loads(A268_RESULT.read_bytes())
    route = json.loads(A269_ROUTE.read_bytes())
    if (
        a268.get("retention_gate", {}).get("passed") is not False
        or a268.get("causal", {}).get("personal_semantic_readback", {})
        .get("next_gap", {})
        .get("expected_object_type")
        != "local_pairwise_intervention_on_A268_without_model_refit"
        or route.get("frozen_plan", {}).get("route_if_A268_does_not_pass")
        != "do_not_generate_targets_test_local_pairwise_intervention_on_A268_without_model_refit"
    ):
        raise RuntimeError("A270 A268/A269 route prerequisite differs")
    return {
        "schema": "chacha20-round20-local-pairwise-intervention-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_after_A268_boundary_before_any_local_pairwise_residual_rank_margin_or_XOR_control",
        "anchors": {
            "A268_result_path": str(A268_RESULT.relative_to(ROOT)),
            "A268_result_sha256": A268_RESULT_SHA256,
            "A268_causal_path": str(A268_CAUSAL.relative_to(ROOT)),
            "A268_causal_sha256": A268_CAUSAL_SHA256,
            "A269_route_path": str(A269_ROUTE.relative_to(ROOT)),
            "A269_route_sha256": A269_ROUTE_SHA256,
            "operator_source_path": str(OPERATOR_SOURCE.relative_to(ROOT)),
            "operator_source_sha256": _file_sha256(OPERATOR_SOURCE),
            "operator_test_path": str(OPERATOR_TEST.relative_to(ROOT)),
            "operator_test_sha256": _file_sha256(OPERATOR_TEST),
            "runner_path": str(RUNNER.relative_to(ROOT)),
            "runner_sha256": _file_sha256(RUNNER),
        },
        "operator": {
            "name": "normalized_8cube_graph_laplacian",
            "formula": "local_score[c]=raw_score[c]-mean_b(raw_score[c_xor_2^b])",
            "candidate_bits": 8,
            "neighbors_per_candidate": 8,
            "fitted_parameters": 0,
            "sign_or_scale_selection_permitted": False,
            "candidate_labels_used_only_after_all_local_scores_exist": True,
        },
        "controls": {
            "shared_XOR_offsets": 256,
            "rank_statistic": "mean_log2_descending_midrank",
            "pairwise_statistic": "mean_directed_raw_logit_margin_over_20x8_true_neighbor_pairs",
            "operator_family_selection": 1,
        },
        "retention_gate": {
            "maximum_exact_shared_xor_p": 0.05,
            "local_bit_gain_must_exceed_raw_A268_bit_gain": True,
            "minimum_positive_prefix_groups": 3,
            "next_if_passed": "prospective_disjoint_local_pairwise_validation",
            "next_if_not_passed": "channel_signed_pairwise_ablation_without_model_refit",
        },
        "information_boundary": {
            "A268_result_known_at_freeze": True,
            "A268_raw_rank_boundary_known_at_freeze": True,
            "local_pairwise_residual_computed_at_freeze": False,
            "local_pairwise_rank_margin_or_XOR_control_known_at_freeze": False,
            "operator_selected_from_A268_local_outcome": False,
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
                "operator_source_sha256": protocol["anchors"][
                    "operator_source_sha256"
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
