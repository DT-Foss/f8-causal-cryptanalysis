#!/usr/bin/env python3
"""Freeze the post-A268 target-recovery route before A268 ranks exist."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
ATTEMPT_ID = "A269"
SCHEMA = "chacha20-round20-trajectory-shape-target-route-preflight-v1"
A267_RESULT = (
    ROOT
    / "research/results/v1/chacha20_round20_fresh_trajectory_shape_reader_v1.json"
)
A268_PREFLIGHT = (
    ROOT
    / "research/provenance/chacha20_round20_a268_prospective_trajectory_shape_preflight_v1.json"
)
A268_PROTOCOL = (
    ROOT
    / "research/configs/chacha20_round20_prospective_trajectory_shape_validation_v1.json"
)
A268_RESULT = (
    ROOT
    / "research/results/v1/chacha20_round20_prospective_trajectory_shape_validation_v1.json"
)
OUTPUT = (
    ROOT
    / "research/provenance/chacha20_round20_a269_target_route_preflight_v1.json"
)

A267_RESULT_SHA256 = "a6a623b442a0ad76eb6a15b90183c87a4dcd558a5856e625d48f2086da43f492"
A268_PREFLIGHT_SHA256 = "d8fdbb88254b40ea90812c29563baf8f82b693d5fa9980f28a116089abfa9a17"
A268_PROTOCOL_SHA256 = "274cdc5b4e2ef0a4887e67d13106b17b6011d0917d473de158e72cbc55f14221"
FROZEN_MODEL_SHA256 = "b096c08616a81712da881862b65f0c95388e4db3cf6b8e462bf7c2a072cb0da4"
TARGET_COUNT = 4
DEEP_MAX_CELLS = 128
DEEP_SECONDS_PER_CELL = 30.0
MAX_CONCURRENT_TARGETS = 2


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _canonical_sha256(value: Any) -> str:
    return _sha256(_canonical_bytes(value))


def _atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(
        value,
        indent=2,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii") + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _a267_ranks(payload: dict[str, Any]) -> list[float]:
    rows = payload.get("evaluation", {}).get("outer_holdout_rows", [])
    ranks = [float(row["midrank"]) for row in rows]
    if (
        len(ranks) != 20
        or any(not math.isfinite(rank) or rank < 1.0 or rank > 256.0 for rank in ranks)
    ):
        raise RuntimeError("A269 A267 rank anchor differs")
    return ranks


def build_preflight() -> dict[str, Any]:
    if A268_RESULT.exists():
        raise RuntimeError("A269 route must be frozen before the A268 result exists")
    if _file_sha256(A267_RESULT) != A267_RESULT_SHA256:
        raise RuntimeError("A269 A267 result hash differs")
    if _file_sha256(A268_PREFLIGHT) != A268_PREFLIGHT_SHA256:
        raise RuntimeError("A269 A268 preflight hash differs")
    if _file_sha256(A268_PROTOCOL) != A268_PROTOCOL_SHA256:
        raise RuntimeError("A269 A268 protocol hash differs")

    a267 = json.loads(A267_RESULT.read_bytes())
    a268_preflight = json.loads(A268_PREFLIGHT.read_bytes())
    if (
        a267.get("attempt_id") != "A267"
        or a267.get("evidence_stage")
        != "FULLROUND_R20_SCALE_FREE_TRAJECTORY_SHAPE_CROSSVALIDATED_SIGNAL"
        or a267.get("retention_gate", {}).get("passed") is not True
        or a268_preflight.get("frozen_model", {}).get("model_sha256")
        != FROZEN_MODEL_SHA256
    ):
        raise RuntimeError("A269 retained-reader prerequisite differs")

    ranks = _a267_ranks(a267)
    top128 = sum(rank <= DEEP_MAX_CELLS for rank in ranks)
    plan = {
        "target_count": TARGET_COUNT,
        "target_generation": (
            "one_shot_OS_random_low20_assignments_used_only_to_form_public_"
            "eight_block_R20_relations_then_discarded_with_builder_process_exit"
        ),
        "target_disjointness": (
            "all_targets_unique_and_disjoint_from_A220_A267_A268_known_key_rows"
        ),
        "shallow_measurement": {
            "candidate_regions": 256,
            "fresh_solver_state_per_candidate": True,
            "conflict_horizons": [1, 2, 4, 8],
            "complete_cover_required_before_scoring": True,
            "model_sha256": FROZEN_MODEL_SHA256,
            "model_refit_or_coefficient_update_permitted": False,
            "A268_rows_or_labels_used_for_fit_or_threshold_selection": False,
        },
        "candidate_order": {
            "rule": "descending_frozen_logit_then_numeric_candidate_tiebreak",
            "all_256_positions_hash_frozen_before_deep_solver_execution": True,
        },
        "deep_recovery": {
            "solver": "CaDiCaL_3.0.0_single_retained_state_per_target",
            "maximum_candidate_regions": DEEP_MAX_CELLS,
            "seconds_per_region": DEEP_SECONDS_PER_CELL,
            "maximum_concurrent_targets": MAX_CONCURRENT_TARGETS,
            "early_stop_rule": "first_independently_confirmed_SAT_model_only",
            "strict_subset_of_complete_256_region_cover": True,
            "all_declared_targets_must_execute": True,
            "independent_confirmation": (
                "standalone_RFC8439_all_eight_blocks_4096_output_bits"
            ),
        },
        "route_if_A268_passes": (
            "generate_four_fresh_targets_freeze_all_orders_then_execute_"
            "ranked_strict_subset_recovery"
        ),
        "route_if_A268_does_not_pass": (
            "do_not_generate_targets_test_local_pairwise_intervention_on_A268_"
            "without_model_refit"
        ),
    }
    return {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "state": "target_route_frozen_while_A268_measurement_is_in_progress_before_any_A268_rank_or_result",
        "anchors": {
            "A267_result_path": str(A267_RESULT.relative_to(ROOT)),
            "A267_result_sha256": A267_RESULT_SHA256,
            "A268_preflight_path": str(A268_PREFLIGHT.relative_to(ROOT)),
            "A268_preflight_sha256": A268_PREFLIGHT_SHA256,
            "A268_protocol_path": str(A268_PROTOCOL.relative_to(ROOT)),
            "A268_protocol_sha256": A268_PROTOCOL_SHA256,
            "frozen_model_sha256": FROZEN_MODEL_SHA256,
        },
        "A267_fixed_route_basis": {
            "outer_holdout_ranks": ranks,
            "top128_count": top128,
            "top128_fraction": top128 / len(ranks),
            "mean_rank": sum(ranks) / len(ranks),
            "mean_log2_rank_bit_gain": a267["evaluation"][
                "mean_log2_rank_bit_gain"
            ],
            "exact_shared_xor_p": a267["evaluation"]["exact_shared_xor_p"],
        },
        "frozen_plan": plan,
        "frozen_plan_sha256": _canonical_sha256(plan),
        "information_boundary": {
            "A268_result_exists_at_freeze": False,
            "A268_scores_ranks_or_XOR_controls_read_at_freeze": False,
            "future_target_generated_at_freeze": False,
            "future_target_secret_or_output_available_at_freeze": False,
            "deep_subset_threshold_selected_from_A267_only": True,
            "future_A268_outcome_can_change_only_route_not_threshold": True,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", action="store_true")
    args = parser.parse_args()
    if not args.freeze:
        print(json.dumps({"attempt_id": ATTEMPT_ID, "output": str(OUTPUT)}, indent=2))
        return
    if OUTPUT.exists():
        raise FileExistsError(f"A269 preflight already exists: {OUTPUT}")
    payload = build_preflight()
    _atomic_json(OUTPUT, payload)
    print(
        json.dumps(
            {
                "output": str(OUTPUT),
                "sha256": _file_sha256(OUTPUT),
                "plan_sha256": payload["frozen_plan_sha256"],
                "top128_count": payload["A267_fixed_route_basis"]["top128_count"],
                "target_count": TARGET_COUNT,
                "deep_max_cells": DEEP_MAX_CELLS,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
