#!/usr/bin/env python3
"""Synthetic A267 solver-native trajectory-shape preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.solver_trajectory_shape import (  # noqa: E402
    BASE_FEATURE_NAMES,
    FEATURE_NAMES,
    TrajectoryShapeTable,
    nested_trajectory_shape_evaluate,
)

ATTEMPT_ID = "A267"
SCHEMA = "chacha20-round20-trajectory-shape-preflight-v1"
OUTPUT = ROOT / "research/provenance/chacha20_round20_a267_trajectory_shape_preflight_v1.json"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(
        value,
        indent=2,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _synthetic_tables() -> list[TrajectoryShapeTable]:
    tables = []
    prefixes = [23, 71, 107, 181, 233]
    signal_indices = (
        FEATURE_NAMES.index("conflicts__profile_h1__raw_z"),
        FEATURE_NAMES.index("decisions__first_difference_1_2__xor_laplacian"),
    )
    for group, prefix in enumerate(prefixes):
        for seed in range(4):
            matrix = np.zeros((256, len(FEATURE_NAMES)), dtype=np.float64)
            matrix[prefix, signal_indices[0]] = 8.0 + seed
            matrix[prefix, signal_indices[1]] = -6.0 - seed
            matrix[:, (signal_indices[1] + 7) % len(FEATURE_NAMES)] = (
                np.arange(256, dtype=np.float64) + group + seed
            ) % 5
            tables.append(
                TrajectoryShapeTable(
                    label=f"synthetic_p{group:02d}_fit_s{seed:02d}",
                    true_prefix=prefix,
                    feature_names=FEATURE_NAMES,
                    matrix=matrix,
                )
            )
    return tables


def build_preflight() -> dict[str, Any]:
    evaluation = nested_trajectory_shape_evaluate(
        _synthetic_tables(), ridge_lambdas=(0.01, 0.1, 1.0, 10.0)
    )
    if (
        evaluation["mean_log2_rank"] != 0.0
        or evaluation["outer_prefix_folds_with_positive_bit_gain"] != 5
        or evaluation["exact_shared_xor_p"] != 1.0 / 256.0
    ):
        raise RuntimeError("A267 synthetic trajectory-shape preflight failed")
    return {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "state": "synthetic_scale_free_trajectory_shape_and_nested_transfer_preflight_completed_before_any_A251_shape_table_or_A267_model_fit",
        "geometry": {
            "base_feature_count": len(BASE_FEATURE_NAMES),
            "orbit_feature_count": len(FEATURE_NAMES),
            "known_key_count": 20,
            "candidates_per_key": 256,
            "ridge_lambdas": [0.01, 0.1, 1.0, 10.0],
        },
        "synthetic_nested_transfer": {
            "mean_log2_rank": evaluation["mean_log2_rank"],
            "mean_log2_rank_bit_gain": evaluation[
                "mean_log2_rank_bit_gain"
            ],
            "positive_outer_prefix_folds": evaluation[
                "outer_prefix_folds_with_positive_bit_gain"
            ],
            "exact_shared_xor_p": evaluation["exact_shared_xor_p"],
        },
        "information_boundary": {
            "used_any_A251_measurement_shard": False,
            "used_any_R20_solver_trajectory_value": False,
            "used_any_A251_true_prefix": False,
            "used_only_synthetic_shape_tables": True,
            "any_A267_operator_outcome_known": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"attempt_id": ATTEMPT_ID, "output": str(OUTPUT)}, indent=2))
        return
    payload = build_preflight()
    _atomic_json(OUTPUT, payload)
    print(
        json.dumps(
            {"output": str(OUTPUT), "sha256": _file_sha256(OUTPUT)},
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
