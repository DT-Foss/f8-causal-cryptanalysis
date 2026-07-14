#!/usr/bin/env python3
"""Synthetic A266 exact learned-clause frequency preflight."""

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

from arx_carry_leak.chacha20_clause_frequency import (  # noqa: E402
    HORIZONS,
    build_clause_frequency_table,
)
from arx_carry_leak.chacha20_continuous_flow import (  # noqa: E402
    ContinuousFlowTable,
    nested_continuous_flow_evaluate,
)

ATTEMPT_ID = "A266"
SCHEMA = "chacha20-round20-clause-frequency-preflight-v1"
OUTPUT = (
    ROOT / "research/provenance/chacha20_round20_a266_clause_frequency_preflight_v1.json"
)


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


def _synthetic_measurement() -> dict[str, Any]:
    assumptions = list(range(91001, 91009))
    stages = []
    for candidate in range(256):
        for horizon in HORIZONS:
            clauses = [
                [assumptions[0], 120 + horizon, -(300 + candidate % 7)]
                for _ in range(1 + candidate % 4)
            ]
            stages.append(
                {
                    "prefix8": f"{candidate:08b}",
                    "horizon": horizon,
                    "assumptions": [
                        value if candidate & (1 << bit) else -value
                        for bit, value in enumerate(assumptions)
                    ],
                    "learned_clauses_stage": clauses,
                }
            )
    return {
        "label": "synthetic_p00_fit_s00",
        "known_key_design": {"prefix8": 37},
        "run": {
            "learned_clause_identity_complete": True,
            "bounded_variable_addition_enabled": False,
            "stages": stages,
        },
    }


def _synthetic_transfer_tables() -> list[ContinuousFlowTable]:
    tables = []
    prefixes = [19, 67, 109, 173, 227]
    for group, prefix in enumerate(prefixes):
        for seed in range(4):
            recurrent = np.ones(256, dtype=np.int32)
            recurrent[prefix] = 13 + seed
            inverse = np.full(256, 9, dtype=np.int32)
            inverse[prefix] = 0
            nuisance = (np.arange(256, dtype=np.int32) * (seed + 3) + group) % 11
            tables.append(
                ContinuousFlowTable(
                    label=f"synthetic_p{group:02d}_fit_s{seed:02d}",
                    true_prefix=prefix,
                    feature_counts={
                        "all_signed_variable|recurrent": recurrent,
                        "all_pair|inverse": inverse,
                        "all_clause_length|nuisance": nuisance,
                    },
                )
            )
    return tables


def build_preflight() -> dict[str, Any]:
    table, builder = build_clause_frequency_table(_synthetic_measurement())
    evaluation = nested_continuous_flow_evaluate(
        _synthetic_transfer_tables(),
        views=("linear_l1", "log1p_l1", "sqrt_l1"),
        maximum_features_grid=(2, 3),
        ridge_grid=(0.25, 1.0),
    )
    if (
        evaluation["mean_log2_rank"] != 0.0
        or evaluation["outer_prefix_folds_with_positive_bit_gain"] != 5
        or evaluation["exact_shared_xor_p"] != 1.0 / 256.0
    ):
        raise RuntimeError("A266 synthetic transfer preflight failed")
    return {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "state": "synthetic_frequency_builder_and_nested_transfer_preflight_completed_before_any_A251_frequency_table_or_A266_model_fit",
        "synthetic_builder": builder,
        "synthetic_retained_feature_count": len(table.feature_counts),
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
            "used_any_R20_learned_clause_or_candidate_value": False,
            "used_any_A251_true_prefix": False,
            "used_only_synthetic_clause_payloads_and_synthetic_transfer_tables": True,
            "any_A266_operator_outcome_known": False,
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
