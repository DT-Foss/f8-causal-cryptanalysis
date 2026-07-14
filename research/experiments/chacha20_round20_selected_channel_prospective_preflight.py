#!/usr/bin/env python3
"""Freeze A272's selected A271 channel and a second disjoint key panel."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
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

ATTEMPT_ID = "A272"
A268_PROTOCOL = (
    ROOT
    / "research/configs/chacha20_round20_prospective_trajectory_shape_validation_v1.json"
)
A268_PREFLIGHT = (
    ROOT
    / "research/provenance/chacha20_round20_a268_prospective_trajectory_shape_preflight_v1.json"
)
A268_PREFLIGHT_RUNNER = Path(__file__).with_name(
    "chacha20_round20_prospective_trajectory_shape_preflight.py"
)
A268_RUNNER = Path(__file__).with_name(
    "chacha20_round20_prospective_trajectory_shape_validation.py"
)
A271_PROTOCOL = ROOT / "research/configs/chacha20_round20_signed_channel_ablation_v1.json"
A271_RESULT = ROOT / "research/results/v1/chacha20_round20_signed_channel_ablation_v1.json"
A271_CAUSAL = A271_RESULT.with_suffix(".causal")
CONTRIBUTION_SOURCE = ROOT / "src/arx_carry_leak/trajectory_contribution.py"
RUNNER = Path(__file__).with_name(
    "chacha20_round20_selected_channel_prospective_validation.py"
)
OUTPUT = (
    ROOT
    / "research/configs/chacha20_round20_selected_channel_prospective_validation_v1.json"
)

A268_PROTOCOL_SHA256 = "274cdc5b4e2ef0a4887e67d13106b17b6011d0917d473de158e72cbc55f14221"
A268_PREFLIGHT_SHA256 = "d8fdbb88254b40ea90812c29563baf8f82b693d5fa9980f28a116089abfa9a17"
A271_PROTOCOL_SHA256 = "da026bcb21805add8a32365a7d9e68dbb00ff6a3226fd89f7f45c3cc8f99c920"
A271_RESULT_SHA256 = "2872e2d32b208558fc433b596134fca3f437165c5d604c319b5da07f212d2fa5"
A271_CAUSAL_SHA256 = "30b1360fc04c469fb0864af58d4c1493fba4184a124680a8afafb07a7098c6c5"
SELECTED_VIEW = "ratio_learned_clause_accepted_stage_versus_conflicts::coefficient_positive::direct_additive_contribution"
SELECTED_GROUP = "ratio_learned_clause_accepted_stage_versus_conflicts::coefficient_positive"
DESIGN_SEED = b"F8-Causal-A272-selected-channel-prospective-design-v1"


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


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A272 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _minimum_hamming(values: list[int]) -> int:
    return min(
        (left ^ right).bit_count()
        for index, left in enumerate(values)
        for right in values[index + 1 :]
    )


def _candidate_stream() -> bytes:
    return hashlib.shake_256(DESIGN_SEED + bytes.fromhex(A271_RESULT_SHA256)).digest(8192)


def _prior_levels() -> tuple[set[int], set[int], set[int]]:
    old = _import_path(A268_PREFLIGHT_RUNNER, "a272_a268_preflight")
    preflight = json.loads(A268_PREFLIGHT.read_bytes())
    prefixes = set(old.OLD_PREFIXES) | set(preflight["prospective_design"]["prefixes"])
    suffixes = set(old.OLD_SUFFIXES) | set(preflight["prospective_design"]["suffixes"])
    low20 = {int(row["low20"]) for row in preflight["prospective_design"]["rows"]}
    return prefixes, suffixes, low20


def _prospective_prefixes(prior: set[int]) -> list[int]:
    pool = []
    for value in _candidate_stream():
        if value not in prior and value not in pool and 2 <= value.bit_count() <= 6:
            pool.append(value)
        if len(pool) >= 36:
            break
    for values in itertools.combinations(pool, 5):
        selected = list(values)
        counts = [sum((value >> bit) & 1 for value in selected) for bit in range(8)]
        if all(count in {2, 3} for count in counts) and _minimum_hamming(selected) >= 3:
            return selected
    raise RuntimeError("A272 deterministic prospective prefix search failed")


def _prospective_suffixes(prior: set[int]) -> list[int]:
    stream = _candidate_stream()[1024:]
    candidates = []
    for index in range(0, len(stream) - 2, 3):
        value = int.from_bytes(stream[index : index + 2], "little") & 0xFFF
        if value not in prior and 4 <= value.bit_count() <= 8:
            candidates.append(value)
        if len(candidates) >= 72:
            break
    for left_index, left in enumerate(candidates):
        complement = left ^ 0xFFF
        if complement in prior or not 4 <= complement.bit_count() <= 8:
            continue
        for right in candidates[left_index + 1 :]:
            values = [left, complement, right, right ^ 0xFFF]
            if (
                len(set(values)) == 4
                and not set(values) & prior
                and all(4 <= value.bit_count() <= 8 for value in values)
                and _minimum_hamming(values) >= 6
            ):
                return values
    raise RuntimeError("A272 deterministic prospective suffix search failed")


def prospective_design() -> list[dict[str, Any]]:
    prior_prefixes, prior_suffixes, _ = _prior_levels()
    prefixes = _prospective_prefixes(prior_prefixes)
    suffixes = _prospective_suffixes(prior_suffixes)
    rows = []
    for prefix_index, prefix8 in enumerate(prefixes):
        for suffix_index, suffix12 in enumerate(suffixes):
            low20 = (prefix8 << 12) | suffix12
            rows.append(
                {
                    "label": f"a272_channel_p{prefix_index:02d}_fit_s{suffix_index:02d}",
                    "prefix_split": "second_prospective",
                    "prefix_index": prefix_index,
                    "prefix8": prefix8,
                    "prefix8_binary": f"{prefix8:08b}",
                    "suffix_split": "second_fresh",
                    "suffix_index": suffix_index,
                    "suffix12": suffix12,
                    "low20": low20,
                    "low20_hex": f"{low20:05x}",
                }
            )
    validate_design(rows)
    return rows


def validate_design(rows: list[dict[str, Any]]) -> None:
    prior_prefixes, prior_suffixes, prior_low20 = _prior_levels()
    if len(rows) != 20 or len({row["low20"] for row in rows}) != 20:
        raise RuntimeError("A272 prospective design size differs")
    prefixes = list(dict.fromkeys(int(row["prefix8"]) for row in rows))
    suffixes = list(dict.fromkeys(int(row["suffix12"]) for row in rows))
    if (
        len(prefixes) != 5
        or len(suffixes) != 4
        or set(prefixes) & prior_prefixes
        or set(suffixes) & prior_suffixes
        or {int(row["low20"]) for row in rows} & prior_low20
        or _minimum_hamming(prefixes) < 3
        or _minimum_hamming(suffixes) < 6
        or any(
            sum((value >> bit) & 1 for value in prefixes) not in {2, 3}
            for bit in range(8)
        )
        or any(
            sum((value >> bit) & 1 for value in suffixes) != 2
            for bit in range(12)
        )
    ):
        raise RuntimeError("A272 prospective design separation differs")
    for prefix_index, prefix8 in enumerate(prefixes):
        group = [row for row in rows if row["prefix8"] == prefix8]
        if len(group) != 4 or [row["suffix_index"] for row in group] != list(range(4)):
            raise RuntimeError("A272 prospective group geometry differs")
        for row in group:
            suffix_index = int(row["suffix_index"])
            if (
                row["label"]
                != f"a272_channel_p{prefix_index:02d}_fit_s{suffix_index:02d}"
                or row["prefix8_binary"] != f"{prefix8:08b}"
                or row["low20"] != (prefix8 << 12) | row["suffix12"]
                or row["low20_hex"] != f"{row['low20']:05x}"
            ):
                raise RuntimeError("A272 prospective row identity differs")


def build_protocol() -> dict[str, Any]:
    if OUTPUT.exists():
        raise FileExistsError(f"A272 protocol already exists: {OUTPUT}")
    fixed = {
        A268_PROTOCOL: A268_PROTOCOL_SHA256,
        A268_PREFLIGHT: A268_PREFLIGHT_SHA256,
        A271_PROTOCOL: A271_PROTOCOL_SHA256,
        A271_RESULT: A271_RESULT_SHA256,
        A271_CAUSAL: A271_CAUSAL_SHA256,
    }
    for path, expected in fixed.items():
        if _file_sha256(path) != expected:
            raise RuntimeError(f"A272 anchored predecessor differs: {path.name}")
    a271 = json.loads(A271_RESULT.read_bytes())
    a268_preflight = json.loads(A268_PREFLIGHT.read_bytes())
    if (
        a271.get("headline", {}).get("best_view") != SELECTED_VIEW
        or a271.get("headline", {}).get("best_view_bit_gain") != 1.216796267632116
        or a271.get("headline", {}).get("best_view_exact_unadjusted_shared_xor_p")
        != 0.03125
        or a271.get("retention_gate", {}).get("passed") is not False
    ):
        raise RuntimeError("A272 selected A271 hypothesis differs")
    model = a268_preflight["frozen_model"]["model"]
    groups = signed_semantic_groups(model["feature_names"], model["coefficients"])
    selected_indices = list(groups[SELECTED_GROUP])
    if selected_indices != [502, 504, 505, 508, 509, 510, 511, 514]:
        raise RuntimeError("A272 selected feature group differs")
    design = prospective_design()
    anchors = {
        "A268_protocol_path": str(A268_PROTOCOL.relative_to(ROOT)),
        "A268_protocol_sha256": A268_PROTOCOL_SHA256,
        "A268_preflight_path": str(A268_PREFLIGHT.relative_to(ROOT)),
        "A268_preflight_sha256": A268_PREFLIGHT_SHA256,
        "A268_preflight_runner_path": str(A268_PREFLIGHT_RUNNER.relative_to(ROOT)),
        "A268_preflight_runner_sha256": _file_sha256(A268_PREFLIGHT_RUNNER),
        "A268_runner_path": str(A268_RUNNER.relative_to(ROOT)),
        "A268_runner_sha256": _file_sha256(A268_RUNNER),
        "A271_protocol_path": str(A271_PROTOCOL.relative_to(ROOT)),
        "A271_protocol_sha256": A271_PROTOCOL_SHA256,
        "A271_result_path": str(A271_RESULT.relative_to(ROOT)),
        "A271_result_sha256": A271_RESULT_SHA256,
        "A271_causal_path": str(A271_CAUSAL.relative_to(ROOT)),
        "A271_causal_sha256": A271_CAUSAL_SHA256,
        "contribution_source_path": str(CONTRIBUTION_SOURCE.relative_to(ROOT)),
        "contribution_source_sha256": _file_sha256(CONTRIBUTION_SOURCE),
        "runner_path": str(RUNNER.relative_to(ROOT)),
        "runner_sha256": _file_sha256(RUNNER),
    }
    return {
        "schema": "chacha20-round20-selected-channel-prospective-validation-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_after_A271_hypothesis_selection_and_second_disjoint_key_design_before_any_A272_target_CNF_solver_measurement_score_or_rank",
        "anchors": anchors,
        "selected_hypothesis": {
            "source_attempt": "A271",
            "selection_status": "posthoc_hypothesis_from_A271_then_prospectively_frozen_for_A272",
            "view_name": SELECTED_VIEW,
            "group_name": SELECTED_GROUP,
            "mode": "direct_additive_contribution",
            "feature_indices": selected_indices,
            "feature_names": [model["feature_names"][index] for index in selected_indices],
            "model_sha256": a268_preflight["frozen_model"]["model_sha256"],
            "model_refit_or_coefficient_update_permitted": False,
        },
        "prospective_design": {
            "seed_ascii": DESIGN_SEED.decode(),
            "seed_sha256": _sha256(DESIGN_SEED),
            "rows": design,
            "rows_sha256": _canonical_sha256(design),
            "prefixes": list(dict.fromkeys(row["prefix8"] for row in design)),
            "suffixes": list(dict.fromkeys(row["suffix12"] for row in design)),
            "disjoint_from_A220_A267_training_and_A268_validation_levels": True,
        },
        "measurement": {
            "fresh_solver_instance_per_candidate": True,
            "identical_unsolved_base_snapshot_per_key": True,
            "candidate_order": "numeric_0_through_255",
            "conflict_horizons": [1, 2, 4, 8],
            "watchdog_seconds_per_stage": 2.0,
            "maximum_concurrent_key_processes": 2,
            "early_stop_permitted": False,
            "bounded_variable_addition_enabled": False,
            "maximum_captured_learned_clause_size": 64,
            "all_twenty_complete_candidate_covers_required": True,
        },
        "controls": {
            "shared_XOR_offsets": 256,
            "statistic": "mean_log2_descending_midrank",
            "view_count": 1,
            "prospective_multiple_selection_adjustment_required": False,
        },
        "retention_gate": {
            "maximum_exact_shared_xor_p": 0.05,
            "minimum_mean_log2_rank_bit_gain": 0.0,
            "minimum_positive_prefix_groups": 3,
            "next_if_passed": "frozen_selected_channel_candidate_order_on_separate_unknown_target",
            "next_if_not_passed": "ordered_clause_event_timing_reader_without_model_refit",
        },
        "information_boundary": {
            "A271_outcome_known_and_best_view_selected_before_A272_freeze": True,
            "A272_design_fixed_after_selection_but_before_any_A272_target": True,
            "any_A272_target_block_or_CNF_generated_before_freeze": False,
            "any_A272_solver_measurement_started_before_freeze": False,
            "any_A272_selected_channel_score_rank_or_XOR_control_known_before_freeze": False,
            "A272_true_prefix_used_for_feature_construction_or_scoring": False,
            "model_refit_or_coefficient_update_permitted": False,
            "early_stop_permitted": False,
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
                "design_sha256": protocol["prospective_design"]["rows_sha256"],
                "prefixes": protocol["prospective_design"]["prefixes"],
                "suffixes": protocol["prospective_design"]["suffixes"],
                "selected_view": protocol["selected_hypothesis"]["view_name"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
