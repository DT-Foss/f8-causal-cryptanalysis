#!/usr/bin/env python3
"""Fresh seven-challenge W32 H16 top-64 prospective recovery batch."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import secrets
import sys
import tempfile
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


A229 = _import_sibling(
    "chacha20_round20_w32_top64_batch_recovery.py",
    "a233_a229_mechanism_anchor",
)
MULTIHORIZON = _import_sibling(
    "chacha20_retained_multihorizon.py",
    "a233_multihorizon_anchor",
)
A223 = A229.A223
A227 = A229.A227
A184 = A229.A184

ATTEMPT_ID = "R20-A233-W32-H16-TOP64-PROSPECTIVE-V1"
PROTOCOL_SCHEMA = "chacha20-round20-w32-h16-top64-protocol-v1"
PREFLIGHT_SCHEMA = "chacha20-round20-w32-h16-top64-preflight-v1"
RESULT_SCHEMA = "chacha20-round20-w32-h16-top64-result-v1"

A232_SOURCE = Path(__file__).with_name("chacha20_round20_a231_tieaware_read.py")
A232_RESULT = (
    RESEARCH / "results" / "v1" / "chacha20_round20_a231_tieaware_read_v1.json"
)
A231_RESULT = (
    RESEARCH
    / "results"
    / "v1"
    / "chacha20_round20_a229_multihorizon_replay_v1.json"
)
PROTOCOL_PATH = RESEARCH / "configs" / "chacha20_round20_w32_h16_top64_v1.json"
PREFLIGHT_PATH = (
    RESEARCH / "results" / "v1" / "chacha20_round20_w32_h16_top64_preflight_v1.json"
)
RESULT_PATH = (
    RESEARCH / "results" / "v1" / "chacha20_round20_w32_h16_top64_v1.json"
)
REPORT_PATH = (
    RESEARCH / "reports" / "CAUSAL_CHACHA20_ROUND20_W32_H16_TOP64_V1.md"
)
ARTIFACT_DIR = RESEARCH / "artifacts" / "a233_w32_h16_top64_v1"
METAL_BUILD_DIR = ARTIFACT_DIR / "metal_build"

WIDTH = 32
CHALLENGE_COUNT = 7
TOP_K = 64
FREE_BITS_PER_CELL = 24
CANDIDATES_PER_CELL = 1 << FREE_BITS_PER_CELL
LIMITED_CANDIDATES_PER_CHALLENGE = TOP_K * CANDIDATES_PER_CELL
FULL_CANDIDATES_PER_CHALLENGE = 1 << WIDTH
SEARCH_REDUCTION_FACTOR = (
    FULL_CANDIDATES_PER_CHALLENGE // LIMITED_CANDIDATES_PER_CHALLENGE
)
HORIZON = 16
WATCHDOG_SECONDS = 30.0
MAX_WORKERS = 4
NULL_SELECTION_PROBABILITY = TOP_K / 256
SCORE_NAME = "H16_cumulative_search_propagations_ascending"
SCORE_DEFINITION = "metrics_cell_cumulative_delta[search_propagations] at one-shot conflict horizon 16"


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
        ).encode()
    )


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def freeze() -> dict[str, Any]:
    if PROTOCOL_PATH.exists():
        raise RuntimeError(f"A233 protocol already exists: {PROTOCOL_PATH}")
    a232 = json.loads(A232_RESULT.read_bytes())
    best = a232.get("evaluation", {}).get("best_global_reader", {})
    if (
        a232.get("schema") != "chacha20-round20-a231-tieaware-read-v1"
        or best.get("reader")
        != "one_shot_h16_wd30.h16.cumulative_search_propagations.asc"
        or best.get("ranks") != [64, 4, 136, 188, 38, 17, 37]
    ):
        raise RuntimeError("A233 A232 calibration identity gate failed")
    challenges = [
        A227._build_challenge(
            key_bytes=secrets.token_bytes(32),
            counter_nonce_bytes=secrets.token_bytes(16),
            challenge_id=secrets.token_hex(16),
        )
        for _ in range(CHALLENGE_COUNT)
    ]
    payload = {
        "schema": PROTOCOL_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_before_any_A233_formula_export_trajectory_score_or_candidate_execution",
        "runner_sha256": _file_sha256(Path(__file__)),
        "anchors": {
            "A232_source_sha256": _file_sha256(A232_SOURCE),
            "A232_result_sha256": _file_sha256(A232_RESULT),
            "A231_raw_result_sha256": _file_sha256(A231_RESULT),
            "A223_runner_sha256": _file_sha256(Path(A223.__file__)),
            "multihorizon_wrapper_sha256": _file_sha256(MULTIHORIZON.WRAPPER),
            "multihorizon_source_sha256": _file_sha256(MULTIHORIZON.SOURCE),
            "Metal_native_source_sha256": A184.NATIVE_SOURCE_SHA256,
        },
        "challenges": [
            {
                "index": index,
                "public_challenge": challenge,
                "public_challenge_sha256": _canonical_sha256(challenge),
            }
            for index, challenge in enumerate(challenges)
        ],
        "reader_plan": {
            "trajectory": "complete_reflected_gray8_retained_one_shot_h16",
            "conflict_horizon": HORIZON,
            "watchdog_seconds_per_cell": WATCHDOG_SECONDS,
            "maximum_parallel_helpers": MAX_WORKERS,
            "score_name": SCORE_NAME,
            "score_definition": SCORE_DEFINITION,
            "sort_key": "ascending_search_propagations_then_ascending_prefix8",
            "selected_cells_per_challenge": TOP_K,
            "candidate_suffix_bits_per_selected_cell": FREE_BITS_PER_CELL,
            "candidate_count_per_challenge": LIMITED_CANDIDATES_PER_CHALLENGE,
            "full_domain_candidate_count_per_challenge": FULL_CANDIDATES_PER_CHALLENGE,
            "candidate_search_reduction_factor": SEARCH_REDUCTION_FACTOR,
            "complete_selected_regions_required": True,
            "early_stop_permitted": False,
        },
        "aggregate_test": {
            "challenge_count": CHALLENGE_COUNT,
            "uniform_null_selection_probability_per_challenge": NULL_SELECTION_PROBABILITY,
            "success_count_and_exact_binomial_upper_tail_reported": True,
        },
        "information_boundary": {
            "unknown_assignments_stored_in_protocol_runner_or_helper": False,
            "unknown_assignments_available_to_run_process": False,
            "target_prefixes_available_to_scores_or_top64_selection": False,
            "full_domain_Metal_labels_permitted_before_limited_searches": False,
            "outcomes_available_when_protocol_frozen": False,
            "score_direction_horizon_or_threshold_may_change_between_challenges": False,
        },
    }
    _atomic_json(PROTOCOL_PATH, payload)
    return {
        "protocol": str(PROTOCOL_PATH),
        "protocol_sha256": _file_sha256(PROTOCOL_PATH),
        "challenge_ids": [challenge["challenge_id"] for challenge in challenges],
    }


def _load_protocol() -> dict[str, Any]:
    protocol = json.loads(PROTOCOL_PATH.read_bytes())
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("runner_sha256") != _file_sha256(Path(__file__))
        or len(protocol.get("challenges", [])) != CHALLENGE_COUNT
        or protocol.get("reader_plan", {}).get("score_definition") != SCORE_DEFINITION
        or protocol.get("reader_plan", {}).get("selected_cells_per_challenge")
        != TOP_K
    ):
        raise RuntimeError("A233 frozen protocol identity gate failed")
    expected_anchors = {
        "A232_source_sha256": _file_sha256(A232_SOURCE),
        "A232_result_sha256": _file_sha256(A232_RESULT),
        "A231_raw_result_sha256": _file_sha256(A231_RESULT),
        "A223_runner_sha256": _file_sha256(Path(A223.__file__)),
        "multihorizon_wrapper_sha256": _file_sha256(MULTIHORIZON.WRAPPER),
        "multihorizon_source_sha256": _file_sha256(MULTIHORIZON.SOURCE),
        "Metal_native_source_sha256": A184.NATIVE_SOURCE_SHA256,
    }
    if protocol.get("anchors") != expected_anchors:
        raise RuntimeError("A233 anchor gate failed")
    for index, row in enumerate(protocol["challenges"]):
        challenge = row["public_challenge"]
        A223._validate_challenge(challenge, width=WIDTH)
        if (
            row.get("index") != index
            or row.get("public_challenge_sha256") != _canonical_sha256(challenge)
        ):
            raise RuntimeError("A233 challenge identity gate failed")
    return protocol


def _challenge_dir(index: int) -> Path:
    return ARTIFACT_DIR / f"challenge_{index:02d}"


def _prepare_preflight(
    protocol: dict[str, Any], config: dict[str, Any]
) -> dict[str, Any]:
    if PREFLIGHT_PATH.exists():
        preflight = json.loads(PREFLIGHT_PATH.read_bytes())
        if (
            preflight.get("schema") != PREFLIGHT_SCHEMA
            or preflight.get("protocol_sha256") != _file_sha256(PROTOCOL_PATH)
            or preflight.get("runner_sha256") != _file_sha256(Path(__file__))
            or len(preflight.get("challenge_preflights", [])) != CHALLENGE_COUNT
        ):
            raise RuntimeError("A233 retained preflight gate failed")
        helper = Path(preflight["native_helper"]["binary_path"])
        if _file_sha256(helper) != preflight["native_helper"]["binary_sha256"]:
            raise RuntimeError("A233 retained helper gate failed")
        for row in preflight["challenge_preflights"]:
            cnf = ROOT / row["structural_CNF"]["artifact"]
            if _file_sha256(cnf) != row["structural_CNF"]["transformed_sha256"]:
                raise RuntimeError("A233 retained CNF gate failed")
        return preflight

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="a233-w32-h16-preflight-") as raw_directory:
        temporary_root = Path(raw_directory)
        contexts = []
        directories = []
        for index, row in enumerate(protocol["challenges"]):
            directory = temporary_root / f"challenge_{index:02d}"
            directory.mkdir()
            directories.append(directory)
            contexts.append(
                A223._base_context(
                    width=WIDTH,
                    challenge=row["public_challenge"],
                    config=config,
                    directory=directory,
                )
            )
        dimensions = list(range(-1, math.ceil(math.log2(WIDTH))))
        tasks = [
            (index, dimension)
            for index in range(CHALLENGE_COUNT)
            for dimension in dimensions
        ]

        def probe(item: tuple[int, int]) -> tuple[int, int, list[int], dict[str, Any]]:
            index, dimension = item
            _, observed_dimension, units, observation = A223._coordinate_probe(
                context=contexts[index],
                dimension=dimension,
                config=config,
                directory=directories[index],
            )
            return index, observed_dimension, units, observation

        with ThreadPoolExecutor(max_workers=6) as executor:
            probe_rows = list(executor.map(probe, tasks))
        challenge_preflights = []
        for index in range(CHALLENGE_COUNT):
            rows = [
                (dimension, units)
                for row_index, dimension, units, _ in probe_rows
                if row_index == index
            ]
            one_literals = A223._decode_mapping(rows, width=WIDTH)
            output_dir = _challenge_dir(index)
            output_dir.mkdir(parents=True, exist_ok=True)
            structural = A223._build_structural_cnf(
                context=contexts[index],
                source_one_literals=one_literals,
                output=output_dir / "shared_b8_bfs_far.cnf",
            )
            challenge_preflights.append(
                {
                    "index": index,
                    "source_formula_sha256": contexts[index]["formula_sha256"],
                    "source_formula_bytes": contexts[index]["formula_bytes"],
                    "mapping_dimensions": dimensions,
                    "mapping_probe_rows": [
                        observation
                        for row_index, _, _, observation in probe_rows
                        if row_index == index
                    ],
                    "source_one_literals_bit0_upward": one_literals,
                    "structural_CNF": structural,
                }
            )
        native_helper = MULTIHORIZON.compile_helper()
    preflight = {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "state": "frozen_after_all_seven_CNF_mappings_and_helper_compile_before_any_H16_trajectory",
        "protocol_sha256": _file_sha256(PROTOCOL_PATH),
        "runner_sha256": _file_sha256(Path(__file__)),
        "native_helper": native_helper,
        "challenge_preflights": challenge_preflights,
        "trajectory_execution_started": False,
        "top64_selected": False,
        "Metal_candidate_execution_started": False,
    }
    _atomic_json(PREFLIGHT_PATH, preflight)
    return preflight


def _mapping20(structural: dict[str, Any]) -> list[int]:
    model = structural["transformed_model_one_literals_bit0_upward"]
    prefix = structural["transformed_prefix_one_literals_high_to_low"]
    if len(model) != 32 or len(prefix) != 8:
        raise RuntimeError("A233 requires a W32 mapping")
    mapping = list(model[:12]) + [0] * 8
    for index, literal in enumerate(prefix):
        mapping[19 - index] = literal
    if len({abs(value) for value in mapping}) != 20:
        raise RuntimeError("A233 compatible mapping projection is not bijective")
    return mapping


def _trajectory_artifact(index: int) -> Path:
    return _challenge_dir(index) / "h16_trajectory.json"


def _run_trajectories(preflight: dict[str, Any]) -> list[dict[str, Any]]:
    helper = Path(preflight["native_helper"]["binary_path"])
    order = A223._gray8_order()

    def run(row: dict[str, Any]) -> dict[str, Any]:
        index = int(row["index"])
        mode = f"A233_h16_challenge_{index:02d}"
        artifact = _trajectory_artifact(index)
        if artifact.exists():
            retained = json.loads(artifact.read_bytes())
            if (
                retained.get("index") != index
                or retained.get("mode") != mode
                or retained.get("conflict_horizons") != [HORIZON]
                or retained.get("watchdog_seconds_per_stage") != WATCHDOG_SECONDS
                or retained.get("all_watchdogs_clear") is not True
                or retained.get("summary", {}).get("cells") != 256
            ):
                raise RuntimeError("A233 retained trajectory identity differs")
            return retained
        result = MULTIHORIZON.run_multihorizon(
            helper=helper,
            cnf=ROOT / row["structural_CNF"]["artifact"],
            mode=mode,
            order=order,
            key_one_literals_bit0_through_bit19=_mapping20(row["structural_CNF"]),
            conflict_horizons=[HORIZON],
            watchdog_seconds=WATCHDOG_SECONDS,
            external_timeout_seconds=300.0,
        )
        retained = {"index": index, **result}
        _atomic_json(artifact, retained)
        return retained

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        rows = list(executor.map(run, preflight["challenge_preflights"]))
    rows.sort(key=lambda row: row["index"])
    return rows


def _ranked_cells(trajectory: dict[str, Any]) -> list[dict[str, Any]]:
    stages = [stage for stage in trajectory["stages"] if stage["horizon"] == HORIZON]
    if len(stages) != 256:
        raise RuntimeError("A233 H16 stage matrix is incomplete")
    rows = [
        {
            "prefix8": stage["prefix8"],
            "cell_index": int(stage["cell_index"]),
            "H16_cumulative_search_propagations": int(
                stage["metrics_cell_cumulative_delta"][2]
            ),
            "H16_conflicts": int(stage["metrics_cell_cumulative_delta"][0]),
            "H16_decisions": int(stage["metrics_cell_cumulative_delta"][1]),
            "H16_elapsed_seconds": float(stage["elapsed_seconds"]),
            "H16_status": stage["status"],
        }
        for stage in stages
    ]
    return sorted(
        rows,
        key=lambda row: (row["H16_cumulative_search_propagations"], row["prefix8"]),
    )


def _binomial_upper_tail(successes: int) -> float:
    return sum(
        math.comb(CHALLENGE_COUNT, count)
        * NULL_SELECTION_PROBABILITY**count
        * (1.0 - NULL_SELECTION_PROBABILITY) ** (CHALLENGE_COUNT - count)
        for count in range(successes, CHALLENGE_COUNT + 1)
    )


def _write_report(payload: dict[str, Any]) -> None:
    aggregate = payload["aggregate"]
    lines = [
        "# A233 — Fresh W32 H16 top-64 prospective recovery",
        "",
        f"- Recoveries: **{aggregate['success_count']} / {CHALLENGE_COUNT}**",
        f"- Candidate-search reduction per challenge: **{SEARCH_REDUCTION_FACTOR}x**",
        f"- Uniform-null binomial upper tail: `{aggregate['uniform_null_binomial_upper_tail']:.9g}`",
        "",
        "| Challenge | Success | Recovered H16 rank |",
        "|---:|---:|---:|",
    ]
    for row in payload["challenge_results"]:
        lines.append(
            f"| {row['index']} | {row['limited_Metal_search']['prospective_recovery_success']} | "
            f"{row['recovered_prefix_rank'] if row['recovered_prefix_rank'] is not None else '-'} |"
        )
    lines.append("")
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = REPORT_PATH.with_name(f".{REPORT_PATH.name}.tmp")
    temporary.write_text("\n".join(lines))
    temporary.replace(REPORT_PATH)


def run() -> dict[str, Any]:
    if RESULT_PATH.exists():
        raise RuntimeError(f"A233 result already exists: {RESULT_PATH}")
    protocol = _load_protocol()
    preflight = _prepare_preflight(protocol, A223._load_config())
    trajectories = _run_trajectories(preflight)
    ranked_and_selected = []
    for trajectory in trajectories:
        ranked = _ranked_cells(trajectory)
        ranked_and_selected.append((ranked, ranked[:TOP_K]))
    executable, native_build = A184._A181._compile_native(METAL_BUILD_DIR, "swiftc")
    challenge_results = []
    for index, (trajectory, protocol_row, ranking) in enumerate(
        zip(
            trajectories,
            protocol["challenges"],
            ranked_and_selected,
            strict=True,
        )
    ):
        ranked, selected = ranking
        limited = A229._limited_search_one(
            executable=executable,
            challenge=protocol_row["public_challenge"],
            selected=selected,
        )
        recovered_rank = None
        if len(limited["exact_confirmed_matches"]) == 1:
            prefix = limited["exact_confirmed_matches"][0]["prefix8"]
            recovered_rank = next(
                rank
                for rank, row in enumerate(ranked, start=1)
                if row["prefix8"] == prefix
            )
        challenge_results.append(
            {
                "index": index,
                "public_challenge_sha256": protocol_row["public_challenge_sha256"],
                "trajectory": trajectory,
                "reader": {
                    "score_name": SCORE_NAME,
                    "score_definition": SCORE_DEFINITION,
                    "ranked_cells": ranked,
                    "selected_top64": selected,
                    "target_label_available_at_selection": False,
                },
                "limited_Metal_search": limited,
                "recovered_prefix_rank": recovered_rank,
            }
        )
    successes = sum(
        row["limited_Metal_search"]["prospective_recovery_success"]
        for row in challenge_results
    )
    payload = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "SEVEN_CHALLENGE_PROSPECTIVE_FULLROUND_W32_H16_TOP64_RECOVERY",
        "anchors": {
            "protocol_sha256": _file_sha256(PROTOCOL_PATH),
            "preflight_sha256": _file_sha256(PREFLIGHT_PATH),
            "runner_sha256": _file_sha256(Path(__file__)),
        },
        "information_boundary": protocol["information_boundary"],
        "native_build": native_build,
        "challenge_results": challenge_results,
        "aggregate": {
            "challenge_count": CHALLENGE_COUNT,
            "success_count": successes,
            "failure_count": CHALLENGE_COUNT - successes,
            "success_rate": successes / CHALLENGE_COUNT,
            "uniform_null_selection_probability_per_challenge": NULL_SELECTION_PROBABILITY,
            "uniform_null_binomial_upper_tail": _binomial_upper_tail(successes),
            "candidate_search_reduction_factor_per_challenge": SEARCH_REDUCTION_FACTOR,
            "logical_candidate_count_per_challenge": LIMITED_CANDIDATES_PER_CHALLENGE,
            "full_domain_candidate_count_per_challenge": FULL_CANDIDATES_PER_CHALLENGE,
            "all_selected_regions_completed_without_early_stop": all(
                row["limited_Metal_search"]["complete_selected_regions_executed"]
                and not row["limited_Metal_search"]["early_stop_used"]
                for row in challenge_results
            ),
        },
    }
    _atomic_json(RESULT_PATH, payload)
    _write_report(payload)
    return payload


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--freeze", action="store_true")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args(argv)
    if args.freeze == args.run:
        parser.error("select exactly one of --freeze or --run")
    value = freeze() if args.freeze else run()["aggregate"]
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
