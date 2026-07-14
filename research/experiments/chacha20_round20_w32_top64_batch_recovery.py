#!/usr/bin/env python3
"""Seven-challenge prospective W32 top-64 recovery batch."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import secrets
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import numpy as np

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


A227 = _import_sibling(
    "chacha20_round20_w32_top4_prospective_recovery.py",
    "a229_a227_mechanism_anchor",
)
A223 = A227.A223
A184 = A227.A184
A119 = A227.A119

ATTEMPT_ID = "R20-A229-W32-TOP64-BATCH-RECOVERY-V1"
PROTOCOL_SCHEMA = "chacha20-round20-w32-top64-batch-protocol-v1"
PREFLIGHT_SCHEMA = "chacha20-round20-w32-top64-batch-preflight-v1"
RESULT_SCHEMA = "chacha20-round20-w32-top64-batch-result-v1"

PROTOCOL_PATH = RESEARCH / "configs" / "chacha20_round20_w32_top64_batch_v1.json"
PREFLIGHT_PATH = RESEARCH / "results" / "v1" / "chacha20_round20_w32_top64_batch_preflight_v1.json"
RESULT_PATH = RESEARCH / "results" / "v1" / "chacha20_round20_w32_top64_batch_v1.json"
REPORT_PATH = RESEARCH / "reports" / "CAUSAL_CHACHA20_ROUND20_W32_TOP64_BATCH_RECOVERY_V1.md"
ARTIFACT_DIR = RESEARCH / "artifacts" / "a229_w32_top64_batch_v1"
HELPER_PATH = ARTIFACT_DIR / "cadical_capacity_moonshot_a229"
METAL_BUILD_DIR = ARTIFACT_DIR / "metal_build"

WIDTH = 32
CHALLENGE_COUNT = 7
TOP_K = 64
FREE_BITS_PER_CELL = 24
CANDIDATES_PER_CELL = 1 << FREE_BITS_PER_CELL
LIMITED_CANDIDATES_PER_CHALLENGE = TOP_K * CANDIDATES_PER_CELL
FULL_CANDIDATES_PER_CHALLENGE = 1 << WIDTH
SEARCH_REDUCTION_FACTOR = FULL_CANDIDATES_PER_CHALLENGE // LIMITED_CANDIDATES_PER_CHALLENGE
SOLVER_SECONDS_PER_CELL = 10
SCORE_NAME = A227.SCORE_NAME
SCORE_DEFINITION = A227.SCORE_DEFINITION
NULL_SELECTION_PROBABILITY = TOP_K / 256


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
        raise RuntimeError(f"A229 protocol already exists: {PROTOCOL_PATH}")
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
        "protocol_state": "frozen_before_any_A229_formula_export_trajectory_or_candidate_execution",
        "runner_sha256": _file_sha256(Path(__file__)),
        "anchors": {
            "A224_source_sha256": _file_sha256(Path(A227.A224.__file__)),
            "A224_result_sha256": _file_sha256(A227.A224.DEFAULT_RESULT_PATH),
            "A227_protocol_sha256": _file_sha256(A227.PROTOCOL_PATH),
            "A227_result_sha256": _file_sha256(A227.RESULT_PATH),
            "A228_result_sha256": _file_sha256(
                RESEARCH / "results" / "v1" / "chacha20_round20_a227_postbarrier_label_v1.json"
            ),
            "A223_runner_sha256": _file_sha256(Path(A223.__file__)),
            "A223_helper_source_sha256": _file_sha256(A223.HELPER_SOURCE),
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
            "trajectory_per_challenge": "complete_reflected_gray8_order_retained_CaDiCaL_state",
            "seconds_per_cell": SOLVER_SECONDS_PER_CELL,
            "cells_per_challenge": 256,
            "concurrent_challenge_trajectories": CHALLENGE_COUNT,
            "score_name": SCORE_NAME,
            "score_definition": SCORE_DEFINITION,
            "sort_key": "descending_constraint_coherence_then_ascending_prefix8",
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
            "score_or_threshold_may_change_between_challenges": False,
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
        or protocol.get("reader_plan", {}).get("selected_cells_per_challenge") != TOP_K
    ):
        raise RuntimeError("A229 frozen protocol identity gate failed")
    for index, row in enumerate(protocol["challenges"]):
        challenge = row["public_challenge"]
        A223._validate_challenge(challenge, width=WIDTH)
        if row.get("index") != index or row.get("public_challenge_sha256") != _canonical_sha256(challenge):
            raise RuntimeError("A229 challenge identity gate failed")
    anchors = protocol["anchors"]
    expected = {
        "A224_source_sha256": _file_sha256(Path(A227.A224.__file__)),
        "A224_result_sha256": _file_sha256(A227.A224.DEFAULT_RESULT_PATH),
        "A227_protocol_sha256": _file_sha256(A227.PROTOCOL_PATH),
        "A227_result_sha256": _file_sha256(A227.RESULT_PATH),
        "A228_result_sha256": _file_sha256(
            RESEARCH / "results" / "v1" / "chacha20_round20_a227_postbarrier_label_v1.json"
        ),
        "A223_runner_sha256": _file_sha256(Path(A223.__file__)),
        "A223_helper_source_sha256": _file_sha256(A223.HELPER_SOURCE),
        "Metal_native_source_sha256": A184.NATIVE_SOURCE_SHA256,
    }
    if anchors != expected:
        raise RuntimeError("A229 anchor gate failed")
    return protocol


def _challenge_dir(index: int) -> Path:
    return ARTIFACT_DIR / f"challenge_{index:02d}"


def _prepare_preflight(protocol: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    if PREFLIGHT_PATH.exists():
        preflight = json.loads(PREFLIGHT_PATH.read_bytes())
        if (
            preflight.get("schema") != PREFLIGHT_SCHEMA
            or preflight.get("protocol_sha256") != _file_sha256(PROTOCOL_PATH)
            or preflight.get("runner_sha256") != _file_sha256(Path(__file__))
            or len(preflight.get("challenge_preflights", [])) != CHALLENGE_COUNT
            or _file_sha256(HELPER_PATH) != preflight["native_helper"]["binary_sha256"]
        ):
            raise RuntimeError("A229 retained preflight gate failed")
        for row in preflight["challenge_preflights"]:
            cnf = ROOT / row["structural_CNF"]["artifact"]
            if _file_sha256(cnf) != row["structural_CNF"]["transformed_sha256"]:
                raise RuntimeError("A229 retained CNF gate failed")
        return preflight

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="a229-w32-batch-preflight-") as raw_directory:
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
        tasks = [(index, dimension) for index in range(CHALLENGE_COUNT) for dimension in dimensions]

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
            rows = [(dimension, units) for row_index, dimension, units, _ in probe_rows if row_index == index]
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
        native_helper = A223._compile_helper(
            config=config,
            output=HELPER_PATH,
            directory=temporary_root,
        )
    preflight = {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "state": "frozen_after_all_seven_CNF_mappings_and_helper_compile_before_any_trajectory",
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


def _command(index: int, structural: dict[str, Any]) -> list[str]:
    directory = _challenge_dir(index)
    return [
        str(HELPER_PATH),
        "--cnf",
        str(ROOT / structural["artifact"]),
        "--arm",
        f"a229_challenge_{index:02d}_gray8_w32",
        *A223._helper_args(structural),
        "--cell-order",
        ",".join(A223._gray8_order()),
        "--seconds",
        str(SOLVER_SECONDS_PER_CELL),
        "--model-spool",
        str(directory / "models.spool"),
    ]


def _run_trajectories(
    *, protocol: dict[str, Any], preflight: dict[str, Any]
) -> list[dict[str, Any]]:
    processes = []
    opened = []
    commands = []
    started = time.perf_counter()
    for index, row in enumerate(preflight["challenge_preflights"]):
        directory = _challenge_dir(index)
        stdout_path = directory / "trajectory.stdout"
        stderr_path = directory / "trajectory.stderr"
        spool_path = directory / "models.spool"
        if stdout_path.exists() or stderr_path.exists() or spool_path.exists():
            raise RuntimeError("A229 trajectory artifact already exists without final result")
        stdout_file = stdout_path.open("wb")
        stderr_file = stderr_path.open("wb")
        opened.extend((stdout_file, stderr_file))
        command = _command(index, row["structural_CNF"])
        commands.append(command)
        processes.append(subprocess.Popen(command, stdout=stdout_file, stderr=stderr_file))

    def wait(process: subprocess.Popen[bytes]) -> tuple[int | None, bool]:
        try:
            return process.wait(timeout=3400), False
        except subprocess.TimeoutExpired:
            process.kill()
            return process.wait(timeout=10), True

    try:
        with ThreadPoolExecutor(max_workers=CHALLENGE_COUNT) as executor:
            statuses = list(executor.map(wait, processes))
    finally:
        for handle in opened:
            handle.close()
    # Global barrier: no stdout/model spool is read above this point.
    parsed = []
    for index, ((returncode, timed_out), command, preflight_row, protocol_row) in enumerate(
        zip(statuses, commands, preflight["challenge_preflights"], protocol["challenges"], strict=True)
    ):
        directory = _challenge_dir(index)
        stdout = (directory / "trajectory.stdout").read_text()
        stderr = (directory / "trajectory.stderr").read_text()
        spool_path = directory / "models.spool"
        spool = spool_path.read_text() if spool_path.exists() else ""
        arm = f"a229_challenge_{index:02d}_gray8_w32"
        result = A223._parse_arm_after_global_barrier(
            arm_plan={"arm": arm, "width": WIDTH, "order": "reflected_gray8"},
            stdout=stdout,
            stderr=stderr,
            spool=spool,
            returncode=returncode,
            externally_timed_out=timed_out,
            preflight={"width_preflights": {str(WIDTH): {"structural_CNF": preflight_row["structural_CNF"]}}},
            challenge=protocol_row["public_challenge"],
        )
        if result.get("complete_valid_arm") is not True:
            raise RuntimeError(f"A229 challenge {index} trajectory is incomplete")
        parsed.append(
            {
                **result,
                "index": index,
                "command_sha256": _canonical_sha256(command),
            }
        )
    elapsed = time.perf_counter() - started
    for row in parsed:
        row["volatile_parallel_batch_elapsed_seconds"] = elapsed
    return parsed


def _selected_top64(observations: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ranked = A227._score_rows(observations)
    return ranked, ranked[:TOP_K]


def _initial(challenge: dict[str, Any]) -> np.ndarray:
    return A227._initial(challenge)


def _limited_search_one(
    *, executable: Path, challenge: dict[str, Any], selected: list[dict[str, Any]]
) -> dict[str, Any]:
    target = np.array(challenge["target_words"][0], dtype=np.uint32)
    control = np.array(challenge["control_target_words"], dtype=np.uint32)
    initial = _initial(challenge)
    host = A184.SliceMetalHost(executable, initial, target, control)
    try:
        observed = host.blocks(0x34567800, 8)
        scalar = np.repeat(initial.reshape(1, 16), 8, axis=0)
        scalar[:, 4] = np.arange(0x34567800, 0x34567808, dtype=np.uint32)
        expected = (A119._core(scalar.copy(), 20) + scalar).astype(np.uint32)
        if not np.array_equal(observed, expected):
            raise RuntimeError("A229 Metal mapping gate differs")
        factual: list[int] = []
        controls: list[int] = []
        regions = []
        for rank, row in enumerate(selected, start=1):
            first = int(row["prefix8"], 2) << FREE_BITS_PER_CELL
            response = host.filter(first, CANDIDATES_PER_CELL)
            factual.extend(int(value) for value in response["factual"])
            controls.extend(int(value) for value in response["control"])
            regions.append(
                {
                    "reader_rank": rank,
                    "prefix8": row["prefix8"],
                    "first_candidate": first,
                    "candidate_count": CANDIDATES_PER_CELL,
                    "factual_filter_matches": [int(value) for value in response["factual"]],
                    "control_filter_matches": [int(value) for value in response["control"]],
                }
            )
        identity = host.identity
    finally:
        host.close()
    confirmations = [A227._confirm_candidate(challenge, value) for value in factual]
    exact = [row for row in confirmations if row["all_blocks_match"] and row["flipped_control_rejected"]]
    return {
        "host_identity": identity,
        "mapping_gate_exact_numpy_identity": True,
        "selected_region_count": len(selected),
        "logical_candidate_count": LIMITED_CANDIDATES_PER_CHALLENGE,
        "full_domain_candidate_count": FULL_CANDIDATES_PER_CHALLENGE,
        "candidate_search_reduction_factor": SEARCH_REDUCTION_FACTOR,
        "complete_selected_regions_executed": len(regions) == TOP_K,
        "early_stop_used": False,
        "regions": regions,
        "factual_filter_matches": factual,
        "control_filter_matches": controls,
        "confirmations": confirmations,
        "exact_confirmed_matches": exact,
        "prospective_recovery_success": len(exact) == 1 and not controls,
    }


def _binomial_upper_tail(successes: int) -> float:
    return sum(
        math.comb(CHALLENGE_COUNT, count)
        * NULL_SELECTION_PROBABILITY**count
        * (1.0 - NULL_SELECTION_PROBABILITY) ** (CHALLENGE_COUNT - count)
        for count in range(successes, CHALLENGE_COUNT + 1)
    )


def _write_report(payload: dict[str, Any]) -> None:
    summary = payload["aggregate"]
    lines = [
        "# A229 — Seven-challenge prospective W32 top-64 batch",
        "",
        "## Outcome",
        "",
        f"- Recoveries: **{summary['success_count']} / {CHALLENGE_COUNT}**",
        f"- Candidate-search reduction per challenge: **{SEARCH_REDUCTION_FACTOR}x**",
        f"- Exact binomial upper-tail under uniform top-64 selection: `{summary['uniform_null_binomial_upper_tail']:.9g}`",
        "",
        "| Challenge | Success | Selected regions | Recovered reader rank |",
        "|---:|---:|---:|---:|",
    ]
    for row in payload["challenge_results"]:
        lines.append(
            f"| {row['index']} | {row['limited_Metal_search']['prospective_recovery_success']} | "
            f"{row['limited_Metal_search']['selected_region_count']} | "
            f"{row['recovered_prefix_rank'] if row['recovered_prefix_rank'] is not None else '-'} |"
        )
    lines.append("")
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = REPORT_PATH.with_name(f".{REPORT_PATH.name}.tmp")
    temporary.write_text("\n".join(lines))
    temporary.replace(REPORT_PATH)


def run() -> dict[str, Any]:
    if RESULT_PATH.exists():
        raise RuntimeError(f"A229 result already exists: {RESULT_PATH}")
    protocol = _load_protocol()
    config = A223._load_config()
    preflight = _prepare_preflight(protocol, config)
    trajectories = _run_trajectories(protocol=protocol, preflight=preflight)
    executable, native_build = A184._A181._compile_native(METAL_BUILD_DIR, "swiftc")
    results = []
    for index, (trajectory, protocol_row) in enumerate(
        zip(trajectories, protocol["challenges"], strict=True)
    ):
        ranked, selected = _selected_top64(trajectory["observations"])
        limited = _limited_search_one(
            executable=executable,
            challenge=protocol_row["public_challenge"],
            selected=selected,
        )
        recovered_rank = None
        if len(limited["exact_confirmed_matches"]) == 1:
            prefix = limited["exact_confirmed_matches"][0]["prefix8"]
            recovered_rank = next(i + 1 for i, row in enumerate(ranked) if row["prefix8"] == prefix)
        results.append(
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
    successes = sum(row["limited_Metal_search"]["prospective_recovery_success"] for row in results)
    payload = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "SEVEN_CHALLENGE_PROSPECTIVE_FULLROUND_W32_TOP64_RECOVERY_BATCH",
        "anchors": {
            "protocol_sha256": _file_sha256(PROTOCOL_PATH),
            "preflight_sha256": _file_sha256(PREFLIGHT_PATH),
            "runner_sha256": _file_sha256(Path(__file__)),
        },
        "information_boundary": protocol["information_boundary"],
        "native_build": native_build,
        "challenge_results": results,
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
                for row in results
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
