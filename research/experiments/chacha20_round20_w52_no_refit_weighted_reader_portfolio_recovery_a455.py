#!/usr/bin/env python3
"""A455: execute A454's non-factorized BOOHH weighted W52 pair stream."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

STEM = "chacha20_round20_w52_no_refit_weighted_reader_portfolio_recovery_a455"
DESIGN = CONFIGS / f"{STEM}_design_v1.json"
IMPLEMENTATION = CONFIGS / f"{STEM}_implementation_v1.json"
PROTOCOL = CONFIGS / f"{STEM}_v1.json"
RESULT = RESULTS / f"{STEM}_v1.json"
STOP = RESULTS / f"{STEM}_confirmed_stop_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / f"tests/test_{STEM}.py"
REPRO = ROOT / f"scripts/reproduce_{STEM}.sh"

A435_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_dual_axis_square_wavefront_recovery_a435.py"
)
A435_IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w52_dual_axis_square_wavefront_recovery_a435_implementation_v1.json"
)
A435_PROTOCOL = (
    CONFIGS / "chacha20_round20_w52_dual_axis_square_wavefront_recovery_a435_v1.json"
)
A454_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_no_refit_weighted_reader_portfolio_a454.py"
)
A454_DESIGN = (
    CONFIGS
    / "chacha20_round20_w52_no_refit_weighted_reader_portfolio_a454_design_v1.json"
)
A454_IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w52_no_refit_weighted_reader_portfolio_a454_implementation_v2.json"
)
A454_RESULT = (
    RESULTS / "chacha20_round20_w52_no_refit_weighted_reader_portfolio_a454_v1.json"
)
A454_PAIR_STREAM = (
    RESULTS
    / "chacha20_round20_w52_no_refit_weighted_reader_portfolio_a454_pair_stream_uint16be_uint16be_v1.bin"
)
A454_CAUSAL = A454_RESULT.with_suffix(".causal")
A454_READBACK = RESEARCH / "reports/CAUSAL_CHACHA20_A454_PERSONAL_READER_READBACK_V1.md"
A434_QUALIFICATION = (
    RESULTS / "chacha20_round20_w52_dual_axis_square_wavefront_a434_qualification_v1.json"
)
A426_PROTOCOL = (
    CONFIGS / "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_v1.json"
)
A426_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426.py"
)

ATTEMPT_ID = "A455"
DESIGN_SHA256 = "1f0bb67882401ba302a9fc2ffeb23f179524bf0bd9a07323479c6accd73c9658"
A435_RUNNER_SHA256 = "c9d355f1afda18b6a5f3367f56ba3d9d7658a2b3c3e79ce80d1e8618578fb3b6"
A435_IMPLEMENTATION_SHA256 = (
    "fd37e58b9786cafbe605fb1738204e815de610d20982b459b1007492615ee126"
)
A435_PROTOCOL_SHA256 = "a6616f0ce3ef8c92a67381e8d3c6acde649f0842d85ea7be9cc488e2182044cd"
A454_RUNNER_SHA256 = "ef327b61026dea463384c0fe3b1793289e51fe9246953ae982ee89275c810eb1"
A454_DESIGN_SHA256 = "7a55c5201141734ff10bc55434a4bcf8265a72c9d3a3585b4b964d3bb28308ed"
A454_IMPLEMENTATION_SHA256 = (
    "368855583aa58c520069974631726fbe467f05917a8bee36fc7875897e215334"
)
A454_RESULT_SHA256 = "afa2faa05c83e97b9cd8aeee03063ce4493d9c3ea5388fdb9dc39bf3f2093856"
A454_CAUSAL_SHA256 = "3c14b8a31484bd6bda279d5010056ee7700af89dd81707244f7fafcdf255063f"
A454_READBACK_SHA256 = "bb7c6c9d1c1d630f6a12d4a21f0cedbb38fdc81d19012190dba70c081794676f"
A454_RESULT_COMMITMENT_SHA256 = (
    "508cec4cbb82bc3ba4852cf29a4ee14ac62b049ec3d3003d1fede26c274c311e"
)
A454_PAIR_STREAM_SHA256 = "a82fbe129f6eccaf2ddd560064df1efb471668a116cd52a97490bc66b720b749"
A454_CALIBRATION_SHA256 = "233ee76ee261f79771bddc05774d666e882ccc69c5465aead4658432f9e4fb13"
A454_GUARANTEE_SHA256 = "5ee8c540427a841e9739f4fd76360c06eaebd844f4df63236e7cff7b4ba1c676"
A426_PROTOCOL_SHA256 = "746c880115464383247ee0ef8d52d6095195f26fa4b69178a8de281cd4c483a3"
A426_RUNNER_SHA256 = "d849065a0bc33f1d3eff3f5b7638948c86b683f8020bfd8a0f5ed0e9ca449637"
PUBLIC_CHALLENGE_SHA256 = (
    "5d60dac2570756d681f248a6cfb818681c644d87843d273bc0e9b2ee46731b54"
)

WIDTH = 52
KNOWN_KEY_BITS = 256 - WIDTH
AXIS_CELLS = 1 << 12
PAIR_CELLS = 1 << 24
CELL_ASSIGNMENTS = 1 << 28
DOMAIN_ASSIGNMENTS = 1 << WIDTH
WORKERS = 8
WORKER_TASKS = PAIR_CELLS // WORKERS
BLOCK_COUNT = 8
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A455 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A454 = load_module(A454_RUNNER, "a455_a454")
file_sha256 = A454.file_sha256
canonical_sha256 = A454.canonical_sha256
atomic_json = A454.atomic_json
atomic_bytes = A454.atomic_bytes
anchor = A454.anchor
path_from_ref = A454.path_from_ref
relative = A454.relative
_A435: Any | None = None
_PAIR_STREAM: PairStream | None = None


class PairStream:
    """Read-only random access over A454's packed pair permutation."""

    def __init__(self, path: Path) -> None:
        if path.stat().st_size != PAIR_CELLS * 4:
            raise RuntimeError("A455 pair stream size differs")
        self.path = path
        self._mapped = np.memmap(
            path, dtype=">u4", mode="r", shape=(PAIR_CELLS,)
        )

    def __len__(self) -> int:
        return PAIR_CELLS

    def pair_at(self, global_index: int) -> tuple[int, int]:
        if not 0 <= global_index < PAIR_CELLS:
            raise ValueError("A455 global pair index differs")
        packed = int(self._mapped[global_index])
        prefix = packed >> 16
        off_axis = packed & 0xFFFF
        if prefix >= AXIS_CELLS or off_axis >= AXIS_CELLS:
            raise RuntimeError("A455 packed pair coordinate differs")
        return prefix, off_axis

    def global_index(self, prefix: int, off_axis: int) -> int:
        if not 0 <= prefix < AXIS_CELLS or not 0 <= off_axis < AXIS_CELLS:
            raise ValueError("A455 pair coordinate differs")
        target = np.uint32((prefix << 16) | off_axis)
        for start in range(0, PAIR_CELLS, 1 << 20):
            stop = min(start + (1 << 20), PAIR_CELLS)
            chunk = np.asarray(self._mapped[start:stop], dtype=np.uint32)
            hits = np.flatnonzero(chunk == target)
            if hits.size:
                if hits.size != 1:
                    raise RuntimeError("A455 pair stream inverse is not unique")
                return start + int(hits[0])
        raise RuntimeError("A455 pair absent from complete stream")


def pair_stream() -> PairStream:
    global _PAIR_STREAM
    if _PAIR_STREAM is None:
        anchor(A454_PAIR_STREAM, A454_PAIR_STREAM_SHA256)
        _PAIR_STREAM = PairStream(A454_PAIR_STREAM)
    return _PAIR_STREAM


def runtime_a435() -> Any:
    global _A435
    if _A435 is None:
        anchor(A435_RUNNER, A435_RUNNER_SHA256)
        _A435 = load_module(A435_RUNNER, "a455_a435_runtime")
    return _A435


def progress_path(worker_index: int) -> Path:
    if not 0 <= worker_index < WORKERS:
        raise ValueError("A455 worker index differs")
    return RESULTS / f"{STEM}_worker_{worker_index}_progress_v1.json"


def no_downstream_artifacts() -> bool:
    return not any(
        path.exists()
        for path in (
            PROTOCOL,
            RESULT,
            STOP,
            CAUSAL,
            REPORT,
            *(progress_path(index) for index in range(WORKERS)),
        )
    )


def load_design() -> dict[str, Any]:
    anchor(DESIGN, DESIGN_SHA256)
    value = json.loads(DESIGN.read_bytes())
    execution = value.get("execution_contract", {})
    schedule = value.get("schedule_transfer_contract", {})
    engine = value.get("engine_reuse_contract", {})
    challenge = value.get("challenge_contract", {})
    queue = value.get("queue_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-no-refit-weighted-reader-portfolio-recovery-a455-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or execution.get("full_rounds") != 20
        or execution.get("feedforward_included") is not True
        or execution.get("unknown_key_bits") != WIDTH
        or execution.get("known_key_bits") != KNOWN_KEY_BITS
        or execution.get("pair_cells") != PAIR_CELLS
        or execution.get("candidates_per_complete_pair_cell") != CELL_ASSIGNMENTS
        or execution.get("complete_domain_assignments") != DOMAIN_ASSIGNMENTS
        or execution.get("workers") != WORKERS
        or execution.get("worker_tasks_each") != WORKER_TASKS
        or execution.get("complete_pair_cell_before_success_evaluation") is not True
        or execution.get("early_stop_inside_pair_cell") is not False
        or execution.get("shared_stop_only_after_independent_confirmation") is not True
        or schedule.get("source_attempt") != "A454"
        or schedule.get("source_result_sha256") != A454_RESULT_SHA256
        or schedule.get("source_result_commitment_sha256")
        != A454_RESULT_COMMITMENT_SHA256
        or schedule.get("source_pair_stream_sha256")
        != A454_PAIR_STREAM_SHA256
        or schedule.get("source_pair_stream_bytes") != PAIR_CELLS * 4
        or schedule.get("source_pair_stream_cells") != PAIR_CELLS
        or schedule.get("source_complete_permutation") is not True
        or schedule.get("source_fusion_algorithm")
        != "deduplicated_periodic_weighted_first_encounter"
        or schedule.get("source_selected_pattern") != "BOOHH"
        or schedule.get("source_hard_rank_violations") != 0
        or schedule.get("read_only_memory_map") is not True
        or schedule.get("random_access_pair_at_global_index") is not True
        or schedule.get("W52_true_pair_rank_known_at_freeze") is not False
        or schedule.get("target_labels_used") != 0
        or schedule.get("feature_refits") != 0
        or schedule.get("model_refits") != 0
        or schedule.get("production_candidate_assignments_executed") != 0
        or engine.get("A454_nonfactorized_pair_stream_used") is not True
        or engine.get("prior_candidate_progress_or_outcome_consumed") is not False
        or challenge.get("source_attempt") != "A426"
        or challenge.get("secret_assignment_absent_from_protocol") is not True
        or queue.get("A455_runs_after_terminal_A452") is not True
        or queue.get("A455_runs_after_A452_supervisor_and_workers_close") is not True
        or boundary.get(
            "A454_result_and_authentic_Causal_personally_read_at_design_freeze"
        )
        is not True
        or boundary.get("A452_candidate_progress_or_result_read") is not False
        or boundary.get(
            "A426_A438_A440_A443_A450_secret_result_stop_or_worker_progress_read"
        )
        is not False
        or boundary.get("A455_candidate_or_progress_available_at_design_freeze")
        is not False
        or boundary.get("A455_target_labels_used_for_schedule") != 0
        or boundary.get("A455_feature_refits") != 0
        or boundary.get("A455_model_refits") != 0
        or boundary.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A455 frozen design semantics differ")
    sources = value["source_anchors"]
    for key, item in sources.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, sources[f"{stem}_sha256"])
    return value


def load_source_schedule() -> tuple[dict[str, Any], PairStream, tuple[Any, ...]]:
    anchor(A454_RUNNER, A454_RUNNER_SHA256)
    anchor(A454_DESIGN, A454_DESIGN_SHA256)
    anchor(A454_IMPLEMENTATION, A454_IMPLEMENTATION_SHA256)
    anchor(A454_RESULT, A454_RESULT_SHA256)
    anchor(A454_PAIR_STREAM, A454_PAIR_STREAM_SHA256)
    anchor(A454_CAUSAL, A454_CAUSAL_SHA256)
    anchor(A454_READBACK, A454_READBACK_SHA256)
    packaged = A454.load_result(A454_RESULT_SHA256)
    if (
        packaged.get("schema")
        != "chacha20-round20-w52-no-refit-weighted-reader-portfolio-a454-v1"
        or packaged.get("result_commitment_sha256")
        != A454_RESULT_COMMITMENT_SHA256
        or packaged.get("evidence_stage")
        != "STRICT_NO_REFIT_SELECTED_TARGET_BLIND_W52_WEIGHTED_RECOVERY_STREAM_READY"
        or packaged.get("calibration", {}).get("selected_pattern") != "BOOHH"
        or packaged.get("calibration", {}).get("calibration_sha256")
        != A454_CALIBRATION_SHA256
        or packaged.get("stream", {}).get("artifact", {}).get("sha256")
        != A454_PAIR_STREAM_SHA256
        or packaged.get("stream", {}).get("artifact", {}).get("pair_cells")
        != PAIR_CELLS
        or packaged.get("stream", {}).get("artifact", {}).get(
            "complete_permutation"
        )
        is not True
        or packaged.get("hard_rank_guarantee", {}).get("all_bounds_satisfied")
        is not True
        or packaged.get("W52_target_labels_used") != 0
        or packaged.get("feature_refits") != 0
        or packaged.get("model_refits") != 0
        or packaged.get("W52_candidate_assignments_executed") != 0
        or packaged.get(
            "A426_A438_A440_A443_A450_A452_secret_result_or_worker_progress_read"
        )
        is not False
    ):
        raise RuntimeError("A455 A454 source schedule differs")
    stream = pair_stream()
    if stream.pair_at(0) != tuple(packaged["stream"]["artifact"]["first_pair"]):
        raise RuntimeError("A455 A454 first pair differs")
    if stream.pair_at(PAIR_CELLS - 1) != tuple(
        packaged["stream"]["artifact"]["last_pair"]
    ):
        raise RuntimeError("A455 A454 last pair differs")
    return packaged, stream, ()


def load_public_challenge() -> tuple[dict[str, Any], dict[str, Any]]:
    anchor(A426_PROTOCOL, A426_PROTOCOL_SHA256)
    anchor(A426_RUNNER, A426_RUNNER_SHA256)
    a426 = json.loads(A426_PROTOCOL.read_bytes())
    challenge = dict(a426["public_challenge"])
    if (
        a426.get("schema")
        != "chacha20-round20-w52-a416-fresh-shared-stop-recovery-a426-protocol-v1"
        or a426.get("complete_domain_assignments") != DOMAIN_ASSIGNMENTS
        or a426.get("public_challenge_sha256") != PUBLIC_CHALLENGE_SHA256
        or canonical_sha256(challenge) != PUBLIC_CHALLENGE_SHA256
        or challenge.get("unknown_key_bits") != WIDTH
        or challenge.get("known_key_bits") != KNOWN_KEY_BITS
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("public_output_blocks") != BLOCK_COUNT
        or challenge.get("rounds") != 20
        or challenge.get("feedforward") is not True
    ):
        raise RuntimeError("A455 A426 public challenge scope differs")
    return a426, challenge


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists() or not no_downstream_artifacts():
        raise FileExistsError("A455 implementation or downstream artifact exists")
    design = load_design()
    source, stream, _unused = load_source_schedule()
    a426, _challenge = load_public_challenge()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A455 tests and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-no-refit-weighted-reader-portfolio-recovery-a455-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_restart_safe_eight_worker_A454_BOOHH_weighted_reader_portfolio_executor_frozen_without_reading_any_prior_secret_result_stop_or_worker_progress",
        "design_sha256": DESIGN_SHA256,
        "execution_contract": design["execution_contract"],
        "schedule_transfer_contract": design["schedule_transfer_contract"],
        "engine_reuse_contract": design["engine_reuse_contract"],
        "source_A454_result_sha256": A454_RESULT_SHA256,
        "source_A454_result_commitment_sha256": source[
            "result_commitment_sha256"
        ],
        "source_A454_pair_stream_sha256": source["stream"]["artifact"]["sha256"],
        "source_A454_calibration_sha256": source["calibration"][
            "calibration_sha256"
        ],
        "source_A454_guarantee_sha256": source["guarantee_sha256"],
        "source_A454_pair_stream_bytes": source["stream"]["artifact"]["bytes"],
        "source_A426_protocol_sha256": A426_PROTOCOL_SHA256,
        "source_A426_public_challenge_sha256": a426["public_challenge_sha256"],
        "source_pair_cells": len(stream),
        "A434_qualification_content_read_at_freeze": False,
        "A452_candidate_progress_or_result_read": False,
        "A426_A438_A440_A443_A450_secret_result_stop_or_worker_progress_read": False,
        "A455_candidate_or_progress_available_at_freeze": False,
        "production_target_labels_used": 0,
        "production_feature_refits": 0,
        "production_model_refits": 0,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A435_runner": anchor(A435_RUNNER, A435_RUNNER_SHA256),
            "A435_implementation": anchor(
                A435_IMPLEMENTATION, A435_IMPLEMENTATION_SHA256
            ),
            "A435_protocol": anchor(A435_PROTOCOL, A435_PROTOCOL_SHA256),
            "A454_runner": anchor(A454_RUNNER, A454_RUNNER_SHA256),
            "A454_design": anchor(A454_DESIGN, A454_DESIGN_SHA256),
            "A454_implementation": anchor(
                A454_IMPLEMENTATION, A454_IMPLEMENTATION_SHA256
            ),
            "A454_result": anchor(A454_RESULT, A454_RESULT_SHA256),
            "A454_pair_stream": anchor(
                A454_PAIR_STREAM, A454_PAIR_STREAM_SHA256
            ),
            "A454_causal": anchor(A454_CAUSAL, A454_CAUSAL_SHA256),
            "A454_personal_readback": anchor(
                A454_READBACK, A454_READBACK_SHA256
            ),
            "A426_protocol": anchor(A426_PROTOCOL, A426_PROTOCOL_SHA256),
            "A426_runner": anchor(A426_RUNNER, A426_RUNNER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    anchor(IMPLEMENTATION, expected_sha256)
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-no-refit-weighted-reader-portfolio-recovery-a455-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("source_A454_result_sha256") != A454_RESULT_SHA256
        or value.get("source_A454_result_commitment_sha256")
        != A454_RESULT_COMMITMENT_SHA256
        or value.get("source_A454_pair_stream_sha256")
        != A454_PAIR_STREAM_SHA256
        or value.get("source_A454_pair_stream_bytes") != PAIR_CELLS * 4
        or value.get("source_A454_calibration_sha256")
        != A454_CALIBRATION_SHA256
        or value.get("source_A454_guarantee_sha256")
        != A454_GUARANTEE_SHA256
        or value.get("source_A426_protocol_sha256") != A426_PROTOCOL_SHA256
        or value.get("source_pair_cells") != PAIR_CELLS
        or value.get("A434_qualification_content_read_at_freeze") is not False
        or value.get("A452_candidate_progress_or_result_read") is not False
        or value.get("A426_A438_A440_A443_A450_secret_result_stop_or_worker_progress_read")
        is not False
        or value.get("A455_candidate_or_progress_available_at_freeze") is not False
        or value.get("production_target_labels_used") != 0
        or value.get("production_feature_refits") != 0
        or value.get("production_model_refits") != 0
        or value.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A455 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A455 implementation commitment differs")
    return value


def square_pair_at(
    global_index: int,
    prefix_order: PairStream,
    off_axis_order: Sequence[int] | None = None,
) -> tuple[int, int]:
    del off_axis_order
    if not isinstance(prefix_order, PairStream):
        raise TypeError("A455 pair source is not the frozen PairStream")
    return prefix_order.pair_at(global_index)


def pair_global_index(
    prefix: int,
    off_axis: int,
    prefix_order: PairStream,
    off_axis_order: Sequence[int] | None = None,
) -> int:
    del off_axis_order
    if not isinstance(prefix_order, PairStream):
        raise TypeError("A455 pair source is not the frozen PairStream")
    index = prefix_order.global_index(prefix, off_axis)
    if prefix_order.pair_at(index) != (prefix, off_axis):
        raise RuntimeError("A455 pair-stream inverse identity failed")
    return index


def factorized_pair_global_index(
    prefix: int,
    off_axis: int,
    prefix_order: Sequence[int],
    off_axis_order: Sequence[int],
) -> int:
    prefix_values = [int(value) for value in prefix_order]
    off_values = [int(value) for value in off_axis_order]
    if (
        len(prefix_values) != AXIS_CELLS
        or len(off_values) != AXIS_CELLS
        or set(prefix_values) != set(range(AXIS_CELLS))
        or set(off_values) != set(range(AXIS_CELLS))
    ):
        raise ValueError("A455 factorized comparison order differs")
    left = prefix_values.index(prefix)
    right = off_values.index(off_axis)
    shell = max(left, right)
    if left == shell:
        return shell * shell + right
    return shell * shell + shell + 1 + left


def freeze_protocol(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if not no_downstream_artifacts():
        raise FileExistsError("A455 protocol or execution artifact exists")
    implementation = load_implementation(expected_implementation_sha256)
    source, stream, unused = load_source_schedule()
    a426, challenge = load_public_challenge()
    sentinels = []
    for index in (0, 1, 7, 8, 255, PAIR_CELLS // 2, PAIR_CELLS - 1):
        left, right = square_pair_at(index, stream, unused)
        sentinels.append(
            {"global_index": index, "prefix": left, "off_axis": right}
        )
    schedule = {
        "algorithm": "A454_BOOHH_deduplicated_periodic_weighted_first_encounter_pair_stream",
        "selected_pattern": "BOOHH",
        "selected_reader_portfolio": [
            A454.COMPONENTS[symbol] for symbol in A454.SYMBOLS
        ],
        "pair_stream_sha256": A454_PAIR_STREAM_SHA256,
        "pair_stream_bytes": PAIR_CELLS * 4,
        "A454_result_commitment_sha256": A454_RESULT_COMMITMENT_SHA256,
        "A454_calibration_sha256": A454_CALIBRATION_SHA256,
        "A454_guarantee_sha256": A454_GUARANTEE_SHA256,
        "exact_component_proposal_bounds": source["hard_rank_guarantee"][
            "per_component_exact_proposal_bounds"
        ],
        "exact_rank_guarantee_violations": 0,
        "maximum_observed_hybrid_rank_ratio": source[
            "hard_rank_guarantee"
        ]["hybrid_rank_ratio"]["maximum"],
        "maximum_observed_best_component_rank_ratio": source[
            "hard_rank_guarantee"
        ]["best_component_rank_ratio"]["maximum"],
        "pair_spearman_to_A451": source["geometry"][
            "comparison_to_A451_fixed_slot_stream"
        ]["spearman_rank_correlation"],
        "top65536_intersection_with_A451": source["geometry"][
            "comparison_to_A451_fixed_slot_stream"
        ]["top_k_overlap"]["65536"]["intersection"],
        "pair_cells": PAIR_CELLS,
        "assignments_per_complete_pair_cell": CELL_ASSIGNMENTS,
        "complete_domain_assignments": DOMAIN_ASSIGNMENTS,
        "workers": WORKERS,
        "worker_tasks_each": WORKER_TASKS,
        "worker_global_index_formula": "worker_index + 8 * zero_based_worker_step",
        "worker_role_formula": "weighted_portfolio_wave_{worker_index}",
        "pair_at_formula": "read_uint32be(A454_pair_stream,4*global_index) -> prefix16 || off_axis16",
        "complete_cover_identity": "disjoint residues modulo 8 over [0,2^24)",
        "direct_inverse_sentinels": sentinels,
        "first_pair": dict(
            zip(("prefix", "off_axis"), square_pair_at(0, stream, unused), strict=True)
        ),
        "last_pair": dict(
            zip(
                ("prefix", "off_axis"),
                square_pair_at(PAIR_CELLS - 1, stream, unused),
                strict=True,
            )
        ),
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-no-refit-weighted-reader-portfolio-recovery-a455-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "A454_exact_BOOHH_weighted_pair_stream_and_A426_public_challenge_bound_before_any_A452_candidate_progress_or_result",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "A454_result_sha256": A454_RESULT_SHA256,
        "A454_result_commitment_sha256": A454_RESULT_COMMITMENT_SHA256,
        "A426_protocol_sha256": A426_PROTOCOL_SHA256,
        "public_challenge": challenge,
        "public_challenge_sha256": a426["public_challenge_sha256"],
        "schedule": schedule,
        "schedule_commitment_sha256": canonical_sha256(schedule),
        "worker_roles": [
            f"weighted_portfolio_wave_{index}" for index in range(WORKERS)
        ],
        "information_boundary": {
            "A454_schedule_frozen_before_A455_challenge_binding": True,
            "A434_qualification_content_read_at_A455_protocol_freeze": False,
            "A426_assignment_absent_from_protocol": True,
            "A426_A438_A440_A443_A450_secret_result_stop_or_worker_progress_read": False,
            "A452_candidate_progress_or_result_read": False,
            "A455_candidate_or_progress_available_at_protocol_freeze": False,
            "A455_target_labels_used_for_schedule": 0,
            "A455_feature_refits": 0,
            "A455_model_refits": 0,
            "prior_live_recovery_filter_outcomes_consumed": False,
        },
        "production_execution_enabled": False,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(
                IMPLEMENTATION, expected_implementation_sha256
            ),
            "A454_runner": anchor(A454_RUNNER, A454_RUNNER_SHA256),
            "A454_design": anchor(A454_DESIGN, A454_DESIGN_SHA256),
            "A454_implementation": anchor(
                A454_IMPLEMENTATION, A454_IMPLEMENTATION_SHA256
            ),
            "A454_result": anchor(A454_RESULT, A454_RESULT_SHA256),
            "A454_pair_stream": anchor(
                A454_PAIR_STREAM, A454_PAIR_STREAM_SHA256
            ),
            "A454_causal": anchor(A454_CAUSAL, A454_CAUSAL_SHA256),
            "A454_personal_readback": anchor(
                A454_READBACK, A454_READBACK_SHA256
            ),
            "A426_protocol": anchor(A426_PROTOCOL, A426_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    anchor(PROTOCOL, expected_sha256)
    value = json.loads(PROTOCOL.read_bytes())
    boundary = value.get("information_boundary", {})
    schedule = value.get("schedule", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-no-refit-weighted-reader-portfolio-recovery-a455-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A454_result_sha256") != A454_RESULT_SHA256
        or value.get("A454_result_commitment_sha256")
        != A454_RESULT_COMMITMENT_SHA256
        or value.get("A426_protocol_sha256") != A426_PROTOCOL_SHA256
        or schedule.get("algorithm")
        != "A454_BOOHH_deduplicated_periodic_weighted_first_encounter_pair_stream"
        or schedule.get("selected_pattern") != "BOOHH"
        or tuple(schedule.get("selected_reader_portfolio", []))
        != tuple(A454.COMPONENTS[symbol] for symbol in A454.SYMBOLS)
        or schedule.get("pair_stream_sha256")
        != A454_PAIR_STREAM_SHA256
        or schedule.get("pair_stream_bytes") != PAIR_CELLS * 4
        or schedule.get("A454_result_commitment_sha256")
        != A454_RESULT_COMMITMENT_SHA256
        or schedule.get("A454_calibration_sha256")
        != A454_CALIBRATION_SHA256
        or schedule.get("A454_guarantee_sha256") != A454_GUARANTEE_SHA256
        or schedule.get("exact_rank_guarantee_violations") != 0
        or schedule.get("pair_cells") != PAIR_CELLS
        or schedule.get("assignments_per_complete_pair_cell") != CELL_ASSIGNMENTS
        or schedule.get("complete_domain_assignments") != DOMAIN_ASSIGNMENTS
        or schedule.get("workers") != WORKERS
        or schedule.get("worker_tasks_each") != WORKER_TASKS
        or value.get("schedule_commitment_sha256") != canonical_sha256(schedule)
        or value.get("worker_roles")
        != [f"weighted_portfolio_wave_{index}" for index in range(WORKERS)]
        or boundary.get("A454_schedule_frozen_before_A455_challenge_binding")
        is not True
        or boundary.get("A434_qualification_content_read_at_A455_protocol_freeze")
        is not False
        or boundary.get("A426_assignment_absent_from_protocol") is not True
        or boundary.get(
            "A426_A438_A440_A443_A450_secret_result_stop_or_worker_progress_read"
        )
        is not False
        or boundary.get("A452_candidate_progress_or_result_read") is not False
        or boundary.get("A455_candidate_or_progress_available_at_protocol_freeze")
        is not False
        or boundary.get("A455_target_labels_used_for_schedule") != 0
        or boundary.get("A455_feature_refits") != 0
        or boundary.get("A455_model_refits") != 0
        or boundary.get("prior_live_recovery_filter_outcomes_consumed") is not False
        or value.get("production_execution_enabled") is not False
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A455 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_implementation(value["implementation_sha256"])
    source, stream, unused = load_source_schedule()
    a426, _challenge = load_public_challenge()
    if (
        schedule["pair_stream_sha256"]
        != source["stream"]["artifact"]["sha256"]
        or schedule["first_pair"]
        != dict(
            zip(
                ("prefix", "off_axis"),
                square_pair_at(0, stream, unused),
                strict=True,
            )
        )
        or schedule["last_pair"]
        != dict(
            zip(
                ("prefix", "off_axis"),
                square_pair_at(PAIR_CELLS - 1, stream, unused),
                strict=True,
            )
        )
        or value["public_challenge"] != a426["public_challenge"]
        or value["public_challenge_sha256"]
        != canonical_sha256(value["public_challenge"])
    ):
        raise RuntimeError("A455 source binding differs")
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "protocol_commitment_sha256"
    }
    if value.get("protocol_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A455 protocol commitment differs")
    return value


def load_a434_qualification(expected_sha256: str) -> dict[str, Any]:
    return runtime_a435().load_a434_qualification(expected_sha256)


def worker_global_index(worker_index: int, zero_based_worker_step: int) -> int:
    if not 0 <= worker_index < WORKERS:
        raise ValueError("A455 worker index differs")
    if not 0 <= zero_based_worker_step < WORKER_TASKS:
        raise ValueError("A455 worker step differs")
    return worker_index + WORKERS * zero_based_worker_step


def worker_pair_at(
    worker_index: int,
    zero_based_worker_step: int,
    prefix_order: PairStream,
    off_axis_order: Sequence[int] | None,
) -> tuple[int, int, int]:
    global_index = worker_global_index(worker_index, zero_based_worker_step)
    prefix, off_axis = square_pair_at(global_index, prefix_order, off_axis_order)
    return global_index, prefix, off_axis


def configure_runtime_shim() -> Any:
    a435 = runtime_a435()
    a435.STOP = STOP
    a435.RESULT = RESULT
    a435.progress_path = progress_path
    a435.worker_pair_at = worker_pair_at
    return a435


def normalize_worker_row(row: Mapping[str, Any], worker_index: int) -> dict[str, Any]:
    value = dict(row)
    value["worker_role"] = f"weighted_portfolio_wave_{worker_index}"
    if "last_shell_zero_based" in value:
        value["last_factorized_shell_zero_based_not_applicable"] = None
        value.pop("last_shell_zero_based", None)
    return value


def load_resume(
    *, worker_index: int, protocol_sha256: str, qualification_sha256: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    path = progress_path(worker_index)
    if not path.exists():
        return 0, 0.0, 0, None
    value = json.loads(path.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-no-refit-weighted-reader-portfolio-recovery-a455-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("worker_index") != worker_index
        or value.get("worker_role") != f"weighted_portfolio_wave_{worker_index}"
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("A434_qualification_sha256") != qualification_sha256
        or value.get("A454_result_commitment_sha256")
        != A454_RESULT_COMMITMENT_SHA256
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A455 progress fingerprint differs")
    status = value.get("status")
    completed = int(value.get("executed_worker_pair_cells", -1))
    factual = value.get("factual_filter_candidates")
    if (
        status
        not in {"running", "candidate_found", "worker_exhausted", "peer_confirmed"}
        or not 0 <= completed <= WORKER_TASKS
        or (
            status == "candidate_found"
            and (not isinstance(factual, list) or len(factual) != 1)
        )
        or (status != "candidate_found" and factual != 0)
    ):
        raise RuntimeError("A455 resumable progress state differs")
    if status in {"candidate_found", "worker_exhausted", "peer_confirmed"}:
        return (
            completed,
            float(value.get("gpu_seconds", 0.0)),
            int(value.get("host_instances", 0)),
            value,
        )
    return (
        completed,
        float(value.get("gpu_seconds", 0.0)),
        int(value.get("host_instances", 0)),
        None,
    )


def ordered_worker_discovery(
    *,
    worker_index: int,
    challenge: Mapping[str, Any],
    prefix_order: PairStream,
    off_axis_order: Sequence[int] | None,
    host_factory: Callable[[], Any],
    start_cell: int,
    prior_gpu_seconds: float,
    prior_host_instances: int,
    progress_callback: Callable[[Mapping[str, Any]], None],
    filter_fn: Callable[..., Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    a435 = configure_runtime_shim()

    def normalized_callback(row: Mapping[str, Any]) -> None:
        progress_callback(normalize_worker_row(row, worker_index))

    value = a435.ordered_worker_discovery(
        worker_index=worker_index,
        challenge=challenge,
        prefix_order=prefix_order,
        off_axis_order=off_axis_order,
        host_factory=host_factory,
        start_cell=start_cell,
        prior_gpu_seconds=prior_gpu_seconds,
        prior_host_instances=prior_host_instances,
        progress_callback=normalized_callback,
        filter_fn=filter_fn,
    )
    return normalize_worker_row(value, worker_index)


def mark_peer_confirmed(
    protocol_sha256: str, qualification_sha256: str, worker_index: int
) -> dict[str, Any]:
    path = progress_path(worker_index)
    if not path.exists():
        return {
            "status": "peer_confirmed",
            "worker_index": worker_index,
            "worker_was_not_started": True,
        }
    value = json.loads(path.read_bytes())
    if (
        value.get("protocol_sha256") != protocol_sha256
        or value.get("A434_qualification_sha256") != qualification_sha256
        or value.get("worker_index") != worker_index
        or value.get("worker_role") != f"weighted_portfolio_wave_{worker_index}"
        or value.get("A454_result_commitment_sha256")
        != A454_RESULT_COMMITMENT_SHA256
    ):
        raise RuntimeError("A455 peer progress fingerprint differs")
    if value.get("status") in {"running", "peer_confirmed"}:
        value["status"] = "peer_confirmed"
        value["factual_filter_candidates"] = 0
        value["confirmed_stop_sha256"] = file_sha256(STOP)
        atomic_json(path, value)
    elif value.get("status") not in {"worker_exhausted", "candidate_found"}:
        raise RuntimeError("A455 peer progress status differs")
    return {"status": "peer_confirmed", "worker_index": worker_index}


def progress_snapshot(protocol_sha256: str, qualification_sha256: str) -> dict[str, Any]:
    panel: dict[str, Any] = {}
    total = 0
    max_depth = 0
    all_controls_empty = True
    for index in range(WORKERS):
        role = f"weighted_portfolio_wave_{index}"
        path = progress_path(index)
        if not path.exists():
            panel[role] = {
                "status": "not_started",
                "executed_worker_pair_cells": 0,
                "worker_pair_cells": WORKER_TASKS,
            }
            continue
        value = json.loads(path.read_bytes())
        if (
            value.get("protocol_sha256") != protocol_sha256
            or value.get("A434_qualification_sha256") != qualification_sha256
            or value.get("worker_index") != index
            or value.get("worker_role") != role
            or value.get("A454_result_commitment_sha256")
            != A454_RESULT_COMMITMENT_SHA256
        ):
            raise RuntimeError("A455 progress snapshot fingerprint differs")
        cells = int(value.get("executed_worker_pair_cells", 0))
        total += cells
        max_depth = max(max_depth, int(value.get("static_parallel_depth", 0)))
        all_controls_empty &= value.get("matched_control_candidates") == 0
        panel[role] = {
            "status": value.get("status"),
            "executed_worker_pair_cells": cells,
            "worker_pair_cells": WORKER_TASKS,
            "static_parallel_depth": int(value.get("static_parallel_depth", 0)),
            "gpu_seconds": float(value.get("gpu_seconds", 0.0)),
            "matched_control_candidates": value.get("matched_control_candidates"),
        }
    return {
        "workers": panel,
        "total_unique_pair_cells_evaluated": total,
        "total_unique_assignments_evaluated": total * CELL_ASSIGNMENTS,
        "maximum_completed_static_parallel_depth": max_depth,
        "theoretical_complete_parallel_depth": WORKER_TASKS,
        "complete_domain_assignments": DOMAIN_ASSIGNMENTS,
        "all_observed_matched_controls_empty": all_controls_empty,
        "pair_cell_sets_are_disjoint_by_modulo_8_construction": True,
    }


def active_started_workers_terminal() -> bool:
    owner = int(json.loads(STOP.read_bytes())["worker_index"])
    for index in range(WORKERS):
        path = progress_path(index)
        if not path.exists():
            continue
        status = json.loads(path.read_bytes()).get("status")
        if index == owner and status == "candidate_found":
            continue
        if status not in {"peer_confirmed", "worker_exhausted"}:
            return False
    return True


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    strict = bool(payload["strict_subset_of_complete_domain"])
    terminal = (
        "strict_subset_fullround_W52_recovery"
        if strict
        else "complete_domain_fullround_W52_recovery"
    )
    writer = CausalWriter(api_id="a455rec")
    writer._rules = []
    writer.add_rule(
        name="weighted_stream_to_factual_model",
        description="Execute the exact A454 BOOHH weighted pair stream as eight disjoint complete-cell streams.",
        pattern=["A454_qualified_recovery_stream_ready"],
        conclusion="A455_sole_factual_W52_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="factual_model_to_confirmed_recovery",
        description="Require dual-reference eight-block confirmation and an empty matched control.",
        pattern=["A455_sole_factual_W52_model"],
        conclusion=f"A455_{terminal}",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A454:qualified_recovery_stream_ready",
        mechanism="eight_disjoint_memory_mapped_complete_cell_streams",
        outcome="A455:sole_factual_W52_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["aggregate_execution"], sort_keys=True),
        evidence=json.dumps(payload["discovery"], sort_keys=True),
        domain="full-round ChaCha20 W52 residual-key recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A455:sole_factual_W52_model",
        mechanism="dual_reference_eight_block_confirmation_plus_empty_control",
        outcome=f"A455:{terminal}",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["rank_analysis"], sort_keys=True),
        evidence=json.dumps(payload["confirmation"], sort_keys=True),
        domain="independent full-round recovery confirmation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A454:qualified_recovery_stream_ready",
        mechanism="materialized_execution_and_confirmation_closure",
        outcome=f"A455:{terminal}",
        confidence=1.0,
        source="materialized:A455_weighted_W52_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A455 weighted portfolio Reader W52 recovery",
        entities=[
            "A454:qualified_recovery_stream_ready",
            "A455:sole_factual_W52_model",
            f"A455:{terminal}",
        ],
    )
    writer.add_gap(
        subject=f"A455:{terminal}",
        predicate="next_required_object",
        expected_object_type="fresh_cross_target_replication_or_W53_transfer",
        confidence=1.0,
        suggested_queries=[
            "Use the post-confirmation fused-versus-component ranks to choose fresh W52 replication or W53 expansion."
        ],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a455rec"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A455 authentic Causal reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(CAUSAL),
        "sha256": file_sha256(CAUSAL),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "reader_source": anchor(Path(inspect.getsourcefile(CausalReader) or "")),
        "writer_stats": stats,
        "personal_semantic_readback": {
            "execution": explicit[0],
            "confirmation": explicit[1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def finalize_confirmed_stop(
    protocol: Mapping[str, Any], qualification_sha256: str
) -> dict[str, Any]:
    if RESULT.exists():
        return {"status": "peer_confirmed", "result_sha256": file_sha256(RESULT)}
    stop = json.loads(STOP.read_bytes())
    if (
        stop.get("schema")
        != "chacha20-round20-w52-no-refit-weighted-reader-portfolio-recovery-a455-confirmed-stop-v1"
        or stop.get("attempt_id") != ATTEMPT_ID
        or stop.get("protocol_sha256") != file_sha256(PROTOCOL)
        or stop.get("A434_qualification_sha256") != qualification_sha256
        or stop.get("A454_result_commitment_sha256")
        != A454_RESULT_COMMITMENT_SHA256
        or stop.get("confirmation", {}).get("all_blocks_match") is not True
        or stop.get("discovery", {}).get("control_filter_candidates") != []
    ):
        raise RuntimeError("A455 confirmed stop fingerprint differs")
    while not active_started_workers_terminal():
        time.sleep(5)
    aggregate = progress_snapshot(file_sha256(PROTOCOL), qualification_sha256)
    unique_cells = int(aggregate["total_unique_pair_cells_evaluated"])
    if not 1 <= unique_cells <= PAIR_CELLS:
        raise RuntimeError("A455 aggregate unique pair-cell count differs")
    strict_subset = unique_cells < PAIR_CELLS
    aggregate["strict_subset_of_complete_domain"] = strict_subset
    aggregate["domain_reduction_factor"] = PAIR_CELLS / unique_cells
    aggregate["search_gain_bits"] = math.log2(PAIR_CELLS / unique_cells)
    discovery = stop["discovery"]
    source, stream, unused = load_source_schedule()
    prefix = int(discovery["prefix12"])
    off_axis = int(discovery["off_axis12"])
    global_index = pair_global_index(
        prefix, off_axis, stream, unused
    )
    if (
        global_index + 1 != int(discovery["global_rank_one_based"])
        or int(discovery["worker_index"]) != global_index % WORKERS
        or int(discovery["worker_step_one_based"]) != global_index // WORKERS + 1
    ):
        raise RuntimeError("A455 discovery rank identity differs")
    a449_row = source["anchors"]["A449_result"]
    a449_path = path_from_ref(a449_row["path"])
    anchor(a449_path, a449_row["sha256"])
    a449 = json.loads(a449_path.read_bytes())
    component_ranks: dict[str, int] = {}
    component_proposal_caps: dict[str, int] = {}
    selected_pattern = source["calibration"]["selected_pattern"]
    for symbol, name in A454.COMPONENTS.items():
        row = a449["operator_schedules"][name]
        rank = factorized_pair_global_index(
            prefix,
            off_axis,
            row["prefix_order"],
            row["off_axis_order"],
        ) + 1
        component_ranks[name] = rank
        slots = [
            index
            for index, item in enumerate(selected_pattern)
            if item == symbol
        ]
        zero_based = rank - 1
        proposal_key = (
            len(selected_pattern) * (zero_based // len(slots))
            + slots[zero_based % len(slots)]
        )
        component_proposal_caps[name] = min(PAIR_CELLS, proposal_key + 1)
    baseline = a449["operator_schedules"]["borda_sum_baseline"]
    a442_rank = factorized_pair_global_index(
        prefix,
        off_axis,
        baseline["prefix_order"],
        baseline["off_axis_order"],
    ) + 1
    minimum_component_rank = min(component_ranks.values())
    fused_rank = global_index + 1
    realized_regret_ratio = fused_rank / minimum_component_rank
    proposal_bound_satisfied = {
        name: fused_rank <= cap for name, cap in component_proposal_caps.items()
    }
    if not all(proposal_bound_satisfied.values()):
        raise RuntimeError("A455 realized A454 proposal bound failed")
    rank_analysis = {
        "prefix12": prefix,
        "off_axis12": off_axis,
        "weighted_reader_portfolio_global_pair_rank_one_based": fused_rank,
        "selected_pattern": selected_pattern,
        "component_global_pair_ranks_one_based": component_ranks,
        "component_proposal_caps_one_based": component_proposal_caps,
        "component_proposal_bounds_satisfied": proposal_bound_satisfied,
        "minimum_component_rank_one_based": minimum_component_rank,
        "realized_fused_over_best_component_rank_ratio": realized_regret_ratio,
        "all_exact_component_proposal_bounds_satisfied": all(
            proposal_bound_satisfied.values()
        ),
        "A442_global_pair_rank_one_based": a442_rank,
        "A442_over_fused_rank_ratio": a442_rank / fused_rank,
        "fused_gain_over_A442_bits": math.log2(a442_rank / fused_rank),
        "winning_worker_index": int(discovery["worker_index"]),
        "winning_worker_step_one_based": int(discovery["worker_step_one_based"]),
        "aggregate_unique_pair_cells_before_confirmed_stop": unique_cells,
        "ranks_computed_only_after_independent_confirmation": True,
    }
    evidence_stage = (
        "FULLROUND_R20_NO_REFIT_WEIGHTED_PORTFOLIO_W52_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_NO_REFIT_WEIGHTED_PORTFOLIO_W52_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-no-refit-weighted-reader-portfolio-recovery-a455-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "implementation_commitment_sha256": protocol[
            "implementation_commitment_sha256"
        ],
        "protocol_sha256": file_sha256(PROTOCOL),
        "protocol_commitment_sha256": protocol["protocol_commitment_sha256"],
        "A454_result_sha256": A454_RESULT_SHA256,
        "A454_result_commitment_sha256": A454_RESULT_COMMITMENT_SHA256,
        "A454_pair_stream_sha256": A454_PAIR_STREAM_SHA256,
        "A434_qualification_sha256": qualification_sha256,
        "A426_protocol_sha256": A426_PROTOCOL_SHA256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "discovery": discovery,
        "confirmation": stop["confirmation"],
        "aggregate_execution": aggregate,
        "rank_analysis": rank_analysis,
        "strict_subset_of_complete_domain": strict_subset,
        "matched_control_candidates": 0,
        "factual_candidates": 1,
        "all_8192_cross_implementation_output_bits_match": True,
        "complete_2pow28_pair_cell_before_stop": True,
        "early_stop_inside_pair_cell": False,
        "production_target_labels_used": 0,
        "production_feature_refits": 0,
        "production_model_refits": 0,
        "A452_candidate_progress_or_result_read": False,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(
                IMPLEMENTATION, protocol["implementation_sha256"]
            ),
            "protocol": anchor(PROTOCOL, file_sha256(PROTOCOL)),
            "confirmed_stop": anchor(STOP, file_sha256(STOP)),
            "A454_runner": anchor(A454_RUNNER, A454_RUNNER_SHA256),
            "A454_result": anchor(A454_RESULT, A454_RESULT_SHA256),
            "A454_pair_stream": anchor(
                A454_PAIR_STREAM, A454_PAIR_STREAM_SHA256
            ),
            "A454_causal": anchor(A454_CAUSAL, A454_CAUSAL_SHA256),
            "A454_personal_readback": anchor(
                A454_READBACK, A454_READBACK_SHA256
            ),
            "A449_result": anchor(a449_path, a449_row["sha256"]),
            "A434_qualification": anchor(
                A434_QUALIFICATION, qualification_sha256
            ),
            "A426_protocol": anchor(A426_PROTOCOL, A426_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    stable_discovery = {
        key: item
        for key, item in discovery.items()
        if not key.startswith("volatile_")
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "discovery": stable_discovery,
            "aggregate_execution": aggregate,
            "rank_analysis": rank_analysis,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {"confirmation": stop["confirmation"], "matched_control_candidates": 0}
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A455 — no-refit weighted portfolio Reader full-round ChaCha20 W52 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            "- Frozen schedule: **A454 target-blind BOOHH no-refit weighted reader portfolio**\n"
            f"- Exact unique 2^28 pair cells evaluated: **{unique_cells:,} / {PAIR_CELLS:,}**\n"
            f"- Complete assignments evaluated: **{aggregate['total_unique_assignments_evaluated']:,} / {DOMAIN_ASSIGNMENTS:,}**\n"
            f"- Search gain: **{aggregate['search_gain_bits']:.9f} bits**\n"
            f"- Weighted portfolio global pair rank: **{fused_rank:,}**\n"
            f"- Best component global pair rank: **{minimum_component_rank:,}**\n"
            f"- Realized fused/best-component ratio: **{realized_regret_ratio:.9f}**\n"
            f"- A442 global pair rank: **{a442_rank:,}**\n"
            f"- Weighted portfolio gain over A442: **{rank_analysis['fused_gain_over_A442_bits']:.9f} bits**\n"
            "- Factual / matched-control candidates: **1 / 0**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Independent confirmation: **two implementations, eight blocks, 8,192 checked output bits**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def recover_worker(
    *,
    worker_index: int,
    expected_protocol_sha256: str,
    expected_a434_qualification_sha256: str,
) -> dict[str, Any]:
    if not 0 <= worker_index < WORKERS:
        raise ValueError("A455 worker index differs")
    a435 = configure_runtime_shim()
    protocol = load_protocol(expected_protocol_sha256)
    load_a434_qualification(expected_a434_qualification_sha256)
    if RESULT.exists():
        return {"status": "peer_confirmed", "result_sha256": file_sha256(RESULT)}
    if STOP.exists():
        stop = json.loads(STOP.read_bytes())
        if int(stop.get("worker_index", -1)) == worker_index:
            return finalize_confirmed_stop(
                protocol, expected_a434_qualification_sha256
            )
        return mark_peer_confirmed(
            expected_protocol_sha256,
            expected_a434_qualification_sha256,
            worker_index,
        )
    _source, prefix_order, off_axis_order = load_source_schedule()
    a422 = a435.A422
    engine_protocol = a422.load_protocol(a435.A434.A422_PROTOCOL_SHA256)
    executable_row = engine_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    challenge = protocol["public_challenge"]
    a435.A426.validate_challenge(challenge)
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return a422.A390.A384.A378.A371.A346.A324.A311.A307.A304.GroupedMetalHost(
            executable,
            a422.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    role = f"weighted_portfolio_wave_{worker_index}"

    def write_progress(row: Mapping[str, Any]) -> None:
        normalized = normalize_worker_row(row, worker_index)
        atomic_json(
            progress_path(worker_index),
            {
                "schema": "chacha20-round20-w52-no-refit-weighted-reader-portfolio-recovery-a455-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "worker_index": worker_index,
                "protocol_sha256": expected_protocol_sha256,
                "A434_qualification_sha256": expected_a434_qualification_sha256,
                "A454_result_commitment_sha256": A454_RESULT_COMMITMENT_SHA256,
                "matched_control_candidates": 0,
                **normalized,
                "worker_role": role,
            },
        )

    start, prior_gpu, prior_hosts, completed = load_resume(
        worker_index=worker_index,
        protocol_sha256=expected_protocol_sha256,
        qualification_sha256=expected_a434_qualification_sha256,
    )
    if completed is not None:
        if completed.get("status") == "candidate_found" and not STOP.exists():
            discovery = completed
        elif STOP.exists():
            return recover_worker(
                worker_index=worker_index,
                expected_protocol_sha256=expected_protocol_sha256,
                expected_a434_qualification_sha256=expected_a434_qualification_sha256,
            )
        else:
            return completed
    else:
        write_progress(
            {
                "status": "running",
                "executed_worker_pair_cells": start,
                "worker_pair_cells": WORKER_TASKS,
                "executed_worker_assignments": start * CELL_ASSIGNMENTS,
                "static_parallel_depth": start,
                "factual_filter_candidates": 0,
                "gpu_seconds": prior_gpu,
                "host_instances": prior_hosts,
            }
        )
        discovery = ordered_worker_discovery(
            worker_index=worker_index,
            challenge=challenge,
            prefix_order=prefix_order,
            off_axis_order=off_axis_order,
            host_factory=host_factory,
            start_cell=start,
            prior_gpu_seconds=prior_gpu,
            prior_host_instances=prior_hosts,
            progress_callback=write_progress,
        )
    if discovery["status"] in {"peer_confirmed", "worker_exhausted"}:
        write_progress(discovery)
        if discovery["status"] == "worker_exhausted":
            exhausted = sum(
                progress_path(index).exists()
                and json.loads(progress_path(index).read_bytes()).get("status")
                == "worker_exhausted"
                for index in range(WORKERS)
            )
            if exhausted == WORKERS:
                raise RuntimeError("A455 all disjoint workers exhausted without a model")
        return discovery
    candidate = int(discovery["candidate"])
    confirmation = a435.A426.confirm(challenge, candidate)
    if confirmation.get("all_blocks_match") is not True:
        raise RuntimeError("A455 dual-reference eight-block confirmation failed")
    if discovery.get("control_filter_candidates") != []:
        raise RuntimeError("A455 matched control produced a candidate")
    if STOP.exists():
        return mark_peer_confirmed(
            expected_protocol_sha256,
            expected_a434_qualification_sha256,
            worker_index,
        )
    atomic_json(
        STOP,
        {
            "schema": "chacha20-round20-w52-no-refit-weighted-reader-portfolio-recovery-a455-confirmed-stop-v1",
            "attempt_id": ATTEMPT_ID,
            "protocol_sha256": expected_protocol_sha256,
            "A434_qualification_sha256": expected_a434_qualification_sha256,
            "A454_result_commitment_sha256": A454_RESULT_COMMITMENT_SHA256,
            "worker_index": worker_index,
            "worker_role": role,
            "discovery": discovery,
            "confirmation": confirmation,
        },
    )
    return finalize_confirmed_stop(protocol, expected_a434_qualification_sha256)


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": file_sha256(DESIGN) if DESIGN.exists() else None,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "result_complete": RESULT.exists(),
        "confirmed_stop_present": STOP.exists(),
        "pair_cells": PAIR_CELLS,
        "workers": WORKERS,
    }
    load_design()
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if PROTOCOL.exists():
        payload["protocol_sha256"] = file_sha256(PROTOCOL)
        load_protocol(payload["protocol_sha256"])
    payload["worker_progress"] = {
        str(index): (
            json.loads(progress_path(index).read_bytes()).get("status")
            if progress_path(index).exists()
            else "absent"
        )
        for index in range(WORKERS)
    }
    if RESULT.exists():
        payload["result_sha256"] = file_sha256(RESULT)
        stored = json.loads(RESULT.read_bytes())
        payload["evidence_stage"] = stored["evidence_stage"]
        payload["strict_subset_of_complete_domain"] = stored[
            "strict_subset_of_complete_domain"
        ]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-protocol", action="store_true")
    action.add_argument("--recover-worker", type=int)
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-a434-qualification-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_protocol:
        if not args.expected_implementation_sha256:
            parser.error("--freeze-protocol requires implementation hash")
        payload = freeze_protocol(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    elif args.recover_worker is not None:
        if not args.expected_protocol_sha256:
            parser.error("--recover-worker requires protocol hash")
        if not args.expected_a434_qualification_sha256:
            parser.error("--recover-worker requires A434 qualification hash")
        payload = recover_worker(
            worker_index=args.recover_worker,
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_a434_qualification_sha256=(
                args.expected_a434_qualification_sha256
            ),
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
