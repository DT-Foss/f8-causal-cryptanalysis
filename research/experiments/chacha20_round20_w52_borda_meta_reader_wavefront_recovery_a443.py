#!/usr/bin/env python3
"""A443: execute A442's Known-key-selected Borda W52 wavefront."""

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

STEM = "chacha20_round20_w52_borda_meta_reader_wavefront_recovery_a443"
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
A442_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_knownkey_meta_reader_transfer_a442.py"
)
A442_DESIGN = (
    CONFIGS
    / "chacha20_round20_w52_knownkey_meta_reader_transfer_a442_design_v1.json"
)
A442_IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w52_knownkey_meta_reader_transfer_a442_implementation_v1.json"
)
A442_RESULT = (
    RESULTS / "chacha20_round20_w52_knownkey_meta_reader_transfer_a442_v1.json"
)
A442_CAUSAL = A442_RESULT.with_suffix(".causal")
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

ATTEMPT_ID = "A443"
DESIGN_SHA256 = "16f12746ed7363879ae87f2f7b5371f95aac851d2e97c129910b2baea500f22b"
A435_RUNNER_SHA256 = "c9d355f1afda18b6a5f3367f56ba3d9d7658a2b3c3e79ce80d1e8618578fb3b6"
A435_IMPLEMENTATION_SHA256 = (
    "fd37e58b9786cafbe605fb1738204e815de610d20982b459b1007492615ee126"
)
A435_PROTOCOL_SHA256 = "a6616f0ce3ef8c92a67381e8d3c6acde649f0842d85ea7be9cc488e2182044cd"
A442_RUNNER_SHA256 = "436f0e2a35949bb2007e7da95ec1558c134c2c30c4d077e72b4d2da81de27314"
A442_DESIGN_SHA256 = "75715e8f0f6f9ecd89c4e2fcafe45f859945b58c5ce1ca162a6fc69c93cd5786"
A442_IMPLEMENTATION_SHA256 = (
    "9d1afe23e1ba57f6e21daaaad6014f8b1e4f95a007cfe3ed041ade07da5b0ee5"
)
A442_RESULT_SHA256 = "8c8222528dc3ef12ffc0fbda513061b39243daade51a70a17f0bd89c65b53b1d"
A442_CAUSAL_SHA256 = "89e079477ca230be5d2d6ba0231bf7833b29b5c6793076e5800622bf0b8ffb6b"
A442_RESULT_COMMITMENT_SHA256 = (
    "31c88ca1468c6fa1b6e789975f1f96ec0f1ba28c581569a66f8f0c69df26b98d"
)
A442_PAIR_STREAM_SHA256 = "b2b6e7a0b716083ae357e1dcde436a68e8ca64334ac5ec9009d74742989c6d48"
A442_PREFIX_ORDER_SHA256 = "7b7eea4c81a15d8dc5347d6affe4ef62702682eace6fd81c08586c477c60947e"
A442_OFF_AXIS_ORDER_SHA256 = "1c021823b0ed8a101adfaa67672a2b35a153ccc7f5953fa9852787ec1326d537"
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
        raise RuntimeError(f"cannot import A443 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A442 = load_module(A442_RUNNER, "a443_a442")
file_sha256 = A442.file_sha256
canonical_sha256 = A442.canonical_sha256
atomic_json = A442.atomic_json
atomic_bytes = A442.atomic_bytes
anchor = A442.anchor
path_from_ref = A442.path_from_ref
relative = A442.relative
_A435: Any | None = None


def runtime_a435() -> Any:
    global _A435
    if _A435 is None:
        anchor(A435_RUNNER, A435_RUNNER_SHA256)
        _A435 = load_module(A435_RUNNER, "a443_a435_runtime")
    return _A435


def progress_path(worker_index: int) -> Path:
    if not 0 <= worker_index < WORKERS:
        raise ValueError("A443 worker index differs")
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


def prior_progress_paths() -> list[Path]:
    values: list[Path] = []
    for stem in (
        "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426",
        "chacha20_round20_w52_dual_axis_square_wavefront_recovery_a435",
        "chacha20_round20_w52_calibration_balanced_wavefront_recovery_a438",
        "chacha20_round20_w52_wide_consensus_wavefront_recovery_a440",
    ):
        values.extend(
            RESULTS / f"{stem}_worker_{index}_progress_v1.json"
            for index in range(WORKERS)
        )
    return values


def assert_no_prior_target_outcome() -> None:
    result_stems = (
        "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426",
        "chacha20_round20_w52_dual_axis_square_wavefront_recovery_a435",
        "chacha20_round20_w52_calibration_balanced_wavefront_recovery_a438",
        "chacha20_round20_w52_wide_consensus_wavefront_recovery_a440",
    )
    outcomes = [
        path
        for stem in result_stems
        for path in (
            RESULTS / f"{stem}_v1.json",
            RESULTS / f"{stem}_confirmed_stop_v1.json",
        )
    ]
    if any(path.exists() for path in (*outcomes, *prior_progress_paths())):
        raise RuntimeError(
            "A443 freeze must precede A426/A435/A438/A440 outcomes or progress"
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
        != "chacha20-round20-w52-borda-meta-reader-wavefront-recovery-a443-design-v1"
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
        or schedule.get("source_attempt") != "A442"
        or schedule.get("source_selected_operator") != "borda_sum"
        or schedule.get("source_result_commitment_sha256")
        != A442_RESULT_COMMITMENT_SHA256
        or schedule.get("source_pair_stream_uint16be_uint16be_sha256")
        != A442_PAIR_STREAM_SHA256
        or schedule.get("prefix_axis_order_sha256") != A442_PREFIX_ORDER_SHA256
        or schedule.get("off_axis_order_sha256") != A442_OFF_AXIS_ORDER_SHA256
        or schedule.get("knownkey_positive_fixed_blocks") != 8
        or schedule.get("material_pair_diversity") is not True
        or schedule.get("W52_true_pair_rank_known_at_freeze") is not False
        or schedule.get("target_labels_used") != 0
        or schedule.get("reader_refits") != 0
        or engine.get("A442_borda_meta_reader_pair_order_used") is not True
        or engine.get("prior_candidate_progress_or_outcome_consumed") is not False
        or challenge.get("source_attempt") != "A426"
        or challenge.get("secret_assignment_absent_from_protocol") is not True
        or queue.get("A443_runs_after_terminal_A438") is not True
        or queue.get("A443_runs_before_A440") is not True
        or boundary.get(
            "A442_result_and_authentic_Causal_personally_read_at_design_freeze"
        )
        is not True
        or boundary.get("A434_qualification_available_at_design_freeze") is not False
        or boundary.get("A443_candidate_or_progress_available_at_design_freeze")
        is not False
        or boundary.get("A443_target_labels_used_for_schedule") != 0
        or boundary.get("A443_reader_refits") != 0
        or boundary.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A443 frozen design semantics differ")
    sources = value["source_anchors"]
    for key, item in sources.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, sources[f"{stem}_sha256"])
    return value


def load_source_schedule() -> tuple[dict[str, Any], list[int], list[int]]:
    anchor(A442_RUNNER, A442_RUNNER_SHA256)
    anchor(A442_DESIGN, A442_DESIGN_SHA256)
    anchor(A442_IMPLEMENTATION, A442_IMPLEMENTATION_SHA256)
    anchor(A442_RESULT, A442_RESULT_SHA256)
    anchor(A442_CAUSAL, A442_CAUSAL_SHA256)
    packaged = A442.load_result(A442_RESULT_SHA256)
    prefix = [int(value) for value in packaged["prefix_order"]]
    off_axis = [int(value) for value in packaged["off_axis_order"]]
    A442.exact_order(prefix, AXIS_CELLS)
    A442.exact_order(off_axis, AXIS_CELLS)
    if (
        packaged.get("schema")
        != "chacha20-round20-w52-knownkey-meta-reader-transfer-a442-v1"
        or packaged.get("result_commitment_sha256")
        != A442_RESULT_COMMITMENT_SHA256
        or packaged.get("selected_operator") != "borda_sum"
        or packaged.get("pair_stream_uint16be_uint16be_sha256")
        != A442_PAIR_STREAM_SHA256
        or packaged.get("material_pair_diversity") is not True
        or packaged.get("target_labels_used_for_W52") != 0
        or packaged.get("reader_refits_on_W52") != 0
        or packaged.get("candidate_assignments_executed") != 0
        or A442.order_sha256(prefix) != A442_PREFIX_ORDER_SHA256
        or A442.order_sha256(off_axis) != A442_OFF_AXIS_ORDER_SHA256
        or len(prefix) * len(off_axis) != PAIR_CELLS
    ):
        raise RuntimeError("A443 A442 source schedule differs")
    return packaged, prefix, off_axis


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
        raise RuntimeError("A443 A426 public challenge scope differs")
    return a426, challenge


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists() or not no_downstream_artifacts():
        raise FileExistsError("A443 implementation or downstream artifact exists")
    assert_no_prior_target_outcome()
    if A434_QUALIFICATION.exists():
        raise RuntimeError("A443 implementation freeze must precede A434 qualification")
    design = load_design()
    source, prefix, off_axis = load_source_schedule()
    a426, _challenge = load_public_challenge()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A443 tests and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-borda-meta-reader-wavefront-recovery-a443-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_restart_safe_eight_worker_A442_borda_executor_frozen_before_A434_qualification_A426_A435_A438_A440_outcome_or_any_A443_candidate_progress_or_filter_outcome",
        "design_sha256": DESIGN_SHA256,
        "execution_contract": design["execution_contract"],
        "schedule_transfer_contract": design["schedule_transfer_contract"],
        "engine_reuse_contract": design["engine_reuse_contract"],
        "source_A442_result_sha256": A442_RESULT_SHA256,
        "source_A442_result_commitment_sha256": source[
            "result_commitment_sha256"
        ],
        "source_A442_pair_stream_sha256": source[
            "pair_stream_uint16be_uint16be_sha256"
        ],
        "source_A442_prefix_order_sha256": source["W52_transfer"]["prefix"][
            "order_uint16be_sha256"
        ],
        "source_A442_off_axis_order_sha256": source["W52_transfer"]["off_axis"][
            "order_uint16be_sha256"
        ],
        "source_A426_protocol_sha256": A426_PROTOCOL_SHA256,
        "source_A426_public_challenge_sha256": a426["public_challenge_sha256"],
        "source_pair_cells": len(prefix) * len(off_axis),
        "A434_qualification_available_at_freeze": False,
        "A426_A435_A438_A440_outcome_or_progress_available_at_freeze": False,
        "A443_candidate_or_progress_available_at_freeze": False,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A435_runner": anchor(A435_RUNNER, A435_RUNNER_SHA256),
            "A435_implementation": anchor(
                A435_IMPLEMENTATION, A435_IMPLEMENTATION_SHA256
            ),
            "A435_protocol": anchor(A435_PROTOCOL, A435_PROTOCOL_SHA256),
            "A442_runner": anchor(A442_RUNNER, A442_RUNNER_SHA256),
            "A442_design": anchor(A442_DESIGN, A442_DESIGN_SHA256),
            "A442_implementation": anchor(
                A442_IMPLEMENTATION, A442_IMPLEMENTATION_SHA256
            ),
            "A442_result": anchor(A442_RESULT, A442_RESULT_SHA256),
            "A442_causal": anchor(A442_CAUSAL, A442_CAUSAL_SHA256),
            "A426_protocol": anchor(A426_PROTOCOL, A426_PROTOCOL_SHA256),
            "A426_runner": anchor(A426_RUNNER, A426_RUNNER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    assert_no_prior_target_outcome()
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    anchor(IMPLEMENTATION, expected_sha256)
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-borda-meta-reader-wavefront-recovery-a443-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("source_A442_result_sha256") != A442_RESULT_SHA256
        or value.get("source_A442_result_commitment_sha256")
        != A442_RESULT_COMMITMENT_SHA256
        or value.get("source_A442_pair_stream_sha256")
        != A442_PAIR_STREAM_SHA256
        or value.get("source_A442_prefix_order_sha256")
        != A442_PREFIX_ORDER_SHA256
        or value.get("source_A442_off_axis_order_sha256")
        != A442_OFF_AXIS_ORDER_SHA256
        or value.get("source_A426_protocol_sha256") != A426_PROTOCOL_SHA256
        or value.get("source_pair_cells") != PAIR_CELLS
        or value.get("A434_qualification_available_at_freeze") is not False
        or value.get("A426_A435_A438_A440_outcome_or_progress_available_at_freeze")
        is not False
        or value.get("A443_candidate_or_progress_available_at_freeze") is not False
        or value.get("production_target_labels_used") != 0
        or value.get("production_reader_refits") != 0
        or value.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A443 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A443 implementation commitment differs")
    return value


def square_pair_at(
    global_index: int,
    prefix_order: Sequence[int],
    off_axis_order: Sequence[int],
) -> tuple[int, int]:
    if not 0 <= global_index < PAIR_CELLS:
        raise ValueError("A443 global pair index differs")
    prefix = A442.exact_order(prefix_order, AXIS_CELLS)
    off_axis = A442.exact_order(off_axis_order, AXIS_CELLS)
    shell = math.isqrt(global_index)
    offset = global_index - shell * shell
    if offset <= shell:
        return int(prefix[shell]), int(off_axis[offset])
    return int(prefix[offset - shell - 1]), int(off_axis[shell])


def pair_global_index(
    prefix: int,
    off_axis: int,
    prefix_order: Sequence[int],
    off_axis_order: Sequence[int],
) -> int:
    prefix_values = [int(value) for value in prefix_order]
    off_values = [int(value) for value in off_axis_order]
    if not 0 <= prefix < AXIS_CELLS or not 0 <= off_axis < AXIS_CELLS:
        raise ValueError("A443 pair coordinate differs")
    left = prefix_values.index(prefix)
    right = off_values.index(off_axis)
    shell = max(left, right)
    if left == shell:
        index = shell * shell + right
    else:
        index = shell * shell + shell + 1 + left
    if square_pair_at(index, prefix_values, off_values) != (prefix, off_axis):
        raise RuntimeError("A443 square-wavefront inverse identity failed")
    return index


def freeze_protocol(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if not no_downstream_artifacts():
        raise FileExistsError("A443 protocol or execution artifact exists")
    assert_no_prior_target_outcome()
    if A434_QUALIFICATION.exists():
        raise RuntimeError("A443 protocol freeze must precede A434 qualification")
    implementation = load_implementation(expected_implementation_sha256)
    source, prefix, off_axis = load_source_schedule()
    a426, challenge = load_public_challenge()
    sentinels = []
    for index in (0, 1, 7, 8, 255, PAIR_CELLS // 2, PAIR_CELLS - 1):
        left, right = square_pair_at(index, prefix, off_axis)
        sentinels.append(
            {"global_index": index, "prefix": left, "off_axis": right}
        )
    schedule = {
        "algorithm": "A442_knownkey_selected_borda_dual_axis_square_wavefront",
        "selected_meta_operator": "borda_sum",
        "pair_stream_uint16be_uint16be_sha256": A442_PAIR_STREAM_SHA256,
        "A442_result_commitment_sha256": A442_RESULT_COMMITMENT_SHA256,
        "prefix_order_uint16be_sha256": A442_PREFIX_ORDER_SHA256,
        "off_axis_order_uint16be_sha256": A442_OFF_AXIS_ORDER_SHA256,
        "knownkey_minimum_fixed_block_bit_gain": source["selected_evaluation"][
            "minimum_fixed_block_bit_gain"
        ],
        "knownkey_balanced_two_corpus_bit_gain": source["selected_evaluation"][
            "balanced_two_corpus_bit_gain"
        ],
        "pair_spearman_to_A439": source["pair_comparison_to_A439"][
            "spearman_rank_correlation"
        ],
        "top65536_intersection_with_A439": source["pair_comparison_to_A439"][
            "top_k_overlap"
        ]["65536"]["intersection"],
        "pair_cells": PAIR_CELLS,
        "assignments_per_complete_pair_cell": CELL_ASSIGNMENTS,
        "complete_domain_assignments": DOMAIN_ASSIGNMENTS,
        "workers": WORKERS,
        "worker_tasks_each": WORKER_TASKS,
        "worker_global_index_formula": "worker_index + 8 * zero_based_worker_step",
        "worker_role_formula": "borda_meta_wave_{worker_index}",
        "pair_at_formula": "square_pair_at(global_index,A442_prefix_order,A442_off_axis_order)",
        "complete_cover_identity": "disjoint residues modulo 8 over [0,2^24)",
        "direct_inverse_sentinels": sentinels,
        "first_pair": dict(
            zip(("prefix", "off_axis"), square_pair_at(0, prefix, off_axis), strict=True)
        ),
        "last_pair": dict(
            zip(
                ("prefix", "off_axis"),
                square_pair_at(PAIR_CELLS - 1, prefix, off_axis),
                strict=True,
            )
        ),
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-borda-meta-reader-wavefront-recovery-a443-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "A442_exact_borda_square_schedule_and_A426_public_challenge_bound_before_A434_qualification_A426_A435_A438_A440_outcome_or_any_A443_candidate_progress_or_filter_outcome",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "A442_result_sha256": A442_RESULT_SHA256,
        "A442_result_commitment_sha256": A442_RESULT_COMMITMENT_SHA256,
        "A426_protocol_sha256": A426_PROTOCOL_SHA256,
        "public_challenge": challenge,
        "public_challenge_sha256": a426["public_challenge_sha256"],
        "schedule": schedule,
        "schedule_commitment_sha256": canonical_sha256(schedule),
        "worker_roles": [f"borda_meta_wave_{index}" for index in range(WORKERS)],
        "information_boundary": {
            "A442_schedule_frozen_before_A443_challenge_binding": True,
            "A434_qualification_available_at_A443_protocol_freeze": False,
            "A426_assignment_absent_from_protocol": True,
            "A426_A435_A438_A440_candidate_progress_or_outcome_available_at_freeze": False,
            "A443_candidate_or_progress_available_at_protocol_freeze": False,
            "A443_target_labels_used_for_schedule": 0,
            "A443_reader_refits": 0,
            "prior_live_recovery_filter_outcomes_consumed": False,
        },
        "production_execution_enabled": False,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(
                IMPLEMENTATION, expected_implementation_sha256
            ),
            "A442_runner": anchor(A442_RUNNER, A442_RUNNER_SHA256),
            "A442_design": anchor(A442_DESIGN, A442_DESIGN_SHA256),
            "A442_implementation": anchor(
                A442_IMPLEMENTATION, A442_IMPLEMENTATION_SHA256
            ),
            "A442_result": anchor(A442_RESULT, A442_RESULT_SHA256),
            "A442_causal": anchor(A442_CAUSAL, A442_CAUSAL_SHA256),
            "A426_protocol": anchor(A426_PROTOCOL, A426_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(PROTOCOL, payload)
    assert_no_prior_target_outcome()
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    anchor(PROTOCOL, expected_sha256)
    value = json.loads(PROTOCOL.read_bytes())
    boundary = value.get("information_boundary", {})
    schedule = value.get("schedule", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-borda-meta-reader-wavefront-recovery-a443-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A442_result_sha256") != A442_RESULT_SHA256
        or value.get("A442_result_commitment_sha256")
        != A442_RESULT_COMMITMENT_SHA256
        or value.get("A426_protocol_sha256") != A426_PROTOCOL_SHA256
        or schedule.get("algorithm")
        != "A442_knownkey_selected_borda_dual_axis_square_wavefront"
        or schedule.get("selected_meta_operator") != "borda_sum"
        or schedule.get("pair_stream_uint16be_uint16be_sha256")
        != A442_PAIR_STREAM_SHA256
        or schedule.get("A442_result_commitment_sha256")
        != A442_RESULT_COMMITMENT_SHA256
        or schedule.get("prefix_order_uint16be_sha256")
        != A442_PREFIX_ORDER_SHA256
        or schedule.get("off_axis_order_uint16be_sha256")
        != A442_OFF_AXIS_ORDER_SHA256
        or schedule.get("pair_cells") != PAIR_CELLS
        or schedule.get("assignments_per_complete_pair_cell") != CELL_ASSIGNMENTS
        or schedule.get("complete_domain_assignments") != DOMAIN_ASSIGNMENTS
        or schedule.get("workers") != WORKERS
        or schedule.get("worker_tasks_each") != WORKER_TASKS
        or value.get("schedule_commitment_sha256") != canonical_sha256(schedule)
        or value.get("worker_roles")
        != [f"borda_meta_wave_{index}" for index in range(WORKERS)]
        or boundary.get("A442_schedule_frozen_before_A443_challenge_binding")
        is not True
        or boundary.get("A434_qualification_available_at_A443_protocol_freeze")
        is not False
        or boundary.get("A426_assignment_absent_from_protocol") is not True
        or boundary.get(
            "A426_A435_A438_A440_candidate_progress_or_outcome_available_at_freeze"
        )
        is not False
        or boundary.get("A443_candidate_or_progress_available_at_protocol_freeze")
        is not False
        or boundary.get("A443_target_labels_used_for_schedule") != 0
        or boundary.get("A443_reader_refits") != 0
        or boundary.get("prior_live_recovery_filter_outcomes_consumed") is not False
        or value.get("production_execution_enabled") is not False
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A443 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_implementation(value["implementation_sha256"])
    source, prefix, off_axis = load_source_schedule()
    a426, _challenge = load_public_challenge()
    if (
        schedule["pair_stream_uint16be_uint16be_sha256"]
        != source["pair_stream_uint16be_uint16be_sha256"]
        or schedule["prefix_order_uint16be_sha256"] != A442.order_sha256(prefix)
        or schedule["off_axis_order_uint16be_sha256"]
        != A442.order_sha256(off_axis)
        or value["public_challenge"] != a426["public_challenge"]
        or value["public_challenge_sha256"]
        != canonical_sha256(value["public_challenge"])
    ):
        raise RuntimeError("A443 source binding differs")
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "protocol_commitment_sha256"
    }
    if value.get("protocol_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A443 protocol commitment differs")
    return value


def load_a434_qualification(expected_sha256: str) -> dict[str, Any]:
    return runtime_a435().load_a434_qualification(expected_sha256)


def worker_global_index(worker_index: int, zero_based_worker_step: int) -> int:
    if not 0 <= worker_index < WORKERS:
        raise ValueError("A443 worker index differs")
    if not 0 <= zero_based_worker_step < WORKER_TASKS:
        raise ValueError("A443 worker step differs")
    return worker_index + WORKERS * zero_based_worker_step


def worker_pair_at(
    worker_index: int,
    zero_based_worker_step: int,
    prefix_order: Sequence[int],
    off_axis_order: Sequence[int],
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
    value["worker_role"] = f"borda_meta_wave_{worker_index}"
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
        != "chacha20-round20-w52-borda-meta-reader-wavefront-recovery-a443-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("worker_index") != worker_index
        or value.get("worker_role") != f"borda_meta_wave_{worker_index}"
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("A434_qualification_sha256") != qualification_sha256
        or value.get("A442_result_commitment_sha256")
        != A442_RESULT_COMMITMENT_SHA256
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A443 progress fingerprint differs")
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
        raise RuntimeError("A443 resumable progress state differs")
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
    prefix_order: Sequence[int],
    off_axis_order: Sequence[int],
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
        or value.get("worker_role") != f"borda_meta_wave_{worker_index}"
        or value.get("A442_result_commitment_sha256")
        != A442_RESULT_COMMITMENT_SHA256
    ):
        raise RuntimeError("A443 peer progress fingerprint differs")
    if value.get("status") in {"running", "peer_confirmed"}:
        value["status"] = "peer_confirmed"
        value["factual_filter_candidates"] = 0
        value["confirmed_stop_sha256"] = file_sha256(STOP)
        atomic_json(path, value)
    elif value.get("status") not in {"worker_exhausted", "candidate_found"}:
        raise RuntimeError("A443 peer progress status differs")
    return {"status": "peer_confirmed", "worker_index": worker_index}


def progress_snapshot(protocol_sha256: str, qualification_sha256: str) -> dict[str, Any]:
    panel: dict[str, Any] = {}
    total = 0
    max_depth = 0
    all_controls_empty = True
    for index in range(WORKERS):
        role = f"borda_meta_wave_{index}"
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
            or value.get("A442_result_commitment_sha256")
            != A442_RESULT_COMMITMENT_SHA256
        ):
            raise RuntimeError("A443 progress snapshot fingerprint differs")
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
    writer = CausalWriter(api_id="a443recover")
    writer._rules = []
    writer.add_rule(
        name="orthogonal_borda_schedule_to_factual_model",
        description="Execute the exact A442 Borda pair order as eight disjoint complete-cell streams.",
        pattern=["A442_orthogonal_W52_recovery_ready"],
        conclusion="A443_sole_factual_W52_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="factual_model_to_confirmed_recovery",
        description="Require dual-reference eight-block confirmation and an empty matched control.",
        pattern=["A443_sole_factual_W52_model"],
        conclusion=f"A443_{terminal}",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A442:orthogonal_W52_recovery_ready",
        mechanism="eight_disjoint_complete_cell_borda_wavefront_execution",
        outcome="A443:sole_factual_W52_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["aggregate_execution"], sort_keys=True),
        evidence=json.dumps(payload["discovery"], sort_keys=True),
        domain="full-round ChaCha20 W52 residual-key recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A443:sole_factual_W52_model",
        mechanism="dual_reference_eight_block_confirmation_plus_empty_control",
        outcome=f"A443:{terminal}",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["rank_analysis"], sort_keys=True),
        evidence=json.dumps(payload["confirmation"], sort_keys=True),
        domain="independent full-round recovery confirmation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A442:orthogonal_W52_recovery_ready",
        mechanism="materialized_execution_and_confirmation_closure",
        outcome=f"A443:{terminal}",
        confidence=1.0,
        source="materialized:A443_borda_W52_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A443 Borda meta-Reader W52 recovery",
        entities=[
            "A442:orthogonal_W52_recovery_ready",
            "A443:sole_factual_W52_model",
            f"A443:{terminal}",
        ],
    )
    writer.add_gap(
        subject=f"A443:{terminal}",
        predicate="next_required_object",
        expected_object_type="fresh_cross_target_replication_or_W53_transfer",
        confidence=1.0,
        suggested_queries=[
            "Use the post-confirmation Borda and A439 ranks to choose fresh W52 replication or W53 expansion."
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
        reader.api_id != "a443recover"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A443 authentic Causal reopen gate failed")
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
        != "chacha20-round20-w52-borda-meta-reader-wavefront-recovery-a443-confirmed-stop-v1"
        or stop.get("attempt_id") != ATTEMPT_ID
        or stop.get("protocol_sha256") != file_sha256(PROTOCOL)
        or stop.get("A434_qualification_sha256") != qualification_sha256
        or stop.get("A442_result_commitment_sha256")
        != A442_RESULT_COMMITMENT_SHA256
        or stop.get("confirmation", {}).get("all_blocks_match") is not True
        or stop.get("discovery", {}).get("control_filter_candidates") != []
    ):
        raise RuntimeError("A443 confirmed stop fingerprint differs")
    while not active_started_workers_terminal():
        time.sleep(5)
    aggregate = progress_snapshot(file_sha256(PROTOCOL), qualification_sha256)
    unique_cells = int(aggregate["total_unique_pair_cells_evaluated"])
    if not 1 <= unique_cells <= PAIR_CELLS:
        raise RuntimeError("A443 aggregate unique pair-cell count differs")
    strict_subset = unique_cells < PAIR_CELLS
    aggregate["strict_subset_of_complete_domain"] = strict_subset
    aggregate["domain_reduction_factor"] = PAIR_CELLS / unique_cells
    aggregate["search_gain_bits"] = math.log2(PAIR_CELLS / unique_cells)
    discovery = stop["discovery"]
    source, prefix_order, off_axis_order = load_source_schedule()
    prefix = int(discovery["prefix12"])
    off_axis = int(discovery["off_axis12"])
    global_index = pair_global_index(
        prefix, off_axis, prefix_order, off_axis_order
    )
    prefix_rank = prefix_order.index(prefix) + 1
    off_axis_rank = off_axis_order.index(off_axis) + 1
    if (
        global_index + 1 != int(discovery["global_rank_one_based"])
        or int(discovery["worker_index"]) != global_index % WORKERS
        or int(discovery["worker_step_one_based"]) != global_index // WORKERS + 1
    ):
        raise RuntimeError("A443 discovery rank identity differs")
    a439_row = source["anchors"]["A439_result"]
    a439_path = path_from_ref(a439_row["path"])
    anchor(a439_path, a439_row["sha256"])
    a439 = json.loads(a439_path.read_bytes())
    a439_prefix = [int(value) for value in a439["axes"]["prefix"]["portfolio_order"]]
    a439_off_axis = [
        int(value) for value in a439["axes"]["off_axis"]["portfolio_order"]
    ]
    a439_global_index = pair_global_index(
        prefix, off_axis, a439_prefix, a439_off_axis
    )
    rank_analysis = {
        "prefix12": prefix,
        "off_axis12": off_axis,
        "borda_prefix_rank_one_based": prefix_rank,
        "borda_off_axis_rank_one_based": off_axis_rank,
        "borda_global_pair_rank_one_based": global_index + 1,
        "A439_global_pair_rank_one_based": a439_global_index + 1,
        "A439_over_borda_rank_ratio": (a439_global_index + 1) / (global_index + 1),
        "borda_gain_over_A439_bits": math.log2(
            (a439_global_index + 1) / (global_index + 1)
        ),
        "winning_worker_index": int(discovery["worker_index"]),
        "winning_worker_step_one_based": int(discovery["worker_step_one_based"]),
        "aggregate_unique_pair_cells_before_confirmed_stop": unique_cells,
        "ranks_computed_only_after_independent_confirmation": True,
    }
    evidence_stage = (
        "FULLROUND_R20_BORDA_META_READER_W52_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_BORDA_META_READER_W52_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-borda-meta-reader-wavefront-recovery-a443-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "implementation_commitment_sha256": protocol[
            "implementation_commitment_sha256"
        ],
        "protocol_sha256": file_sha256(PROTOCOL),
        "protocol_commitment_sha256": protocol["protocol_commitment_sha256"],
        "A442_result_sha256": A442_RESULT_SHA256,
        "A442_result_commitment_sha256": A442_RESULT_COMMITMENT_SHA256,
        "A442_pair_stream_sha256": A442_PAIR_STREAM_SHA256,
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
        "production_reader_refits": 0,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(
                IMPLEMENTATION, protocol["implementation_sha256"]
            ),
            "protocol": anchor(PROTOCOL, file_sha256(PROTOCOL)),
            "confirmed_stop": anchor(STOP, file_sha256(STOP)),
            "A442_runner": anchor(A442_RUNNER, A442_RUNNER_SHA256),
            "A442_result": anchor(A442_RESULT, A442_RESULT_SHA256),
            "A442_causal": anchor(A442_CAUSAL, A442_CAUSAL_SHA256),
            "A439_result": anchor(a439_path, a439_row["sha256"]),
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
            "# A443 — Borda meta-Reader full-round ChaCha20 W52 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            "- Frozen schedule: **A442 Known-key-selected Borda dual-axis wavefront**\n"
            f"- Exact unique 2^28 pair cells evaluated: **{unique_cells:,} / {PAIR_CELLS:,}**\n"
            f"- Complete assignments evaluated: **{aggregate['total_unique_assignments_evaluated']:,} / {DOMAIN_ASSIGNMENTS:,}**\n"
            f"- Search gain: **{aggregate['search_gain_bits']:.9f} bits**\n"
            f"- Borda prefix / off-axis ranks: **{prefix_rank} / {off_axis_rank}**\n"
            f"- Borda global pair rank: **{global_index + 1:,}**\n"
            f"- A439 global pair rank: **{a439_global_index + 1:,}**\n"
            f"- Borda gain over A439: **{rank_analysis['borda_gain_over_A439_bits']:.9f} bits**\n"
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
        raise ValueError("A443 worker index differs")
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

    role = f"borda_meta_wave_{worker_index}"

    def write_progress(row: Mapping[str, Any]) -> None:
        normalized = normalize_worker_row(row, worker_index)
        atomic_json(
            progress_path(worker_index),
            {
                "schema": "chacha20-round20-w52-borda-meta-reader-wavefront-recovery-a443-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "worker_index": worker_index,
                "protocol_sha256": expected_protocol_sha256,
                "A434_qualification_sha256": expected_a434_qualification_sha256,
                "A442_result_commitment_sha256": A442_RESULT_COMMITMENT_SHA256,
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
                raise RuntimeError("A443 all disjoint workers exhausted without a model")
        return discovery
    candidate = int(discovery["candidate"])
    confirmation = a435.A426.confirm(challenge, candidate)
    if confirmation.get("all_blocks_match") is not True:
        raise RuntimeError("A443 dual-reference eight-block confirmation failed")
    if discovery.get("control_filter_candidates") != []:
        raise RuntimeError("A443 matched control produced a candidate")
    if STOP.exists():
        return mark_peer_confirmed(
            expected_protocol_sha256,
            expected_a434_qualification_sha256,
            worker_index,
        )
    atomic_json(
        STOP,
        {
            "schema": "chacha20-round20-w52-borda-meta-reader-wavefront-recovery-a443-confirmed-stop-v1",
            "attempt_id": ATTEMPT_ID,
            "protocol_sha256": expected_protocol_sha256,
            "A434_qualification_sha256": expected_a434_qualification_sha256,
            "A442_result_commitment_sha256": A442_RESULT_COMMITMENT_SHA256,
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
