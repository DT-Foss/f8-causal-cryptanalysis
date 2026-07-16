#!/usr/bin/env python3
"""A438: execute A437's calibration-balanced W52 wavefront on the A426 challenge."""

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

STEM = "chacha20_round20_w52_calibration_balanced_wavefront_recovery_a438"
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
    RESEARCH / "experiments/chacha20_round20_w52_dual_axis_square_wavefront_recovery_a435.py"
)
A435_IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w52_dual_axis_square_wavefront_recovery_a435_implementation_v1.json"
)
A435_PROTOCOL = (
    CONFIGS / "chacha20_round20_w52_dual_axis_square_wavefront_recovery_a435_v1.json"
)
A435_RESULT = (
    RESULTS / "chacha20_round20_w52_dual_axis_square_wavefront_recovery_a435_v1.json"
)
A435_STOP = (
    RESULTS
    / "chacha20_round20_w52_dual_axis_square_wavefront_recovery_a435_confirmed_stop_v1.json"
)
A437_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437.py"
)
A437_PROTOCOL = (
    CONFIGS / "chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_v1.json"
)
A437_V2_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_v2.py"
)
A437_V2_PROTOCOL = (
    CONFIGS / "chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_v2.json"
)
A437_V2_RESULT = (
    RESULTS / "chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_v2.json"
)
A437_V2_CAUSAL = A437_V2_RESULT.with_suffix(".causal")
A434_QUALIFICATION = (
    RESULTS / "chacha20_round20_w52_dual_axis_square_wavefront_a434_qualification_v1.json"
)
A426_PROTOCOL = CONFIGS / "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_v1.json"
A426_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426.py"
)
A426_RESULT = RESULTS / "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_v1.json"
A426_STOP = (
    RESULTS / "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_confirmed_stop_v1.json"
)

ATTEMPT_ID = "A438"
DESIGN_SHA256 = "3c71a84e5b9f463f47e7eac3d341562525a5e23b8c37506aec56f666e0802b62"
A435_RUNNER_SHA256 = "c9d355f1afda18b6a5f3367f56ba3d9d7658a2b3c3e79ce80d1e8618578fb3b6"
A435_IMPLEMENTATION_SHA256 = (
    "fd37e58b9786cafbe605fb1738204e815de610d20982b459b1007492615ee126"
)
A435_PROTOCOL_SHA256 = "a6616f0ce3ef8c92a67381e8d3c6acde649f0842d85ea7be9cc488e2182044cd"
A437_RUNNER_SHA256 = "57a2889bb3dcdd2592e19b20fbb626fac706982ddf6bcc99e6a58fb8e83bdad7"
A437_PROTOCOL_SHA256 = "30652dc6a24838568b22ebe01bca367264c9b65f2cf20d3b3281994936b89685"
A437_V2_RUNNER_SHA256 = "e6bb01ee2ba114d69c157d72dd381ab9daf3226bf41d797e9964d6f46ba09538"
A437_V2_PROTOCOL_SHA256 = (
    "ce224ed6093ac5c225bf636008f573204e2455c69cb4e71548f511b88d1bb001"
)
A437_V2_RESULT_SHA256 = "a484e7b79831bcfbde0205f5009ee7103cb8047022009c00f4d6a5cff3c5b80e"
A437_V2_CAUSAL_SHA256 = "42a05c65a3951ad730a49be665a40c58400b62ae0ea36bd9c67a3cb296e3a6dc"
A437_SCHEDULE_COMMITMENT_SHA256 = (
    "79b3e2c0fe0a7aecc4f18e505ab6454cba96923033df319df7ca3ff8ed5ff401"
)
A437_PAIR_STREAM_SHA256 = "6fec353dd64c98d3956c5308995e4cea1ee50cbd5a96436c67bbd426091d12aa"
A426_PROTOCOL_SHA256 = "746c880115464383247ee0ef8d52d6095195f26fa4b69178a8de281cd4c483a3"
A426_RUNNER_SHA256 = "d849065a0bc33f1d3eff3f5b7638948c86b683f8020bfd8a0f5ed0e9ca449637"

WIDTH = 52
KNOWN_KEY_BITS = 256 - WIDTH
PAIR_CELLS = 1 << 24
CELL_ASSIGNMENTS = 1 << 28
DOMAIN_ASSIGNMENTS = 1 << WIDTH
WORKERS = 8
WORKER_TASKS = PAIR_CELLS // WORKERS
HOST_REFRESH_CELLS = 1
BLOCK_COUNT = 8
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A438 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A435 = load_module(A435_RUNNER, "a438_a435")
A437 = load_module(A437_RUNNER, "a438_a437")
A437V2 = load_module(A437_V2_RUNNER, "a438_a437_v2")
A422 = A435.A422
A426 = A435.A426
file_sha256 = A435.file_sha256
canonical_sha256 = A435.canonical_sha256
atomic_json = A435.atomic_json
anchor = A435.anchor
path_from_ref = A435.path_from_ref
relative = A435.relative
atomic_bytes = A435.atomic_bytes


def progress_path(worker_index: int) -> Path:
    if not 0 <= worker_index < WORKERS:
        raise ValueError("A438 worker index differs")
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


def assert_no_prior_target_outcome() -> None:
    paths = [
        A426_RESULT,
        A426_STOP,
        A435_RESULT,
        A435_STOP,
        *(A435.progress_path(index) for index in range(WORKERS)),
        *(
            RESULTS
            / f"chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_worker_{index}_progress_v1.json"
            for index in range(WORKERS)
        ),
    ]
    if any(path.exists() for path in paths):
        raise RuntimeError("A438 freeze must precede all A426/A435 target outcomes or progress")


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A438 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    execution = value.get("execution_contract", {})
    schedule = value.get("schedule_transfer_contract", {})
    engine = value.get("engine_reuse_contract", {})
    challenge = value.get("challenge_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-calibration-balanced-wavefront-recovery-a438-design-v1"
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
        or schedule.get("source_attempt") != "A437"
        or schedule.get("source_schedule_commitment_sha256")
        != A437_SCHEDULE_COMMITMENT_SHA256
        or schedule.get("source_pair_stream_uint16be_uint16be_sha256")
        != A437_PAIR_STREAM_SHA256
        or schedule.get("copy_pair_at_and_worker_modulo_mapping_without_refit") is not True
        or schedule.get("W52_true_pair_rank_known_at_freeze") is not False
        or schedule.get("target_labels_used") != 0
        or schedule.get("reader_refits") != 0
        or engine.get("A435_square_pair_codec_reused") is not False
        or engine.get("A437_anisotropic_pair_codec_used") is not True
        or engine.get("A435_candidate_or_outcome_consumed") is not False
        or challenge.get("source_attempt") != "A426"
        or challenge.get("secret_assignment_absent_from_protocol") is not True
        or boundary.get("A434_qualification_available_at_design_freeze") is not False
        or boundary.get("A426_candidate_or_progress_available_at_design_freeze") is not False
        or boundary.get("A426_outcome_available_at_design_freeze") is not False
        or boundary.get("A435_candidate_progress_or_outcome_consumed") is not False
        or boundary.get("A438_candidate_or_progress_available_at_design_freeze") is not False
        or boundary.get("A438_target_labels_used_for_schedule") != 0
        or boundary.get("A438_reader_refits") != 0
    ):
        raise RuntimeError("A438 frozen design semantics differ")
    sources = value["source_anchors"]
    for key, item in sources.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, sources[f"{stem}_sha256"])
    return value


def load_source_schedule() -> tuple[
    dict[str, Any],
    dict[str, Any],
    list[int],
    list[int],
]:
    anchor(A437_RUNNER, A437_RUNNER_SHA256)
    anchor(A437_PROTOCOL, A437_PROTOCOL_SHA256)
    anchor(A437_V2_RUNNER, A437_V2_RUNNER_SHA256)
    anchor(A437_V2_PROTOCOL, A437_V2_PROTOCOL_SHA256)
    anchor(A437_V2_RESULT, A437_V2_RESULT_SHA256)
    anchor(A437_V2_CAUSAL, A437_V2_CAUSAL_SHA256)
    v1 = A437.load_protocol(A437_PROTOCOL_SHA256)
    v2 = A437V2.load_protocol(A437_V2_PROTOCOL_SHA256)
    packaged = json.loads(A437_V2_RESULT.read_bytes())
    _prefix_source, prefix, _off_source, off_axis = A437.load_axis_sources()
    if (
        v1.get("schedule_commitment_sha256") != A437_SCHEDULE_COMMITMENT_SHA256
        or v1.get("schedule", {}).get("pair_stream_uint16be_uint16be_sha256")
        != A437_PAIR_STREAM_SHA256
        or v2.get("schedule_commitment_sha256") != A437_SCHEDULE_COMMITMENT_SHA256
        or v2.get("pair_stream_uint16be_uint16be_sha256") != A437_PAIR_STREAM_SHA256
        or packaged.get("schedule_commitment_sha256")
        != A437_SCHEDULE_COMMITMENT_SHA256
        or packaged.get("pair_stream_uint16be_uint16be_sha256")
        != A437_PAIR_STREAM_SHA256
        or packaged.get("target_labels_used") != 0
        or packaged.get("reader_refits") != 0
        or packaged.get("candidate_assignments_executed") != 0
        or packaged.get("A426_progress_or_filter_outcomes_consumed") is not False
        or len(prefix) * len(off_axis) != PAIR_CELLS
    ):
        raise RuntimeError("A438 A437 source schedule differs")
    return v1, v2, prefix, off_axis


def load_public_challenge() -> tuple[dict[str, Any], dict[str, Any]]:
    anchor(A426_RUNNER, A426_RUNNER_SHA256)
    a426 = A426.load_protocol(A426_PROTOCOL_SHA256)
    challenge = dict(a426["public_challenge"])
    A426.validate_challenge(challenge)
    if (
        a426.get("complete_domain_assignments") != DOMAIN_ASSIGNMENTS
        or challenge.get("unknown_key_bits") != WIDTH
        or challenge.get("unknown_assignment_included") is not False
        or a426.get("public_challenge_sha256")
        != "5d60dac2570756d681f248a6cfb818681c644d87843d273bc0e9b2ee46731b54"
    ):
        raise RuntimeError("A438 A426 public challenge scope differs")
    return a426, challenge


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists() or not no_downstream_artifacts():
        raise FileExistsError("A438 implementation or downstream artifact exists")
    assert_no_prior_target_outcome()
    if A434_QUALIFICATION.exists():
        raise RuntimeError("A438 implementation freeze must precede A434 qualification")
    design = load_design()
    v1, _v2, prefix, off_axis = load_source_schedule()
    a426, _challenge = load_public_challenge()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A438 tests and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-calibration-balanced-wavefront-recovery-a438-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_restart_safe_eight_worker_A437_executor_frozen_before_A434_qualification_A426_A435_outcome_or_any_A438_candidate_progress_or_filter_outcome",
        "design_sha256": DESIGN_SHA256,
        "execution_contract": design["execution_contract"],
        "schedule_transfer_contract": design["schedule_transfer_contract"],
        "engine_reuse_contract": design["engine_reuse_contract"],
        "source_A437_protocol_sha256": A437_PROTOCOL_SHA256,
        "source_A437_schedule_commitment_sha256": v1[
            "schedule_commitment_sha256"
        ],
        "source_A437_pair_stream_sha256": v1["schedule"][
            "pair_stream_uint16be_uint16be_sha256"
        ],
        "source_A426_protocol_sha256": A426_PROTOCOL_SHA256,
        "source_A426_public_challenge_sha256": a426["public_challenge_sha256"],
        "source_pair_cells": len(prefix) * len(off_axis),
        "A434_qualification_available_at_freeze": False,
        "A426_A435_outcome_or_progress_available_at_freeze": False,
        "A438_candidate_or_progress_available_at_freeze": False,
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
            "A437_V1_runner": anchor(A437_RUNNER, A437_RUNNER_SHA256),
            "A437_V1_protocol": anchor(A437_PROTOCOL, A437_PROTOCOL_SHA256),
            "A437_V2_runner": anchor(A437_V2_RUNNER, A437_V2_RUNNER_SHA256),
            "A437_V2_protocol": anchor(
                A437_V2_PROTOCOL, A437_V2_PROTOCOL_SHA256
            ),
            "A437_V2_result": anchor(A437_V2_RESULT, A437_V2_RESULT_SHA256),
            "A437_V2_causal": anchor(A437_V2_CAUSAL, A437_V2_CAUSAL_SHA256),
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
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A438 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-calibration-balanced-wavefront-recovery-a438-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("source_A437_protocol_sha256") != A437_PROTOCOL_SHA256
        or value.get("source_A437_schedule_commitment_sha256")
        != A437_SCHEDULE_COMMITMENT_SHA256
        or value.get("source_A437_pair_stream_sha256") != A437_PAIR_STREAM_SHA256
        or value.get("source_A426_protocol_sha256") != A426_PROTOCOL_SHA256
        or value.get("source_pair_cells") != PAIR_CELLS
        or value.get("A434_qualification_available_at_freeze") is not False
        or value.get("A426_A435_outcome_or_progress_available_at_freeze") is not False
        or value.get("A438_candidate_or_progress_available_at_freeze") is not False
        or value.get("production_target_labels_used") != 0
        or value.get("production_reader_refits") != 0
        or value.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A438 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A438 implementation commitment differs")
    return value


def freeze_protocol(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if not no_downstream_artifacts():
        raise FileExistsError("A438 protocol or execution artifact exists")
    assert_no_prior_target_outcome()
    if A434_QUALIFICATION.exists():
        raise RuntimeError("A438 protocol freeze must precede A434 qualification")
    implementation = load_implementation(expected_implementation_sha256)
    v1, _v2, _prefix, _off_axis = load_source_schedule()
    a426, challenge = load_public_challenge()
    schedule = {
        "algorithm": "A437_calibration_balanced_anisotropic_rectangle_growth",
        "pair_stream_uint16be_uint16be_sha256": A437_PAIR_STREAM_SHA256,
        "A437_schedule_commitment_sha256": A437_SCHEDULE_COMMITMENT_SHA256,
        "prefix_order_uint16be_sha256": v1["schedule"][
            "prefix_order_uint16be_sha256"
        ],
        "off_axis_order_uint16be_sha256": v1["schedule"][
            "off_axis_order_uint16be_sha256"
        ],
        "calibration_growth_ratio": "418:561",
        "exact_integer_growth_test": "(P+1)*561 <= (O+1)*418",
        "pair_cells": PAIR_CELLS,
        "assignments_per_complete_pair_cell": CELL_ASSIGNMENTS,
        "complete_domain_assignments": DOMAIN_ASSIGNMENTS,
        "workers": WORKERS,
        "worker_tasks_each": WORKER_TASKS,
        "worker_global_index_formula": "worker_index + 8 * zero_based_worker_step",
        "worker_role_formula": "anisotropic_wave_{worker_index}",
        "pair_at_formula": "A437.anisotropic_pair_at(global_index)",
        "complete_cover_identity": "disjoint residues modulo 8 over [0,2^24)",
        "growth_events": v1["schedule"]["growth_events"],
        "sentinels": v1["schedule"]["sentinels"],
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-calibration-balanced-wavefront-recovery-a438-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "A437_exact_anisotropic_schedule_and_A426_public_challenge_bound_before_A434_qualification_A426_A435_outcome_or_any_A438_candidate_progress_or_filter_outcome",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "A437_protocol_sha256": A437_PROTOCOL_SHA256,
        "A437_V2_protocol_sha256": A437_V2_PROTOCOL_SHA256,
        "A426_protocol_sha256": A426_PROTOCOL_SHA256,
        "public_challenge": challenge,
        "public_challenge_sha256": a426["public_challenge_sha256"],
        "schedule": schedule,
        "schedule_commitment_sha256": canonical_sha256(schedule),
        "worker_roles": [f"anisotropic_wave_{index}" for index in range(WORKERS)],
        "information_boundary": {
            "A437_schedule_frozen_before_A438_challenge_binding": True,
            "A434_qualification_available_at_A438_protocol_freeze": False,
            "A426_assignment_absent_from_protocol": True,
            "A426_A435_candidate_progress_or_outcome_available_at_freeze": False,
            "A438_candidate_or_progress_available_at_protocol_freeze": False,
            "A438_target_labels_used_for_schedule": 0,
            "A438_reader_refits": 0,
            "prior_live_recovery_filter_outcomes_consumed": False,
        },
        "production_execution_enabled": False,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A437_V1_protocol": anchor(A437_PROTOCOL, A437_PROTOCOL_SHA256),
            "A437_V2_protocol": anchor(
                A437_V2_PROTOCOL, A437_V2_PROTOCOL_SHA256
            ),
            "A437_V2_result": anchor(A437_V2_RESULT, A437_V2_RESULT_SHA256),
            "A437_V2_causal": anchor(A437_V2_CAUSAL, A437_V2_CAUSAL_SHA256),
            "A426_protocol": anchor(A426_PROTOCOL, A426_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(PROTOCOL, payload)
    assert_no_prior_target_outcome()
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A438 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    boundary = value.get("information_boundary", {})
    schedule = value.get("schedule", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-calibration-balanced-wavefront-recovery-a438-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A437_protocol_sha256") != A437_PROTOCOL_SHA256
        or value.get("A437_V2_protocol_sha256") != A437_V2_PROTOCOL_SHA256
        or value.get("A426_protocol_sha256") != A426_PROTOCOL_SHA256
        or schedule.get("algorithm")
        != "A437_calibration_balanced_anisotropic_rectangle_growth"
        or schedule.get("pair_stream_uint16be_uint16be_sha256")
        != A437_PAIR_STREAM_SHA256
        or schedule.get("A437_schedule_commitment_sha256")
        != A437_SCHEDULE_COMMITMENT_SHA256
        or schedule.get("pair_cells") != PAIR_CELLS
        or schedule.get("assignments_per_complete_pair_cell") != CELL_ASSIGNMENTS
        or schedule.get("complete_domain_assignments") != DOMAIN_ASSIGNMENTS
        or schedule.get("workers") != WORKERS
        or schedule.get("worker_tasks_each") != WORKER_TASKS
        or value.get("schedule_commitment_sha256") != canonical_sha256(schedule)
        or value.get("worker_roles")
        != [f"anisotropic_wave_{index}" for index in range(WORKERS)]
        or boundary.get("A437_schedule_frozen_before_A438_challenge_binding") is not True
        or boundary.get("A434_qualification_available_at_A438_protocol_freeze") is not False
        or boundary.get("A426_assignment_absent_from_protocol") is not True
        or boundary.get("A426_A435_candidate_progress_or_outcome_available_at_freeze")
        is not False
        or boundary.get("A438_candidate_or_progress_available_at_protocol_freeze")
        is not False
        or boundary.get("A438_target_labels_used_for_schedule") != 0
        or boundary.get("A438_reader_refits") != 0
        or boundary.get("prior_live_recovery_filter_outcomes_consumed") is not False
        or value.get("production_execution_enabled") is not False
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A438 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_implementation(value["implementation_sha256"])
    v1, _v2, _prefix, _off_axis = load_source_schedule()
    a426, _challenge = load_public_challenge()
    if (
        schedule["pair_stream_uint16be_uint16be_sha256"]
        != v1["schedule"]["pair_stream_uint16be_uint16be_sha256"]
        or value["public_challenge"] != a426["public_challenge"]
        or value["public_challenge_sha256"]
        != canonical_sha256(value["public_challenge"])
    ):
        raise RuntimeError("A438 source binding differs")
    A426.validate_challenge(value["public_challenge"])
    unsigned = {key: item for key, item in value.items() if key != "protocol_commitment_sha256"}
    if value.get("protocol_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A438 protocol commitment differs")
    return value


def load_a434_qualification(expected_sha256: str) -> dict[str, Any]:
    return A435.load_a434_qualification(expected_sha256)


def worker_global_index(worker_index: int, zero_based_worker_step: int) -> int:
    if not 0 <= worker_index < WORKERS:
        raise ValueError("A438 worker index differs")
    if not 0 <= zero_based_worker_step < WORKER_TASKS:
        raise ValueError("A438 worker step differs")
    return worker_index + WORKERS * zero_based_worker_step


def worker_pair_at(
    worker_index: int,
    zero_based_worker_step: int,
    prefix_order: Sequence[int],
    off_axis_order: Sequence[int],
) -> tuple[int, int, int]:
    global_index = worker_global_index(worker_index, zero_based_worker_step)
    prefix, off_axis = A437.anisotropic_pair_at(
        global_index, prefix_order, off_axis_order
    )
    return global_index, prefix, off_axis


def configure_runtime_shim() -> None:
    A435.STOP = STOP
    A435.RESULT = RESULT
    A435.progress_path = progress_path
    A435.worker_pair_at = worker_pair_at


def normalize_worker_row(row: Mapping[str, Any], worker_index: int) -> dict[str, Any]:
    value = dict(row)
    value["worker_role"] = f"anisotropic_wave_{worker_index}"
    value.pop("last_shell_zero_based", None)
    if "last_global_index_zero_based" in value:
        event = A437.event_for_global_index(int(value["last_global_index_zero_based"]))
        value["last_growth_event_axis"] = event.axis
        value["last_active_prefix_count_after"] = event.prefix_count_after
        value["last_active_off_axis_count_after"] = event.off_axis_count_after
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
        != "chacha20-round20-w52-calibration-balanced-wavefront-recovery-a438-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("worker_index") != worker_index
        or value.get("worker_role") != f"anisotropic_wave_{worker_index}"
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("A434_qualification_sha256") != qualification_sha256
        or value.get("A437_schedule_commitment_sha256")
        != A437_SCHEDULE_COMMITMENT_SHA256
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A438 progress fingerprint differs")
    status = value.get("status")
    completed = int(value.get("executed_worker_pair_cells", -1))
    factual = value.get("factual_filter_candidates")
    if (
        status not in {"running", "candidate_found", "worker_exhausted", "peer_confirmed"}
        or not 0 <= completed <= WORKER_TASKS
        or (status == "candidate_found" and (not isinstance(factual, list) or len(factual) != 1))
        or (status != "candidate_found" and factual != 0)
    ):
        raise RuntimeError("A438 resumable progress state differs")
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
    configure_runtime_shim()

    def normalized_callback(row: Mapping[str, Any]) -> None:
        progress_callback(normalize_worker_row(row, worker_index))

    value = A435.ordered_worker_discovery(
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
    ):
        raise RuntimeError("A438 peer progress fingerprint differs")
    if value.get("status") in {"running", "peer_confirmed"}:
        value["status"] = "peer_confirmed"
        value["factual_filter_candidates"] = 0
        value["confirmed_stop_sha256"] = file_sha256(STOP)
        atomic_json(path, value)
    elif value.get("status") not in {"worker_exhausted", "candidate_found"}:
        raise RuntimeError("A438 peer progress status differs")
    return {"status": "peer_confirmed", "worker_index": worker_index}


def progress_snapshot(protocol_sha256: str, qualification_sha256: str) -> dict[str, Any]:
    panel: dict[str, Any] = {}
    total = 0
    max_depth = 0
    all_controls_empty = True
    for index in range(WORKERS):
        role = f"anisotropic_wave_{index}"
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
        ):
            raise RuntimeError("A438 progress snapshot fingerprint differs")
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

    strict = payload["strict_subset_of_complete_domain"]
    terminal = (
        "confirmed_strict_subset_anisotropic_W52_recovery"
        if strict
        else "confirmed_complete_domain_anisotropic_W52_recovery"
    )
    writer = CausalWriter(api_id="a438w52")
    writer._rules = []
    writer.add_rule(
        name="calibrated_axes_and_exact_subcell_engine_to_model",
        description="Execute A437's frozen calibration-balanced pair order as eight disjoint complete 2^28-cell streams.",
        pattern=["A437_exact_anisotropic_wavefront", "A434_exact_2pow28_subcell_engine"],
        conclusion="A438_sole_factual_W52_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="anisotropic_model_to_confirmed_recovery",
        description="Require empty matched control and dual independent eight-block confirmation before retaining the W52 result.",
        pattern=["A438_sole_factual_W52_model"],
        conclusion=f"A438_{terminal}",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A437:exact_calibration_balanced_anisotropic_wavefront",
        mechanism="eight_disjoint_complete_2pow28_subcell_streams_with_confirmed_shared_stop",
        outcome="A438:sole_factual_W52_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["aggregate_execution"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="full-round ChaCha20 W52 anisotropic recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A438:sole_factual_W52_model",
        mechanism="matched_control_rejection_and_dual_reference_eight_block_confirmation",
        outcome=f"A438:{terminal}",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W52 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A437:exact_calibration_balanced_anisotropic_wavefront",
        mechanism="materialized_anisotropic_search_and_confirmation_closure",
        outcome=f"A438:{terminal}",
        confidence=1.0,
        source="materialized:A438_anisotropic_W52_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A438 calibration-balanced W52 recovery",
        entities=[
            "A437:exact_calibration_balanced_anisotropic_wavefront",
            "A438:sole_factual_W52_model",
            f"A438:{terminal}",
        ],
    )
    writer.add_gap(
        subject=f"A438:{terminal}",
        predicate="next_required_object",
        expected_object_type="higher_width_multiaxis_recovery_or_cross_target_replication",
        confidence=1.0,
        suggested_queries=[
            "Use the post-confirmation anisotropic-versus-neutral rank delta to choose between W53 multiaxis expansion and a fresh W52 cross-target replication."
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
        reader.api_id != "a438w52"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A438 authentic Causal reopen gate failed")
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
        != "chacha20-round20-w52-calibration-balanced-wavefront-recovery-a438-confirmed-stop-v1"
        or stop.get("attempt_id") != ATTEMPT_ID
        or stop.get("protocol_sha256") != file_sha256(PROTOCOL)
        or stop.get("A434_qualification_sha256") != qualification_sha256
        or stop.get("confirmation", {}).get("all_blocks_match") is not True
        or stop.get("discovery", {}).get("control_filter_candidates") != []
    ):
        raise RuntimeError("A438 confirmed stop fingerprint differs")
    while not active_started_workers_terminal():
        time.sleep(5)
    aggregate = progress_snapshot(file_sha256(PROTOCOL), qualification_sha256)
    unique_cells = int(aggregate["total_unique_pair_cells_evaluated"])
    if not 1 <= unique_cells <= PAIR_CELLS:
        raise RuntimeError("A438 aggregate unique pair-cell count differs")
    strict_subset = unique_cells < PAIR_CELLS
    aggregate["strict_subset_of_complete_domain"] = strict_subset
    aggregate["domain_reduction_factor"] = PAIR_CELLS / unique_cells
    aggregate["search_gain_bits"] = math.log2(PAIR_CELLS / unique_cells)
    discovery = stop["discovery"]
    _v1, _v2, prefix_order, off_axis_order = load_source_schedule()
    prefix = int(discovery["prefix12"])
    off_axis = int(discovery["off_axis12"])
    global_index = A437.anisotropic_pair_global_index(
        prefix, off_axis, prefix_order, off_axis_order
    )
    neutral_index = A435.A434.pair_global_index(
        prefix, off_axis, prefix_order, off_axis_order
    )
    prefix_rank = prefix_order.index(prefix) + 1
    off_axis_rank = off_axis_order.index(off_axis) + 1
    if (
        global_index + 1 != int(discovery["global_rank_one_based"])
        or int(discovery["worker_index"]) != global_index % WORKERS
        or int(discovery["worker_step_one_based"]) != global_index // WORKERS + 1
    ):
        raise RuntimeError("A438 discovery rank identity differs")
    rank_analysis = {
        "prefix12": prefix,
        "off_axis12": off_axis,
        "prefix_rank_one_based": prefix_rank,
        "off_axis_rank_one_based": off_axis_rank,
        "anisotropic_global_pair_rank_one_based": global_index + 1,
        "neutral_square_global_pair_rank_one_based": neutral_index + 1,
        "anisotropic_cells_saved_vs_neutral": neutral_index - global_index,
        "anisotropic_factor_vs_neutral": (neutral_index + 1) / (global_index + 1),
        "anisotropic_gain_bits_vs_neutral": math.log2(
            (neutral_index + 1) / (global_index + 1)
        ),
        "winning_worker_index": int(discovery["worker_index"]),
        "winning_worker_step_one_based": int(discovery["worker_step_one_based"]),
        "aggregate_unique_pair_cells_before_confirmed_stop": unique_cells,
        "ranks_computed_only_after_independent_confirmation": True,
    }
    evidence_stage = (
        "FULLROUND_R20_CALIBRATION_BALANCED_W52_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_CALIBRATION_BALANCED_W52_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-calibration-balanced-wavefront-recovery-a438-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "implementation_commitment_sha256": protocol[
            "implementation_commitment_sha256"
        ],
        "protocol_sha256": file_sha256(PROTOCOL),
        "protocol_commitment_sha256": protocol["protocol_commitment_sha256"],
        "A437_protocol_sha256": A437_PROTOCOL_SHA256,
        "A437_schedule_commitment_sha256": A437_SCHEDULE_COMMITMENT_SHA256,
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
            "implementation": anchor(IMPLEMENTATION, protocol["implementation_sha256"]),
            "protocol": anchor(PROTOCOL, file_sha256(PROTOCOL)),
            "confirmed_stop": anchor(STOP, file_sha256(STOP)),
            "A437_V1_protocol": anchor(A437_PROTOCOL, A437_PROTOCOL_SHA256),
            "A437_V2_result": anchor(A437_V2_RESULT, A437_V2_RESULT_SHA256),
            "A437_V2_causal": anchor(A437_V2_CAUSAL, A437_V2_CAUSAL_SHA256),
            "A434_qualification": anchor(A434_QUALIFICATION, qualification_sha256),
            "A426_protocol": anchor(A426_PROTOCOL, A426_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    stable_discovery = {
        key: item for key, item in discovery.items() if not key.startswith("volatile_")
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
            "# A438 — Calibration-balanced full-round ChaCha20 W52 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            "- Frozen schedule: **A437 calibration-balanced anisotropic wavefront**\n"
            f"- Exact unique 2^28 pair cells evaluated: **{unique_cells:,} / {PAIR_CELLS:,}**\n"
            f"- Complete assignments evaluated: **{aggregate['total_unique_assignments_evaluated']:,} / {DOMAIN_ASSIGNMENTS:,}**\n"
            f"- Search gain: **{aggregate['search_gain_bits']:.9f} bits**\n"
            f"- Prefix / off-axis ranks: **{prefix_rank} / {off_axis_rank}**\n"
            f"- Anisotropic / neutral pair ranks: **{global_index + 1} / {neutral_index + 1}**\n"
            f"- Anisotropic gain versus neutral: **{rank_analysis['anisotropic_gain_bits_vs_neutral']:.9f} bits**\n"
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
        raise ValueError("A438 worker index differs")
    configure_runtime_shim()
    protocol = load_protocol(expected_protocol_sha256)
    load_a434_qualification(expected_a434_qualification_sha256)
    if RESULT.exists():
        return {"status": "peer_confirmed", "result_sha256": file_sha256(RESULT)}
    if STOP.exists():
        stop = json.loads(STOP.read_bytes())
        if int(stop.get("worker_index", -1)) == worker_index:
            return finalize_confirmed_stop(protocol, expected_a434_qualification_sha256)
        return mark_peer_confirmed(
            expected_protocol_sha256,
            expected_a434_qualification_sha256,
            worker_index,
        )
    _v1, _v2, prefix_order, off_axis_order = load_source_schedule()
    engine_protocol = A422.load_protocol(A435.A434.A422_PROTOCOL_SHA256)
    executable_row = engine_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    challenge = protocol["public_challenge"]
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A422.A390.A384.A378.A371.A346.A324.A311.A307.A304.GroupedMetalHost(
            executable,
            A422.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    role = f"anisotropic_wave_{worker_index}"

    def write_progress(row: Mapping[str, Any]) -> None:
        normalized = normalize_worker_row(row, worker_index)
        atomic_json(
            progress_path(worker_index),
            {
                "schema": "chacha20-round20-w52-calibration-balanced-wavefront-recovery-a438-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "worker_index": worker_index,
                "protocol_sha256": expected_protocol_sha256,
                "A434_qualification_sha256": expected_a434_qualification_sha256,
                "A437_schedule_commitment_sha256": A437_SCHEDULE_COMMITMENT_SHA256,
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
                raise RuntimeError("A438 all disjoint workers exhausted without a model")
        return discovery
    candidate = int(discovery["candidate"])
    confirmation = A426.confirm(challenge, candidate)
    if confirmation.get("all_blocks_match") is not True:
        raise RuntimeError("A438 dual-reference eight-block confirmation failed")
    if discovery.get("control_filter_candidates") != []:
        raise RuntimeError("A438 matched control produced a candidate")
    if STOP.exists():
        return mark_peer_confirmed(
            expected_protocol_sha256,
            expected_a434_qualification_sha256,
            worker_index,
        )
    atomic_json(
        STOP,
        {
            "schema": "chacha20-round20-w52-calibration-balanced-wavefront-recovery-a438-confirmed-stop-v1",
            "attempt_id": ATTEMPT_ID,
            "protocol_sha256": expected_protocol_sha256,
            "A434_qualification_sha256": expected_a434_qualification_sha256,
            "A437_schedule_commitment_sha256": A437_SCHEDULE_COMMITMENT_SHA256,
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
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "A434_qualification_complete": A434_QUALIFICATION.exists(),
        "confirmed_stop_available": STOP.exists(),
        "result_complete": RESULT.exists(),
        "pair_cells": PAIR_CELLS,
        "assignments_per_complete_pair_cell": CELL_ASSIGNMENTS,
        "complete_domain_assignments": DOMAIN_ASSIGNMENTS,
        "worker_progress": {},
    }
    load_design()
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if PROTOCOL.exists():
        payload["protocol_sha256"] = file_sha256(PROTOCOL)
        load_protocol(payload["protocol_sha256"])
    if A434_QUALIFICATION.exists():
        payload["A434_qualification_sha256"] = file_sha256(A434_QUALIFICATION)
        load_a434_qualification(payload["A434_qualification_sha256"])
    for index in range(WORKERS):
        path = progress_path(index)
        if path.exists():
            payload["worker_progress"][str(index)] = json.loads(path.read_bytes())
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["evidence_stage"] = value["evidence_stage"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-protocol", action="store_true")
    action.add_argument("--recover-worker", type=int, choices=range(WORKERS))
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
        if not args.expected_protocol_sha256 or not args.expected_a434_qualification_sha256:
            parser.error("--recover-worker requires protocol and qualification hashes")
        payload = recover_worker(
            worker_index=args.recover_worker,
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_a434_qualification_sha256=args.expected_a434_qualification_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
