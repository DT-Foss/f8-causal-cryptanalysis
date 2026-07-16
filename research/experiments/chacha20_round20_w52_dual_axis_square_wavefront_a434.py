#!/usr/bin/env python3
"""A434: freeze and qualify the exact W52 dual-axis 2^28-cell Metal adapter."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import sys
import time
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w52_dual_axis_square_wavefront_a434_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w52_dual_axis_square_wavefront_a434_implementation_v1.json"
)
PROTOCOL = CONFIGS / "chacha20_round20_w52_dual_axis_square_wavefront_a434_v1.json"
QUALIFICATION = (
    RESULTS / "chacha20_round20_w52_dual_axis_square_wavefront_a434_qualification_v1.json"
)

A422_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422.py"
)
A422_DESIGN = (
    CONFIGS / "chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422_design_v1.json"
)
A422_PROTOCOL = CONFIGS / "chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422_v1.json"
A422_QUALIFICATION = (
    RESULTS
    / "chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422_qualification_v1.json"
)
A432_RESULT = RESULTS / "chacha20_round20_w52_public_output_direct12_eight_worker_a432_v1.json"
A432_CAUSAL = A432_RESULT.with_suffix(".causal")
A433_DESIGN = (
    CONFIGS / "chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_design_v1.json"
)
A433_IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_implementation_v2.json"
)
A433_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_v2.py"
)
A433_PREFLIGHT = (
    RESULTS / "chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_preflight_v2.json"
)
A433_RESULT = RESULTS / "chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_v2.json"
A433_CAUSAL = A433_RESULT.with_suffix(".causal")
A426_RESULT = RESULTS / "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_v1.json"
A426_STOP = (
    RESULTS / "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_confirmed_stop_v1.json"
)
TEST = ROOT / "tests/test_chacha20_round20_w52_dual_axis_square_wavefront_a434.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w52_dual_axis_square_wavefront_a434.sh"

ATTEMPT_ID = "A434"
DESIGN_SHA256 = "98ee9a940c566510fa0f53fca34313b1c1fce88b7f11b49c6d0ab17719f92453"
A422_DESIGN_SHA256 = "eec874d7b680e65c34322e0a1b7a4cabccde3082b6c911944486ec968633cc68"
A422_PROTOCOL_SHA256 = "1c50ef355d5b1fe0a13a6860d57923ed3e380b5c069e0587d84535c7f89d6dd6"
A422_RUNNER_SHA256 = "379c300d3ba8ad4399e4c726aee7473e946e62ac5d9d331bab01e733842f881a"
A432_RESULT_SHA256 = "3d0ed27a25288db589ddb6608407314d1fa32f4cb678806e142eb819159a7e6d"
A432_CAUSAL_SHA256 = "e08948ffcb85766c0c4dcf74ce4c965c77003358ab3e5e6a0755fbbbaee2ea72"
A433_DESIGN_SHA256 = "7024b47b2e591a96723d4a1ff26ec1193c47ddff67aeb270660b3705380f3100"
A433_IMPLEMENTATION_SHA256 = "aef8c643d85fd5f3702549f1856ed42aa0f3d318edd1ecfc3b324f8573b5609e"
A433_RUNNER_SHA256 = "17a466cbb7be143e4ed77c48d975ac54c1cc860aee5964dfd5c7ca4f020b7442"
A433_PREFLIGHT_SHA256 = "c1edef54740c77031a33e87f500df40a5da9db1e98ca1f0d6a07782cdaccb6c4"
GROUPED_EXECUTABLE_SHA256 = "d1c41a049db90997ada5eba880d1ba2d0787b1d74be499f0a254183f1b577acf"

AXIS_BITS = 12
AXIS_CELLS = 1 << AXIS_BITS
PAIR_CELLS = AXIS_CELLS * AXIS_CELLS
WORD0_SUFFIX_BITS = 20
WORD0_COUNT = 1 << WORD0_SUFFIX_BITS
LOW8_COUNT = 1 << 8
CELL_ASSIGNMENTS = WORD0_COUNT * LOW8_COUNT
DOMAIN_ASSIGNMENTS = PAIR_CELLS * CELL_ASSIGNMENTS
WORKERS = 8
WORKER_TASKS = PAIR_CELLS // WORKERS


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A434 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A422 = load_module(A422_RUNNER, "a434_a422")
file_sha256 = A422.file_sha256
canonical_sha256 = A422.canonical_sha256
atomic_json = A422.atomic_json
anchor = A422.anchor
path_from_ref = A422.path_from_ref
relative = A422.relative


def assert_no_a426_outcome() -> None:
    paths = [
        A426_RESULT,
        A426_STOP,
        *(
            RESULTS
            / f"chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_worker_{index}_progress_v1.json"
            for index in range(WORKERS)
        ),
    ]
    if any(path.exists() for path in paths):
        raise RuntimeError("A434 prospective freeze must precede every A426 outcome")


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A434 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    domain = value.get("domain_contract", {})
    metal = value.get("metal_subcell_contract", {})
    wave = value.get("square_wavefront_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w52-dual-axis-square-wavefront-a434-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or domain.get("cells") != PAIR_CELLS
        or domain.get("assignments_per_cell") != CELL_ASSIGNMENTS
        or domain.get("complete_domain_assignments") != DOMAIN_ASSIGNMENTS
        or domain.get("residual_bits_inside_cell") != 28
        or metal.get("word0_count") != WORD0_COUNT
        or metal.get("outer_count") != LOW8_COUNT
        or metal.get("logical_candidates_per_dispatch") != CELL_ASSIGNMENTS
        or wave.get("workers") != WORKERS
        or wave.get("worker_tasks_each") != WORKER_TASKS
        or wave.get("streaming_generation") is not True
        or boundary.get("A433_measurement_or_result_available_at_design_freeze") is not False
        or boundary.get("A426_result_stop_or_progress_available_at_design_freeze") is not False
        or boundary.get("A434_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A434 frozen design semantics differ")
    sources = value["source_anchors"]
    for key, item in sources.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, sources[f"{stem}_sha256"])
    return value


def exact_axis_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != AXIS_CELLS or set(order) != set(range(AXIS_CELLS)):
        raise ValueError(f"{label} is not one exact 4,096-cell permutation")
    return order


def load_off_axis_order() -> tuple[dict[str, Any], list[int]]:
    if file_sha256(A432_RESULT) != A432_RESULT_SHA256:
        raise RuntimeError("A434 A432 result hash differs")
    value = json.loads(A432_RESULT.read_bytes())
    order = exact_axis_order(value["W52_public_output_direct12_order"], "A432 off-axis order")
    if (
        value.get("schema")
        != "chacha20-round20-w52-public-output-direct12-eight-worker-a432-result-v1"
        or value.get("selected_view") != "A342_selected_pair_slice_z"
        or value.get("W52_public_output_direct12_order_uint16be_sha256")
        != "e888570d1f5611680af9cd496b529c7290ed20e1ed09f4af093377011c6deffb"
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A434 frozen A432 off-axis order semantics differ")
    return value, order


def load_prefix_order(expected_result_sha256: str) -> tuple[dict[str, Any], list[int]]:
    if file_sha256(A433_RESULT) != expected_result_sha256:
        raise RuntimeError("A434 A433 result hash differs")
    value = json.loads(A433_RESULT.read_bytes())
    order = exact_axis_order(value["W52_prefix_aligned_direct12_order"], "A433 prefix order")
    coordinate = value.get("coordinate_contract", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-prefix-aligned-direct12-eight-worker-a433-result-v2"
        or value.get("selected_view") != "A340_selected8_global_raw"
        or coordinate.get("A433_prefix_aligned_measured_assignment_bit_interval") != [20, 31]
        or coordinate.get("all_4096_cells_match_A422_group_ids") is not True
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
        or value.get("A426_progress_or_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A434 A433 prefix-order semantics differ")
    return value, order


def subcell_geometry(prefix: int, off_axis: int) -> dict[str, int]:
    if not 0 <= prefix < AXIS_CELLS or not 0 <= off_axis < AXIS_CELLS:
        raise ValueError("A434 axis cell exceeds twelve bits")
    slab = off_axis >> 3
    outer_first = (off_axis & 7) << 8
    result = {
        "prefix": prefix,
        "off_axis": off_axis,
        "first_word0": prefix << WORD0_SUFFIX_BITS,
        "word0_count": WORD0_COUNT,
        "slab": slab,
        "outer_first": outer_first,
        "outer_count": LOW8_COUNT,
        "first_word1_low20": off_axis << 8,
        "last_word1_low20": (off_axis << 8) | 0xFF,
        "logical_candidates": CELL_ASSIGNMENTS,
    }
    if (
        result["first_word0"] >> WORD0_SUFFIX_BITS != prefix
        or result["first_word1_low20"] >> 8 != off_axis
        or result["last_word1_low20"] >> 8 != off_axis
        or result["first_word1_low20"] >> A422.OUTER_LOW_BITS != slab
        or (result["first_word1_low20"] & (A422.OUTER_SLICES - 1)) != outer_first
    ):
        raise RuntimeError("A434 Metal subcell geometry identity failed")
    return result


def encode_pair_cell(prefix: int, off_axis: int) -> int:
    subcell_geometry(prefix, off_axis)
    return (prefix << AXIS_BITS) | off_axis


def decode_pair_cell(cell: int) -> tuple[int, int]:
    if not 0 <= cell < PAIR_CELLS:
        raise ValueError("A434 pair cell exceeds twenty-four bits")
    return cell >> AXIS_BITS, cell & (AXIS_CELLS - 1)


def iter_square_wavefront(
    prefix_order: Sequence[int], off_axis_order: Sequence[int]
) -> Iterator[tuple[int, int]]:
    prefix = exact_axis_order(prefix_order, "A434 prefix order")
    off_axis = exact_axis_order(off_axis_order, "A434 off-axis order")
    for shell in range(AXIS_CELLS):
        for off_rank in range(shell + 1):
            yield prefix[shell], off_axis[off_rank]
        for prefix_rank in range(shell):
            yield prefix[prefix_rank], off_axis[shell]


def square_pair_at(
    global_index: int, prefix_order: Sequence[int], off_axis_order: Sequence[int]
) -> tuple[int, int]:
    if not 0 <= global_index < PAIR_CELLS:
        raise ValueError("A434 global pair index exceeds exact cover")
    prefix = exact_axis_order(prefix_order, "A434 prefix order")
    off_axis = exact_axis_order(off_axis_order, "A434 off-axis order")
    shell = math.isqrt(global_index)
    offset = global_index - shell * shell
    if offset <= shell:
        return prefix[shell], off_axis[offset]
    return prefix[offset - shell - 1], off_axis[shell]


def pair_global_index(
    prefix: int,
    off_axis: int,
    prefix_order: Sequence[int],
    off_axis_order: Sequence[int],
) -> int:
    prefix_values = exact_axis_order(prefix_order, "A434 prefix order")
    off_axis_values = exact_axis_order(off_axis_order, "A434 off-axis order")
    prefix_rank = [0] * AXIS_CELLS
    off_axis_rank = [0] * AXIS_CELLS
    for rank, cell in enumerate(prefix_values):
        prefix_rank[cell] = rank
    for rank, cell in enumerate(off_axis_values):
        off_axis_rank[cell] = rank
    left = prefix_rank[prefix]
    right = off_axis_rank[off_axis]
    shell = max(left, right)
    if left == shell:
        index = shell * shell + right
    else:
        index = shell * shell + shell + 1 + left
    if square_pair_at(index, prefix_values, off_axis_values) != (prefix, off_axis):
        raise RuntimeError("A434 square-wavefront inverse identity failed")
    return index


def worker_location(global_index: int) -> dict[str, int | str]:
    if not 0 <= global_index < PAIR_CELLS:
        raise ValueError("A434 worker index exceeds exact cover")
    worker = global_index % WORKERS
    step = global_index // WORKERS + 1
    return {
        "worker_index": worker,
        "worker_role": f"dual_axis_wave_{worker}",
        "worker_step_one_based": step,
        "global_rank_one_based": global_index + 1,
        "exact_parallel_depth": step,
    }


def pair_stream_sha256(prefix_order: Sequence[int], off_axis_order: Sequence[int]) -> str:
    digest = hashlib.sha256()
    chunk = bytearray()
    count = 0
    for prefix, off_axis in iter_square_wavefront(prefix_order, off_axis_order):
        chunk.extend(prefix.to_bytes(2, "big"))
        chunk.extend(off_axis.to_bytes(2, "big"))
        count += 1
        if len(chunk) >= 1 << 20:
            digest.update(chunk)
            chunk.clear()
    digest.update(chunk)
    if count != PAIR_CELLS:
        raise RuntimeError("A434 pair-stream cover differs")
    return digest.hexdigest()


def filter_subcell(
    *,
    host: Any,
    challenge: Mapping[str, Any],
    prefix: int,
    off_axis: int,
    target: np.ndarray,
    control: np.ndarray,
    word0_first_offset: int = 0,
    word0_count: int = WORD0_COUNT,
    low8_first: int = 0,
    low8_count: int = LOW8_COUNT,
) -> dict[str, Any]:
    geometry = subcell_geometry(prefix, off_axis)
    if (
        word0_count <= 0
        or word0_first_offset < 0
        or word0_first_offset + word0_count > WORD0_COUNT
        or low8_count <= 0
        or low8_first < 0
        or low8_first + low8_count > LOW8_COUNT
    ):
        raise ValueError("A434 reduced subcell interval differs")
    host.configure(A422.initial_for_slab(challenge, geometry["slab"]), target, control)
    observed = host.filter_group(
        first_word0=geometry["first_word0"] + word0_first_offset,
        word0_count=word0_count,
        outer_first=geometry["outer_first"] + low8_first,
        outer_count=low8_count,
    )
    factual = sorted(
        A422.encode_assignment(
            word0=int(word0), slab=geometry["slab"], outer_low11=int(outer_low11)
        )
        for word0, outer_low11 in observed["factual"]
    )
    controls = sorted(
        A422.encode_assignment(
            word0=int(word0), slab=geometry["slab"], outer_low11=int(outer_low11)
        )
        for word0, outer_low11 in observed["control"]
    )
    for assignment in (*factual, *controls):
        decoded = A422.decode_assignment(assignment)
        if decoded["word0"] >> WORD0_SUFFIX_BITS != prefix:
            raise RuntimeError("A434 returned candidate left the prefix axis")
        if decoded["word1_low20"] >> 8 != off_axis:
            raise RuntimeError("A434 returned candidate left the off-axis cell")
    return {
        **geometry,
        "word0_first_offset": word0_first_offset,
        "executed_word0_count": word0_count,
        "low8_first": low8_first,
        "executed_low8_count": low8_count,
        "factual_candidates": factual,
        "control_candidates": controls,
        "logical_candidates_executed": word0_count * low8_count,
        "gpu_seconds": float(observed["gpu_seconds"]),
        "complete_declared_subcell": word0_count == WORD0_COUNT and low8_count == LOW8_COUNT,
        "early_stop_inside_executed_interval": False,
    }


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists() or PROTOCOL.exists() or QUALIFICATION.exists():
        raise FileExistsError("A434 implementation, protocol or qualification already exists")
    if A433_RESULT.exists():
        raise RuntimeError("A434 implementation freeze must precede the A433 result")
    assert_no_a426_outcome()
    load_design()
    A422.load_protocol(A422_PROTOCOL_SHA256)
    load_off_axis_order()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A434 tests and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-dual-axis-square-wavefront-a434-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_dual_axis_geometry_wavefront_and_qualification_code_frozen_before_A433_result_A426_outcome_or_any_A434_candidate",
        "design_sha256": DESIGN_SHA256,
        "A433_result_available_at_implementation_freeze": False,
        "A426_outcome_available_at_implementation_freeze": False,
        "A434_candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A422_design": anchor(A422_DESIGN, A422_DESIGN_SHA256),
            "A422_protocol": anchor(A422_PROTOCOL, A422_PROTOCOL_SHA256),
            "A422_runner": anchor(A422_RUNNER, A422_RUNNER_SHA256),
            "A432_result": anchor(A432_RESULT, A432_RESULT_SHA256),
            "A432_causal": anchor(A432_CAUSAL, A432_CAUSAL_SHA256),
            "A433_design": anchor(A433_DESIGN, A433_DESIGN_SHA256),
            "A433_implementation": anchor(A433_IMPLEMENTATION, A433_IMPLEMENTATION_SHA256),
            "A433_runner": anchor(A433_RUNNER, A433_RUNNER_SHA256),
            "A433_preflight": anchor(A433_PREFLIGHT, A433_PREFLIGHT_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    assert_no_a426_outcome()
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A434 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-dual-axis-square-wavefront-a434-implementation-v1"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A433_result_available_at_implementation_freeze") is not False
        or value.get("A426_outcome_available_at_implementation_freeze") is not False
        or value.get("A434_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A434 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A434 implementation commitment differs")
    return value


def freeze_protocol(
    *, expected_implementation_sha256: str, expected_a433_result_sha256: str
) -> dict[str, Any]:
    if PROTOCOL.exists() or QUALIFICATION.exists():
        raise FileExistsError("A434 protocol or qualification already exists")
    assert_no_a426_outcome()
    implementation = load_implementation(expected_implementation_sha256)
    a433, prefix_order = load_prefix_order(expected_a433_result_sha256)
    a432, off_axis_order = load_off_axis_order()
    started = time.perf_counter()
    stream_sha = pair_stream_sha256(prefix_order, off_axis_order)
    sentinels = []
    for index in (0, 1, 2, 3, 4, 8, 15, 16, PAIR_CELLS - 2, PAIR_CELLS - 1):
        prefix, off_axis = square_pair_at(index, prefix_order, off_axis_order)
        sentinels.append(
            {
                "global_index_zero_based": index,
                "prefix": prefix,
                "off_axis": off_axis,
                "pair_cell": encode_pair_cell(prefix, off_axis),
                **worker_location(index),
            }
        )
    schedule = {
        "algorithm": "square_wavefront_prefix_front_shell_order",
        "prefix_order_uint16be_sha256": a433["W52_prefix_aligned_direct12_order_uint16be_sha256"],
        "off_axis_order_uint16be_sha256": a432["W52_public_output_direct12_order_uint16be_sha256"],
        "pair_stream_uint16be_uint16be_sha256": stream_sha,
        "cells": PAIR_CELLS,
        "assignments_per_cell": CELL_ASSIGNMENTS,
        "complete_domain_assignments": DOMAIN_ASSIGNMENTS,
        "workers": WORKERS,
        "worker_tasks_each": WORKER_TASKS,
        "shell_first_index_identity": "m^2",
        "shell_size_identity": "2m+1",
        "pair_rank_upper_bound": "max(R_prefix,R_off_axis)^2",
        "worker_depth_identity": "ceil(R_pair/8)",
        "sentinels": sentinels,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-dual-axis-square-wavefront-a434-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "dual_axis_24bit_schedule_materialized_after_complete_A433_unlabeled_field_before_A426_outcome_or_any_A434_candidate",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A433_result_sha256": expected_a433_result_sha256,
        "A433_order_commitment_sha256": a433["order_commitment_sha256"],
        "A432_order_commitment_sha256": a432["order_commitment_sha256"],
        "schedule": schedule,
        "schedule_commitment_sha256": canonical_sha256(schedule),
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "A426_progress_or_filter_outcomes_consumed": False,
        "production_execution_enabled": False,
        "volatile_stream_hash_seconds": time.perf_counter() - started,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A422_protocol": anchor(A422_PROTOCOL, A422_PROTOCOL_SHA256),
            "A432_result": anchor(A432_RESULT, A432_RESULT_SHA256),
            "A432_causal": anchor(A432_CAUSAL, A432_CAUSAL_SHA256),
            "A433_result": anchor(A433_RESULT, expected_a433_result_sha256),
            "A433_causal": anchor(A433_CAUSAL, a433["causal"]["sha256"]),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(
        {key: item for key, item in payload.items() if not key.startswith("volatile_")}
    )
    atomic_json(PROTOCOL, payload)
    assert_no_a426_outcome()
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A434 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    schedule = value.get("schedule", {})
    if (
        value.get("schema") != "chacha20-round20-w52-dual-axis-square-wavefront-a434-protocol-v1"
        or schedule.get("cells") != PAIR_CELLS
        or schedule.get("assignments_per_cell") != CELL_ASSIGNMENTS
        or schedule.get("complete_domain_assignments") != DOMAIN_ASSIGNMENTS
        or schedule.get("workers") != WORKERS
        or schedule.get("worker_tasks_each") != WORKER_TASKS
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
        or value.get("A426_progress_or_filter_outcomes_consumed") is not False
        or value.get("production_execution_enabled") is not False
        or value.get("schedule_commitment_sha256") != canonical_sha256(schedule)
    ):
        raise RuntimeError("A434 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {key: item for key, item in value.items() if not key.startswith("volatile_")}
    unsigned.pop("protocol_commitment_sha256")
    if value.get("protocol_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A434 protocol commitment differs")
    return value


def qualify(
    *, expected_protocol_sha256: str, expected_a422_qualification_sha256: str
) -> dict[str, Any]:
    if QUALIFICATION.exists():
        raise FileExistsError("A434 qualification already exists")
    load_protocol(expected_protocol_sha256)
    if file_sha256(A422_QUALIFICATION) != expected_a422_qualification_sha256:
        raise RuntimeError("A434 A422 qualification hash differs")
    a422_qualification = json.loads(A422_QUALIFICATION.read_bytes())
    if (
        a422_qualification.get("schema")
        != "chacha20-round20-w52-fivehundredtwelve-slab-grouped-engine-a422-qualification-v1"
        or a422_qualification.get("synthetic_filter_exact") is not True
        or a422_qualification.get("matched_control_empty") is not True
    ):
        raise RuntimeError("A434 A422 qualification semantics differ")
    challenge = A422.source_challenge()
    executable = path_from_ref(
        A422.load_protocol(A422_PROTOCOL_SHA256)["anchors"]["grouped_executable"]["path"]
    )
    anchor(executable, GROUPED_EXECUTABLE_SHA256)
    placeholder = np.asarray([0, 0], dtype=np.uint32)
    host = A422.A390.A384.A378.A371.A346.A324.A311.A307.A304.GroupedMetalHost(
        executable, A422.initial_for_slab(challenge, 0), placeholder, placeholder
    )
    boundary_rows = []
    first_word0 = 0x34567000
    count = 17
    try:
        for off_axis in (0, 1, 7, 8, 2047, 2048, 4094, 4095):
            geometry = subcell_geometry(0x345, off_axis)
            for low8 in (0, 1, 254, 255):
                outer20 = (off_axis << 8) | low8
                host.configure(
                    A422.initial_for_slab(challenge, geometry["slab"]), placeholder, placeholder
                )
                observed = host.blocks_group(
                    first_word0=first_word0,
                    word0_count=count,
                    outer_first=geometry["outer_first"] + low8,
                    outer_count=1,
                )[0]
                expected = A422.scalar_blocks_w52(
                    challenge=challenge,
                    outer20=outer20,
                    first_word0=first_word0,
                    count=count,
                )
                if not np.array_equal(observed, expected):
                    raise RuntimeError("A434 boundary scalar identity gate failed")
                boundary_rows.append(
                    {
                        "off_axis": off_axis,
                        "low8": low8,
                        "outer20": outer20,
                        "slab": geometry["slab"],
                        "outer_low11": geometry["outer_first"] + low8,
                        "word0_count": count,
                        "output_sha256": hashlib.sha256(
                            expected.astype("<u4").tobytes()
                        ).hexdigest(),
                        "grouped_equals_scalar": True,
                    }
                )

        target_prefix = 0xB29
        target_word0 = (target_prefix << WORD0_SUFFIX_BITS) | 0x13579
        target_outer20 = 0xD6437
        target_off_axis = target_outer20 >> 8
        target_low8 = target_outer20 & 0xFF
        target_block = A422.scalar_blocks_w52(
            challenge=challenge,
            outer20=target_outer20,
            first_word0=target_word0,
            count=1,
        )[0]
        control = target_block.copy()
        control[0] ^= np.uint32(1)
        word0_offset = (target_word0 & (WORD0_COUNT - 1)) - 8
        reduced = filter_subcell(
            host=host,
            challenge=challenge,
            prefix=target_prefix,
            off_axis=target_off_axis,
            target=target_block,
            control=control,
            word0_first_offset=word0_offset,
            word0_count=17,
            low8_first=target_low8,
            low8_count=1,
        )
        expected_assignment = (target_outer20 << 32) | target_word0
        if reduced["factual_candidates"] != [expected_assignment]:
            raise RuntimeError("A434 reduced subcell factual gate failed")
        if reduced["control_candidates"] != []:
            raise RuntimeError("A434 reduced subcell control gate failed")
        identity = host.identity
    finally:
        host.close()

    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-dual-axis-square-wavefront-a434-qualification-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "TARGET_FREE_DUAL_AXIS_2POW28_SUBCELL_ADAPTER_EXACTLY_QUALIFIED",
        "protocol_sha256": expected_protocol_sha256,
        "A422_qualification_sha256": expected_a422_qualification_sha256,
        "source_executable_sha256": GROUPED_EXECUTABLE_SHA256,
        "metal_identity": identity,
        "boundary_full_block_rows": boundary_rows,
        "reduced_exact_subcell_gate": {
            key: item for key, item in reduced.items() if key != "gpu_seconds"
        },
        "expected_synthetic_assignment": expected_assignment,
        "synthetic_filter_exact": True,
        "matched_control_empty": True,
        "production_W52_challenge_used": False,
        "production_W52_candidate_used": False,
        "anchors": {
            "protocol": anchor(PROTOCOL, expected_protocol_sha256),
            "A422_qualification": anchor(A422_QUALIFICATION, expected_a422_qualification_sha256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["qualification_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(QUALIFICATION, payload)
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "implementation_sha256": file_sha256(IMPLEMENTATION) if IMPLEMENTATION.exists() else None,
        "A433_result_available": A433_RESULT.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "protocol_sha256": file_sha256(PROTOCOL) if PROTOCOL.exists() else None,
        "A422_qualification_available": A422_QUALIFICATION.exists(),
        "qualification_complete": QUALIFICATION.exists(),
        "pair_cells": PAIR_CELLS,
        "assignments_per_cell": CELL_ASSIGNMENTS,
        "complete_domain_assignments": DOMAIN_ASSIGNMENTS,
        "candidate_assignments_executed": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-protocol", action="store_true")
    action.add_argument("--qualify", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-a433-result-sha256")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-a422-qualification-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_protocol:
        if not args.expected_implementation_sha256 or not args.expected_a433_result_sha256:
            parser.error("--freeze-protocol requires implementation and A433 result hashes")
        payload = freeze_protocol(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a433_result_sha256=args.expected_a433_result_sha256,
        )
    elif args.qualify:
        if not args.expected_protocol_sha256 or not args.expected_a422_qualification_sha256:
            parser.error("--qualify requires protocol and A422 qualification hashes")
        payload = qualify(
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_a422_qualification_sha256=args.expected_a422_qualification_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
