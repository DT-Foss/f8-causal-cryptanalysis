#!/usr/bin/env python3
"""A437: exact calibration-balanced W52 dual-axis wavefront."""

from __future__ import annotations

import argparse
import bisect
import hashlib
import importlib.util
import inspect
import json
import math
import os
import sys
import time
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = (
    CONFIGS
    / "chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_design_v1.json"
)
IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_implementation_v1.json"
)
PROTOCOL = (
    CONFIGS / "chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_v1.json"
)
RESULT = (
    RESULTS / "chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437_v1.json"
)
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")

A434_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w52_dual_axis_square_wavefront_a434.py"
)
A434_PROTOCOL = CONFIGS / "chacha20_round20_w52_dual_axis_square_wavefront_a434_v1.json"
A435_PROTOCOL = (
    CONFIGS / "chacha20_round20_w52_dual_axis_square_wavefront_recovery_a435_v1.json"
)
A354_RESULT = RESULTS / "chacha20_round20_w46_direct12_coordinate_codec_audit_a354_v1.json"
A348_RESULT = RESULTS / "chacha20_round20_w46_direct12_sliced_reader_a348_v1.json"
A355_RESULT = (
    RESULTS / "chacha20_round20_w46_corrected_group_direct12_reader_a355_v1.json"
)
A433_RESULT = (
    RESULTS / "chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_v2.json"
)
A433_CAUSAL = A433_RESULT.with_suffix(".causal")
A436_RESULT = RESULTS / "chacha20_round20_w52_corrected_off_axis_reader_a436_v1.json"
A436_CAUSAL = A436_RESULT.with_suffix(".causal")
A426_RESULT = RESULTS / "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_v1.json"
A426_STOP = (
    RESULTS / "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_confirmed_stop_v1.json"
)
TEST = (
    ROOT / "tests/test_chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437.py"
)
REPRO = (
    ROOT / "scripts/reproduce_chacha20_round20_w52_calibration_balanced_dual_axis_wavefront_a437.sh"
)
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)

ATTEMPT_ID = "A437"
DESIGN_SHA256 = "6d4f7eaa72d06b5b02345dafdf038fa20e1abca66e051471b3973ae491e8c607"
A434_PROTOCOL_SHA256 = "fca88cf01efdf2dde2ca56b87ae2d3b2bb0b320318c1201faa3f54b6af50acba"
A435_PROTOCOL_SHA256 = "a6616f0ce3ef8c92a67381e8d3c6acde649f0842d85ea7be9cc488e2182044cd"
A354_RESULT_SHA256 = "9fc3487266aee3f4e637b9a1afc0b434a5f0c56fa430e9aa14b576cfe8782ac4"
A348_RESULT_SHA256 = "f09bba039b26c8b78804f48169df62db167a9d95fbfff91e7099a01c1be1c812"
A355_RESULT_SHA256 = "b197ba0145e85119fabfc32d14116836a905e260f70fc4bb7dc779924077b686"
A433_RESULT_SHA256 = "3ffa28081437ed12276bac868ca1de780fe2d419ea986c68fba52098c0649e07"
A433_CAUSAL_SHA256 = "3c9ac990753e6763c8d61fbfa773f75e023edf5f60613eca36f5ebc1ea07f818"
A436_RESULT_SHA256 = "28e35b1bc2cefbf90c7358ca09f61f8028e9ebdcda6fbf69e3107c3389eb2baf"
A436_CAUSAL_SHA256 = "2dce03d1fed10da0c22618f37cad6242a67598ad3c3c64498b572a2ecded672d"

AXIS_BITS = 12
AXIS_CELLS = 1 << AXIS_BITS
PAIR_CELLS = AXIS_CELLS * AXIS_CELLS
CELL_ASSIGNMENTS = 1 << 28
DOMAIN_ASSIGNMENTS = PAIR_CELLS * CELL_ASSIGNMENTS
WORKERS = 8
WORKER_TASKS = PAIR_CELLS // WORKERS

PREFIX_CALIBRATION_CELL = 0xBAE
OFF_AXIS_CALIBRATION_CELL = 0x77C
PREFIX_CALIBRATION_RANK = 418
OFF_AXIS_CALIBRATION_RANK = 561
EXPECTED_ANISOTROPIC_CALIBRATION_RANK = 234_498
EXPECTED_NEUTRAL_CALIBRATION_RANK = 314_579


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A437 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A434 = load_module(A434_RUNNER, "a437_a434")
file_sha256 = A434.file_sha256
canonical_sha256 = A434.canonical_sha256
atomic_json = A434.atomic_json
anchor = A434.anchor
path_from_ref = A434.path_from_ref
relative = A434.relative


@dataclass(frozen=True, slots=True)
class GrowthEvent:
    axis: str
    new_rank: int
    other_count: int
    start: int
    stop: int
    prefix_count_after: int
    off_axis_count_after: int


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
        raise RuntimeError("A437 prospective freeze must precede every A426 outcome")


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A437 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    domain = value.get("domain_contract", {})
    axes = value.get("axis_contract", {})
    wave = value.get("anisotropic_rectangle_growth_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-calibration-balanced-dual-axis-wavefront-a437-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or domain.get("cells") != PAIR_CELLS
        or domain.get("assignments_per_cell") != CELL_ASSIGNMENTS
        or domain.get("complete_domain_assignments") != DOMAIN_ASSIGNMENTS
        or axes.get("prefix_W46_calibration_rank_one_based") != PREFIX_CALIBRATION_RANK
        or axes.get("off_axis_W46_calibration_rank_one_based") != OFF_AXIS_CALIBRATION_RANK
        or wave.get("W46_calibration_pair_rank_one_based_expected")
        != EXPECTED_ANISOTROPIC_CALIBRATION_RANK
        or wave.get("W46_neutral_square_calibration_pair_rank_one_based")
        != EXPECTED_NEUTRAL_CALIBRATION_RANK
        or wave.get("W52_same_cell_positions_used_as_target_information") is not False
        or wave.get("growth_events") != 2 * AXIS_CELLS - 1
        or wave.get("workers") != WORKERS
        or wave.get("worker_tasks_each") != WORKER_TASKS
        or boundary.get("A426_result_stop_or_progress_available_at_design_freeze") is not False
        or boundary.get("A437_target_derived_labels_used") != 0
        or boundary.get("A437_reader_refits") != 0
        or boundary.get("A437_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A437 frozen design semantics differ")
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


def load_axis_sources(
    expected_a433_result_sha256: str = A433_RESULT_SHA256,
    expected_a436_result_sha256: str = A436_RESULT_SHA256,
) -> tuple[dict[str, Any], list[int], dict[str, Any], list[int]]:
    if file_sha256(A433_RESULT) != expected_a433_result_sha256:
        raise RuntimeError("A437 A433 result hash differs")
    if file_sha256(A436_RESULT) != expected_a436_result_sha256:
        raise RuntimeError("A437 A436 result hash differs")
    prefix_source = json.loads(A433_RESULT.read_bytes())
    off_source = json.loads(A436_RESULT.read_bytes())
    prefix = exact_axis_order(
        prefix_source["W52_prefix_aligned_direct12_order"], "A437 prefix order"
    )
    off_axis = exact_axis_order(
        off_source["W52_corrected_off_axis_order"], "A437 corrected off-axis order"
    )
    prefix_coordinate = prefix_source.get("coordinate_contract", {})
    off_selection = off_source.get("coordinate_selection", {})
    off_measurement = off_source.get("measurement_summary", {})
    if (
        prefix_source.get("schema")
        != "chacha20-round20-w52-prefix-aligned-direct12-eight-worker-a433-result-v2"
        or prefix_source.get("selected_view") != "A340_selected8_global_raw"
        or prefix_source.get("W52_prefix_aligned_direct12_order_uint16be_sha256")
        != "195c4f021b1330adaaff15d05d5daf81699c09878427fd6d9f2d0139d76fd6ba"
        or prefix_coordinate.get("A433_prefix_aligned_measured_assignment_bit_interval")
        != [20, 31]
        or prefix_source.get("target_labels_used") != 0
        or prefix_source.get("reader_refits") != 0
        or prefix_source.get("candidate_assignments_executed") != 0
        or prefix_source.get("A426_progress_or_filter_outcomes_consumed") is not False
        or off_source.get("schema")
        != "chacha20-round20-w52-corrected-off-axis-reader-a436-result-v1"
        or off_source.get("selected_view") != "A342_selected_pair_global_raw"
        or off_source.get("W52_corrected_off_axis_order_uint16be_sha256")
        != "87f9cb66b3f1f958ce7588ac70b2df3e3e55a29de03a621a4d0b6d5eaf7156f9"
        or off_selection.get("actual_measured_cell") != OFF_AXIS_CALIBRATION_CELL
        or off_selection.get("selected_rank_one_based") != OFF_AXIS_CALIBRATION_RANK
        or off_measurement.get("target_labels_used") != 0
        or off_measurement.get("reader_refits") != 0
        or off_measurement.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A437 frozen axis-source semantics differ")
    return prefix_source, prefix, off_source, off_axis


def load_calibration_sources() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if file_sha256(A348_RESULT) != A348_RESULT_SHA256:
        raise RuntimeError("A437 A348 result hash differs")
    if file_sha256(A354_RESULT) != A354_RESULT_SHA256:
        raise RuntimeError("A437 A354 result hash differs")
    if file_sha256(A355_RESULT) != A355_RESULT_SHA256:
        raise RuntimeError("A437 A355 result hash differs")
    a348 = json.loads(A348_RESULT.read_bytes())
    a354 = json.loads(A354_RESULT.read_bytes())
    a355 = json.loads(A355_RESULT.read_bytes())
    witness = a354.get("candidate_codec_witness", {})
    selected = a355.get("selected_view", {})
    if (
        witness.get("Metal_group_cell_word0_bits20_through31")
        != PREFIX_CALIBRATION_CELL
        or witness.get("A348_actual_measured_cell_bits34_through45")
        != OFF_AXIS_CALIBRATION_CELL
        or witness.get("cells_are_distinct") is not True
        or selected.get("name") != "A340_selected8_global_raw"
        or selected.get("rank_one_based") != PREFIX_CALIBRATION_RANK
        or a348.get("schema")
        != "chacha20-round20-w46-direct12-sliced-reader-a348-result-v1"
        or a348.get("orders", {}).get("A342_selected_pair_global_raw", []).index(
            OFF_AXIS_CALIBRATION_CELL
        )
        + 1
        != OFF_AXIS_CALIBRATION_RANK
    ):
        raise RuntimeError("A437 corrected W46 calibration contract differs")
    return a348, a354, a355


@cache
def build_growth_events(
    axis_cells: int = AXIS_CELLS,
    prefix_calibration_rank: int = PREFIX_CALIBRATION_RANK,
    off_axis_calibration_rank: int = OFF_AXIS_CALIBRATION_RANK,
) -> tuple[GrowthEvent, ...]:
    if axis_cells <= 0 or prefix_calibration_rank <= 0 or off_axis_calibration_rank <= 0:
        raise ValueError("A437 growth geometry requires positive sizes and calibration ranks")
    prefix_count = 1
    off_axis_count = 1
    total = 1
    events = [GrowthEvent("seed", 0, 1, 0, 1, 1, 1)]
    while prefix_count < axis_cells or off_axis_count < axis_cells:
        grow_prefix = prefix_count < axis_cells and (
            off_axis_count == axis_cells
            or (prefix_count + 1) * off_axis_calibration_rank
            <= (off_axis_count + 1) * prefix_calibration_rank
        )
        if grow_prefix:
            stop = total + off_axis_count
            events.append(
                GrowthEvent(
                    "prefix",
                    prefix_count,
                    off_axis_count,
                    total,
                    stop,
                    prefix_count + 1,
                    off_axis_count,
                )
            )
            prefix_count += 1
        else:
            stop = total + prefix_count
            events.append(
                GrowthEvent(
                    "off_axis",
                    off_axis_count,
                    prefix_count,
                    total,
                    stop,
                    prefix_count,
                    off_axis_count + 1,
                )
            )
            off_axis_count += 1
        total = stop
    if len(events) != 2 * axis_cells - 1 or total != axis_cells * axis_cells:
        raise RuntimeError("A437 rectangle-growth exact-cover identity failed")
    return tuple(events)


def event_for_global_index(
    global_index: int,
    axis_cells: int = AXIS_CELLS,
    prefix_calibration_rank: int = PREFIX_CALIBRATION_RANK,
    off_axis_calibration_rank: int = OFF_AXIS_CALIBRATION_RANK,
) -> GrowthEvent:
    if not 0 <= global_index < axis_cells * axis_cells:
        raise ValueError("A437 global pair index exceeds exact cover")
    events = build_growth_events(
        axis_cells, prefix_calibration_rank, off_axis_calibration_rank
    )
    event_index = bisect.bisect_right(tuple(event.stop for event in events), global_index)
    return events[event_index]


def anisotropic_rank_pair_at(
    global_index: int,
    axis_cells: int = AXIS_CELLS,
    prefix_calibration_rank: int = PREFIX_CALIBRATION_RANK,
    off_axis_calibration_rank: int = OFF_AXIS_CALIBRATION_RANK,
) -> tuple[int, int]:
    event = event_for_global_index(
        global_index, axis_cells, prefix_calibration_rank, off_axis_calibration_rank
    )
    if event.axis == "seed":
        return 0, 0
    offset = global_index - event.start
    if not 0 <= offset < event.other_count:
        raise RuntimeError("A437 event offset exceeds emitted boundary")
    if event.axis == "prefix":
        return event.new_rank, offset
    return offset, event.new_rank


def anisotropic_rank_pair_global_index(
    prefix_rank: int,
    off_axis_rank: int,
    axis_cells: int = AXIS_CELLS,
    prefix_calibration_rank: int = PREFIX_CALIBRATION_RANK,
    off_axis_calibration_rank: int = OFF_AXIS_CALIBRATION_RANK,
) -> int:
    if not 0 <= prefix_rank < axis_cells or not 0 <= off_axis_rank < axis_cells:
        raise ValueError("A437 rank pair exceeds exact cover")
    events = build_growth_events(
        axis_cells, prefix_calibration_rank, off_axis_calibration_rank
    )
    prefix_activation = [-1] * axis_cells
    off_axis_activation = [-1] * axis_cells
    prefix_activation[0] = 0
    off_axis_activation[0] = 0
    for event_index, event in enumerate(events[1:], start=1):
        if event.axis == "prefix":
            prefix_activation[event.new_rank] = event_index
        else:
            off_axis_activation[event.new_rank] = event_index
    prefix_event = prefix_activation[prefix_rank]
    off_axis_event = off_axis_activation[off_axis_rank]
    if prefix_event == off_axis_event:
        if prefix_rank != 0 or off_axis_rank != 0:
            raise RuntimeError("A437 non-seed activations unexpectedly coincide")
        index = 0
    elif prefix_event > off_axis_event:
        event = events[prefix_event]
        index = event.start + off_axis_rank
    else:
        event = events[off_axis_event]
        index = event.start + prefix_rank
    if anisotropic_rank_pair_at(
        index, axis_cells, prefix_calibration_rank, off_axis_calibration_rank
    ) != (prefix_rank, off_axis_rank):
        raise RuntimeError("A437 anisotropic direct/inverse identity failed")
    return index


def iter_anisotropic_rank_pairs(
    axis_cells: int = AXIS_CELLS,
    prefix_calibration_rank: int = PREFIX_CALIBRATION_RANK,
    off_axis_calibration_rank: int = OFF_AXIS_CALIBRATION_RANK,
) -> Iterator[tuple[int, int]]:
    for event in build_growth_events(
        axis_cells, prefix_calibration_rank, off_axis_calibration_rank
    ):
        if event.axis == "seed":
            yield 0, 0
        elif event.axis == "prefix":
            for off_axis_rank in range(event.other_count):
                yield event.new_rank, off_axis_rank
        else:
            for prefix_rank in range(event.other_count):
                yield prefix_rank, event.new_rank


def iter_anisotropic_wavefront(
    prefix_order: Sequence[int], off_axis_order: Sequence[int]
) -> Iterator[tuple[int, int]]:
    prefix = exact_axis_order(prefix_order, "A437 prefix order")
    off_axis = exact_axis_order(off_axis_order, "A437 off-axis order")
    for prefix_rank, off_axis_rank in iter_anisotropic_rank_pairs():
        yield prefix[prefix_rank], off_axis[off_axis_rank]


def anisotropic_pair_at(
    global_index: int, prefix_order: Sequence[int], off_axis_order: Sequence[int]
) -> tuple[int, int]:
    prefix = exact_axis_order(prefix_order, "A437 prefix order")
    off_axis = exact_axis_order(off_axis_order, "A437 off-axis order")
    prefix_rank, off_axis_rank = anisotropic_rank_pair_at(global_index)
    return prefix[prefix_rank], off_axis[off_axis_rank]


def anisotropic_pair_global_index(
    prefix_cell: int,
    off_axis_cell: int,
    prefix_order: Sequence[int],
    off_axis_order: Sequence[int],
) -> int:
    prefix = exact_axis_order(prefix_order, "A437 prefix order")
    off_axis = exact_axis_order(off_axis_order, "A437 off-axis order")
    prefix_rank = [0] * AXIS_CELLS
    off_axis_rank = [0] * AXIS_CELLS
    for rank, cell in enumerate(prefix):
        prefix_rank[cell] = rank
    for rank, cell in enumerate(off_axis):
        off_axis_rank[cell] = rank
    index = anisotropic_rank_pair_global_index(
        prefix_rank[prefix_cell], off_axis_rank[off_axis_cell]
    )
    if anisotropic_pair_at(index, prefix, off_axis) != (prefix_cell, off_axis_cell):
        raise RuntimeError("A437 cell-level direct/inverse identity failed")
    return index


def worker_location(global_index: int) -> dict[str, int | str]:
    if not 0 <= global_index < PAIR_CELLS:
        raise ValueError("A437 worker index exceeds exact cover")
    worker = global_index % WORKERS
    step = global_index // WORKERS + 1
    return {
        "worker_index": worker,
        "worker_role": f"calibration_balanced_wave_{worker}",
        "worker_step_one_based": step,
        "global_rank_one_based": global_index + 1,
        "exact_parallel_depth": step,
    }


def pair_stream_sha256(prefix_order: Sequence[int], off_axis_order: Sequence[int]) -> str:
    digest = hashlib.sha256()
    chunk = bytearray()
    count = 0
    for prefix, off_axis in iter_anisotropic_wavefront(prefix_order, off_axis_order):
        chunk.extend(prefix.to_bytes(2, "big"))
        chunk.extend(off_axis.to_bytes(2, "big"))
        count += 1
        if len(chunk) >= 1 << 20:
            digest.update(chunk)
            chunk.clear()
    digest.update(chunk)
    if count != PAIR_CELLS:
        raise RuntimeError("A437 pair-stream cover differs")
    return digest.hexdigest()


def calibration_comparison(
    prefix_order: Sequence[int], off_axis_order: Sequence[int]
) -> dict[str, Any]:
    transferred_prefix = exact_axis_order(prefix_order, "A437 transferred W52 prefix order")
    transferred_off_axis = exact_axis_order(
        off_axis_order, "A437 transferred W52 off-axis order"
    )
    a348, _, a355 = load_calibration_sources()
    calibration_prefix = exact_axis_order(
        a355["orders"]["A340_selected8_global_raw"],
        "A437 W46 prefix calibration order",
    )
    calibration_off_axis = exact_axis_order(
        a348["orders"]["A342_selected_pair_global_raw"],
        "A437 W46 corrected off-axis calibration order",
    )
    prefix_rank = calibration_prefix.index(PREFIX_CALIBRATION_CELL) + 1
    off_axis_rank = calibration_off_axis.index(OFF_AXIS_CALIBRATION_CELL) + 1
    if (
        prefix_rank != PREFIX_CALIBRATION_RANK
        or off_axis_rank != OFF_AXIS_CALIBRATION_RANK
    ):
        raise RuntimeError("A437 calibration cells do not occupy frozen ranks")
    anisotropic_rank = (
        anisotropic_pair_global_index(
            PREFIX_CALIBRATION_CELL,
            OFF_AXIS_CALIBRATION_CELL,
            calibration_prefix,
            calibration_off_axis,
        )
        + 1
    )
    neutral_rank = (
        A434.pair_global_index(
            PREFIX_CALIBRATION_CELL,
            OFF_AXIS_CALIBRATION_CELL,
            calibration_prefix,
            calibration_off_axis,
        )
        + 1
    )
    if (
        anisotropic_rank != EXPECTED_ANISOTROPIC_CALIBRATION_RANK
        or neutral_rank != EXPECTED_NEUTRAL_CALIBRATION_RANK
        or anisotropic_rank != prefix_rank * off_axis_rank
    ):
        raise RuntimeError("A437 frozen calibration-rank identities differ")
    return {
        "scope": "known-key W46 calibration geometry only; transferred as a frozen growth ratio, never as an A426 target cell",
        "prefix_calibration_cell": PREFIX_CALIBRATION_CELL,
        "prefix_calibration_rank_one_based": prefix_rank,
        "off_axis_calibration_cell": OFF_AXIS_CALIBRATION_CELL,
        "off_axis_calibration_rank_one_based": off_axis_rank,
        "anisotropic_pair_rank_one_based": anisotropic_rank,
        "anisotropic_pair_rank_product_identity": prefix_rank * off_axis_rank,
        "neutral_square_pair_rank_one_based": neutral_rank,
        "cells_removed_before_calibration_pair_vs_neutral": neutral_rank - anisotropic_rank,
        "factor_vs_neutral_square": neutral_rank / anisotropic_rank,
        "additional_gain_bits_vs_neutral_square": math.log2(neutral_rank / anisotropic_rank),
        "gain_bits_vs_complete_uniform_pair_cover": math.log2(PAIR_CELLS / anisotropic_rank),
        "candidate_assignments_before_calibration_pair": anisotropic_rank * CELL_ASSIGNMENTS,
        "W52_same_prefix_cell_position_one_based": transferred_prefix.index(
            PREFIX_CALIBRATION_CELL
        )
        + 1,
        "W52_same_off_axis_cell_position_one_based": transferred_off_axis.index(
            OFF_AXIS_CALIBRATION_CELL
        )
        + 1,
        "W52_same_cell_positions_used_as_target_information": False,
        "W52_true_pair_rank_known": False,
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "A426_progress_or_filter_outcomes_consumed": False,
    }


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, PROTOCOL, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A437 implementation, protocol or result already exists")
    assert_no_a426_outcome()
    load_design()
    load_axis_sources()
    load_calibration_sources()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A437 tests and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-calibration-balanced-dual-axis-wavefront-a437-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_anisotropic_schedule_codec_hashing_calibration_and_causal_code_frozen_before_A426_outcome_or_any_A437_candidate",
        "design_sha256": DESIGN_SHA256,
        "A426_outcome_available_at_implementation_freeze": False,
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A354_result": anchor(A354_RESULT, A354_RESULT_SHA256),
            "A348_result": anchor(A348_RESULT, A348_RESULT_SHA256),
            "A355_result": anchor(A355_RESULT, A355_RESULT_SHA256),
            "A433_result": anchor(A433_RESULT, A433_RESULT_SHA256),
            "A433_causal": anchor(A433_CAUSAL, A433_CAUSAL_SHA256),
            "A436_result": anchor(A436_RESULT, A436_RESULT_SHA256),
            "A436_causal": anchor(A436_CAUSAL, A436_CAUSAL_SHA256),
            "A434_protocol": anchor(A434_PROTOCOL, A434_PROTOCOL_SHA256),
            "A435_protocol": anchor(A435_PROTOCOL, A435_PROTOCOL_SHA256),
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
        raise RuntimeError("A437 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-calibration-balanced-dual-axis-wavefront-a437-implementation-v1"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A426_outcome_available_at_implementation_freeze") is not False
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A437 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A437 implementation commitment differs")
    return value


def freeze_protocol(
    *,
    expected_implementation_sha256: str,
    expected_a433_result_sha256: str = A433_RESULT_SHA256,
    expected_a436_result_sha256: str = A436_RESULT_SHA256,
) -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A437 protocol or result already exists")
    assert_no_a426_outcome()
    implementation = load_implementation(expected_implementation_sha256)
    prefix_source, prefix, off_source, off_axis = load_axis_sources(
        expected_a433_result_sha256, expected_a436_result_sha256
    )
    load_calibration_sources()
    comparison = calibration_comparison(prefix, off_axis)
    started = time.perf_counter()
    stream_sha = pair_stream_sha256(prefix, off_axis)
    sentinels = []
    sentinel_indices = (
        0,
        1,
        2,
        3,
        4,
        8,
        15,
        16,
        comparison["anisotropic_pair_rank_one_based"] - 1,
        PAIR_CELLS - 2,
        PAIR_CELLS - 1,
    )
    for index in sentinel_indices:
        prefix_cell, off_axis_cell = anisotropic_pair_at(index, prefix, off_axis)
        event = event_for_global_index(index)
        sentinels.append(
            {
                "global_index_zero_based": index,
                "prefix": prefix_cell,
                "off_axis": off_axis_cell,
                "pair_cell": A434.encode_pair_cell(prefix_cell, off_axis_cell),
                "event_axis": event.axis,
                "active_prefix_after": event.prefix_count_after,
                "active_off_axis_after": event.off_axis_count_after,
                **worker_location(index),
            }
        )
    schedule = {
        "algorithm": "calibration_balanced_anisotropic_rectangle_growth",
        "prefix_order_uint16be_sha256": prefix_source[
            "W52_prefix_aligned_direct12_order_uint16be_sha256"
        ],
        "off_axis_order_uint16be_sha256": off_source[
            "W52_corrected_off_axis_order_uint16be_sha256"
        ],
        "pair_stream_uint16be_uint16be_sha256": stream_sha,
        "prefix_calibration_rank_one_based": PREFIX_CALIBRATION_RANK,
        "off_axis_calibration_rank_one_based": OFF_AXIS_CALIBRATION_RANK,
        "exact_integer_growth_test": "(P+1)*561 <= (O+1)*418",
        "tie_break": "prefix_axis",
        "growth_events": len(build_growth_events()),
        "prefix_growth_events": sum(
            event.axis == "prefix" for event in build_growth_events()
        ),
        "off_axis_growth_events": sum(
            event.axis == "off_axis" for event in build_growth_events()
        ),
        "cells": PAIR_CELLS,
        "assignments_per_cell": CELL_ASSIGNMENTS,
        "complete_domain_assignments": DOMAIN_ASSIGNMENTS,
        "workers": WORKERS,
        "worker_tasks_each": WORKER_TASKS,
        "worker_assignment": "global_pair_index_mod_8",
        "streaming_generation": True,
        "sentinels": sentinels,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-calibration-balanced-dual-axis-wavefront-a437-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "complete_anisotropic_24bit_schedule_materialized_before_A426_outcome_or_any_A437_candidate",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "A433_result_sha256": expected_a433_result_sha256,
        "A436_result_sha256": expected_a436_result_sha256,
        "schedule": schedule,
        "schedule_commitment_sha256": canonical_sha256(schedule),
        "calibration_comparison": comparison,
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "A426_progress_or_filter_outcomes_consumed": False,
        "production_execution_enabled": False,
        "volatile_stream_hash_seconds": time.perf_counter() - started,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A354_result": anchor(A354_RESULT, A354_RESULT_SHA256),
            "A348_result": anchor(A348_RESULT, A348_RESULT_SHA256),
            "A355_result": anchor(A355_RESULT, A355_RESULT_SHA256),
            "A433_result": anchor(A433_RESULT, expected_a433_result_sha256),
            "A433_causal": anchor(A433_CAUSAL, A433_CAUSAL_SHA256),
            "A436_result": anchor(A436_RESULT, expected_a436_result_sha256),
            "A436_causal": anchor(A436_CAUSAL, A436_CAUSAL_SHA256),
            "A434_protocol": anchor(A434_PROTOCOL, A434_PROTOCOL_SHA256),
            "A435_protocol": anchor(A435_PROTOCOL, A435_PROTOCOL_SHA256),
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
        raise RuntimeError("A437 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    schedule = value.get("schedule", {})
    comparison = value.get("calibration_comparison", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-calibration-balanced-dual-axis-wavefront-a437-protocol-v1"
        or schedule.get("algorithm")
        != "calibration_balanced_anisotropic_rectangle_growth"
        or schedule.get("growth_events") != 2 * AXIS_CELLS - 1
        or schedule.get("prefix_growth_events") != AXIS_CELLS - 1
        or schedule.get("off_axis_growth_events") != AXIS_CELLS - 1
        or schedule.get("cells") != PAIR_CELLS
        or schedule.get("assignments_per_cell") != CELL_ASSIGNMENTS
        or schedule.get("complete_domain_assignments") != DOMAIN_ASSIGNMENTS
        or schedule.get("workers") != WORKERS
        or schedule.get("worker_tasks_each") != WORKER_TASKS
        or comparison.get("anisotropic_pair_rank_one_based")
        != EXPECTED_ANISOTROPIC_CALIBRATION_RANK
        or comparison.get("neutral_square_pair_rank_one_based")
        != EXPECTED_NEUTRAL_CALIBRATION_RANK
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
        or value.get("A426_progress_or_filter_outcomes_consumed") is not False
        or value.get("production_execution_enabled") is not False
        or value.get("schedule_commitment_sha256") != canonical_sha256(schedule)
    ):
        raise RuntimeError("A437 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {key: item for key, item in value.items() if not key.startswith("volatile_")}
    unsigned.pop("protocol_commitment_sha256")
    if value.get("protocol_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A437 protocol commitment differs")
    return value


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    writer = CausalWriter(api_id="a437ani")
    writer._rules = []
    writer.add_rule(
        name="corrected_axes_to_calibration_geometry",
        description="Bind A433 prefix rank 418 and A436 corrected off-axis rank 561 without reading any A426 target outcome.",
        pattern=["A433_prefix_order", "A436_corrected_off_axis_order"],
        conclusion="A437_calibration_geometry_418_by_561",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="calibration_geometry_to_anisotropic_wavefront",
        description="Grow the next exact rectangle boundary with the smaller normalized calibration coordinate, using an integer cross-product and a frozen prefix tie break.",
        pattern=["A437_calibration_geometry_418_by_561"],
        conclusion="A437_anisotropic_rectangle_growth",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="wavefront_to_exact_cover_and_rank_gain",
        description="Every row or column is emitted once at activation, giving all 2^24 pairs exactly once and moving the W46 calibration pair from 314579 to 234498.",
        pattern=["A437_anisotropic_rectangle_growth"],
        conclusion="A437_exact_complete_schedule",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A433:prefix_rank_418_and_A436:off_axis_rank_561",
        mechanism="corrected_known_key_calibration_geometry",
        outcome="A437:calibration_ratio_418_to_561",
        confidence=1.0,
        source=canonical_sha256(payload["anchors"]),
        quantification=json.dumps(
            {
                "prefix_rank_one_based": PREFIX_CALIBRATION_RANK,
                "off_axis_rank_one_based": OFF_AXIS_CALIBRATION_RANK,
                "target_labels_used": 0,
                "reader_refits": 0,
            },
            sort_keys=True,
        ),
        evidence="two complete target-blind W52 axis orders plus corrected W46 calibration",
        domain="ChaCha20 R20 W52 dual-axis Reader composition",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A437:calibration_ratio_418_to_561",
        mechanism="exact_integer_normalized_boundary_growth",
        outcome="A437:anisotropic_rectangle_wavefront",
        confidence=1.0,
        source=payload["schedule_commitment_sha256"],
        quantification=json.dumps(
            {
                "growth_test": "(P+1)*561 <= (O+1)*418",
                "growth_events": 8191,
                "tie_break": "prefix_axis",
            },
            sort_keys=True,
        ),
        evidence=payload["schedule"]["pair_stream_uint16be_uint16be_sha256"],
        domain="exact streaming pair schedule",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A437:anisotropic_rectangle_wavefront",
        mechanism="single_activation_row_or_column_emission",
        outcome="A437:exact_2pow24_cover_rank_234498",
        confidence=1.0,
        source=payload["protocol_commitment_sha256"],
        quantification=json.dumps(payload["calibration_comparison"], sort_keys=True),
        evidence="16,777,216 unique pair cells; zero labels, refits, candidates, or A426 outcomes",
        domain="prospective W52 recovery schedule",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A433:prefix_rank_418_and_A436:off_axis_rank_561",
        mechanism="materialized_calibration_geometry_schedule_cover_chain",
        outcome="A437:exact_2pow24_cover_rank_234498",
        confidence=1.0,
        source="materialized:A437_anisotropic_chain",
        quantification="exact retained closure",
        evidence="CALIBRATION_BALANCED_COMPLETE_TARGET_BLIND_WAVEFRONT_FROZEN",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A437 calibration-balanced W52 wavefront",
        entities=[
            "A433:prefix_rank_418_and_A436:off_axis_rank_561",
            "A437:calibration_ratio_418_to_561",
            "A437:anisotropic_rectangle_wavefront",
            "A437:exact_2pow24_cover_rank_234498",
        ],
    )
    writer.add_gap(
        subject="A437:exact_2pow24_cover_rank_234498",
        predicate="next_required_object",
        expected_object_type="restart_safe_A438_production_executor",
        confidence=1.0,
        suggested_queries=[
            "Replace A435's square pair codec with A437's frozen anisotropic codec while retaining its qualified Metal subcell filter, eight-worker progress, shared stop, and dual 8-block confirmation."
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
        reader.api_id != "a437ani"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A437 authentic Causal reopen gate failed")
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
            "axis_geometry": explicit[0],
            "wavefront": explicit[1],
            "cover_and_gain": explicit[2],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def assemble_result(*, expected_protocol_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A437 result already exists")
    assert_no_a426_outcome()
    protocol = load_protocol(expected_protocol_sha256)
    _, prefix, _, off_axis = load_axis_sources(
        protocol["A433_result_sha256"], protocol["A436_result_sha256"]
    )
    comparison = calibration_comparison(prefix, off_axis)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-calibration-balanced-dual-axis-wavefront-a437-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "CALIBRATION_BALANCED_COMPLETE_TARGET_BLIND_W52_WAVEFRONT_FROZEN",
        "protocol_sha256": expected_protocol_sha256,
        "protocol_commitment_sha256": protocol["protocol_commitment_sha256"],
        "schedule_commitment_sha256": protocol["schedule_commitment_sha256"],
        "pair_stream_uint16be_uint16be_sha256": protocol["schedule"][
            "pair_stream_uint16be_uint16be_sha256"
        ],
        "schedule_summary": {
            "algorithm": protocol["schedule"]["algorithm"],
            "growth_events": protocol["schedule"]["growth_events"],
            "cells": PAIR_CELLS,
            "assignments_per_cell": CELL_ASSIGNMENTS,
            "complete_domain_assignments": DOMAIN_ASSIGNMENTS,
            "workers": WORKERS,
            "worker_tasks_each": WORKER_TASKS,
            "duplicate_pairs": 0,
            "uncovered_pairs": 0,
        },
        "calibration_comparison": comparison,
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "A426_progress_or_filter_outcomes_consumed": False,
        "production_execution_enabled": False,
        "next_executor": "A438",
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(
                IMPLEMENTATION, protocol["implementation_sha256"]
            ),
            "protocol": anchor(PROTOCOL, expected_protocol_sha256),
            "A354_result": anchor(A354_RESULT, A354_RESULT_SHA256),
            "A348_result": anchor(A348_RESULT, A348_RESULT_SHA256),
            "A355_result": anchor(A355_RESULT, A355_RESULT_SHA256),
            "A433_result": anchor(A433_RESULT, protocol["A433_result_sha256"]),
            "A433_causal": anchor(A433_CAUSAL, A433_CAUSAL_SHA256),
            "A436_result": anchor(A436_RESULT, protocol["A436_result_sha256"]),
            "A436_causal": anchor(A436_CAUSAL, A436_CAUSAL_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["causal"] = build_causal(payload)
    payload["result_sha256"] = canonical_sha256(payload)
    atomic_json(RESULT, payload)
    REPORT.write_text(
        "# A437 — calibration-balanced dual-axis W52 wavefront\n\n"
        f"- Exact pair cover: **{PAIR_CELLS:,} cells**\n"
        f"- Assignments per cell: **2^28**\n"
        f"- Complete residual domain: **2^52**\n"
        f"- W46 calibration ranks: **{PREFIX_CALIBRATION_RANK} × {OFF_AXIS_CALIBRATION_RANK}**\n"
        f"- Anisotropic calibration-pair rank: **{EXPECTED_ANISOTROPIC_CALIBRATION_RANK:,}**\n"
        f"- Neutral-square calibration-pair rank: **{EXPECTED_NEUTRAL_CALIBRATION_RANK:,}**\n"
        f"- Earlier by: **{comparison['cells_removed_before_calibration_pair_vs_neutral']:,} cells / {comparison['additional_gain_bits_vs_neutral_square']:.6f} bits**\n"
        "- Target labels / refits / candidates / A426 outcomes: **0 / 0 / 0 / 0**\n"
        "- Authentic AI-native Causal readback: **3 explicit + 1 inferred chain**\n",
        encoding="utf-8",
    )
    assert_no_a426_outcome()
    return payload


def analyze() -> dict[str, Any]:
    value: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design": anchor(DESIGN, DESIGN_SHA256),
        "implementation_exists": IMPLEMENTATION.exists(),
        "protocol_exists": PROTOCOL.exists(),
        "result_exists": RESULT.exists(),
        "A426_outcome_exists": A426_RESULT.exists() or A426_STOP.exists(),
    }
    if RESULT.exists():
        value["result"] = json.loads(RESULT.read_bytes())
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--freeze-implementation", action="store_true")
    mode.add_argument("--freeze-protocol", action="store_true")
    mode.add_argument("--assemble", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-a433-result-sha256", default=A433_RESULT_SHA256)
    parser.add_argument("--expected-a436-result-sha256", default=A436_RESULT_SHA256)
    parser.add_argument("--expected-protocol-sha256")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.freeze_implementation:
        value = freeze_implementation()
    elif args.freeze_protocol:
        if not args.expected_implementation_sha256:
            raise SystemExit("--expected-implementation-sha256 is required")
        value = freeze_protocol(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a433_result_sha256=args.expected_a433_result_sha256,
            expected_a436_result_sha256=args.expected_a436_result_sha256,
        )
    elif args.assemble:
        if not args.expected_protocol_sha256:
            raise SystemExit("--expected-protocol-sha256 is required")
        value = assemble_result(expected_protocol_sha256=args.expected_protocol_sha256)
    else:
        value = analyze()
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
