#!/usr/bin/env python3
"""A458: extend the A456 single-block frequency ray and ablate B."""

from __future__ import annotations

import argparse
import gc
import hashlib
import importlib.util
import inspect
import json
import os
import subprocess
import sys
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

STEM = "chacha20_round20_w52_no_refit_frequency_ray_extension_a458"
DESIGN = CONFIGS / f"{STEM}_design_v1.json"
IMPLEMENTATION = CONFIGS / f"{STEM}_implementation_v1.json"
RESULT = RESULTS / f"{STEM}_v1.json"
ARTIFACT = RESULTS / f"{STEM}_pair_stream_uint16be_uint16be_v1.bin"
COMPONENT_INPUT = RESULTS / f"{STEM}_component_orders_v1.bin"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / f"tests/test_{STEM}.py"
REPRO = ROOT / f"scripts/reproduce_{STEM}.sh"
NATIVE_SOURCE = RESEARCH / "native/a458_frequency_ray_compiler.cpp"
NATIVE_EXECUTABLE = RESEARCH / "bin/a458_frequency_ray_compiler"

A456_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_no_refit_frequency_ray_portfolio_a456.py"
)
A456_DESIGN = (
    CONFIGS
    / "chacha20_round20_w52_no_refit_frequency_ray_portfolio_a456_design_v1.json"
)
A456_IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w52_no_refit_frequency_ray_portfolio_a456_implementation_v1.json"
)
A456_RESULT = (
    RESULTS / "chacha20_round20_w52_no_refit_frequency_ray_portfolio_a456_v1.json"
)
A456_PAIR_STREAM = (
    RESULTS
    / "chacha20_round20_w52_no_refit_frequency_ray_portfolio_a456_pair_stream_uint16be_uint16be_v1.bin"
)
A456_CAUSAL = A456_RESULT.with_suffix(".causal")
A456_READBACK = RESEARCH / "reports/CAUSAL_CHACHA20_A456_PERSONAL_READER_READBACK_V1.md"

ATTEMPT_ID = "A458"
DESIGN_SHA256 = "269d10b462dd1da0c1d1dc30d96ed8b32b543ae98a1754750324a2079801d1d2"
A456_RUNNER_SHA256 = "4a2a69351775b6db7096ea6fef182bd30a77b8f725d4b26205474c437dd2f74b"
A456_DESIGN_SHA256 = "a1a2529fbb9280d4f031f7fb816eb3aa85a64671406c38bbd60b4c80056a800f"
A456_IMPLEMENTATION_SHA256 = (
    "c31ce92b9d32dd08406e1f1563336381f8bd63b8a0118edd9dc6099616974369"
)
A456_RESULT_SHA256 = "8a06661bd6ace82fc9b6854eb4158ddc8a92a47563d71d4aee1cf47707cbbc88"
A456_RESULT_COMMITMENT_SHA256 = (
    "6ef9c4d507892052abf766ee9d34e08fb3833c2377d05c4255e34ff083b80908"
)
A456_CALIBRATION_SHA256 = "581145b5a2e9973596e5911f21ad70bfb7319676dcc930b4ba1f675ab30a2f8d"
A456_PAIR_STREAM_SHA256 = "9a3af1cfb71f96d186815086170127cd5340e7ac102a5fe9dc65414c14df7352"
A456_CAUSAL_SHA256 = "ef9024b9c5644958ca4a3f7ebff8ec16c2a448867f4a7e86445b83e07390213d"
A456_READBACK_SHA256 = "37898bba41c518b0f07c7c415a32ecc9afe7264a3936003b14b60513f7ec6a32"
NATIVE_SOURCE_SHA256 = "bb0c95cee7f07c1092cdbd6df685dfb14458bfa53b27170f86248ed61312ca03"
NATIVE_EXECUTABLE_SHA256 = (
    "621c74121cb8c31d7331ebf6ec6e58e14b32897ec907daca854f291cee8dec79"
)

SYMBOLS = ("H", "B", "O")
COMPONENTS = {
    "H": "hybrid_proof_top16_equal",
    "B": "proof_borda_top32",
    "O": "proof_best_single",
}
M_VALUES = tuple(range(7, 16))
ARMS = ("B1", "B0")
EXPECTED_BY_ARM = {"B1": 207, "B0": 198}
EXPECTED_ORBITS_BY_ARM = {"B1": 9, "B0": 9}
EXPECTED_PATTERNS = 405
EXPECTED_ORBITS = 18
A456_CONTROL_PATTERN = "BOOOOOOHHHHHH"
A456_CONTROL_AGGREGATE = 0.4894376102314375
A456_CONTROL_MINIMUM = 0.17634772194140247
AXIS_CELLS = 1 << 12
PAIR_CELLS = 1 << 24
CHUNK = 1 << 20
TOP_KS = (16, 64, 256, 1024, 65536, 1048576)
MAGIC = b"A458RANKV1" + bytes(6)
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A458 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A456 = load_module(A456_RUNNER, "a458_a456")
A454 = A456.A454
A448 = A456.A448
file_sha256 = A456.file_sha256
canonical_sha256 = A456.canonical_sha256
atomic_json = A456.atomic_json
atomic_bytes = A456.atomic_bytes
anchor = A456.anchor
path_from_ref = A456.path_from_ref
relative = A456.relative


def array_sha256(value: np.ndarray, dtype: str) -> str:
    digest = hashlib.sha256()
    array = np.asarray(value)
    for start in range(0, array.size, CHUNK):
        digest.update(
            array[start : start + CHUNK].astype(dtype, copy=False).tobytes()
        )
    return digest.hexdigest()


def rotations(value: str) -> set[str]:
    return {value[index:] + value[:index] for index in range(len(value))}


def canonical_rotation(value: str) -> str:
    return min(rotations(value))


def canonical_pattern(arm: str, m: int) -> str:
    if arm not in ARMS or m not in M_VALUES:
        raise ValueError("A458 arm or scale differs")
    return ("B" if arm == "B1" else "") + "O" * m + "H" * m


def enumerate_patterns() -> dict[str, dict[int, tuple[str, ...]]]:
    output: dict[str, dict[int, tuple[str, ...]]] = {}
    for arm in ARMS:
        output[arm] = {}
        for m in M_VALUES:
            ordered = tuple(sorted(rotations(canonical_pattern(arm, m))))
            expected = 2 * m + (1 if arm == "B1" else 0)
            if len(ordered) != expected:
                raise RuntimeError(f"A458 {arm} m={m} phase count differs")
            if any(
                row.count("H") != m
                or row.count("B") != (1 if arm == "B1" else 0)
                or row.count("O") != m
                for row in ordered
            ):
                raise RuntimeError(f"A458 {arm} m={m} symbol counts differ")
            output[arm][m] = ordered
        if sum(len(output[arm][m]) for m in M_VALUES) != EXPECTED_BY_ARM[arm]:
            raise RuntimeError(f"A458 {arm} candidate count differs")
    return output


PATTERNS_BY_ARM_M = enumerate_patterns()
PATTERNS = tuple(
    pattern
    for arm in ARMS
    for m in M_VALUES
    for pattern in PATTERNS_BY_ARM_M[arm][m]
)
if len(PATTERNS) != EXPECTED_PATTERNS or len(set(PATTERNS)) != EXPECTED_PATTERNS:
    raise RuntimeError("A458 total candidate count or uniqueness differs")
PATTERN_M = {
    pattern: m
    for arm in ARMS
    for m in M_VALUES
    for pattern in PATTERNS_BY_ARM_M[arm][m]
}
PATTERN_ARM = {
    pattern: arm
    for arm in ARMS
    for m in M_VALUES
    for pattern in PATTERNS_BY_ARM_M[arm][m]
}
PATTERN_ORBIT = {pattern: canonical_rotation(pattern) for pattern in PATTERNS}
ORBITS: dict[str, tuple[str, ...]] = {
    orbit: tuple(sorted(pattern for pattern in PATTERNS if PATTERN_ORBIT[pattern] == orbit))
    for orbit in sorted(set(PATTERN_ORBIT.values()))
}
if len(ORBITS) != EXPECTED_ORBITS:
    raise RuntimeError("A458 cyclic orbit count differs")
for arm in ARMS:
    count = sum(PATTERN_ARM[orbit] == arm for orbit in ORBITS)
    if count != EXPECTED_ORBITS_BY_ARM[arm]:
        raise RuntimeError(f"A458 {arm} orbit count differs")
for orbit, rows in ORBITS.items():
    if set(rows) != rotations(orbit):
        raise RuntimeError("A458 cyclic orbit phase cover differs")


def cyclic_ho_transitions(pattern: str) -> int:
    word = pattern.replace("B", "")
    return sum(
        word[index] != word[(index + 1) % len(word)]
        for index in range(len(word))
    )


def load_design() -> dict[str, Any]:
    anchor(DESIGN, DESIGN_SHA256)
    value = json.loads(DESIGN.read_bytes())
    source = value.get("source_contract", {})
    family = value.get("candidate_family_contract", {})
    selection = value.get("selection_contract", {})
    materialization = value.get("W52_materialization_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-no-refit-frequency-ray-extension-a458-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or source.get("A456_result_sha256") != A456_RESULT_SHA256
        or source.get("A456_result_commitment_sha256")
        != A456_RESULT_COMMITMENT_SHA256
        or source.get("A456_calibration_sha256") != A456_CALIBRATION_SHA256
        or source.get("A456_selected_pattern") != A456_CONTROL_PATTERN
        or source.get("component_symbol_map") != COMPONENTS
        or tuple(family.get("m_values", [])) != M_VALUES
        or family.get("expected_unique_patterns") != EXPECTED_PATTERNS
        or family.get("expected_cyclic_orbits") != EXPECTED_ORBITS
        or family.get("B1_main_ray", {}).get("expected_unique_patterns")
        != EXPECTED_BY_ARM["B1"]
        or family.get("B0_matched_endpoint_ray", {}).get(
            "expected_unique_patterns"
        )
        != EXPECTED_BY_ARM["B0"]
        or family.get("complete_permutation_required") is not True
        or family.get("exact_per_active_component_proposal_bound_required")
        is not True
        or selection.get("selection_scope")
        != "A448_remaining96_A447_fixed_model_no_refit_only"
        or selection.get("required_positive_fixed_blocks") != 8
        or selection.get(
            "A456_BOOOOOOHHHHHH_is_frozen_external_control_not_a_candidate"
        )
        is not True
        or selection.get("B1_and_B0_are_both_selection_eligible") is not True
        or selection.get("complete128_crossfit_is_report_only_not_selection")
        is not True
        or selection.get("W52_pair_geometry_is_report_only_not_selection")
        is not True
        or materialization.get("pair_cells") != PAIR_CELLS
        or materialization.get("native_compiler_period_limit") != 31
        or materialization.get(
            "native_compiler_must_support_HBO_and_HO_active_component_sets"
        )
        is not True
        or materialization.get("candidate_assignments_executed") != 0
        or boundary.get("A458_candidate_results_seen_before_design") is not False
        or boundary.get("A458_selected_pattern_seen_before_design") is not False
        or boundary.get("A458_W52_pair_stream_seen_before_design") is not False
        or boundary.get(
            "A426_A438_A440_A443_A450_A452_A455_A457_secret_result_stop_or_worker_progress_read"
        )
        is not False
        or boundary.get("W52_target_labels_used") != 0
        or boundary.get("feature_refits") != 0
        or boundary.get("model_refits") != 0
        or boundary.get("production_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A458 frozen design semantics differ")
    for key, item in value["source_anchors"].items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, value["source_anchors"][f"{stem}_sha256"])
    return value


def load_sources() -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    anchor(A456_RUNNER, A456_RUNNER_SHA256)
    anchor(A456_DESIGN, A456_DESIGN_SHA256)
    anchor(A456_IMPLEMENTATION, A456_IMPLEMENTATION_SHA256)
    anchor(A456_RESULT, A456_RESULT_SHA256)
    anchor(A456_PAIR_STREAM, A456_PAIR_STREAM_SHA256)
    anchor(A456_CAUSAL, A456_CAUSAL_SHA256)
    anchor(A456_READBACK, A456_READBACK_SHA256)
    a456 = A456.load_result(A456_RESULT_SHA256)
    a454, a448, a449, a451, a453 = A456.load_sources()
    if (
        a456.get("result_commitment_sha256")
        != A456_RESULT_COMMITMENT_SHA256
        or a456.get("calibration", {}).get("calibration_sha256")
        != A456_CALIBRATION_SHA256
        or a456.get("calibration", {}).get("selected_pattern")
        != A456_CONTROL_PATTERN
        or a456.get("W52_target_labels_used") != 0
        or a456.get("feature_refits") != 0
        or a456.get("model_refits") != 0
        or a456.get("W52_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A458 A456 source semantics differ")
    return a456, a454, a448, a449, a451, a453


def freeze_implementation() -> dict[str, Any]:
    downstream = (IMPLEMENTATION, RESULT, ARTIFACT, COMPONENT_INPUT, CAUSAL, REPORT)
    if any(path.exists() for path in downstream):
        raise FileExistsError("A458 implementation or downstream artifact exists")
    design = load_design()
    load_sources()
    for path in (TEST, REPRO, NATIVE_SOURCE, NATIVE_EXECUTABLE):
        if not path.exists():
            raise FileNotFoundError(f"A458 required artifact absent: {path}")
    anchor(NATIVE_SOURCE, NATIVE_SOURCE_SHA256)
    anchor(NATIVE_EXECUTABLE, NATIVE_EXECUTABLE_SHA256)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-no-refit-frequency-ray-extension-a458-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_paired_B1_B0_single_block_ray_evaluator_and_active_component_period31_W52_compiler_frozen_before_any_A458_candidate_value_or_selected_pattern",
        "design_sha256": DESIGN_SHA256,
        "candidate_family_sha256": canonical_sha256(list(PATTERNS)),
        "candidate_count": len(PATTERNS),
        "orbit_family_sha256": canonical_sha256(
            {key: list(value) for key, value in ORBITS.items()}
        ),
        "orbit_count": len(ORBITS),
        "patterns_by_arm_m": {
            arm: {
                str(m): len(PATTERNS_BY_ARM_M[arm][m]) for m in M_VALUES
            }
            for arm in ARMS
        },
        "orbits_by_arm": {
            arm: sum(PATTERN_ARM[orbit] == arm for orbit in ORBITS)
            for arm in ARMS
        },
        "selection_objective": design["selection_contract"][
            "lexicographic_objective"
        ],
        "A458_candidate_results_seen_at_freeze": False,
        "A458_selected_pattern_seen_at_freeze": False,
        "A458_W52_pair_stream_seen_at_freeze": False,
        "prior_secret_recovery_progress_or_result_read": False,
        "W52_target_labels_used": 0,
        "feature_refits": 0,
        "model_refits": 0,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A456_runner": anchor(A456_RUNNER, A456_RUNNER_SHA256),
            "A456_design": anchor(A456_DESIGN, A456_DESIGN_SHA256),
            "A456_implementation": anchor(
                A456_IMPLEMENTATION, A456_IMPLEMENTATION_SHA256
            ),
            "A456_result": anchor(A456_RESULT, A456_RESULT_SHA256),
            "A456_pair_stream": anchor(
                A456_PAIR_STREAM, A456_PAIR_STREAM_SHA256
            ),
            "A456_causal": anchor(A456_CAUSAL, A456_CAUSAL_SHA256),
            "A456_personal_readback": anchor(
                A456_READBACK, A456_READBACK_SHA256
            ),
            "native_source": anchor(NATIVE_SOURCE, NATIVE_SOURCE_SHA256),
            "native_executable": anchor(
                NATIVE_EXECUTABLE, NATIVE_EXECUTABLE_SHA256
            ),
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
        != "chacha20-round20-w52-no-refit-frequency-ray-extension-a458-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("candidate_family_sha256")
        != canonical_sha256(list(PATTERNS))
        or value.get("candidate_count") != EXPECTED_PATTERNS
        or value.get("orbit_count") != EXPECTED_ORBITS
        or value.get("A458_candidate_results_seen_at_freeze") is not False
        or value.get("A458_selected_pattern_seen_at_freeze") is not False
        or value.get("A458_W52_pair_stream_seen_at_freeze") is not False
        or value.get("prior_secret_recovery_progress_or_result_read") is not False
        or value.get("W52_target_labels_used") != 0
        or value.get("feature_refits") != 0
        or value.get("model_refits") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A458 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A458 implementation commitment differs")
    return value


def active_symbols(pattern: str) -> tuple[str, ...]:
    if not pattern or set(pattern) - set(SYMBOLS):
        raise ValueError("A458 pattern is outside the declared alphabet")
    active = tuple(symbol for symbol in SYMBOLS if symbol in pattern)
    if "H" not in active or "O" not in active or active not in (
        ("H", "B", "O"),
        ("H", "O"),
    ):
        raise ValueError("A458 pattern must activate H/O and may activate B")
    return active


def occurrence_slots(pattern: str, symbol: str) -> np.ndarray:
    if symbol not in active_symbols(pattern):
        raise ValueError(f"A458 pattern omits component {symbol}")
    return np.asarray(
        [index for index, item in enumerate(pattern) if item == symbol],
        dtype=np.int64,
    )


def proposal_key_vector(
    ranks: np.ndarray,
    pattern: str,
    symbol: str,
    *,
    require_complete_permutation: bool = True,
) -> np.ndarray:
    row = np.asarray(ranks, dtype=np.int64)
    if row.ndim != 1 or np.any(row < 1):
        raise ValueError("A458 component ranks must be positive and one dimensional")
    if require_complete_permutation and (
        int(row.min()) != 1
        or int(row.max()) != row.size
        or np.unique(row).size != row.size
    ):
        raise ValueError("A458 component ranks are not a complete permutation")
    slots = occurrence_slots(pattern, symbol)
    zero_based = row - 1
    return (
        len(pattern) * (zero_based // slots.size)
        + slots[zero_based % slots.size]
    )


def weighted_first_encounter_ranks(
    component_ranks: Mapping[str, np.ndarray], pattern: str
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    active = active_symbols(pattern)
    if not set(active) <= set(component_ranks):
        raise ValueError("A458 active component cover differs")
    keys = {
        symbol: proposal_key_vector(component_ranks[symbol], pattern, symbol)
        for symbol in active
    }
    first_key = np.minimum.reduce(list(keys.values()))
    if np.unique(first_key).size != first_key.size:
        raise RuntimeError("A458 first-encounter keys are not unique")
    ids = np.arange(first_key.size, dtype=np.int64)
    order = np.lexsort((ids, first_key))
    fused_rank = np.empty(first_key.size, dtype=np.int32)
    fused_rank[order] = np.arange(1, first_key.size + 1, dtype=np.int32)
    bounds: dict[str, Any] = {}
    for symbol in active:
        cap = np.minimum(first_key.size, keys[symbol] + 1)
        violations = int(np.count_nonzero(fused_rank.astype(np.int64) > cap))
        bounds[symbol] = {
            "frequency": pattern.count(symbol),
            "period": len(pattern),
            "asymptotic_regret": len(pattern) / pattern.count(symbol),
            "violations": violations,
            "minimum_slack": int((cap - fused_rank).min()),
        }
        if violations:
            raise RuntimeError(f"A458 exact proposal bound failed for {symbol}")
    return fused_rank, first_key, bounds


def pattern_complexity(pattern: str) -> dict[str, Any]:
    active = active_symbols(pattern)
    regrets = {
        symbol: len(pattern) / pattern.count(symbol) for symbol in active
    }
    return {
        "arm": PATTERN_ARM[pattern],
        "m": PATTERN_M[pattern],
        "period": len(pattern),
        "frequencies": {symbol: pattern.count(symbol) for symbol in SYMBOLS},
        "active_symbols": list(active),
        "excluded_symbols": [symbol for symbol in SYMBOLS if symbol not in active],
        "asymptotic_active_component_regret": regrets,
        "maximum_asymptotic_active_component_regret": max(regrets.values()),
        "cyclic_orbit": PATTERN_ORBIT[pattern],
        "cyclic_HO_transitions": cyclic_ho_transitions(pattern),
    }


def calibration_field(
    fields: Mapping[str, np.ndarray], targets: Sequence[int], pattern: str
) -> np.ndarray:
    output = np.zeros((A448.TARGETS, A448.CELLS), dtype=np.int16)
    for target in targets:
        ranks, _keys, _bounds = weighted_first_encounter_ranks(
            {
                symbol: fields[name][target]
                for symbol, name in COMPONENTS.items()
            },
            pattern,
        )
        output[target] = ranks.astype(np.int16)
    return output


def compact_statistics(stats: Mapping[str, Any]) -> dict[str, Any]:
    return A454.compact_statistics(stats)


def orbit_statistics(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    minima = np.asarray(
        [
            row["remaining96_A447_fixed_model_no_refit"][
                "minimum_fixed_block_bit_gain"
            ]
            for row in rows
        ],
        dtype=np.float64,
    )
    aggregates = np.asarray(
        [
            row["remaining96_A447_fixed_model_no_refit"]["aggregate_bit_gain"]
            for row in rows
        ],
        dtype=np.float64,
    )
    positives = np.asarray(
        [
            row["remaining96_A447_fixed_model_no_refit"][
                "positive_fixed_block_count"
            ]
            for row in rows
        ],
        dtype=np.int64,
    )
    return {
        "cyclic_orbit": rows[0]["complexity"]["cyclic_orbit"],
        "arm": rows[0]["complexity"]["arm"],
        "m": rows[0]["complexity"]["m"],
        "period": rows[0]["complexity"]["period"],
        "cyclic_HO_transitions": rows[0]["complexity"][
            "cyclic_HO_transitions"
        ],
        "phase_count": len(rows),
        "minimum_fixed_block_bit_gain": {
            "minimum": float(minima.min()),
            "median": float(np.median(minima)),
            "maximum": float(minima.max()),
        },
        "aggregate_bit_gain": {
            "minimum": float(aggregates.min()),
            "median": float(np.median(aggregates)),
            "maximum": float(aggregates.max()),
        },
        "eight_block_positive_phase_count": int(np.count_nonzero(positives == 8)),
    }


def selection_key(
    row: Mapping[str, Any], orbit: Mapping[str, Any]
) -> tuple[Any, ...]:
    stats = row["remaining96_A447_fixed_model_no_refit"]
    return (
        -float(stats["minimum_fixed_block_bit_gain"]),
        -float(orbit["minimum_fixed_block_bit_gain"]["median"]),
        -float(stats["aggregate_bit_gain"]),
        -float(orbit["aggregate_bit_gain"]["median"]),
        -int(stats["targets_at_or_above_median_rank"]),
        int(stats["worst_rank"]),
        int(row["complexity"]["period"]),
        str(row["complexity"]["arm"]),
        str(row["pattern"]),
    )


def calibration_result() -> dict[str, Any]:
    a456, _a454, _a448, _a449, _a451, _a453 = load_sources()
    measurements, ledgers = A448.load_complete_measurements()
    borda, truths, borda_contract = A448.reconstruct_borda()
    rank_panel, feature_names, feature_contract = A448.build_rank_panel(
        measurements, borda
    )
    a447_result = A448.load_a447_result()
    fixed_evaluations, fixed_fields, _fixed_order = A448.fixed_no_refit_evaluation(
        rank_panel, truths, borda, feature_names, a447_result
    )
    crossfit_evaluations, crossfit_selected, crossfit_fields = (
        A448.complete128_crossfit(rank_panel, truths, borda, feature_names)
    )
    remaining = np.asarray(
        [
            row["target_index"]
            for row in A448.complete_manifest()
            if not row["reused_from_A447"]
        ],
        dtype=np.int64,
    )
    rows: list[dict[str, Any]] = []
    for index, pattern in enumerate(PATTERNS, start=1):
        field = calibration_field(fixed_fields, remaining, pattern)
        stats = A448.statistics(
            field,
            truths,
            remaining,
            evaluation_scope="remaining96",
        )
        compact = compact_statistics(stats)
        compact["evaluation_mode"] = "A447_fixed_model_no_refit_remaining96"
        rows.append(
            {
                "pattern": pattern,
                "complexity": pattern_complexity(pattern),
                "remaining96_A447_fixed_model_no_refit": compact,
                "remaining96_rank_field_sha256": A448.array_sha256(
                    field[remaining], "<i2"
                ),
            }
        )
        if index % 25 == 0 or index == len(PATTERNS):
            print(
                f"A458 calibrated {index}/{len(PATTERNS)} structured schedules",
                file=sys.stderr,
                flush=True,
            )
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["complexity"]["cyclic_orbit"]].append(row)
    orbit_rows = {
        orbit: orbit_statistics(grouped[orbit]) for orbit in sorted(grouped)
    }
    eligible = [
        row
        for row in rows
        if row["remaining96_A447_fixed_model_no_refit"][
            "positive_fixed_block_count"
        ]
        == 8
    ]
    if not eligible:
        raise RuntimeError("A458 candidate family has no eight-block-positive schedule")
    ranked = sorted(
        eligible,
        key=lambda row: selection_key(
            row, orbit_rows[row["complexity"]["cyclic_orbit"]]
        ),
    )
    selected_row = ranked[0]
    selected_pattern = selected_row["pattern"]
    selected_orbit = orbit_rows[selected_row["complexity"]["cyclic_orbit"]]
    all_targets = np.arange(A448.TARGETS, dtype=np.int64)
    selected_complete_field = calibration_field(
        crossfit_fields, all_targets, selected_pattern
    )
    selected_complete = A448.statistics(
        selected_complete_field,
        truths,
        all_targets,
        evaluation_scope="complete128",
    )
    selected_fixed_field = calibration_field(
        fixed_fields, remaining, selected_pattern
    )
    selected_fixed_full = A448.statistics(
        selected_fixed_field,
        truths,
        remaining,
        evaluation_scope="remaining96",
    )
    selected_stats = selected_row["remaining96_A447_fixed_model_no_refit"]
    a456_stats = a456["calibration"]["selected_remaining96_full_statistics"]
    a456_complete = a456["calibration"]["selected_complete128_report_only"]
    strict_improvement = bool(
        selected_stats["minimum_fixed_block_bit_gain"]
        > a456_stats["minimum_fixed_block_bit_gain"]
        or (
            selected_stats["minimum_fixed_block_bit_gain"]
            == a456_stats["minimum_fixed_block_bit_gain"]
            and selected_stats["aggregate_bit_gain"]
            > a456_stats["aggregate_bit_gain"]
        )
    )
    per_arm_m: dict[str, dict[str, Any]] = {arm: {} for arm in ARMS}
    best_by_arm_m: dict[tuple[str, int], dict[str, Any] | None] = {}
    for arm in ARMS:
        for m in M_VALUES:
            subset = [
                row
                for row in rows
                if row["complexity"]["arm"] == arm
                and row["complexity"]["m"] == m
            ]
            subset_eligible = [
                row
                for row in subset
                if row["remaining96_A447_fixed_model_no_refit"][
                    "positive_fixed_block_count"
                ]
                == 8
            ]
            best = (
                min(
                    subset_eligible,
                    key=lambda row: selection_key(
                        row, orbit_rows[row["complexity"]["cyclic_orbit"]]
                    ),
                )
                if subset_eligible
                else None
            )
            best_by_arm_m[(arm, m)] = best
            per_arm_m[arm][str(m)] = {
                "candidate_count": len(subset),
                "eligible_eight_block_positive_count": len(subset_eligible),
                "best_pattern": best["pattern"] if best else None,
                "best_statistics": (
                    best["remaining96_A447_fixed_model_no_refit"]
                    if best
                    else None
                ),
                "best_orbit_statistics": (
                    orbit_rows[best["complexity"]["cyclic_orbit"]]
                    if best
                    else None
                ),
            }
    matched_B_effect_by_m: dict[str, Any] = {}
    for m in M_VALUES:
        b1 = best_by_arm_m[("B1", m)]
        b0 = best_by_arm_m[("B0", m)]
        row: dict[str, Any] = {
            "B1_best_pattern": b1["pattern"] if b1 else None,
            "B0_best_pattern": b0["pattern"] if b0 else None,
        }
        if b1 and b0:
            b1_stats = b1["remaining96_A447_fixed_model_no_refit"]
            b0_stats = b0["remaining96_A447_fixed_model_no_refit"]
            row["B1_minus_B0"] = {
                "minimum_fixed_block_bit_gain": b1_stats[
                    "minimum_fixed_block_bit_gain"
                ]
                - b0_stats["minimum_fixed_block_bit_gain"],
                "aggregate_bit_gain": b1_stats["aggregate_bit_gain"]
                - b0_stats["aggregate_bit_gain"],
                "targets_at_or_above_median_rank": b1_stats[
                    "targets_at_or_above_median_rank"
                ]
                - b0_stats["targets_at_or_above_median_rank"],
            }
        matched_B_effect_by_m[str(m)] = row
    result: dict[str, Any] = {
        "selection_scope": "A448_remaining96_A447_fixed_model_no_refit_only",
        "candidate_count": len(rows),
        "cyclic_orbit_count": len(orbit_rows),
        "eligible_eight_block_positive_count": len(eligible),
        "selected_pattern": selected_pattern,
        "selected_complexity": selected_row["complexity"],
        "selected_orbit_statistics": selected_orbit,
        "selected_remaining96_full_statistics": selected_fixed_full,
        "selected_complete128_report_only": selected_complete,
        "A456_BOOOOOOHHHHHH_external_control_remaining96": a456_stats,
        "A456_BOOOOOOHHHHHH_external_control_complete128_report_only": a456_complete,
        "selected_delta_over_A456_BOOOOOOHHHHHH": {
            "remaining96_aggregate_bit_gain": selected_stats[
                "aggregate_bit_gain"
            ]
            - a456_stats["aggregate_bit_gain"],
            "remaining96_minimum_fixed_block_bit_gain": selected_stats[
                "minimum_fixed_block_bit_gain"
            ]
            - a456_stats["minimum_fixed_block_bit_gain"],
            "remaining96_targets_at_or_above_median_rank": selected_stats[
                "targets_at_or_above_median_rank"
            ]
            - a456_stats["targets_at_or_above_median_rank"],
            "complete128_aggregate_bit_gain": selected_complete[
                "aggregate_bit_gain"
            ]
            - a456_complete["aggregate_bit_gain"],
            "complete128_minimum_fixed_block_bit_gain": selected_complete[
                "minimum_fixed_block_bit_gain"
            ]
            - a456_complete["minimum_fixed_block_bit_gain"],
        },
        "qualifies_separate_recovery_queue": strict_improvement,
        "selection_key": list(selection_key(selected_row, selected_orbit)),
        "per_arm_m_frontier": per_arm_m,
        "matched_B_effect_by_m": matched_B_effect_by_m,
        "top_32_candidates": ranked[:32],
        "all_candidate_summaries": rows,
        "cyclic_orbit_summaries": orbit_rows,
        "candidate_family_sha256": canonical_sha256(rows),
        "orbit_family_sha256": canonical_sha256(orbit_rows),
        "selected_complete128_rank_field_sha256": A448.array_sha256(
            selected_complete_field, "<i2"
        ),
        "A448_crossfit_selected_individual_operator": crossfit_selected,
        "A448_individual_complete128": {
            name: crossfit_evaluations[name] for name in COMPONENTS.values()
        },
        "A448_individual_remaining96_no_refit": {
            name: fixed_evaluations[name] for name in COMPONENTS.values()
        },
        "measurement_ledger_sha256": canonical_sha256(ledgers),
        "borda_contract": borda_contract,
        "feature_contract_sha256": canonical_sha256(feature_contract),
        "W52_target_labels_used": 0,
        "reader_refits": 0,
        "model_refits": 0,
    }
    result["calibration_sha256"] = canonical_sha256(result)
    del (
        rank_panel,
        fixed_fields,
        crossfit_fields,
        selected_complete_field,
        selected_fixed_field,
        measurements,
    )
    gc.collect()
    return result


def write_component_input(a449: Mapping[str, Any]) -> dict[str, Any]:
    payload = bytearray(MAGIC)
    components: dict[str, Any] = {}
    for symbol in SYMBOLS:
        name = COMPONENTS[symbol]
        schedule = a449["operator_schedules"][name]
        prefix = np.asarray(schedule["prefix_order"], dtype=np.uint16)
        off_axis = np.asarray(schedule["off_axis_order"], dtype=np.uint16)
        expected = set(range(AXIS_CELLS))
        if (
            prefix.shape != (AXIS_CELLS,)
            or off_axis.shape != (AXIS_CELLS,)
            or set(prefix.tolist()) != expected
            or set(off_axis.tolist()) != expected
        ):
            raise RuntimeError(f"A458 W52 component {name} order differs")
        payload.extend(prefix.astype(">u2", copy=False).tobytes())
        payload.extend(off_axis.astype(">u2", copy=False).tobytes())
        components[symbol] = {
            "operator": name,
            "prefix_order_uint16be_sha256": schedule[
                "prefix_order_uint16be_sha256"
            ],
            "off_axis_order_uint16be_sha256": schedule[
                "off_axis_order_uint16be_sha256"
            ],
            "pair_stream_uint16be_uint16be_sha256": schedule[
                "pair_stream_uint16be_uint16be_sha256"
            ],
        }
    expected_bytes = len(MAGIC) + len(SYMBOLS) * 2 * AXIS_CELLS * 2
    if len(payload) != expected_bytes:
        raise RuntimeError("A458 component input size differs")
    atomic_bytes(COMPONENT_INPUT, bytes(payload))
    return {
        "path": relative(COMPONENT_INPUT),
        "sha256": file_sha256(COMPONENT_INPUT),
        "bytes": len(payload),
        "magic_hex": MAGIC.hex(),
        "components": components,
    }


def artifact_rank_vector(path: Path) -> tuple[np.ndarray, dict[str, Any]]:
    return A454.artifact_rank_vector(path)


def compare_ranks(left: np.ndarray, right: np.ndarray) -> dict[str, Any]:
    return A454.compare_ranks(left, right)


def exact_W52_bounds(
    fused_rank: np.ndarray,
    component_ranks: Mapping[str, np.ndarray],
    pattern: str,
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for symbol in active_symbols(pattern):
        violations = 0
        minimum_slack = PAIR_CELLS
        for start in range(0, PAIR_CELLS, CHUNK):
            stop = min(start + CHUNK, PAIR_CELLS)
            keys = proposal_key_vector(
                component_ranks[symbol][start:stop],
                pattern,
                symbol,
                require_complete_permutation=False,
            )
            cap = np.minimum(PAIR_CELLS, keys + 1)
            slack = cap - fused_rank[start:stop].astype(np.int64)
            violations += int(np.count_nonzero(slack < 0))
            minimum_slack = min(minimum_slack, int(slack.min()))
        output[symbol] = {
            "operator": COMPONENTS[symbol],
            "frequency": pattern.count(symbol),
            "period": len(pattern),
            "asymptotic_regret": len(pattern) / pattern.count(symbol),
            "formula": "fused_rank <= min(2^24, component_proposal_key + 1)",
            "violations": violations,
            "minimum_slack": minimum_slack,
            "satisfied": violations == 0,
        }
    if not all(row["satisfied"] for row in output.values()):
        raise RuntimeError("A458 complete W52 proposal-bound gate failed")
    return output


def compile_W52_stream(
    a449: Mapping[str, Any], selected_pattern: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    component_input = write_component_input(a449)
    temporary = ARTIFACT.with_name(f".{ARTIFACT.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    subprocess.run(
        [
            str(NATIVE_EXECUTABLE),
            str(COMPONENT_INPUT),
            str(temporary),
            selected_pattern,
        ],
        check=True,
    )
    if temporary.stat().st_size != PAIR_CELLS * 4:
        temporary.unlink(missing_ok=True)
        raise RuntimeError("A458 native compiler artifact size differs")
    os.replace(temporary, ARTIFACT)
    fused_rank, artifact = artifact_rank_vector(ARTIFACT)
    component_ranks = {
        symbol: A454.reference_square_rank_vector(
            a449["operator_schedules"][name]["prefix_order"],
            a449["operator_schedules"][name]["off_axis_order"],
        )
        for symbol, name in COMPONENTS.items()
    }
    active = active_symbols(selected_pattern)
    bounds = exact_W52_bounds(fused_rank, component_ranks, selected_pattern)
    first_key = np.minimum.reduce(
        [
            proposal_key_vector(
                component_ranks[symbol], selected_pattern, symbol
            )
            for symbol in active
        ]
    )
    expected_order = np.argsort(first_key, kind="stable")
    sorted_keys = first_key[expected_order]
    if np.any(sorted_keys[1:] <= sorted_keys[:-1]):
        raise RuntimeError("A458 complete W52 first keys are not unique")
    if np.any(
        fused_rank[expected_order]
        != np.arange(1, PAIR_CELLS + 1, dtype=np.uint32)
    ):
        raise RuntimeError("A458 native stream differs from Python first-key order")
    del expected_order, sorted_keys
    h_ratio = fused_rank.astype(np.float64) / component_ranks["H"].astype(
        np.float64
    )
    minimum_component = np.minimum.reduce(
        [component_ranks[symbol] for symbol in active]
    )
    best_ratio = fused_rank.astype(np.float64) / minimum_component.astype(
        np.float64
    )
    a456_rank, a456_artifact = artifact_rank_vector(A456_PAIR_STREAM)
    comparison_a456 = compare_ranks(fused_rank, a456_rank)
    del a456_rank
    geometry = {
        "comparison_to_A456_BOOOOOOHHHHHH_stream": comparison_a456,
        "active_component_comparisons": {
            symbol: compare_ranks(fused_rank, component_ranks[symbol])
            for symbol in active
        },
        "excluded_component_comparisons_report_only": {
            symbol: compare_ranks(fused_rank, component_ranks[symbol])
            for symbol in SYMBOLS
            if symbol not in active
        },
        "A456_source_artifact": a456_artifact,
        "A456_result_commitment_sha256": A456_RESULT_COMMITMENT_SHA256,
    }
    guarantee = {
        "selected_pattern": selected_pattern,
        "active_symbols": list(active),
        "pattern_complexity": pattern_complexity(selected_pattern),
        "per_component_exact_proposal_bounds": bounds,
        "cells_checked": PAIR_CELLS,
        "all_bounds_satisfied": all(row["satisfied"] for row in bounds.values()),
        "hybrid_rank_ratio": {
            "maximum": float(h_ratio.max()),
            "p99": float(np.quantile(h_ratio, 0.99)),
            "median": float(np.median(h_ratio)),
        },
        "best_component_rank_ratio": {
            "maximum": float(best_ratio.max()),
            "p99": float(np.quantile(best_ratio, 0.99)),
            "median": float(np.median(best_ratio)),
        },
    }
    stream = {
        "component_input": component_input,
        "artifact": artifact,
        "selected_pattern": selected_pattern,
        "first_encounter_key_uint64be_sha256": array_sha256(first_key, ">u8"),
        "compiled_rank_vector_uint32be_sha256": array_sha256(fused_rank, ">u4"),
        "compiler_source_sha256": NATIVE_SOURCE_SHA256,
        "compiler_executable_sha256": NATIVE_EXECUTABLE_SHA256,
        "target_labels_used": 0,
        "feature_refits": 0,
        "model_refits": 0,
        "candidate_assignments_executed": 0,
    }
    del first_key, h_ratio, best_ratio, minimum_component, component_ranks
    gc.collect()
    return stream, guarantee, geometry


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    decision = payload["decision"]["outcome"]
    writer = CausalWriter(api_id="a458ray")
    writer._rules = []
    writer.add_rule(
        name="A456_boundary_to_paired_single_block_extension",
        description="Extend the A456 winning cyclic orbit through m=7..15 and pair every B1 scale with its B0 active-component ablation.",
        pattern=["A456_m6_single_block_frequency_boundary"],
        conclusion="A458_selected_no_refit_single_block_extension_pattern",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="selected_pattern_to_exact_geometry",
        description="Compile the selected pattern into a complete W52 permutation and verify every component proposal bound.",
        pattern=["A458_selected_no_refit_single_block_extension_pattern"],
        conclusion="A458_exact_W52_frequency_ray_geometry",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="exact_geometry_to_decision",
        description="Apply the frozen A456 comparison rule to choose a separate recovery queue or retain the A456 m6 stream.",
        pattern=["A458_exact_W52_frequency_ray_geometry"],
        conclusion=f"A458_{decision}",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A456:m6_single_block_frequency_boundary",
        mechanism="paired_m7_to_m15_B1_and_B0_single_block_phase_extension_with_fixed_no_refit_measurement",
        outcome="A458:selected_no_refit_single_block_extension_pattern",
        confidence=1.0,
        source=payload["calibration"]["calibration_sha256"],
        quantification=json.dumps(
            {
                "frontier": payload["calibration"]["per_arm_m_frontier"],
                "matched_B_effect": payload["calibration"][
                    "matched_B_effect_by_m"
                ],
            },
            sort_keys=True,
        ),
        evidence=json.dumps(
            payload["calibration"]["selected_remaining96_full_statistics"],
            sort_keys=True,
        ),
        domain="full-round ChaCha20 no-refit Reader allocation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A458:selected_no_refit_single_block_extension_pattern",
        mechanism="period31_active_component_native_first_encounter_compiler",
        outcome="A458:complete_W52_pair_permutation",
        confidence=1.0,
        source=payload["stream"]["artifact"]["sha256"],
        quantification=json.dumps(payload["stream"]["artifact"], sort_keys=True),
        evidence=payload["stream"]["selected_pattern"],
        domain="target-blind W52 recovery scheduling",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A458:complete_W52_pair_permutation",
        mechanism="exhaustive_component_proposal_bound_and_geometry_gate",
        outcome="A458:exact_W52_frequency_ray_geometry",
        confidence=1.0,
        source=payload["guarantee_sha256"],
        quantification=json.dumps(payload["hard_rank_guarantee"], sort_keys=True),
        evidence=json.dumps(payload["geometry"], sort_keys=True),
        domain="exact W52 search-order geometry",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A458:exact_W52_frequency_ray_geometry",
        mechanism="frozen_A456_minimum_then_aggregate_comparison",
        outcome=f"A458:{decision}",
        confidence=1.0,
        source=payload["decision_sha256"],
        quantification=json.dumps(payload["decision"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="recovery-front selection",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A456:m6_single_block_frequency_boundary",
        mechanism="materialized_paired_ray_calibration_and_exact_geometry_closure",
        outcome="A458:exact_W52_frequency_ray_geometry",
        confidence=1.0,
        source="materialized:A458_frequency_ray_geometry_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_triplet(
        trigger="A458:selected_no_refit_single_block_extension_pattern",
        mechanism="frozen_decision_rule_over_materialized_geometry",
        outcome=f"A458:{decision}",
        confidence=1.0,
        source="materialized:A458_frequency_ray_decision_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A458 paired B1/B0 single-block frequency extension",
        entities=[
            "A456:m6_single_block_frequency_boundary",
            "A458:selected_no_refit_single_block_extension_pattern",
            "A458:complete_W52_pair_permutation",
            "A458:exact_W52_frequency_ray_geometry",
            f"A458:{decision}",
        ],
    )
    next_type = (
        "exclusive_queued_A458_W52_recovery_execution"
        if decision == "separate_recovery_queue_qualified"
        else "state_adaptive_component_allocation"
    )
    writer.add_gap(
        subject=f"A458:{decision}",
        predicate="next_required_object",
        expected_object_type=next_type,
        confidence=1.0,
        suggested_queries=[
            "Execute the frozen A458 stream after A457."
            if decision == "separate_recovery_queue_qualified"
            else "Use calibration-only prefix state to allocate active Reader proposals adaptively while retaining complete-cover guarantees."
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
        reader.api_id != "a458ray"
        or len(explicit) != 4
        or len(all_rows) != 6
        or len(inferred) != 2
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A458 authentic Causal reopen gate failed")
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
        "semantic_readback": {
            "calibration": explicit[0],
            "materialization": explicit[1],
            "guarantee": explicit[2],
            "decision": explicit[3],
            "inferred_closure": inferred,
            "next_gap": reader._gaps[0],
        },
    }


def _build_result_once(*, expected_implementation_sha256: str) -> dict[str, Any]:
    load_design()
    implementation = load_implementation(expected_implementation_sha256)
    _a456, _a454, _a448, a449, _a451, _a453 = load_sources()
    calibration = calibration_result()
    stream, guarantee, geometry = compile_W52_stream(
        a449, calibration["selected_pattern"]
    )
    qualifies = bool(calibration["qualifies_separate_recovery_queue"])
    decision = {
        "outcome": (
            "separate_recovery_queue_qualified"
            if qualifies
            else "A456_BOOOOOOHHHHHH_retained"
        ),
        "qualifies_separate_recovery_queue": qualifies,
        "rule": "A458 minimum > A456 minimum, or equal minimum with A458 aggregate > A456 aggregate",
        "selected_delta_over_A456_BOOOOOOHHHHHH": calibration[
            "selected_delta_over_A456_BOOOOOOHHHHHH"
        ],
        "W52_target_labels_used": 0,
        "candidate_assignments_executed": 0,
    }
    ready = bool(
        calibration["selected_remaining96_full_statistics"][
            "positive_fixed_block_count"
        ]
        == 8
        and stream["artifact"]["complete_permutation"]
        and guarantee["all_bounds_satisfied"]
    )
    if not ready:
        raise RuntimeError("A458 exact materialization gate failed")
    evidence_stage = (
        "STRICT_NO_REFIT_PAIRED_FREQUENCY_EXTENSION_W52_RECOVERY_STREAM_QUALIFIED"
        if qualifies
        else "STRICT_NO_REFIT_SINGLE_BLOCK_FREQUENCY_BOUNDARY_LOCALIZED_A456_RETAINED"
    )
    core: dict[str, Any] = {
        "schema": "chacha20-round20-w52-no-refit-frequency-ray-extension-a458-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "calibration": calibration,
        "stream": stream,
        "hard_rank_guarantee": guarantee,
        "geometry": geometry,
        "decision": decision,
        "materialization_ready": ready,
        "A458_candidate_results_seen_before_design": False,
        "A458_selected_pattern_seen_before_design": False,
        "A458_W52_pair_stream_seen_before_design": False,
        "A426_A438_A440_A443_A450_A452_A455_A457_secret_result_or_worker_progress_read": False,
        "W52_target_labels_used": 0,
        "feature_refits": 0,
        "model_refits": 0,
        "W52_candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A456_runner": anchor(A456_RUNNER, A456_RUNNER_SHA256),
            "A456_design": anchor(A456_DESIGN, A456_DESIGN_SHA256),
            "A456_implementation": anchor(
                A456_IMPLEMENTATION, A456_IMPLEMENTATION_SHA256
            ),
            "A456_result": anchor(A456_RESULT, A456_RESULT_SHA256),
            "A456_pair_stream": anchor(
                A456_PAIR_STREAM, A456_PAIR_STREAM_SHA256
            ),
            "A456_causal": anchor(A456_CAUSAL, A456_CAUSAL_SHA256),
            "A456_personal_readback": anchor(
                A456_READBACK, A456_READBACK_SHA256
            ),
            "native_source": anchor(NATIVE_SOURCE, NATIVE_SOURCE_SHA256),
            "native_executable": anchor(
                NATIVE_EXECUTABLE, NATIVE_EXECUTABLE_SHA256
            ),
            "pair_stream_artifact": anchor(
                ARTIFACT, stream["artifact"]["sha256"]
            ),
            "runner": anchor(Path(__file__)),
        },
    }
    core["guarantee_sha256"] = canonical_sha256(guarantee)
    core["geometry_sha256"] = canonical_sha256(geometry)
    core["decision_sha256"] = canonical_sha256(decision)
    core["result_commitment_sha256"] = canonical_sha256(
        {
            "implementation_commitment_sha256": core[
                "implementation_commitment_sha256"
            ],
            "calibration_sha256": calibration["calibration_sha256"],
            "artifact_sha256": stream["artifact"]["sha256"],
            "guarantee_sha256": core["guarantee_sha256"],
            "geometry_sha256": core["geometry_sha256"],
            "decision_sha256": core["decision_sha256"],
        }
    )
    core["causal"] = build_causal(core)
    atomic_json(RESULT, core)
    fixed = calibration["selected_remaining96_full_statistics"]
    delta = calibration["selected_delta_over_A456_BOOOOOOHHHHHH"]
    comparison = geometry["comparison_to_A456_BOOOOOOHHHHHH_stream"]
    atomic_bytes(
        REPORT,
        (
            "# A458 — paired no-refit single-block frequency extension\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Prospectively structured schedules / cyclic orbits: **{calibration['candidate_count']} / {calibration['cyclic_orbit_count']}**\n"
            f"- Selected pattern: **{calibration['selected_pattern']}**\n"
            f"- Selected H:B:O counts: **{fixed['evaluation_targets']} target evaluations; {calibration['selected_complexity']['frequencies']}**\n"
            f"- Strict remaining96 aggregate / minimum gain: **{fixed['aggregate_bit_gain']:+.12f} / {fixed['minimum_fixed_block_bit_gain']:+.12f} bits**\n"
            f"- Delta over A456 BOOOOOOHHHHHH aggregate / minimum: **{delta['remaining96_aggregate_bit_gain']:+.12f} / {delta['remaining96_minimum_fixed_block_bit_gain']:+.12f} bits**\n"
            f"- Recovery-queue decision: **{decision['outcome']}**\n"
            f"- Complete W52 pair permutation: **{PAIR_CELLS:,} cells**\n"
            f"- Pair-stream SHA-256: `{stream['artifact']['sha256']}`\n"
            f"- Exact active-component proposal bounds: **all {len(guarantee['active_symbols'])} satisfied over all 16,777,216 cells**\n"
            f"- Spearman / top-65,536 overlap with A456: **{comparison['spearman_rank_correlation']:.12f} / {comparison['top_k_overlap']['65536']['overlap_fraction']:.12f}**\n"
            "- W52 target labels / refits / candidate executions: **0 / 0 / 0**\n"
            "- Authentic AI-native Causal readback: **4 explicit + 2 inferred chains**\n"
        ).encode(),
    )
    return core


def build_result(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if RESULT.exists():
        return load_result(file_sha256(RESULT))
    try:
        return _build_result_once(
            expected_implementation_sha256=expected_implementation_sha256
        )
    except Exception:
        if not RESULT.exists():
            CAUSAL.unlink(missing_ok=True)
            REPORT.unlink(missing_ok=True)
            ARTIFACT.unlink(missing_ok=True)
            COMPONENT_INPUT.unlink(missing_ok=True)
        raise


def load_result(expected_sha256: str) -> dict[str, Any]:
    anchor(RESULT, expected_sha256)
    value = json.loads(RESULT.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-no-refit-frequency-ray-extension-a458-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("materialization_ready") is not True
        or value.get("calibration", {}).get("candidate_count")
        != EXPECTED_PATTERNS
        or value.get("calibration", {}).get("cyclic_orbit_count")
        != EXPECTED_ORBITS
        or value.get("hard_rank_guarantee", {}).get("all_bounds_satisfied")
        is not True
        or value.get("stream", {}).get("artifact", {}).get("complete_permutation")
        is not True
        or value.get("A458_candidate_results_seen_before_design") is not False
        or value.get("A458_selected_pattern_seen_before_design") is not False
        or value.get("A458_W52_pair_stream_seen_before_design") is not False
        or value.get(
            "A426_A438_A440_A443_A450_A452_A455_A457_secret_result_or_worker_progress_read"
        )
        is not False
        or value.get("W52_target_labels_used") != 0
        or value.get("feature_refits") != 0
        or value.get("model_refits") != 0
        or value.get("W52_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A458 result semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    _ranks, artifact = artifact_rank_vector(ARTIFACT)
    if artifact["sha256"] != value["stream"]["artifact"]["sha256"]:
        raise RuntimeError("A458 pair-stream hash differs")
    return value


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": file_sha256(DESIGN) if DESIGN.exists() else None,
        "candidate_count": len(PATTERNS),
        "cyclic_orbit_count": len(ORBITS),
        "implementation_frozen": IMPLEMENTATION.exists(),
        "result_complete": RESULT.exists(),
        "artifact_present": ARTIFACT.exists(),
    }
    load_design()
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if RESULT.exists():
        payload["result_sha256"] = file_sha256(RESULT)
        value = load_result(payload["result_sha256"])
        payload["evidence_stage"] = value["evidence_stage"]
        payload["selected_pattern"] = value["calibration"]["selected_pattern"]
        payload["decision"] = value["decision"]["outcome"]
        payload["artifact_sha256"] = value["stream"]["artifact"]["sha256"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--build", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.build:
        if not args.expected_implementation_sha256:
            parser.error("--build requires implementation hash")
        payload = build_result(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
