#!/usr/bin/env python3
"""A454: select and materialize a no-refit weighted proof-Reader portfolio."""

from __future__ import annotations

import argparse
import gc
import hashlib
import importlib.util
import inspect
import itertools
import json
import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

STEM = "chacha20_round20_w52_no_refit_weighted_reader_portfolio_a454"
DESIGN = CONFIGS / f"{STEM}_design_v1.json"
IMPLEMENTATION_V1 = CONFIGS / f"{STEM}_implementation_v1.json"
IMPLEMENTATION = CONFIGS / f"{STEM}_implementation_v2.json"
RESULT = RESULTS / f"{STEM}_v1.json"
ARTIFACT = RESULTS / f"{STEM}_pair_stream_uint16be_uint16be_v1.bin"
COMPONENT_INPUT = RESULTS / f"{STEM}_component_orders_v1.bin"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / f"tests/test_{STEM}.py"
REPRO = ROOT / f"scripts/reproduce_{STEM}.sh"
NATIVE_SOURCE = RESEARCH / "native/a454_weighted_first_encounter_compiler.cpp"
NATIVE_EXECUTABLE = RESEARCH / "bin/a454_weighted_first_encounter_compiler"

A448_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w46_full128_proof_antecedent_transfer_a448.py"
)
A448_RESULT = (
    RESULTS / "chacha20_round20_w46_full128_proof_antecedent_transfer_a448_v1.json"
)
A449_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_target_blind_proof_antecedent_trace_a449.py"
)
A449_RESULT = (
    RESULTS / "chacha20_round20_w52_target_blind_proof_antecedent_trace_a449_v1.json"
)
A451_RESULT = (
    RESULTS / "chacha20_round20_w52_deduplicated_reader_portfolio_a451_v1.json"
)
A451_PAIR_STREAM = (
    RESULTS
    / "chacha20_round20_w52_deduplicated_reader_portfolio_a451_pair_stream_uint16be_uint16be_v1.bin"
)
A453_RESULT = (
    RESULTS / "chacha20_round20_w52_deadline_compiled_proof_portfolio_a453_v1.json"
)
A453_PAIR_STREAM = (
    RESULTS
    / "chacha20_round20_w52_deadline_compiled_proof_portfolio_a453_pair_stream_uint16be_uint16be_v1.bin"
)
A453_READBACK = RESEARCH / "reports/CAUSAL_CHACHA20_A453_PERSONAL_READER_READBACK_V1.md"

ATTEMPT_ID = "A454"
DESIGN_SHA256 = "7a55c5201141734ff10bc55434a4bcf8265a72c9d3a3585b4b964d3bb28308ed"
A448_RUNNER_SHA256 = "33cf14799282e52a6e23857d15dba096ba61e003fdef8b53a2b6a93a5dcd9d60"
A448_RESULT_SHA256 = "4f3bfbc7be7932917a40a3ad9ff3db76c1bf1ca8799d7a887025f3e98e5464db"
A448_RESULT_COMMITMENT_SHA256 = (
    "8b437a85395cab19316453eb8908b8dac20ca0455f54eea2443daf8d99622408"
)
A449_RUNNER_SHA256 = "cd19406ba8964aceea1dfe16904f505097fb91aed738cb825c934f89c460e875"
A449_RESULT_SHA256 = "f054125c5c363e379ddca661334a57867a0d367a5c57d0caa2bb0f8814b322a7"
A449_RESULT_COMMITMENT_SHA256 = (
    "4cfd5edf10a9f4e491e5e4b2d289eca78113d67973069eea60ded00a4b64f2cf"
)
A451_RESULT_SHA256 = "f2501e5e85f6d37305473738bb0840c12651720e6f7e3fbab2fc4a253b40bdf6"
A451_RESULT_COMMITMENT_SHA256 = (
    "d699e1150e902fd66dd530a60cc4b71d69be379eb46e355c08121e8526ca2b9f"
)
A451_PAIR_STREAM_SHA256 = "826d10e8cfb8ba2cb51e2d1cee35d29f29b9a313928dbdabbf6b92ad2a546cf9"
A453_RESULT_SHA256 = "b876db904a4abbfe938de060307f95cb1936c64546367e947302c8cabcfd36aa"
A453_RESULT_COMMITMENT_SHA256 = (
    "22887b6591f22e7d503907f38c3e9be023da053af344c72fa542253e04c69ec6"
)
A453_PAIR_STREAM_SHA256 = "73c64ef70ab11498a1dfe8be19bbeb1f8e5d151c16e7fc4abcbfc3e65197df79"
A453_READBACK_SHA256 = "34af49ba39031a3e3d2c23da1c1076d1e670bc2a7f2ad49cc9b1bd543d963ed9"
NATIVE_SOURCE_SHA256 = "36c887342b4a9644437c6769ee1ccf755637f7f48ab44617901195c09a1d505c"
NATIVE_EXECUTABLE_SHA256 = (
    "60bb4dff6231fecf4125a9d53ae11f75493b8c26b16f43c6dd00534f267bdd17"
)
IMPLEMENTATION_V1_SHA256 = (
    "b233002a2d04d6e9981e1709207ca277a9b51a8f628038f0256683643e6c0c75"
)
IMPLEMENTATION_V1_COMMITMENT_SHA256 = (
    "96d0cfa1d40bc6afdce20c1a4259e1b30c0fb594031ace546ff16413891a1169"
)

SYMBOLS = ("H", "B", "O")
COMPONENTS = {
    "H": "hybrid_proof_top16_equal",
    "B": "proof_borda_top32",
    "O": "proof_best_single",
}
COUNT_TUPLES = (
    (1, 1, 1),
    (2, 1, 1),
    (3, 1, 1),
    (4, 1, 1),
    (2, 2, 1),
    (2, 1, 2),
    (3, 2, 1),
    (3, 1, 2),
)
EXPECTED_PATTERNS = 248
A451_CONTROL_PATTERN = "BHO"
AXIS_CELLS = 1 << 12
PAIR_CELLS = 1 << 24
CHUNK = 1 << 20
TOP_KS = (16, 64, 256, 1024, 65536, 1048576)
MAGIC = b"A454RANKV1" + bytes(6)
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A454 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A448 = load_module(A448_RUNNER, "a454_a448")
file_sha256 = A448.file_sha256
canonical_sha256 = A448.canonical_sha256
atomic_json = A448.atomic_json
atomic_bytes = A448.atomic_bytes
anchor = A448.anchor
path_from_ref = A448.path_from_ref
relative = A448.relative


def array_sha256(value: np.ndarray, dtype: str) -> str:
    digest = hashlib.sha256()
    array = np.asarray(value)
    for start in range(0, array.size, CHUNK):
        digest.update(
            array[start : start + CHUNK].astype(dtype, copy=False).tobytes()
        )
    return digest.hexdigest()


def enumerate_patterns() -> tuple[str, ...]:
    patterns: set[str] = set()
    for h_count, b_count, o_count in COUNT_TUPLES:
        multiset = "H" * h_count + "B" * b_count + "O" * o_count
        patterns.update("".join(row) for row in itertools.permutations(multiset))
    output = tuple(sorted(patterns))
    if len(output) != EXPECTED_PATTERNS or A451_CONTROL_PATTERN not in output:
        raise RuntimeError("A454 prospective candidate family differs")
    return output


PATTERNS = enumerate_patterns()


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
        != "chacha20-round20-w52-no-refit-weighted-reader-portfolio-a454-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or source.get("A448_complete128_result_sha256") != A448_RESULT_SHA256
        or source.get("A449_target_blind_W52_result_sha256")
        != A449_RESULT_SHA256
        or source.get("A451_fixed_slot_result_sha256") != A451_RESULT_SHA256
        or source.get("A453_deadline_result_sha256") != A453_RESULT_SHA256
        or source.get("component_symbol_map") != COMPONENTS
        or family.get("algorithm")
        != "deduplicated_periodic_weighted_first_encounter"
        or tuple(tuple(row) for row in family.get("period_symbol_count_tuples_H_B_O", []))
        != COUNT_TUPLES
        or family.get("expected_unique_patterns") != EXPECTED_PATTERNS
        or family.get("complete_permutation_required") is not True
        or family.get("exact_per_component_proposal_bound_required") is not True
        or selection.get("selection_scope")
        != "A448_remaining96_A447_fixed_model_no_refit_only"
        or selection.get("required_positive_fixed_blocks") != 8
        or selection.get("complete128_crossfit_is_report_only_not_selection")
        is not True
        or selection.get("W52_pair_geometry_is_report_only_not_selection")
        is not True
        or materialization.get("pair_cells") != PAIR_CELLS
        or materialization.get("candidate_assignments_executed") != 0
        or boundary.get("A454_weighted_candidate_results_seen_before_design")
        is not False
        or boundary.get("A454_selected_pattern_seen_before_design") is not False
        or boundary.get("A454_W52_pair_stream_seen_before_design") is not False
        or boundary.get(
            "A426_A438_A440_A443_A450_A452_secret_result_or_worker_progress_read"
        )
        is not False
        or boundary.get("W52_target_labels_used") != 0
        or boundary.get("production_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A454 frozen design semantics differ")
    for key, item in value["source_anchors"].items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, value["source_anchors"][f"{stem}_sha256"])
    return value


def load_sources() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    anchor(A448_RUNNER, A448_RUNNER_SHA256)
    anchor(A448_RESULT, A448_RESULT_SHA256)
    anchor(A449_RUNNER, A449_RUNNER_SHA256)
    anchor(A449_RESULT, A449_RESULT_SHA256)
    anchor(A451_RESULT, A451_RESULT_SHA256)
    anchor(A451_PAIR_STREAM, A451_PAIR_STREAM_SHA256)
    anchor(A453_RESULT, A453_RESULT_SHA256)
    anchor(A453_PAIR_STREAM, A453_PAIR_STREAM_SHA256)
    anchor(A453_READBACK, A453_READBACK_SHA256)
    a448 = A448.load_result(A448_RESULT_SHA256)
    a449 = json.loads(A449_RESULT.read_bytes())
    a451 = json.loads(A451_RESULT.read_bytes())
    a453 = json.loads(A453_RESULT.read_bytes())
    if (
        a448.get("result_commitment_sha256") != A448_RESULT_COMMITMENT_SHA256
        or a449.get("result_commitment_sha256") != A449_RESULT_COMMITMENT_SHA256
        or a451.get("result_commitment_sha256") != A451_RESULT_COMMITMENT_SHA256
        or a453.get("result_commitment_sha256") != A453_RESULT_COMMITMENT_SHA256
        or a449.get("W52_target_labels_used") != 0
        or a449.get("production_candidate_assignments_executed") != 0
        or a451.get("W52_target_labels_used") != 0
        or a451.get("production_candidate_assignments_executed") != 0
        or a453.get("W52_target_labels_used") != 0
        or a453.get("W52_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A454 source semantics differ")
    for name in COMPONENTS.values():
        if name not in a449.get("operator_schedules", {}):
            raise RuntimeError(f"A454 source operator {name} is absent")
    return a448, a449, a451, a453


def freeze_implementation() -> dict[str, Any]:
    downstream = (IMPLEMENTATION, RESULT, ARTIFACT, COMPONENT_INPUT, CAUSAL, REPORT)
    if any(path.exists() for path in downstream):
        raise FileExistsError("A454 v2 implementation or downstream artifact exists")
    design = load_design()
    load_sources()
    anchor(IMPLEMENTATION_V1, IMPLEMENTATION_V1_SHA256)
    implementation_v1 = json.loads(IMPLEMENTATION_V1.read_bytes())
    if (
        implementation_v1.get("implementation_commitment_sha256")
        != IMPLEMENTATION_V1_COMMITMENT_SHA256
    ):
        raise RuntimeError("A454 v1 implementation commitment differs")
    for path in (TEST, REPRO, NATIVE_SOURCE, NATIVE_EXECUTABLE):
        if not path.exists():
            raise FileNotFoundError(f"A454 required implementation artifact absent: {path}")
    anchor(NATIVE_SOURCE, NATIVE_SOURCE_SHA256)
    anchor(NATIVE_EXECUTABLE, NATIVE_EXECUTABLE_SHA256)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-no-refit-weighted-reader-portfolio-a454-implementation-v2",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "metadata_projection_only_correction_frozen_after_v1_KeyError_before_any_candidate_value_was_exposed_or_consumed_and_before_selection_or_W52_stream",
        "design_sha256": DESIGN_SHA256,
        "implementation_v1_sha256": IMPLEMENTATION_V1_SHA256,
        "implementation_v1_commitment_sha256": IMPLEMENTATION_V1_COMMITMENT_SHA256,
        "v1_correction_contract": {
            "failure": "compact_statistics requested evaluation_mode and rank_field_sha256 fields absent from the direct A448.statistics return value",
            "correction": "project only fields actually returned by A448.statistics; rank-field hashes remain separately computed from the frozen field arrays",
            "candidate_family_changed": False,
            "selection_rule_changed": False,
            "weighted_rank_algorithm_changed": False,
            "native_compiler_changed": False,
            "candidate_values_exposed_or_consumed_before_v2_freeze": False,
            "selected_pattern_known_before_v2_freeze": False,
            "W52_stream_known_before_v2_freeze": False,
        },
        "candidate_family_sha256": canonical_sha256(list(PATTERNS)),
        "candidate_count": len(PATTERNS),
        "count_tuples_H_B_O": [list(row) for row in COUNT_TUPLES],
        "selection_objective": design["selection_contract"]["lexicographic_objective"],
        "A454_weighted_candidate_results_seen_at_freeze": False,
        "A454_selected_pattern_seen_at_freeze": False,
        "A454_W52_pair_stream_seen_at_freeze": False,
        "prior_secret_recovery_progress_or_result_read": False,
        "W52_target_labels_used": 0,
        "feature_refits": 0,
        "model_refits": 0,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation_v1": anchor(
                IMPLEMENTATION_V1, IMPLEMENTATION_V1_SHA256
            ),
            "A448_runner": anchor(A448_RUNNER, A448_RUNNER_SHA256),
            "A448_result": anchor(A448_RESULT, A448_RESULT_SHA256),
            "A449_runner": anchor(A449_RUNNER, A449_RUNNER_SHA256),
            "A449_result": anchor(A449_RESULT, A449_RESULT_SHA256),
            "A451_result": anchor(A451_RESULT, A451_RESULT_SHA256),
            "A451_pair_stream": anchor(A451_PAIR_STREAM, A451_PAIR_STREAM_SHA256),
            "A453_result": anchor(A453_RESULT, A453_RESULT_SHA256),
            "A453_pair_stream": anchor(A453_PAIR_STREAM, A453_PAIR_STREAM_SHA256),
            "A453_personal_readback": anchor(A453_READBACK, A453_READBACK_SHA256),
            "native_source": anchor(NATIVE_SOURCE, NATIVE_SOURCE_SHA256),
            "native_executable": anchor(NATIVE_EXECUTABLE, NATIVE_EXECUTABLE_SHA256),
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
        != "chacha20-round20-w52-no-refit-weighted-reader-portfolio-a454-implementation-v2"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("implementation_v1_sha256") != IMPLEMENTATION_V1_SHA256
        or value.get("implementation_v1_commitment_sha256")
        != IMPLEMENTATION_V1_COMMITMENT_SHA256
        or value.get("v1_correction_contract", {}).get("candidate_family_changed")
        is not False
        or value.get("v1_correction_contract", {}).get("selection_rule_changed")
        is not False
        or value.get("v1_correction_contract", {}).get(
            "candidate_values_exposed_or_consumed_before_v2_freeze"
        )
        is not False
        or value.get("candidate_family_sha256") != canonical_sha256(list(PATTERNS))
        or value.get("candidate_count") != EXPECTED_PATTERNS
        or value.get("A454_weighted_candidate_results_seen_at_freeze") is not False
        or value.get("A454_selected_pattern_seen_at_freeze") is not False
        or value.get("A454_W52_pair_stream_seen_at_freeze") is not False
        or value.get("prior_secret_recovery_progress_or_result_read") is not False
        or value.get("W52_target_labels_used") != 0
        or value.get("feature_refits") != 0
        or value.get("model_refits") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A454 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A454 implementation commitment differs")
    return value


def occurrence_slots(pattern: str, symbol: str) -> np.ndarray:
    if pattern not in PATTERNS and set(pattern) != set(SYMBOLS):
        raise ValueError("A454 pattern is outside the declared symbol alphabet")
    slots = np.asarray(
        [index for index, item in enumerate(pattern) if item == symbol],
        dtype=np.int64,
    )
    if slots.size == 0:
        raise ValueError(f"A454 pattern omits component {symbol}")
    return slots


def proposal_key_vector(
    ranks: np.ndarray,
    pattern: str,
    symbol: str,
    *,
    require_complete_permutation: bool = True,
) -> np.ndarray:
    row = np.asarray(ranks, dtype=np.int64)
    if row.ndim != 1 or np.any(row < 1):
        raise ValueError("A454 component ranks must be positive and one dimensional")
    if require_complete_permutation and (
        int(row.min()) != 1
        or int(row.max()) != row.size
        or np.unique(row).size != row.size
    ):
        raise ValueError("A454 component ranks are not a complete permutation")
    slots = occurrence_slots(pattern, symbol)
    zero_based = row - 1
    return (
        len(pattern) * (zero_based // slots.size)
        + slots[zero_based % slots.size]
    )


def weighted_first_encounter_ranks(
    component_ranks: Mapping[str, np.ndarray], pattern: str
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    if set(component_ranks) != set(SYMBOLS):
        raise ValueError("A454 component symbol cover differs")
    keys = {
        symbol: proposal_key_vector(component_ranks[symbol], pattern, symbol)
        for symbol in SYMBOLS
    }
    first_key = np.minimum.reduce(list(keys.values()))
    if np.unique(first_key).size != first_key.size:
        raise RuntimeError("A454 first-encounter keys are not unique")
    ids = np.arange(first_key.size, dtype=np.int64)
    order = np.lexsort((ids, first_key))
    fused_rank = np.empty(first_key.size, dtype=np.int32)
    fused_rank[order] = np.arange(1, first_key.size + 1, dtype=np.int32)
    bounds: dict[str, Any] = {}
    for symbol in SYMBOLS:
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
            raise RuntimeError(f"A454 exact proposal bound failed for {symbol}")
    return fused_rank, first_key, bounds


def pattern_complexity(pattern: str) -> dict[str, Any]:
    regrets = {
        symbol: len(pattern) / pattern.count(symbol) for symbol in SYMBOLS
    }
    return {
        "period": len(pattern),
        "frequencies": {symbol: pattern.count(symbol) for symbol in SYMBOLS},
        "asymptotic_component_regret": regrets,
        "maximum_asymptotic_component_regret": max(regrets.values()),
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


def selection_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    stats = row["remaining96_A447_fixed_model_no_refit"]
    complexity = row["complexity"]
    return (
        -float(stats["minimum_fixed_block_bit_gain"]),
        -float(stats["aggregate_bit_gain"]),
        -int(stats["targets_at_or_above_median_rank"]),
        int(stats["worst_rank"]),
        float(complexity["maximum_asymptotic_component_regret"]),
        int(complexity["period"]),
        str(row["pattern"]),
    )


def compact_statistics(stats: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: stats[key]
        for key in (
            "evaluation_scope",
            "evaluation_targets",
            "aggregate_bit_gain",
            "balanced_eight_block_bit_gain",
            "minimum_fixed_block_bit_gain",
            "positive_fixed_block_count",
            "targets_at_or_above_median_rank",
            "worst_rank",
            "fixed_block_bit_gains",
        )
    }


def calibration_result() -> dict[str, Any]:
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
    for pattern in PATTERNS:
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
    eligible = [
        row
        for row in rows
        if row["remaining96_A447_fixed_model_no_refit"][
            "positive_fixed_block_count"
        ]
        == 8
    ]
    if not eligible:
        raise RuntimeError("A454 candidate family has no eight-block-positive schedule")
    selected_row = min(eligible, key=selection_key)
    selected_pattern = selected_row["pattern"]
    control_row = next(row for row in rows if row["pattern"] == A451_CONTROL_PATTERN)
    all_targets = np.arange(A448.TARGETS, dtype=np.int64)
    selected_complete_field = calibration_field(
        crossfit_fields, all_targets, selected_pattern
    )
    control_complete_field = calibration_field(
        crossfit_fields, all_targets, A451_CONTROL_PATTERN
    )
    selected_complete = A448.statistics(
        selected_complete_field,
        truths,
        all_targets,
        evaluation_scope="complete128",
    )
    control_complete = A448.statistics(
        control_complete_field,
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
    control_stats = control_row["remaining96_A447_fixed_model_no_refit"]
    ranked = sorted(rows, key=selection_key)
    result: dict[str, Any] = {
        "selection_scope": "A448_remaining96_A447_fixed_model_no_refit_only",
        "candidate_count": len(rows),
        "eligible_eight_block_positive_count": len(eligible),
        "selected_pattern": selected_pattern,
        "selected_complexity": selected_row["complexity"],
        "selected_remaining96_full_statistics": selected_fixed_full,
        "selected_complete128_report_only": selected_complete,
        "A451_BHO_control_remaining96": control_stats,
        "A451_BHO_control_complete128_report_only": control_complete,
        "selected_delta_over_A451_BHO": {
            "remaining96_aggregate_bit_gain": selected_stats[
                "aggregate_bit_gain"
            ]
            - control_stats["aggregate_bit_gain"],
            "remaining96_minimum_fixed_block_bit_gain": selected_stats[
                "minimum_fixed_block_bit_gain"
            ]
            - control_stats["minimum_fixed_block_bit_gain"],
            "remaining96_targets_at_or_above_median_rank": selected_stats[
                "targets_at_or_above_median_rank"
            ]
            - control_stats["targets_at_or_above_median_rank"],
            "complete128_aggregate_bit_gain": selected_complete[
                "aggregate_bit_gain"
            ]
            - control_complete["aggregate_bit_gain"],
            "complete128_minimum_fixed_block_bit_gain": selected_complete[
                "minimum_fixed_block_bit_gain"
            ]
            - control_complete["minimum_fixed_block_bit_gain"],
        },
        "selection_key": list(selection_key(selected_row)),
        "top_16_candidates": ranked[:16],
        "all_candidate_summaries": rows,
        "candidate_family_sha256": canonical_sha256(rows),
        "selected_complete128_rank_field_sha256": A448.array_sha256(
            selected_complete_field, "<i2"
        ),
        "A451_BHO_complete128_rank_field_sha256": A448.array_sha256(
            control_complete_field, "<i2"
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
        control_complete_field,
        selected_fixed_field,
        measurements,
    )
    gc.collect()
    return result


def reference_square_rank_vector(
    prefix_order: Sequence[int], off_axis_order: Sequence[int]
) -> np.ndarray:
    prefix = np.asarray(prefix_order, dtype=np.int64)
    off_axis = np.asarray(off_axis_order, dtype=np.int64)
    expected = set(range(AXIS_CELLS))
    if (
        prefix.shape != (AXIS_CELLS,)
        or off_axis.shape != (AXIS_CELLS,)
        or set(prefix.tolist()) != expected
        or set(off_axis.tolist()) != expected
    ):
        raise ValueError("A454 factorized source order differs")
    prefix_inverse = np.empty(AXIS_CELLS, dtype=np.uint32)
    off_axis_inverse = np.empty(AXIS_CELLS, dtype=np.uint32)
    prefix_inverse[prefix] = np.arange(AXIS_CELLS, dtype=np.uint32)
    off_axis_inverse[off_axis] = np.arange(AXIS_CELLS, dtype=np.uint32)
    ids = np.arange(PAIR_CELLS, dtype=np.uint32)
    left = prefix_inverse[ids >> 12]
    right = off_axis_inverse[ids & (AXIS_CELLS - 1)]
    shell = np.maximum(left, right)
    ranks = np.where(
        left == shell,
        shell * shell + right,
        shell * shell + shell + 1 + left,
    ).astype(np.uint32)
    ranks += 1
    if int(ranks.min()) != 1 or int(ranks.max()) != PAIR_CELLS:
        raise RuntimeError("A454 reference square-rank cover differs")
    return ranks


def write_component_input(a449: Mapping[str, Any]) -> dict[str, Any]:
    payload = bytearray(MAGIC)
    component_rows: dict[str, Any] = {}
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
            raise RuntimeError(f"A454 W52 component {name} order differs")
        payload.extend(prefix.astype(">u2", copy=False).tobytes())
        payload.extend(off_axis.astype(">u2", copy=False).tobytes())
        component_rows[symbol] = {
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
        raise RuntimeError("A454 component input size differs")
    atomic_bytes(COMPONENT_INPUT, bytes(payload))
    return {
        "path": relative(COMPONENT_INPUT),
        "sha256": file_sha256(COMPONENT_INPUT),
        "bytes": len(payload),
        "magic_hex": MAGIC.hex(),
        "components": component_rows,
    }


def artifact_rank_vector(path: Path) -> tuple[np.ndarray, dict[str, Any]]:
    if path.stat().st_size != PAIR_CELLS * 4:
        raise RuntimeError("A454 pair-stream size differs")
    mapped = np.memmap(path, dtype=">u4", mode="r", shape=(PAIR_CELLS,))
    ranks = np.empty(PAIR_CELLS, dtype=np.uint32)
    seen = np.zeros(PAIR_CELLS, dtype=np.bool_)
    first_pair: list[int] | None = None
    last_pair: list[int] | None = None
    for start in range(0, PAIR_CELLS, CHUNK):
        stop = min(start + CHUNK, PAIR_CELLS)
        packed = np.asarray(mapped[start:stop], dtype=np.uint32)
        prefix = packed >> 16
        off_axis = packed & 0xFFFF
        if np.any(prefix >= AXIS_CELLS) or np.any(off_axis >= AXIS_CELLS):
            raise RuntimeError("A454 pair-stream coordinate differs")
        ids = (prefix << 12) | off_axis
        if np.unique(ids).size != ids.size or np.any(seen[ids]):
            raise RuntimeError("A454 pair-stream contains a duplicate")
        seen[ids] = True
        ranks[ids] = np.arange(start + 1, stop + 1, dtype=np.uint32)
        if first_pair is None:
            first_pair = [int(prefix[0]), int(off_axis[0])]
        last_pair = [int(prefix[-1]), int(off_axis[-1])]
    del mapped
    if not bool(np.all(seen)):
        raise RuntimeError("A454 pair-stream cover is incomplete")
    return ranks, {
        "path": relative(path),
        "sha256": file_sha256(path),
        "bytes": path.stat().st_size,
        "pair_cells": PAIR_CELLS,
        "encoding": "uint16be_prefix_then_uint16be_off_axis",
        "complete_permutation": True,
        "first_pair": first_pair,
        "last_pair": last_pair,
    }


def compare_ranks(left: np.ndarray, right: np.ndarray) -> dict[str, Any]:
    if left.shape != right.shape or left.shape != (PAIR_CELLS,):
        raise ValueError("A454 rank comparison geometry differs")
    mean = (PAIR_CELLS + 1.0) / 2.0
    variance = (PAIR_CELLS * PAIR_CELLS - 1.0) / 12.0
    covariance_sum = 0.0
    for start in range(0, PAIR_CELLS, CHUNK):
        stop = min(start + CHUNK, PAIR_CELLS)
        a = left[start:stop].astype(np.float64)
        b = right[start:stop].astype(np.float64)
        covariance_sum += float(np.dot(a - mean, b - mean))
    top = {}
    for k in TOP_KS:
        intersection = int(np.count_nonzero((left <= k) & (right <= k)))
        top[str(k)] = {
            "intersection": intersection,
            "overlap_fraction": intersection / k,
        }
    return {
        "spearman_rank_correlation": covariance_sum / (PAIR_CELLS * variance),
        "earlier": int(np.count_nonzero(left < right)),
        "equal": int(np.count_nonzero(left == right)),
        "later": int(np.count_nonzero(left > right)),
        "top_k_overlap": top,
    }


def exact_W52_bounds(
    fused_rank: np.ndarray,
    component_ranks: Mapping[str, np.ndarray],
    pattern: str,
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for symbol in SYMBOLS:
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
        raise RuntimeError("A454 complete W52 proposal-bound gate failed")
    return output


def compile_W52_stream(
    a449: Mapping[str, Any],
    a451: Mapping[str, Any],
    a453: Mapping[str, Any],
    selected_pattern: str,
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
        raise RuntimeError("A454 native compiler artifact size differs")
    os.replace(temporary, ARTIFACT)
    fused_rank, artifact = artifact_rank_vector(ARTIFACT)
    component_ranks = {
        symbol: reference_square_rank_vector(
            a449["operator_schedules"][name]["prefix_order"],
            a449["operator_schedules"][name]["off_axis_order"],
        )
        for symbol, name in COMPONENTS.items()
    }
    bounds = exact_W52_bounds(fused_rank, component_ranks, selected_pattern)
    first_key = np.minimum.reduce(
        [
            proposal_key_vector(component_ranks[symbol], selected_pattern, symbol)
            for symbol in SYMBOLS
        ]
    )
    expected_order = np.argsort(first_key, kind="stable")
    sorted_keys = first_key[expected_order]
    if np.any(sorted_keys[1:] <= sorted_keys[:-1]):
        raise RuntimeError("A454 complete W52 first keys are not unique")
    if np.any(
        fused_rank[expected_order]
        != np.arange(1, PAIR_CELLS + 1, dtype=np.uint32)
    ):
        raise RuntimeError("A454 native stream differs from Python first-key order")
    del expected_order, sorted_keys
    h_ratio = fused_rank.astype(np.float64) / component_ranks["H"].astype(np.float64)
    minimum_component = np.minimum.reduce(list(component_ranks.values()))
    best_ratio = fused_rank.astype(np.float64) / minimum_component.astype(np.float64)
    a451_rank, a451_artifact = artifact_rank_vector(A451_PAIR_STREAM)
    comparison_a451 = compare_ranks(fused_rank, a451_rank)
    del a451_rank
    a453_rank, a453_artifact = artifact_rank_vector(A453_PAIR_STREAM)
    comparison_a453 = compare_ranks(fused_rank, a453_rank)
    del a453_rank
    geometry = {
        "comparison_to_A451_fixed_slot_stream": comparison_a451,
        "comparison_to_A453_deadline_median_stream": comparison_a453,
        "component_comparisons": {
            symbol: compare_ranks(fused_rank, component_ranks[symbol])
            for symbol in SYMBOLS
        },
        "A451_source_artifact": a451_artifact,
        "A451_result_commitment_sha256": a451["result_commitment_sha256"],
        "A453_source_artifact": a453_artifact,
        "A453_result_commitment_sha256": a453["result_commitment_sha256"],
    }
    guarantee = {
        "selected_pattern": selected_pattern,
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

    writer = CausalWriter(api_id="a454wgt")
    writer._rules = []
    writer.add_rule(
        name="strict_no_refit_strength_selects_reader_bandwidth",
        description="When one frozen Reader dominates strict no-refit block stability, periodic proposal frequency can allocate it more slots while retaining complementary exact bounds.",
        pattern=["A453:remaining96_consensus_boundary"],
        conclusion="A454:selected_no_refit_weighted_pattern",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="periodic_first_encounter_implies_component_bounds",
        description="A component occurrence advances exactly one rank, so every cell is emitted no later than its component-specific proposal key after deduplication.",
        pattern=["A454:selected_no_refit_weighted_pattern"],
        conclusion="A454:exact_component_bounded_W52_stream",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A453:remaining96_consensus_boundary",
        mechanism="prospectively_enumerated_periodic_slot_weighting",
        outcome="A454:selected_no_refit_weighted_pattern",
        confidence=1.0,
        source=payload["calibration"]["calibration_sha256"],
        quantification=json.dumps(
            payload["calibration"]["selected_delta_over_A451_BHO"],
            sort_keys=True,
        ),
        evidence=json.dumps(
            {
                "pattern": payload["calibration"]["selected_pattern"],
                "candidate_count": payload["calibration"]["candidate_count"],
                "selection_scope": payload["calibration"]["selection_scope"],
            },
            sort_keys=True,
        ),
        domain="full-round ChaCha20 proof-Reader transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A454:selected_no_refit_weighted_pattern",
        mechanism="native_periodic_first_encounter_compilation",
        outcome="A454:complete_W52_pair_permutation",
        confidence=1.0,
        source=payload["stream"]["artifact"]["sha256"],
        quantification=json.dumps(payload["stream"]["artifact"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="target-blind W52 schedule materialization",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A454:complete_W52_pair_permutation",
        mechanism="exact_per_component_proposal_bound_validation",
        outcome="A454:exact_component_bounded_W52_stream",
        confidence=1.0,
        source=payload["guarantee_sha256"],
        quantification=json.dumps(payload["hard_rank_guarantee"], sort_keys=True),
        evidence=json.dumps(payload["geometry"], sort_keys=True),
        domain="bounded-regret multi-Reader scheduling",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A453:remaining96_consensus_boundary",
        mechanism="materialized_no_refit_weighting_closure",
        outcome="A454:exact_component_bounded_W52_stream",
        confidence=1.0,
        source="materialized:A454_no_refit_weighting_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_triplet(
        trigger="A454:selected_no_refit_weighted_pattern",
        mechanism="materialized_recovery_readiness_closure",
        outcome="A454:qualified_recovery_stream_ready",
        confidence=1.0,
        source="materialized:A454_recovery_ready_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A454 no-refit weighted W52 proof portfolio",
        entities=[
            "A453:remaining96_consensus_boundary",
            "A454:selected_no_refit_weighted_pattern",
            "A454:complete_W52_pair_permutation",
            "A454:exact_component_bounded_W52_stream",
            "A454:qualified_recovery_stream_ready",
        ],
    )
    writer.add_gap(
        subject="A454:qualified_recovery_stream_ready",
        predicate="next_required_object",
        expected_object_type="exclusive_queued_A454_W52_recovery_execution",
        confidence=1.0,
        suggested_queries=[
            "Bind the selected A454 pair stream to the A434-qualified complete-cell engine after the existing A452 queue without consuming prior target outcomes."
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
        reader.api_id != "a454wgt"
        or len(explicit) != 3
        or len(all_rows) != 5
        or len(inferred) != 2
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A454 authentic Causal reopen gate failed")
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
            "selection": explicit[0],
            "materialization": explicit[1],
            "guarantee": explicit[2],
            "inferred_closure": inferred,
            "next_gap": reader._gaps[0],
        },
    }


def _build_result_once(*, expected_implementation_sha256: str) -> dict[str, Any]:
    load_design()
    implementation = load_implementation(expected_implementation_sha256)
    _a448, a449, a451, a453 = load_sources()
    calibration = calibration_result()
    stream, guarantee, geometry = compile_W52_stream(
        a449,
        a451,
        a453,
        calibration["selected_pattern"],
    )
    ready = bool(
        calibration["selected_remaining96_full_statistics"][
            "positive_fixed_block_count"
        ]
        == 8
        and stream["artifact"]["complete_permutation"]
        and guarantee["all_bounds_satisfied"]
    )
    if not ready:
        raise RuntimeError("A454 recovery-readiness gate failed")
    core: dict[str, Any] = {
        "schema": "chacha20-round20-w52-no-refit-weighted-reader-portfolio-a454-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "STRICT_NO_REFIT_SELECTED_TARGET_BLIND_W52_WEIGHTED_RECOVERY_STREAM_READY",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "calibration": calibration,
        "stream": stream,
        "hard_rank_guarantee": guarantee,
        "geometry": geometry,
        "recovery_ready": ready,
        "A454_weighted_candidate_results_seen_before_design": False,
        "A454_selected_pattern_seen_before_design": False,
        "A454_W52_pair_stream_seen_before_design": False,
        "A426_A438_A440_A443_A450_A452_secret_result_or_worker_progress_read": False,
        "W52_target_labels_used": 0,
        "feature_refits": 0,
        "model_refits": 0,
        "W52_candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A448_runner": anchor(A448_RUNNER, A448_RUNNER_SHA256),
            "A448_result": anchor(A448_RESULT, A448_RESULT_SHA256),
            "A449_runner": anchor(A449_RUNNER, A449_RUNNER_SHA256),
            "A449_result": anchor(A449_RESULT, A449_RESULT_SHA256),
            "A451_result": anchor(A451_RESULT, A451_RESULT_SHA256),
            "A451_pair_stream": anchor(A451_PAIR_STREAM, A451_PAIR_STREAM_SHA256),
            "A453_result": anchor(A453_RESULT, A453_RESULT_SHA256),
            "A453_pair_stream": anchor(A453_PAIR_STREAM, A453_PAIR_STREAM_SHA256),
            "A453_personal_readback": anchor(A453_READBACK, A453_READBACK_SHA256),
            "native_source": anchor(NATIVE_SOURCE, NATIVE_SOURCE_SHA256),
            "native_executable": anchor(NATIVE_EXECUTABLE, NATIVE_EXECUTABLE_SHA256),
            "pair_stream_artifact": anchor(ARTIFACT, stream["artifact"]["sha256"]),
            "runner": anchor(Path(__file__)),
        },
    }
    core["guarantee_sha256"] = canonical_sha256(guarantee)
    core["geometry_sha256"] = canonical_sha256(geometry)
    core["result_commitment_sha256"] = canonical_sha256(
        {
            "implementation_commitment_sha256": core[
                "implementation_commitment_sha256"
            ],
            "calibration_sha256": calibration["calibration_sha256"],
            "artifact_sha256": stream["artifact"]["sha256"],
            "guarantee_sha256": core["guarantee_sha256"],
            "geometry_sha256": core["geometry_sha256"],
        }
    )
    core["causal"] = build_causal(core)
    atomic_json(RESULT, core)
    delta = calibration["selected_delta_over_A451_BHO"]
    fixed = calibration["selected_remaining96_full_statistics"]
    comparison = geometry["comparison_to_A451_fixed_slot_stream"]
    atomic_bytes(
        REPORT,
        (
            "# A454 — no-refit weighted W52 proof-Reader portfolio\n\n"
            "Evidence stage: **STRICT_NO_REFIT_SELECTED_TARGET_BLIND_W52_WEIGHTED_RECOVERY_STREAM_READY**\n\n"
            f"- Prospectively enumerated schedules: **{calibration['candidate_count']}**\n"
            f"- Selected periodic pattern: **{calibration['selected_pattern']}**\n"
            f"- Strict remaining96 aggregate / minimum gain: **{fixed['aggregate_bit_gain']:+.12f} / {fixed['minimum_fixed_block_bit_gain']:+.12f} bits**\n"
            f"- Delta over A451 BHO aggregate / minimum: **{delta['remaining96_aggregate_bit_gain']:+.12f} / {delta['remaining96_minimum_fixed_block_bit_gain']:+.12f} bits**\n"
            f"- Complete W52 pair permutation: **{PAIR_CELLS:,} cells**\n"
            f"- Pair-stream SHA-256: `{stream['artifact']['sha256']}`\n"
            "- Exact component-specific proposal bounds: **all 3 satisfied over all 16,777,216 cells**\n"
            f"- A451 Spearman / top-65,536 overlap: **{comparison['spearman_rank_correlation']:.12f} / {comparison['top_k_overlap']['65536']['overlap_fraction']:.12f}**\n"
            "- W52 target labels / refits / candidate executions: **0 / 0 / 0**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 2 inferred chains**\n"
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
        != "chacha20-round20-w52-no-refit-weighted-reader-portfolio-a454-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("recovery_ready") is not True
        or value.get("calibration", {}).get("candidate_count") != EXPECTED_PATTERNS
        or value.get("hard_rank_guarantee", {}).get("all_bounds_satisfied")
        is not True
        or value.get("stream", {}).get("artifact", {}).get("complete_permutation")
        is not True
        or value.get("A454_weighted_candidate_results_seen_before_design")
        is not False
        or value.get("A454_selected_pattern_seen_before_design") is not False
        or value.get("A454_W52_pair_stream_seen_before_design") is not False
        or value.get(
            "A426_A438_A440_A443_A450_A452_secret_result_or_worker_progress_read"
        )
        is not False
        or value.get("W52_target_labels_used") != 0
        or value.get("feature_refits") != 0
        or value.get("model_refits") != 0
        or value.get("W52_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A454 result semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    _ranks, artifact = artifact_rank_vector(ARTIFACT)
    if artifact["sha256"] != value["stream"]["artifact"]["sha256"]:
        raise RuntimeError("A454 pair-stream hash differs")
    return value


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": file_sha256(DESIGN) if DESIGN.exists() else None,
        "candidate_count": len(PATTERNS),
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
