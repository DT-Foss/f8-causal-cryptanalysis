#!/usr/bin/env python3
"""A453: compile three proof Readers into an exact-deadline W52 stream."""

from __future__ import annotations

import argparse
import gc
import hashlib
import importlib.util
import inspect
import json
import math
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

STEM = "chacha20_round20_w52_deadline_compiled_proof_portfolio_a453"
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
NATIVE_SOURCE = RESEARCH / "native/a453_deadline_compiler.cpp"
NATIVE_EXECUTABLE = RESEARCH / "bin/a453_deadline_compiler"

A448_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w46_full128_proof_antecedent_transfer_a448.py"
)
A448_DESIGN = (
    CONFIGS
    / "chacha20_round20_w46_full128_proof_antecedent_transfer_a448_design_v1.json"
)
A448_IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w46_full128_proof_antecedent_transfer_a448_implementation_v1.json"
)
A448_RESULT = (
    RESULTS / "chacha20_round20_w46_full128_proof_antecedent_transfer_a448_v1.json"
)
A448_CAUSAL = A448_RESULT.with_suffix(".causal")
A448_READBACK = RESEARCH / "reports/CAUSAL_CHACHA20_A448_PERSONAL_READER_READBACK_V1.md"
A449_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_target_blind_proof_antecedent_trace_a449.py"
)
A449_RESULT = (
    RESULTS / "chacha20_round20_w52_target_blind_proof_antecedent_trace_a449_v1.json"
)
A451_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_deduplicated_reader_portfolio_a451.py"
)
A451_RESULT = (
    RESULTS / "chacha20_round20_w52_deduplicated_reader_portfolio_a451_v1.json"
)
A451_PAIR_STREAM = (
    RESULTS
    / "chacha20_round20_w52_deduplicated_reader_portfolio_a451_pair_stream_uint16be_uint16be_v1.bin"
)

ATTEMPT_ID = "A453"
DESIGN_SHA256 = "160df2738635fe0a749af4a4563c81de64c80d3df70218382dda445e00339332"
A448_RUNNER_SHA256 = "33cf14799282e52a6e23857d15dba096ba61e003fdef8b53a2b6a93a5dcd9d60"
A448_DESIGN_SHA256 = "482033be6c5d6e123f4efbe0c527933f832f73e4382bdb4b51172417f339f555"
A448_IMPLEMENTATION_SHA256 = (
    "0924803bf5f2d7168b51b205e125303a18165b72d8a9718fc57cb4f395251801"
)
A448_RESULT_SHA256 = "4f3bfbc7be7932917a40a3ad9ff3db76c1bf1ca8799d7a887025f3e98e5464db"
A448_CAUSAL_SHA256 = "3a3092311c7ba15ad4be27f53e6e7db2137edd045c8b6a818d9876310b0c564f"
A448_READBACK_SHA256 = "1f3914f78874754a74a71cc335581e310a0391e9326f310ae0c5f5126e4500b0"
A448_RESULT_COMMITMENT_SHA256 = (
    "8b437a85395cab19316453eb8908b8dac20ca0455f54eea2443daf8d99622408"
)
A449_RUNNER_SHA256 = "cd19406ba8964aceea1dfe16904f505097fb91aed738cb825c934f89c460e875"
A449_RESULT_SHA256 = "f054125c5c363e379ddca661334a57867a0d367a5c57d0caa2bb0f8814b322a7"
A449_RESULT_COMMITMENT_SHA256 = (
    "4cfd5edf10a9f4e491e5e4b2d289eca78113d67973069eea60ded00a4b64f2cf"
)
A451_RUNNER_SHA256 = "e03ca42e450fc3de76e7368d0d92e86803fb5808c6206ab301a79f926510791a"
A451_RESULT_SHA256 = "f2501e5e85f6d37305473738bb0840c12651720e6f7e3fbab2fc4a253b40bdf6"
A451_RESULT_COMMITMENT_SHA256 = (
    "d699e1150e902fd66dd530a60cc4b71d69be379eb46e355c08121e8526ca2b9f"
)
A451_PAIR_STREAM_SHA256 = "826d10e8cfb8ba2cb51e2d1cee35d29f29b9a313928dbdabbf6b92ad2a546cf9"
NATIVE_SOURCE_SHA256 = "c113869ead3ff58d5c98585ec4ed1dfbe678a2fa88c45073303823049acbd329"
NATIVE_EXECUTABLE_SHA256 = (
    "37450450cdb14239127734e26ffd1a25c6cae1d9b3f4685f4b064a0f1631b0a6"
)
IMPLEMENTATION_V1_SHA256 = (
    "7bebc52bb4f958f9cae68a698b5679c721300539ab7e5df4369c67d512058364"
)
IMPLEMENTATION_V1_COMMITMENT_SHA256 = (
    "eea0113e79e6e68840328d516d41023f00551fe3362a5f39750831dfe7e528d3"
)

COMPONENTS = (
    "proof_borda_top32",
    "hybrid_proof_top16_equal",
    "proof_best_single",
)
CANDIDATES = (
    "A451_fixed_slot_first_encounter",
    "deadline_product",
    "deadline_sum",
    "deadline_median",
    "deadline_reciprocal_rank_k0",
    "deadline_reciprocal_rank_k16",
    "unconstrained_product",
)
PRIMARY = "deadline_median"
AXIS_CELLS = 1 << 12
PAIR_CELLS = 1 << 24
COMPONENT_COUNT = len(COMPONENTS)
CHUNK = 1 << 20
TOP_KS = (16, 64, 256, 1024, 65536, 1048576)
MAGIC = b"A453RANKV1" + bytes(6)
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A453 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A448 = load_module(A448_RUNNER, "a453_a448")
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


def no_downstream_artifacts() -> bool:
    return not any(
        path.exists()
        for path in (IMPLEMENTATION, RESULT, ARTIFACT, COMPONENT_INPUT, CAUSAL, REPORT)
    )


def load_design() -> dict[str, Any]:
    anchor(DESIGN, DESIGN_SHA256)
    value = json.loads(DESIGN.read_bytes())
    source = value.get("source_contract", {})
    compiler = value.get("compiler_contract", {})
    calibration = value.get("calibration_contract", {})
    materialization = value.get("W52_materialization_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-deadline-compiled-proof-portfolio-a453-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or source.get("A448_complete128_result_sha256") != A448_RESULT_SHA256
        or source.get("A448_result_commitment_sha256")
        != A448_RESULT_COMMITMENT_SHA256
        or source.get("A449_W52_result_sha256") != A449_RESULT_SHA256
        or source.get("A449_result_commitment_sha256")
        != A449_RESULT_COMMITMENT_SHA256
        or source.get("A451_pair_stream_result_sha256") != A451_RESULT_SHA256
        or source.get("A451_result_commitment_sha256")
        != A451_RESULT_COMMITMENT_SHA256
        or tuple(source.get("component_operators", [])) != COMPONENTS
        or source.get("W52_target_labels_consumed") != 0
        or source.get("W52_candidate_assignments_executed") != 0
        or compiler.get("name") != "latest_free_deadline_majority_consensus"
        or compiler.get("component_count") != COMPONENT_COUNT
        or compiler.get("selected_priority") != "median_component_rank"
        or compiler.get("complete_permutation_required") is not True
        or calibration.get("primary_compiler") != PRIMARY
        or tuple(calibration.get("controls", [])) != tuple(
            candidate for candidate in CANDIDATES if candidate != PRIMARY
        )
        or calibration.get("remaining96_result_known_at_design_freeze") is not False
        or materialization.get("pair_cells") != PAIR_CELLS
        or materialization.get("expected_artifact_bytes") != PAIR_CELLS * 4
        or materialization.get("candidate_execution") is not False
        or boundary.get("W52_target_labels_used") != 0
        or boundary.get("W52_feature_refits") != 0
        or boundary.get("W52_model_refits") != 0
        or boundary.get("W52_candidate_assignments_executed") != 0
        or boundary.get("A450_candidate_progress_or_result_read") is not False
        or boundary.get("A452_candidate_progress_or_result_read") is not False
        or boundary.get(
            "A426_A438_A440_A443_secret_result_stop_or_worker_progress_read"
        )
        is not False
        or boundary.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A453 frozen design semantics differ")
    sources = value["source_anchors"]
    for key, item in sources.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, sources[f"{stem}_sha256"])
    return value


def load_sources() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    anchor(A448_RUNNER, A448_RUNNER_SHA256)
    anchor(A448_DESIGN, A448_DESIGN_SHA256)
    anchor(A448_IMPLEMENTATION, A448_IMPLEMENTATION_SHA256)
    anchor(A448_RESULT, A448_RESULT_SHA256)
    anchor(A448_CAUSAL, A448_CAUSAL_SHA256)
    anchor(A448_READBACK, A448_READBACK_SHA256)
    anchor(A449_RUNNER, A449_RUNNER_SHA256)
    anchor(A449_RESULT, A449_RESULT_SHA256)
    anchor(A451_RUNNER, A451_RUNNER_SHA256)
    anchor(A451_RESULT, A451_RESULT_SHA256)
    anchor(A451_PAIR_STREAM, A451_PAIR_STREAM_SHA256)
    a448 = A448.load_result(A448_RESULT_SHA256)
    a449 = json.loads(A449_RESULT.read_bytes())
    a451 = json.loads(A451_RESULT.read_bytes())
    if (
        a448.get("result_commitment_sha256")
        != A448_RESULT_COMMITMENT_SHA256
        or a449.get("schema")
        != "chacha20-round20-w52-target-blind-proof-antecedent-trace-a449-v1"
        or a449.get("result_commitment_sha256")
        != A449_RESULT_COMMITMENT_SHA256
        or a451.get("schema")
        != "chacha20-round20-w52-deduplicated-reader-portfolio-a451-v1"
        or a451.get("result_commitment_sha256")
        != A451_RESULT_COMMITMENT_SHA256
        or a449.get("W52_target_labels_used") != 0
        or a449.get("W52_feature_refits") != 0
        or a449.get("W52_model_refits") != 0
        or a449.get("production_candidate_assignments_executed") != 0
        or a451.get("W52_target_labels_used") != 0
        or a451.get("feature_refits") != 0
        or a451.get("model_refits") != 0
        or a451.get("production_candidate_assignments_executed") != 0
        or a451.get("A450_candidate_progress_or_result_read") is not False
    ):
        raise RuntimeError("A453 frozen source semantics differ")
    for name in COMPONENTS:
        if name not in a449["operator_schedules"]:
            raise RuntimeError(f"A453 component {name} is absent")
    return a448, a449, a451


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
        raise ValueError("A453 factorized source order differs")
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
        raise RuntimeError("A453 reference square rank cover differs")
    return ranks


def compare_ranks(left: np.ndarray, right: np.ndarray) -> dict[str, Any]:
    if left.shape != right.shape or left.shape != (PAIR_CELLS,):
        raise ValueError("A453 rank comparison geometry differs")
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
        "spearman_rank_correlation": covariance_sum
        / (PAIR_CELLS * variance),
        "earlier": int(np.count_nonzero(left < right)),
        "equal": int(np.count_nonzero(left == right)),
        "later": int(np.count_nonzero(left > right)),
        "top_k_overlap": top,
    }


def union_cover(
    fused_rank: np.ndarray, component_ranks: Sequence[np.ndarray]
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for k in TOP_KS:
        union = np.zeros(PAIR_CELLS, dtype=np.bool_)
        for ranks in component_ranks:
            union |= ranks <= k
        required = int(fused_rank[union].max(initial=0))
        union_cells = int(np.count_nonzero(union))
        output[str(k)] = {
            "component_top_k_union_cells": union_cells,
            "fused_prefix_required_for_complete_union": required,
            "theoretical_three_k_bound": COMPONENT_COUNT * k,
            "bound_satisfied": required <= COMPONENT_COUNT * k,
            "deduplication_saved_slots": COMPONENT_COUNT * k - required,
            "union_overlap_cells": COMPONENT_COUNT * k - union_cells,
        }
    return output


def freeze_implementation() -> dict[str, Any]:
    if not no_downstream_artifacts():
        raise FileExistsError("A453 implementation or downstream artifact exists")
    design = load_design()
    a448, a449, a451 = load_sources()
    anchor(IMPLEMENTATION_V1, IMPLEMENTATION_V1_SHA256)
    implementation_v1 = json.loads(IMPLEMENTATION_V1.read_bytes())
    if (
        implementation_v1.get("implementation_commitment_sha256")
        != IMPLEMENTATION_V1_COMMITMENT_SHA256
    ):
        raise RuntimeError("A453 implementation-v1 commitment differs")
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A453 tests and reproducer must precede freeze")
    subprocess.run([str(NATIVE_EXECUTABLE), "--self-test"], check=True)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-deadline-compiled-proof-portfolio-a453-implementation-v2",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "causal_api_identifier_only_amendment_to_pre_result_frozen_v1_with_identical_calibration_and_native_W52_compiler",
        "implementation_v1_sha256": IMPLEMENTATION_V1_SHA256,
        "implementation_v1_commitment_sha256": IMPLEMENTATION_V1_COMMITMENT_SHA256,
        "amendment_scope": "replace_overlength_Causal_api_id_with_a453dl; no mathematical_schedule_calibration_artifact_or_boundary_change",
        "design_sha256": DESIGN_SHA256,
        "source_A448_result_commitment_sha256": a448[
            "result_commitment_sha256"
        ],
        "source_A449_result_commitment_sha256": a449[
            "result_commitment_sha256"
        ],
        "source_A451_result_commitment_sha256": a451[
            "result_commitment_sha256"
        ],
        "components": list(COMPONENTS),
        "candidates": list(CANDIDATES),
        "primary": PRIMARY,
        "compiler_contract": design["compiler_contract"],
        "calibration_contract": design["calibration_contract"],
        "W52_materialization_contract": design["W52_materialization_contract"],
        "A448_remaining96_fixed_no_refit_fusion_result_known_at_freeze": False,
        "W52_target_labels_used": 0,
        "W52_feature_refits": 0,
        "W52_model_refits": 0,
        "W52_candidate_assignments_executed": 0,
        "A450_candidate_progress_or_result_read": False,
        "A452_candidate_progress_or_result_read": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation_v1": anchor(
                IMPLEMENTATION_V1, IMPLEMENTATION_V1_SHA256
            ),
            "A448_runner": anchor(A448_RUNNER, A448_RUNNER_SHA256),
            "A448_result": anchor(A448_RESULT, A448_RESULT_SHA256),
            "A448_causal": anchor(A448_CAUSAL, A448_CAUSAL_SHA256),
            "A448_personal_readback": anchor(
                A448_READBACK, A448_READBACK_SHA256
            ),
            "A449_runner": anchor(A449_RUNNER, A449_RUNNER_SHA256),
            "A449_result": anchor(A449_RESULT, A449_RESULT_SHA256),
            "A451_runner": anchor(A451_RUNNER, A451_RUNNER_SHA256),
            "A451_result": anchor(A451_RESULT, A451_RESULT_SHA256),
            "A451_pair_stream": anchor(
                A451_PAIR_STREAM, A451_PAIR_STREAM_SHA256
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
        != "chacha20-round20-w52-deadline-compiled-proof-portfolio-a453-implementation-v2"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("implementation_v1_sha256")
        != IMPLEMENTATION_V1_SHA256
        or value.get("implementation_v1_commitment_sha256")
        != IMPLEMENTATION_V1_COMMITMENT_SHA256
        or value.get("amendment_scope")
        != "replace_overlength_Causal_api_id_with_a453dl; no mathematical_schedule_calibration_artifact_or_boundary_change"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("source_A448_result_commitment_sha256")
        != A448_RESULT_COMMITMENT_SHA256
        or value.get("source_A449_result_commitment_sha256")
        != A449_RESULT_COMMITMENT_SHA256
        or value.get("source_A451_result_commitment_sha256")
        != A451_RESULT_COMMITMENT_SHA256
        or tuple(value.get("components", [])) != COMPONENTS
        or tuple(value.get("candidates", [])) != CANDIDATES
        or value.get("primary") != PRIMARY
        or value.get("A448_remaining96_fixed_no_refit_fusion_result_known_at_freeze")
        is not False
        or value.get("W52_target_labels_used") != 0
        or value.get("W52_feature_refits") != 0
        or value.get("W52_model_refits") != 0
        or value.get("W52_candidate_assignments_executed") != 0
        or value.get("A450_candidate_progress_or_result_read") is not False
        or value.get("A452_candidate_progress_or_result_read") is not False
    ):
        raise RuntimeError("A453 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A453 implementation commitment differs")
    return value


def _latest(parent: np.ndarray, value: int) -> int:
    root = value
    while int(parent[root]) != root:
        root = int(parent[root])
    while int(parent[value]) != value:
        next_value = int(parent[value])
        parent[value] = root
        value = next_value
    return root


def deadline_compiled_ranks(
    component_ranks: Sequence[np.ndarray], candidate: str
) -> np.ndarray:
    ranks = np.stack(component_ranks).astype(np.int64, copy=False)
    if ranks.ndim != 2 or ranks.shape[0] != COMPONENT_COUNT:
        raise ValueError("A453 component calibration geometry differs")
    cells = int(ranks.shape[1])
    expected = set(range(1, cells + 1))
    if any(set(row.tolist()) != expected for row in ranks):
        raise ValueError("A453 component calibration row is not a permutation")
    ids = np.arange(cells, dtype=np.int64)
    ordered = np.sort(ranks, axis=0)
    minimum, median, maximum = ordered
    if candidate == "A451_fixed_slot_first_encounter":
        first_key = np.minimum.reduce(
            [COMPONENT_COUNT * (row - 1) + slot for slot, row in enumerate(ranks)]
        )
        order = np.argsort(first_key, kind="stable")
        output = np.empty(cells, dtype=np.int16)
        output[order] = np.arange(1, cells + 1, dtype=np.int16)
        return output
    if candidate == "unconstrained_product":
        product = np.prod(ranks, axis=0, dtype=np.int64)
        order = np.lexsort((ids, minimum, maximum, median, product))
        output = np.empty(cells, dtype=np.int16)
        output[order] = np.arange(1, cells + 1, dtype=np.int16)
        return output
    deadlines = np.minimum(cells, COMPONENT_COUNT * minimum)
    if candidate == "deadline_product":
        primary = np.prod(ranks, axis=0, dtype=np.int64)
        best = np.lexsort((ids, minimum, maximum, median, primary))
    elif candidate == "deadline_sum":
        primary = ranks.sum(axis=0)
        best = np.lexsort((ids, minimum, maximum, median, primary))
    elif candidate == "deadline_median":
        best = np.lexsort((ids, minimum, maximum, median))
    elif candidate == "deadline_reciprocal_rank_k0":
        primary = -(1.0 / ranks.astype(np.float64)).sum(axis=0)
        best = np.lexsort((ids, minimum, maximum, median, primary))
    elif candidate == "deadline_reciprocal_rank_k16":
        primary = -(1.0 / (ranks.astype(np.float64) + 16.0)).sum(axis=0)
        best = np.lexsort((ids, minimum, maximum, median, primary))
    else:
        raise ValueError(f"A453 unknown compiler candidate {candidate}")
    parent = np.arange(cells + 1, dtype=np.int64)
    output = np.empty(cells, dtype=np.int16)
    for cell in best[::-1]:
        slot = _latest(parent, int(deadlines[cell]))
        if slot == 0:
            raise RuntimeError("A453 calibration deadline schedule is infeasible")
        output[cell] = slot
        parent[slot] = _latest(parent, slot - 1)
    if set(output.tolist()) != expected or np.any(output > deadlines):
        raise RuntimeError("A453 calibration deadline guarantee failed")
    return output


def fuse_calibration_panel(
    fields: Mapping[str, np.ndarray], targets: Sequence[int], candidate: str
) -> np.ndarray:
    output = np.zeros((A448.TARGETS, A448.CELLS), dtype=np.int16)
    for target in targets:
        output[target] = deadline_compiled_ranks(
            [fields[name][target] for name in COMPONENTS], candidate
        )
    return output


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
    all_targets = np.arange(A448.TARGETS, dtype=np.int64)
    remaining = np.asarray(
        [
            row["target_index"]
            for row in A448.complete_manifest()
            if not row["reused_from_A447"]
        ],
        dtype=np.int64,
    )
    candidates: dict[str, Any] = {}
    for candidate in CANDIDATES:
        complete_field = fuse_calibration_panel(
            crossfit_fields, all_targets, candidate
        )
        fixed_field = fuse_calibration_panel(fixed_fields, remaining, candidate)
        complete_stats = A448.statistics(
            complete_field,
            truths,
            all_targets,
            evaluation_scope="complete128",
        )
        fixed_stats = A448.statistics(
            fixed_field,
            truths,
            remaining,
            evaluation_scope="remaining96",
        )
        candidates[candidate] = {
            "complete128": complete_stats,
            "remaining96_A447_fixed_model_no_refit": fixed_stats,
            "complete128_rank_field_sha256": A448.array_sha256(
                complete_field, "<i2"
            ),
            "remaining96_rank_field_sha256": A448.array_sha256(
                fixed_field[remaining], "<i2"
            ),
            "exact_threefold_deadline_guarantee": candidate
            != "unconstrained_product",
        }
    preliminary = load_design()["calibration_contract"]
    primary_stats = candidates[PRIMARY]["complete128"]
    control_stats = candidates["A451_fixed_slot_first_encounter"]["complete128"]
    for key in (
        "aggregate_bit_gain",
        "minimum_fixed_block_bit_gain",
        "targets_at_or_above_median_rank",
        "positive_fixed_block_count",
    ):
        expected = preliminary["preliminary_complete128_primary"][key]
        observed = primary_stats[key]
        if isinstance(expected, float):
            if not math.isclose(float(observed), expected, abs_tol=1e-15):
                raise RuntimeError(f"A453 preliminary primary {key} differs")
        elif observed != expected:
            raise RuntimeError(f"A453 preliminary primary {key} differs")
        expected_control = preliminary["preliminary_complete128_A451_control"][key]
        observed_control = control_stats[key]
        if isinstance(expected_control, float):
            if not math.isclose(
                float(observed_control), expected_control, abs_tol=1e-15
            ):
                raise RuntimeError(f"A453 preliminary control {key} differs")
        elif observed_control != expected_control:
            raise RuntimeError(f"A453 preliminary control {key} differs")
    result = {
        "primary": PRIMARY,
        "components": list(COMPONENTS),
        "candidate_order": list(CANDIDATES),
        "candidate_results": candidates,
        "primary_delta_over_A451_control": {
            "complete128_aggregate_bit_gain": primary_stats[
                "aggregate_bit_gain"
            ]
            - control_stats["aggregate_bit_gain"],
            "complete128_minimum_fixed_block_bit_gain": primary_stats[
                "minimum_fixed_block_bit_gain"
            ]
            - control_stats["minimum_fixed_block_bit_gain"],
            "remaining96_aggregate_bit_gain": candidates[PRIMARY][
                "remaining96_A447_fixed_model_no_refit"
            ]["aggregate_bit_gain"]
            - candidates["A451_fixed_slot_first_encounter"][
                "remaining96_A447_fixed_model_no_refit"
            ]["aggregate_bit_gain"],
            "remaining96_minimum_fixed_block_bit_gain": candidates[PRIMARY][
                "remaining96_A447_fixed_model_no_refit"
            ]["minimum_fixed_block_bit_gain"]
            - candidates["A451_fixed_slot_first_encounter"][
                "remaining96_A447_fixed_model_no_refit"
            ]["minimum_fixed_block_bit_gain"],
        },
        "A448_crossfit_selected_individual_operator": crossfit_selected,
        "A448_individual_complete128": {
            name: crossfit_evaluations[name] for name in COMPONENTS
        },
        "A448_individual_remaining96_no_refit": {
            name: fixed_evaluations[name] for name in COMPONENTS
        },
        "measurement_ledger_sha256": canonical_sha256(ledgers),
        "borda_contract": borda_contract,
        "feature_contract_sha256": canonical_sha256(feature_contract),
    }
    result["calibration_sha256"] = canonical_sha256(result)
    del rank_panel, fixed_fields, crossfit_fields, measurements
    gc.collect()
    return result


def write_component_input(a449: Mapping[str, Any]) -> dict[str, Any]:
    payload = bytearray(MAGIC)
    component_rows: dict[str, Any] = {}
    for name in COMPONENTS:
        schedule = a449["operator_schedules"][name]
        prefix = np.asarray(schedule["prefix_order"], dtype=np.uint16)
        off_axis = np.asarray(schedule["off_axis_order"], dtype=np.uint16)
        if (
            prefix.shape != (AXIS_CELLS,)
            or off_axis.shape != (AXIS_CELLS,)
            or set(prefix.tolist()) != set(range(AXIS_CELLS))
            or set(off_axis.tolist()) != set(range(AXIS_CELLS))
        ):
            raise RuntimeError(f"A453 W52 component {name} order differs")
        payload.extend(prefix.astype(">u2", copy=False).tobytes())
        payload.extend(off_axis.astype(">u2", copy=False).tobytes())
        component_rows[name] = {
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
    expected_bytes = len(MAGIC) + COMPONENT_COUNT * 2 * AXIS_CELLS * 2
    if len(payload) != expected_bytes:
        raise RuntimeError("A453 component input size differs")
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
        raise RuntimeError("A453 pair-stream size differs")
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
            raise RuntimeError("A453 pair-stream coordinate differs")
        ids = (prefix << 12) | off_axis
        if np.unique(ids).size != ids.size or np.any(seen[ids]):
            raise RuntimeError("A453 pair-stream contains a duplicate")
        seen[ids] = True
        ranks[ids] = np.arange(start + 1, stop + 1, dtype=np.uint32)
        if first_pair is None:
            first_pair = [int(prefix[0]), int(off_axis[0])]
        last_pair = [int(prefix[-1]), int(off_axis[-1])]
    del mapped
    if not bool(np.all(seen)):
        raise RuntimeError("A453 pair-stream cover is incomplete")
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


def compile_W52_stream(
    a449: Mapping[str, Any], a451: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    component_input = write_component_input(a449)
    temporary = ARTIFACT.with_name(f".{ARTIFACT.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    subprocess.run(
        [str(NATIVE_EXECUTABLE), str(COMPONENT_INPUT), str(temporary)],
        check=True,
    )
    if temporary.stat().st_size != PAIR_CELLS * 4:
        temporary.unlink(missing_ok=True)
        raise RuntimeError("A453 native compiler artifact size differs")
    os.replace(temporary, ARTIFACT)
    compiled_rank, artifact = artifact_rank_vector(ARTIFACT)
    component_ranks = []
    for name in COMPONENTS:
        row = a449["operator_schedules"][name]
        component_ranks.append(
            reference_square_rank_vector(
                row["prefix_order"], row["off_axis_order"]
            )
        )
    minimum_rank = np.minimum.reduce(component_ranks)
    slack = COMPONENT_COUNT * minimum_rank.astype(np.int64) - compiled_rank.astype(
        np.int64
    )
    ratio = compiled_rank.astype(np.float64) / minimum_rank.astype(np.float64)
    violations = int(np.count_nonzero(slack < 0))
    if violations != 0:
        raise RuntimeError("A453 exact W52 deadline guarantee failed")
    a451_rank, a451_artifact = artifact_rank_vector(A451_PAIR_STREAM)
    baseline = a449["operator_schedules"]["borda_sum_baseline"]
    baseline_rank = reference_square_rank_vector(
        baseline["prefix_order"], baseline["off_axis_order"]
    )
    geometry = {
        "comparison_to_A451_fixed_slot_stream": compare_ranks(
            compiled_rank, a451_rank
        ),
        "comparison_to_A442_borda_sum_baseline": compare_ranks(
            compiled_rank, baseline_rank
        ),
        "component_comparisons": {
            name: compare_ranks(compiled_rank, rank)
            for name, rank in zip(COMPONENTS, component_ranks, strict=True)
        },
        "component_top_k_union_cover": union_cover(
            compiled_rank, component_ranks
        ),
        "A451_source_artifact": a451_artifact,
        "A451_result_commitment_sha256": a451[
            "result_commitment_sha256"
        ],
    }
    guarantee = {
        "formula": "compiled_rank_one_based <= 3 * minimum_component_rank_one_based",
        "cells_checked": PAIR_CELLS,
        "violations": violations,
        "minimum_slack_cells": int(slack.min()),
        "maximum_observed_rank_ratio": float(ratio.max()),
        "p99_observed_rank_ratio": float(np.quantile(ratio, 0.99)),
        "median_observed_rank_ratio": float(np.median(ratio)),
        "guarantee_satisfied": violations == 0,
    }
    stream = {
        "component_input": component_input,
        "artifact": artifact,
        "compiled_rank_vector_uint32be_sha256": array_sha256(
            compiled_rank, ">u4"
        ),
        "minimum_component_rank_vector_uint32be_sha256": array_sha256(
            minimum_rank, ">u4"
        ),
        "compiler_source_sha256": NATIVE_SOURCE_SHA256,
        "compiler_executable_sha256": NATIVE_EXECUTABLE_SHA256,
        "priority": "median_component_rank_then_maximum_then_minimum_then_canonical_id",
        "deadline": "min(2^24,3*minimum_component_rank)",
        "target_labels_used": 0,
        "feature_refits": 0,
        "model_refits": 0,
        "candidate_assignments_executed": 0,
    }
    return stream, guarantee, geometry


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    writer = CausalWriter(api_id="a453dl")
    writer._rules = []
    writer.add_rule(
        name="latest_free_deadline_implies_exact_rank_bound",
        description="Assigning every cell to a free slot at or before three times its best component rank preserves the exact all-cell threefold bound.",
        pattern=["A453_deadline_compiled_complete_permutation"],
        conclusion="A453_exact_threefold_rank_guarantee",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="calibrated_bound_stream_to_recovery_readiness",
        description="A calibrated complete random-access stream with zero deadline violations can directly drive the qualified W52 cell engine.",
        pattern=["A453_exact_threefold_rank_guarantee"],
        conclusion="A453_W52_recovery_stream_ready",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A448:three_crossfit_proof_reader_rank_fields",
        mechanism="latest_free_deadline_majority_consensus_calibration",
        outcome="A453:eight_block_deadline_median_transfer",
        confidence=1.0,
        source=payload["calibration"]["calibration_sha256"],
        quantification=json.dumps(
            payload["calibration"]["primary_delta_over_A451_control"],
            sort_keys=True,
        ),
        evidence=json.dumps(
            payload["calibration"]["candidate_results"][PRIMARY], sort_keys=True
        ),
        domain="proof-Reader portfolio calibration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A449:three_target_blind_W52_proof_reader_orders",
        mechanism="native_latest_free_predecessor_deadline_compiler",
        outcome="A453:deadline_compiled_complete_permutation",
        confidence=1.0,
        source=payload["stream"]["artifact"]["sha256"],
        quantification=json.dumps(payload["hard_rank_guarantee"], sort_keys=True),
        evidence=json.dumps(payload["geometry"], sort_keys=True),
        domain="full-round ChaCha20 W52 pair scheduling",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A453:deadline_compiled_complete_permutation",
        mechanism="exact_all_cell_deadline_validation_and_memory_mapped_readout",
        outcome="A453:W52_recovery_stream_ready",
        confidence=1.0,
        source=payload["result_commitment_sha256"],
        quantification=json.dumps(payload["stream"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="restart-safe commodity-hardware recovery execution",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A448:three_crossfit_proof_reader_rank_fields",
        mechanism="materialized_calibration_and_deadline_compilation_closure",
        outcome="A453:exact_threefold_rank_guarantee",
        confidence=1.0,
        source="materialized:A453_deadline_compiler_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_triplet(
        trigger="A453:exact_threefold_rank_guarantee",
        mechanism="materialized_random_access_readiness_closure",
        outcome="A453:W52_recovery_stream_ready",
        confidence=1.0,
        source="materialized:A453_recovery_ready_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A453 deadline-compiled W52 proof portfolio",
        entities=[
            "A448:three_crossfit_proof_reader_rank_fields",
            "A453:eight_block_deadline_median_transfer",
            "A449:three_target_blind_W52_proof_reader_orders",
            "A453:deadline_compiled_complete_permutation",
            "A453:exact_threefold_rank_guarantee",
            "A453:W52_recovery_stream_ready",
        ],
    )
    writer.add_gap(
        subject="A453:W52_recovery_stream_ready",
        predicate="next_required_object",
        expected_object_type="qualified_A453_W52_deadline_stream_recovery_execution",
        confidence=1.0,
        suggested_queries=[
            "Bind the A453 memory-mapped stream to the existing A434-qualified complete-cell engine after the active recovery queue closes."
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
        reader.api_id != "a453dl"
        or len(explicit) != 3
        or len(all_rows) != 5
        or len(inferred) != 2
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A453 authentic Causal reopen gate failed")
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
            "compilation": explicit[1],
            "recovery_readiness": explicit[2],
            "inferred_closure": inferred,
            "next_gap": reader._gaps[0],
        },
    }


def _build_result_once(*, expected_implementation_sha256: str) -> dict[str, Any]:
    load_design()
    implementation = load_implementation(expected_implementation_sha256)
    _a448, a449, a451 = load_sources()
    calibration = calibration_result()
    stream, guarantee, geometry = compile_W52_stream(a449, a451)
    core: dict[str, Any] = {
        "schema": "chacha20-round20-w52-deadline-compiled-proof-portfolio-a453-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "CALIBRATED_TARGET_BLIND_W52_DEADLINE_COMPILED_RECOVERY_STREAM_READY",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "calibration": calibration,
        "stream": stream,
        "hard_rank_guarantee": guarantee,
        "geometry": geometry,
        "recovery_ready": guarantee["guarantee_satisfied"]
        and stream["artifact"]["complete_permutation"],
        "A448_remaining96_fixed_no_refit_fusion_result_known_at_design_freeze": False,
        "W52_target_labels_used": 0,
        "W52_feature_refits": 0,
        "W52_model_refits": 0,
        "W52_candidate_assignments_executed": 0,
        "A450_candidate_progress_or_result_read": False,
        "A452_candidate_progress_or_result_read": False,
        "A426_A438_A440_A443_secret_result_stop_or_worker_progress_read": False,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(
                IMPLEMENTATION, expected_implementation_sha256
            ),
            "A448_runner": anchor(A448_RUNNER, A448_RUNNER_SHA256),
            "A448_result": anchor(A448_RESULT, A448_RESULT_SHA256),
            "A448_causal": anchor(A448_CAUSAL, A448_CAUSAL_SHA256),
            "A448_personal_readback": anchor(
                A448_READBACK, A448_READBACK_SHA256
            ),
            "A449_runner": anchor(A449_RUNNER, A449_RUNNER_SHA256),
            "A449_result": anchor(A449_RESULT, A449_RESULT_SHA256),
            "A451_runner": anchor(A451_RUNNER, A451_RUNNER_SHA256),
            "A451_result": anchor(A451_RESULT, A451_RESULT_SHA256),
            "A451_pair_stream": anchor(
                A451_PAIR_STREAM, A451_PAIR_STREAM_SHA256
            ),
            "native_source": anchor(NATIVE_SOURCE, NATIVE_SOURCE_SHA256),
            "native_executable": anchor(
                NATIVE_EXECUTABLE, NATIVE_EXECUTABLE_SHA256
            ),
            "component_input": anchor(
                COMPONENT_INPUT, stream["component_input"]["sha256"]
            ),
            "pair_stream_artifact": anchor(
                ARTIFACT, stream["artifact"]["sha256"]
            ),
            "runner": anchor(Path(__file__)),
        },
    }
    core["calibration_and_geometry_sha256"] = canonical_sha256(
        {"calibration": calibration, "geometry": geometry}
    )
    core["guarantee_sha256"] = canonical_sha256(guarantee)
    core["result_commitment_sha256"] = canonical_sha256(
        {
            "implementation_commitment_sha256": core[
                "implementation_commitment_sha256"
            ],
            "calibration_and_geometry_sha256": core[
                "calibration_and_geometry_sha256"
            ],
            "guarantee_sha256": core["guarantee_sha256"],
            "artifact_sha256": stream["artifact"]["sha256"],
        }
    )
    core["causal"] = build_causal(core)
    atomic_json(RESULT, core)
    primary = calibration["candidate_results"][PRIMARY]
    delta = calibration["primary_delta_over_A451_control"]
    atomic_bytes(
        REPORT,
        (
            "# A453 — deadline-compiled W52 proof portfolio\n\n"
            "Evidence stage: **CALIBRATED_TARGET_BLIND_W52_DEADLINE_COMPILED_RECOVERY_STREAM_READY**\n\n"
            f"- Complete pair permutation: **{PAIR_CELLS:,} cells / {stream['artifact']['bytes']:,} bytes**\n"
            f"- Pair-stream SHA-256: `{stream['artifact']['sha256']}`\n"
            "- Exact all-cell guarantee: **compiled rank <= 3 x best component rank**\n"
            f"- Exact deadline violations: **{guarantee['violations']}**\n"
            f"- Complete128 minimum block gain: **{primary['complete128']['minimum_fixed_block_bit_gain']:.12f}**\n"
            f"- Complete128 delta over A451: **{delta['complete128_minimum_fixed_block_bit_gain']:+.12f}**\n"
            f"- Remaining96 no-refit delta over A451: **{delta['remaining96_minimum_fixed_block_bit_gain']:+.12f}**\n"
            f"- A451 top-65,536 overlap: **{geometry['comparison_to_A451_fixed_slot_stream']['top_k_overlap']['65536']['overlap_fraction']:.12f}**\n"
            "- W52 target labels / feature refits / model refits / candidate executions: **0 / 0 / 0 / 0**\n"
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
        raise


def load_result(expected_sha256: str) -> dict[str, Any]:
    anchor(RESULT, expected_sha256)
    value = json.loads(RESULT.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-deadline-compiled-proof-portfolio-a453-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("recovery_ready") is not True
        or value.get("hard_rank_guarantee", {}).get("violations") != 0
        or value.get("stream", {}).get("artifact", {}).get(
            "complete_permutation"
        )
        is not True
        or value.get("W52_target_labels_used") != 0
        or value.get("W52_feature_refits") != 0
        or value.get("W52_model_refits") != 0
        or value.get("W52_candidate_assignments_executed") != 0
        or value.get("A450_candidate_progress_or_result_read") is not False
        or value.get("A452_candidate_progress_or_result_read") is not False
    ):
        raise RuntimeError("A453 result semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    _rank, artifact = artifact_rank_vector(ARTIFACT)
    if artifact["sha256"] != value["stream"]["artifact"]["sha256"]:
        raise RuntimeError("A453 result artifact differs")
    return value


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": file_sha256(DESIGN) if DESIGN.exists() else None,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "result_complete": RESULT.exists(),
        "artifact_present": ARTIFACT.exists(),
        "pair_cells": PAIR_CELLS,
        "primary": PRIMARY,
    }
    load_design()
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if RESULT.exists():
        payload["result_sha256"] = file_sha256(RESULT)
        value = load_result(payload["result_sha256"])
        payload["evidence_stage"] = value["evidence_stage"]
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
