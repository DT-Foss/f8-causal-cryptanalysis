#!/usr/bin/env python3
"""A451: fuse three frozen A449 pair orders into one bounded-regret stream."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

STEM = "chacha20_round20_w52_deduplicated_reader_portfolio_a451"
DESIGN = CONFIGS / f"{STEM}_design_v1.json"
IMPLEMENTATION = CONFIGS / f"{STEM}_implementation_v1.json"
RESULT = RESULTS / f"{STEM}_v1.json"
ARTIFACT = RESULTS / f"{STEM}_pair_stream_uint16be_uint16be_v1.bin"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / f"tests/test_{STEM}.py"
REPRO = ROOT / f"scripts/reproduce_{STEM}.sh"

A449_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_target_blind_proof_antecedent_trace_a449.py"
)
A449_DESIGN = (
    CONFIGS
    / "chacha20_round20_w52_target_blind_proof_antecedent_trace_a449_design_v1.json"
)
A449_IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w52_target_blind_proof_antecedent_trace_a449_implementation_v1.json"
)
A449_RESULT = (
    RESULTS / "chacha20_round20_w52_target_blind_proof_antecedent_trace_a449_v1.json"
)
A449_CAUSAL = A449_RESULT.with_suffix(".causal")
A449_READBACK = RESEARCH / "reports/CAUSAL_CHACHA20_A449_PERSONAL_READER_READBACK_V1.md"

ATTEMPT_ID = "A451"
DESIGN_SHA256 = "600408b0ca67b263503cc2d1bb75593a16b03c50df556af121238e83fcd4b9d9"
A449_RUNNER_SHA256 = "cd19406ba8964aceea1dfe16904f505097fb91aed738cb825c934f89c460e875"
A449_DESIGN_SHA256 = "d5be9782d073626309226063119364cf50444cbf7dea9167d1364d2e921e471c"
A449_IMPLEMENTATION_SHA256 = (
    "a6eb39a38dfea3b23c5622f74b5566599ae586a11d7b99087c78d67b6f75c1f2"
)
A449_RESULT_SHA256 = "f054125c5c363e379ddca661334a57867a0d367a5c57d0caa2bb0f8814b322a7"
A449_CAUSAL_SHA256 = "b96389556b19d4bbd71248087354eba1134ff483cd7ce87683f4a5eeb09871cf"
A449_READBACK_SHA256 = "af35c46f57dffcfad9fa0c82bc2ef6f7931fbfd5a95dbd01e8a01e9bf12a815c"
A449_RESULT_COMMITMENT_SHA256 = (
    "4cfd5edf10a9f4e491e5e4b2d289eca78113d67973069eea60ded00a4b64f2cf"
)

COMPONENTS = (
    "proof_borda_top32",
    "hybrid_proof_top16_equal",
    "proof_best_single",
)
COMPONENT_STREAM_SHA256 = {
    "proof_borda_top32": "b54b08eb03164e6f15ddbb9c1709780c435915b0aa65e65154f92b469192c637",
    "hybrid_proof_top16_equal": "81854f76b94fe4b27e0facbc41550b057ccd4881dd684c687b5a0cb02a73533f",
    "proof_best_single": "c06a0a8c77aecbdf71469ef25aa2ef0abc0db24031196e1201220455b585da47",
}
AXIS_CELLS = 1 << 12
PAIR_CELLS = 1 << 24
COMPONENT_COUNT = len(COMPONENTS)
TOP_KS = (16, 64, 256, 1024, 65536, 1048576)
CHUNK = 1 << 20
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A451 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A449 = load_module(A449_RUNNER, "a451_a449")
file_sha256 = A449.file_sha256
canonical_sha256 = A449.canonical_sha256
atomic_json = A449.atomic_json
atomic_bytes = A449.atomic_bytes
anchor = A449.anchor
path_from_ref = A449.path_from_ref
relative = A449.relative


def array_sha256(value: np.ndarray, dtype: str) -> str:
    digest = hashlib.sha256()
    array = np.asarray(value)
    for start in range(0, array.size, CHUNK):
        digest.update(array[start : start + CHUNK].astype(dtype, copy=False).tobytes())
    return digest.hexdigest()


def load_design() -> dict[str, Any]:
    anchor(DESIGN, DESIGN_SHA256)
    value = json.loads(DESIGN.read_bytes())
    source = value.get("source_contract", {})
    selection = value.get("component_selection_contract", {})
    fusion = value.get("fusion_contract", {})
    evaluation = value.get("evaluation_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-deduplicated-reader-portfolio-a451-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or source.get("attempt") != "A449"
        or source.get("result_sha256") != A449_RESULT_SHA256
        or source.get("result_commitment_sha256")
        != A449_RESULT_COMMITMENT_SHA256
        or source.get("recovery_ready") is not True
        or tuple(selection.get("operators_in_fixed_slot_order", []))
        != COMPONENTS
        or selection.get("component_pair_stream_sha256")
        != [COMPONENT_STREAM_SHA256[name] for name in COMPONENTS]
        or selection.get("target_labels_used_for_component_selection") != 0
        or selection.get("component_refits") != 0
        or fusion.get("algorithm")
        != "deduplicated_fixed_slot_round_robin_min_rank"
        or fusion.get("component_count") != COMPONENT_COUNT
        or fusion.get("complete_pair_cells") != PAIR_CELLS
        or fusion.get("expected_artifact_bytes") != PAIR_CELLS * 4
        or fusion.get("random_access_required_for_recovery") is not True
        or evaluation.get("exact_complete_permutation_gate") is not True
        or evaluation.get("exact_hard_rank_guarantee_over_all_16777216_pairs")
        is not True
        or evaluation.get("candidate_assignments_executed") != 0
        or boundary.get("A450_candidate_progress_or_result_read") is not False
        or boundary.get(
            "A426_A438_A440_A443_secret_result_stop_or_worker_progress_read"
        )
        is not False
        or boundary.get("W52_target_labels_used") != 0
        or boundary.get("feature_refits") != 0
        or boundary.get("model_refits") != 0
        or boundary.get("production_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A451 frozen design semantics differ")
    sources = value["source_anchors"]
    for key, item in sources.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, sources[f"{stem}_sha256"])
    return value


def load_source() -> dict[str, Any]:
    anchor(A449_RUNNER, A449_RUNNER_SHA256)
    anchor(A449_DESIGN, A449_DESIGN_SHA256)
    anchor(A449_IMPLEMENTATION, A449_IMPLEMENTATION_SHA256)
    anchor(A449_RESULT, A449_RESULT_SHA256)
    anchor(A449_CAUSAL, A449_CAUSAL_SHA256)
    anchor(A449_READBACK, A449_READBACK_SHA256)
    value = A449.load_result(A449_RESULT_SHA256)
    if (
        value.get("result_commitment_sha256")
        != A449_RESULT_COMMITMENT_SHA256
        or value.get("recovery_ready") is not True
        or value.get("recovery_operator") != COMPONENTS[0]
        or value.get("primary_operator") != COMPONENTS[1]
        or value.get("W52_target_labels_used") != 0
        or value.get("W52_feature_refits") != 0
        or value.get("W52_model_refits") != 0
        or value.get("production_candidate_assignments_executed") != 0
        or value.get(
            "A426_A438_A440_A443_secret_result_stop_or_worker_progress_read"
        )
        is not False
    ):
        raise RuntimeError("A451 A449 source semantics differ")
    for name in COMPONENTS:
        row = value["operator_schedules"][name]
        if (
            row.get("pair_stream_uint16be_uint16be_sha256")
            != COMPONENT_STREAM_SHA256[name]
            or row.get("A448_calibration", {}).get("positive_fixed_block_count")
            != 8
            or row.get("material_pair_diversity_vs_A442") is not True
        ):
            raise RuntimeError(f"A451 component {name} differs")
    proof_rows = [
        value["operator_schedules"][name]
        for name in A449.PROOF_OPERATORS
    ]
    most_decorrelated = min(
        proof_rows,
        key=lambda row: float(
            row["pair_comparison_to_A442"]["spearman_rank_correlation"]
        ),
    )
    if most_decorrelated.get("operator") != COMPONENTS[2]:
        raise RuntimeError("A451 decorrelated component selection differs")
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists() or any(
        path.exists() for path in (RESULT, ARTIFACT, CAUSAL, REPORT)
    ):
        raise FileExistsError("A451 implementation or downstream artifact exists")
    design = load_design()
    source = load_source()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A451 tests and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-deduplicated-reader-portfolio-a451-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_nonfactorized_three_reader_fusion_frozen_before_any_A450_candidate_progress_or_result",
        "design_sha256": DESIGN_SHA256,
        "source_A449_result_sha256": A449_RESULT_SHA256,
        "source_A449_result_commitment_sha256": source[
            "result_commitment_sha256"
        ],
        "operators_in_fixed_slot_order": list(COMPONENTS),
        "component_pair_stream_sha256": [
            COMPONENT_STREAM_SHA256[name] for name in COMPONENTS
        ],
        "fusion_algorithm": design["fusion_contract"]["algorithm"],
        "complete_pair_cells": PAIR_CELLS,
        "expected_artifact_bytes": PAIR_CELLS * 4,
        "A450_candidate_progress_or_result_read": False,
        "prior_secret_recovery_progress_or_result_read": False,
        "W52_target_labels_used": 0,
        "feature_refits": 0,
        "model_refits": 0,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A449_runner": anchor(A449_RUNNER, A449_RUNNER_SHA256),
            "A449_design": anchor(A449_DESIGN, A449_DESIGN_SHA256),
            "A449_implementation": anchor(
                A449_IMPLEMENTATION, A449_IMPLEMENTATION_SHA256
            ),
            "A449_result": anchor(A449_RESULT, A449_RESULT_SHA256),
            "A449_causal": anchor(A449_CAUSAL, A449_CAUSAL_SHA256),
            "A449_personal_readback": anchor(
                A449_READBACK, A449_READBACK_SHA256
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
        != "chacha20-round20-w52-deduplicated-reader-portfolio-a451-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("source_A449_result_sha256") != A449_RESULT_SHA256
        or value.get("source_A449_result_commitment_sha256")
        != A449_RESULT_COMMITMENT_SHA256
        or tuple(value.get("operators_in_fixed_slot_order", [])) != COMPONENTS
        or value.get("component_pair_stream_sha256")
        != [COMPONENT_STREAM_SHA256[name] for name in COMPONENTS]
        or value.get("complete_pair_cells") != PAIR_CELLS
        or value.get("expected_artifact_bytes") != PAIR_CELLS * 4
        or value.get("A450_candidate_progress_or_result_read") is not False
        or value.get("prior_secret_recovery_progress_or_result_read") is not False
        or value.get("W52_target_labels_used") != 0
        or value.get("feature_refits") != 0
        or value.get("model_refits") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A451 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A451 implementation commitment differs")
    return value


def fuse_rank_vectors(
    rank_vectors: Sequence[np.ndarray],
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    if not rank_vectors:
        raise ValueError("A451 needs at least one rank vector")
    cells = int(rank_vectors[0].size)
    count = len(rank_vectors)
    first_key = np.full(cells, np.iinfo(np.uint32).max, dtype=np.uint32)
    owner = np.full(cells, 255, dtype=np.uint8)
    minimum_rank = np.full(cells, np.iinfo(np.uint32).max, dtype=np.uint32)
    for slot, row in enumerate(rank_vectors):
        rank = np.asarray(row, dtype=np.uint32)
        if rank.shape != (cells,) or int(rank.min()) != 1 or int(rank.max()) != cells:
            raise ValueError("A451 component rank geometry differs")
        candidate = ((rank.astype(np.uint64) - 1) * count + slot).astype(
            np.uint32
        )
        replace = candidate < first_key
        first_key[replace] = candidate[replace]
        owner[replace] = slot
        np.minimum(minimum_rank, rank, out=minimum_rank)
    order = np.argsort(first_key, kind="stable").astype(np.uint32)
    sorted_keys = first_key[order]
    if np.any(sorted_keys[1:] <= sorted_keys[:-1]):
        raise RuntimeError("A451 first-encounter keys are not unique")
    fused_rank = np.empty(cells, dtype=np.uint32)
    fused_rank[order] = np.arange(1, cells + 1, dtype=np.uint32)
    if np.any(fused_rank.astype(np.uint64) > count * minimum_rank.astype(np.uint64)):
        raise RuntimeError("A451 hard rank guarantee failed")
    return order, fused_rank, first_key, owner


def packed_pairs(canonical_ids: np.ndarray) -> np.ndarray:
    ids = np.asarray(canonical_ids, dtype=np.uint32)
    prefix = ids >> 12
    off_axis = ids & (AXIS_CELLS - 1)
    return ((prefix << 16) | off_axis).astype(np.uint32)


def write_pair_artifact(order: np.ndarray) -> dict[str, Any]:
    if order.shape != (PAIR_CELLS,):
        raise ValueError("A451 artifact order geometry differs")
    temporary = ARTIFACT.with_name(f".{ARTIFACT.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    mapped = np.memmap(temporary, dtype=">u4", mode="w+", shape=(PAIR_CELLS,))
    for start in range(0, PAIR_CELLS, CHUNK):
        stop = min(start + CHUNK, PAIR_CELLS)
        mapped[start:stop] = packed_pairs(order[start:stop]).astype(
            ">u4", copy=False
        )
    mapped.flush()
    del mapped
    os.replace(temporary, ARTIFACT)
    return validate_pair_artifact(ARTIFACT)


def validate_pair_artifact(
    path: Path, expected_sha256: str | None = None
) -> dict[str, Any]:
    if path.stat().st_size != PAIR_CELLS * 4:
        raise RuntimeError("A451 pair artifact size differs")
    observed_sha256 = file_sha256(path)
    if expected_sha256 is not None and observed_sha256 != expected_sha256:
        raise RuntimeError("A451 pair artifact hash differs")
    mapped = np.memmap(path, dtype=">u4", mode="r", shape=(PAIR_CELLS,))
    seen = np.zeros(PAIR_CELLS, dtype=np.bool_)
    first_pair: list[int] | None = None
    last_pair: list[int] | None = None
    for start in range(0, PAIR_CELLS, CHUNK):
        stop = min(start + CHUNK, PAIR_CELLS)
        packed = np.asarray(mapped[start:stop], dtype=np.uint32)
        prefix = packed >> 16
        off_axis = packed & 0xFFFF
        if np.any(prefix >= AXIS_CELLS) or np.any(off_axis >= AXIS_CELLS):
            raise RuntimeError("A451 packed pair coordinate differs")
        ids = (prefix << 12) | off_axis
        if np.unique(ids).size != ids.size or np.any(seen[ids]):
            raise RuntimeError("A451 pair artifact contains a duplicate")
        seen[ids] = True
        if first_pair is None:
            first_pair = [int(prefix[0]), int(off_axis[0])]
        last_pair = [int(prefix[-1]), int(off_axis[-1])]
    del mapped
    if not bool(np.all(seen)):
        raise RuntimeError("A451 pair artifact cover is incomplete")
    return {
        "path": relative(path),
        "sha256": observed_sha256,
        "bytes": path.stat().st_size,
        "pair_cells": PAIR_CELLS,
        "encoding": "uint16be_prefix_then_uint16be_off_axis",
        "complete_permutation": True,
        "first_pair": first_pair,
        "last_pair": last_pair,
    }


def compare_ranks(left: np.ndarray, right: np.ndarray) -> dict[str, Any]:
    if left.shape != right.shape or left.shape != (PAIR_CELLS,):
        raise ValueError("A451 rank comparison geometry differs")
    mean = (PAIR_CELLS + 1.0) / 2.0
    variance = (PAIR_CELLS * PAIR_CELLS - 1.0) / 12.0
    covariance_sum = 0.0
    for start in range(0, PAIR_CELLS, CHUNK):
        stop = min(start + CHUNK, PAIR_CELLS)
        a = left[start:stop].astype(np.float64)
        b = right[start:stop].astype(np.float64)
        covariance_sum += float(np.dot(a - mean, b - mean))
    top = {
        str(k): {
            "intersection": int(np.count_nonzero((left <= k) & (right <= k))),
            "overlap_fraction": float(
                np.count_nonzero((left <= k) & (right <= k)) / k
            ),
        }
        for k in TOP_KS
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


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    writer = CausalWriter(api_id="a451mix")
    writer._rules = []
    writer.add_rule(
        name="fixed_slot_first_encounter_implies_bounded_regret",
        description="A three-slot deduplicated first-encounter order is never later than three times the best component rank.",
        pattern=["A451_three_frozen_component_orders"],
        conclusion="A451_exact_threefold_rank_guarantee",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="bounded_complete_permutation_to_recovery_stream",
        description="A complete random-access pair permutation with exact rank bound can directly replace a factorized pair schedule.",
        pattern=["A451_exact_threefold_rank_guarantee"],
        conclusion="A451_nonfactorized_W52_recovery_stream_ready",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A449:three_complementary_proof_operators",
        mechanism="fixed_slot_round_robin_first_encounter_deduplication",
        outcome="A451:complete_nonfactorized_pair_permutation",
        confidence=1.0,
        source=payload["fusion_sha256"],
        quantification=json.dumps(payload["component_contract"], sort_keys=True),
        evidence=json.dumps(payload["artifact"], sort_keys=True),
        domain="full-round ChaCha20 W52 pair scheduling",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A451:complete_nonfactorized_pair_permutation",
        mechanism="exact_all_pair_rank_inequality",
        outcome="A451:exact_threefold_rank_guarantee",
        confidence=1.0,
        source=payload["guarantee_sha256"],
        quantification=json.dumps(payload["hard_rank_guarantee"], sort_keys=True),
        evidence=json.dumps(payload["union_cover"], sort_keys=True),
        domain="bounded-regret multi-reader fusion",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A451:exact_threefold_rank_guarantee",
        mechanism="memory_mapped_uint16be_pair_readout",
        outcome="A451:nonfactorized_W52_recovery_stream_ready",
        confidence=1.0,
        source=payload["artifact"]["sha256"],
        quantification=json.dumps(payload["geometry"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="restart-safe commodity-hardware recovery execution",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A449:three_complementary_proof_operators",
        mechanism="materialized_bounded_regret_fusion_closure",
        outcome="A451:exact_threefold_rank_guarantee",
        confidence=1.0,
        source="materialized:A451_reader_portfolio_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_triplet(
        trigger="A451:complete_nonfactorized_pair_permutation",
        mechanism="materialized_recovery_readiness_closure",
        outcome="A451:nonfactorized_W52_recovery_stream_ready",
        confidence=1.0,
        source="materialized:A451_recovery_ready_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A451 bounded-regret W52 reader portfolio",
        entities=[
            "A449:three_complementary_proof_operators",
            "A451:complete_nonfactorized_pair_permutation",
            "A451:exact_threefold_rank_guarantee",
            "A451:nonfactorized_W52_recovery_stream_ready",
        ],
    )
    writer.add_gap(
        subject="A451:nonfactorized_W52_recovery_stream_ready",
        predicate="next_required_object",
        expected_object_type="qualified_W52_nonfactorized_portfolio_recovery_execution",
        confidence=1.0,
        suggested_queries=[
            "Bind the A451 memory-mapped stream to the existing A434-qualified complete-cell engine without reading any prior target outcome."
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
        reader.api_id != "a451mix"
        or len(explicit) != 3
        or len(all_rows) != 5
        or len(inferred) != 2
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A451 authentic Causal reopen gate failed")
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
            "fusion": explicit[0],
            "guarantee": explicit[1],
            "recovery_readiness": explicit[2],
            "inferred_closure": inferred,
            "next_gap": reader._gaps[0],
        },
    }


def _build_result_once(*, expected_implementation_sha256: str) -> dict[str, Any]:
    load_design()
    implementation = load_implementation(expected_implementation_sha256)
    source = load_source()
    component_ranks: list[np.ndarray] = []
    component_contract: dict[str, Any] = {}
    for name in COMPONENTS:
        schedule = source["operator_schedules"][name]
        ranks = A449.A442.reference_square_rank_vector(
            schedule["prefix_order"], schedule["off_axis_order"]
        )
        component_ranks.append(ranks)
        component_contract[name] = {
            "slot": COMPONENTS.index(name),
            "pair_stream_sha256": COMPONENT_STREAM_SHA256[name],
            "prefix_order_sha256": schedule[
                "prefix_order_uint16be_sha256"
            ],
            "off_axis_order_sha256": schedule[
                "off_axis_order_uint16be_sha256"
            ],
            "A448_calibration": schedule["A448_calibration"],
            "pair_spearman_to_A442": schedule["pair_comparison_to_A442"][
                "spearman_rank_correlation"
            ],
        }
    order, fused_rank, first_key, owner = fuse_rank_vectors(component_ranks)
    artifact = write_pair_artifact(order)
    minimum_rank = np.minimum.reduce(component_ranks)
    ratio = fused_rank.astype(np.float64) / minimum_rank.astype(np.float64)
    slack = COMPONENT_COUNT * minimum_rank.astype(np.int64) - fused_rank.astype(
        np.int64
    )
    hard_rank_guarantee = {
        "formula": "fused_rank_one_based <= 3 * minimum_component_rank_one_based",
        "cells_checked": PAIR_CELLS,
        "violations": int(np.count_nonzero(slack < 0)),
        "minimum_slack_cells": int(slack.min()),
        "maximum_observed_rank_ratio": float(ratio.max()),
        "p99_observed_rank_ratio": float(np.quantile(ratio, 0.99)),
        "median_observed_rank_ratio": float(np.median(ratio)),
        "guarantee_satisfied": bool(np.all(slack >= 0)),
    }
    if not hard_rank_guarantee["guarantee_satisfied"]:
        raise RuntimeError("A451 complete hard-rank gate failed")
    geometry: dict[str, Any] = {
        "comparisons": {
            name: compare_ranks(fused_rank, ranks)
            for name, ranks in zip(COMPONENTS, component_ranks, strict=True)
        },
        "first_encounter_owner_counts": {
            name: int(np.count_nonzero(owner == slot))
            for slot, name in enumerate(COMPONENTS)
        },
        "first_encounter_owner_top_k": {
            str(k): {
                name: int(np.count_nonzero(owner[order[:k]] == slot))
                for slot, name in enumerate(COMPONENTS)
            }
            for k in TOP_KS
        },
    }
    baseline = source["operator_schedules"]["borda_sum_baseline"]
    baseline_rank = A449.A442.reference_square_rank_vector(
        baseline["prefix_order"], baseline["off_axis_order"]
    )
    geometry["comparison_to_A442_borda_sum_baseline"] = compare_ranks(
        fused_rank, baseline_rank
    )
    cover = union_cover(fused_rank, component_ranks)
    if not all(row["bound_satisfied"] for row in cover.values()):
        raise RuntimeError("A451 component-union cover gate failed")
    core: dict[str, Any] = {
        "schema": "chacha20-round20-w52-deduplicated-reader-portfolio-a451-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "TARGET_BLIND_NONFACTORIZED_W52_BOUNDED_REGRET_RECOVERY_STREAM_READY",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "component_contract": component_contract,
        "fusion_algorithm": "deduplicated_fixed_slot_round_robin_min_rank",
        "artifact": artifact,
        "hard_rank_guarantee": hard_rank_guarantee,
        "union_cover": cover,
        "geometry": geometry,
        "fused_first_encounter_key_uint32be_sha256": array_sha256(
            first_key, ">u4"
        ),
        "fused_canonical_pair_order_uint32be_sha256": array_sha256(order, ">u4"),
        "fused_rank_vector_uint32be_sha256": array_sha256(fused_rank, ">u4"),
        "A450_candidate_progress_or_result_read": False,
        "A426_A438_A440_A443_secret_result_stop_or_worker_progress_read": False,
        "W52_target_labels_used": 0,
        "feature_refits": 0,
        "model_refits": 0,
        "production_candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(
                IMPLEMENTATION, expected_implementation_sha256
            ),
            "A449_runner": anchor(A449_RUNNER, A449_RUNNER_SHA256),
            "A449_result": anchor(A449_RESULT, A449_RESULT_SHA256),
            "A449_causal": anchor(A449_CAUSAL, A449_CAUSAL_SHA256),
            "A449_personal_readback": anchor(
                A449_READBACK, A449_READBACK_SHA256
            ),
            "pair_stream_artifact": anchor(ARTIFACT, artifact["sha256"]),
            "runner": anchor(Path(__file__)),
        },
    }
    core["fusion_sha256"] = canonical_sha256(
        {
            "component_contract": component_contract,
            "fusion_algorithm": core["fusion_algorithm"],
            "first_encounter_key_sha256": core[
                "fused_first_encounter_key_uint32be_sha256"
            ],
            "canonical_pair_order_sha256": core[
                "fused_canonical_pair_order_uint32be_sha256"
            ],
            "artifact_sha256": artifact["sha256"],
        }
    )
    core["guarantee_sha256"] = canonical_sha256(
        {
            "hard_rank_guarantee": hard_rank_guarantee,
            "union_cover": cover,
        }
    )
    core["geometry_sha256"] = canonical_sha256(geometry)
    core["result_commitment_sha256"] = canonical_sha256(
        {
            "implementation_commitment_sha256": core[
                "implementation_commitment_sha256"
            ],
            "fusion_sha256": core["fusion_sha256"],
            "guarantee_sha256": core["guarantee_sha256"],
            "geometry_sha256": core["geometry_sha256"],
        }
    )
    core["causal"] = build_causal(core)
    atomic_json(RESULT, core)
    atomic_bytes(
        REPORT,
        (
            "# A451 — deduplicated non-factorized W52 reader portfolio\n\n"
            "Evidence stage: **TARGET_BLIND_NONFACTORIZED_W52_BOUNDED_REGRET_RECOVERY_STREAM_READY**\n\n"
            f"- Complete pair permutation: **{PAIR_CELLS:,} cells / {artifact['bytes']:,} bytes**\n"
            f"- Pair-stream SHA-256: `{artifact['sha256']}`\n"
            f"- Components: **{', '.join(COMPONENTS)}**\n"
            "- Exact all-cell guarantee: **fused rank <= 3 x best component rank**\n"
            f"- Maximum observed ratio: **{hard_rank_guarantee['maximum_observed_rank_ratio']:.9f}**\n"
            f"- A442 Spearman: **{geometry['comparison_to_A442_borda_sum_baseline']['spearman_rank_correlation']:.9f}**\n"
            f"- A442 top-65,536 overlap: **{geometry['comparison_to_A442_borda_sum_baseline']['top_k_overlap']['65536']['overlap_fraction']:.9f}**\n"
            "- Target labels / feature refits / model refits / candidate executions: **0 / 0 / 0 / 0**\n"
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
        != "chacha20-round20-w52-deduplicated-reader-portfolio-a451-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("fusion_algorithm")
        != "deduplicated_fixed_slot_round_robin_min_rank"
        or set(value.get("component_contract", {})) != set(COMPONENTS)
        or len(value.get("component_contract", {})) != len(COMPONENTS)
        or value.get("hard_rank_guarantee", {}).get("guarantee_satisfied")
        is not True
        or value.get("artifact", {}).get("complete_permutation") is not True
        or value.get("A450_candidate_progress_or_result_read") is not False
        or value.get(
            "A426_A438_A440_A443_secret_result_stop_or_worker_progress_read"
        )
        is not False
        or value.get("W52_target_labels_used") != 0
        or value.get("feature_refits") != 0
        or value.get("model_refits") != 0
        or value.get("production_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A451 result semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    validate_pair_artifact(ARTIFACT, value["artifact"]["sha256"])
    return value


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": file_sha256(DESIGN) if DESIGN.exists() else None,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "result_complete": RESULT.exists(),
        "artifact_present": ARTIFACT.exists(),
        "pair_cells": PAIR_CELLS,
        "components": list(COMPONENTS),
    }
    load_design()
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if RESULT.exists():
        payload["result_sha256"] = file_sha256(RESULT)
        value = load_result(payload["result_sha256"])
        payload["evidence_stage"] = value["evidence_stage"]
        payload["artifact_sha256"] = value["artifact"]["sha256"]
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
