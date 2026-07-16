#!/usr/bin/env python3
"""A392: derive exact no-duplicate parallel lanes from complementary W50 orders."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import math
import os
import statistics
import struct
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = (
    CONFIGS
    / "chacha20_round20_w50_disjoint_parallel_reader_scheduler_a392_design_v1.json"
)
IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w50_disjoint_parallel_reader_scheduler_a392_implementation_v1.json"
)
RESULT = RESULTS / "chacha20_round20_w50_disjoint_parallel_reader_scheduler_a392_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_disjoint_parallel_reader_scheduler_a392.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_disjoint_parallel_reader_scheduler_a392.sh"

A388_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w50_public_output_direct12_factor3_a388.py"
)
A388_ORDER = (
    RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_order_v1.json"
)
A388_CAUSAL = A388_ORDER.with_suffix(".causal")
A391_PROTOCOL = CONFIGS / "chacha20_round20_w50_direct12_only_recovery_a391_v1.json"

ATTEMPT_ID = "A392"
DESIGN_SHA256 = "17c80a59ccd5b8735d6f9c47c6918323c922d122cb65ab7b257cc4826d26aa9b"
A388_RUNNER_SHA256 = "36c933ae5003f92f2b96efb2e30d97c30bf8301bfcaa790333a6712f3041b5a9"
A388_ORDER_SHA256 = "3c56ce8521b1ced20e1e3a90999810c2e563c4de941701c86274f0828b5d01b8"
A388_CAUSAL_SHA256 = "095e4a05b86df98b27899c3055d4ff4c5ea2eab5ffa5961cfb36747320090e3a"
A391_PROTOCOL_SHA256 = "90a1669aafcaaea3f5a2a125587262af1c0f2d850e686536d4db1c7ef2e1c8ed"
CELLS = 4096
ROLE_A385 = "A385_pretarget_six_view"
ROLE_DIRECT = "A388_W50_public_output_direct12"
ROLE_A386 = "A386_calibrated_target_blind_transfer"
TWO_ROLES = (ROLE_A385, ROLE_DIRECT)
THREE_ROLES = (ROLE_A385, ROLE_DIRECT, ROLE_A386)
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A392 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A388 = load_module(A388_RUNNER, "a392_a388")
file_sha256 = A388.file_sha256
canonical_sha256 = A388.canonical_sha256
atomic_json = A388.atomic_json
atomic_bytes = A388.atomic_bytes
relative = A388.relative
path_from_ref = A388.path_from_ref
anchor = A388.anchor


def exact_order(values: Sequence[int], *, size: int, label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != size or set(order) != set(range(size)):
        raise ValueError(f"A392 {label} is not an exact {size:,}-cell order")
    return order


def rank_vector(values: Sequence[int], *, size: int) -> list[int]:
    ranks = [0] * size
    for rank, cell in enumerate(exact_order(values, size=size, label="rank vector"), 1):
        ranks[cell] = rank
    return ranks


def uint16be_sha256(values: Sequence[int]) -> str:
    payload = b"".join(struct.pack(">H", int(value)) for value in values)
    return hashlib.sha256(payload).hexdigest()


def stable_wavefront(
    source_orders: Mapping[str, Sequence[int]],
    role_order: Sequence[str],
    *,
    size: int,
) -> list[int]:
    roles = tuple(str(role) for role in role_order)
    if not roles or set(roles) != set(source_orders) or len(roles) != len(set(roles)):
        raise ValueError("A392 wavefront role contract differs")
    ranks = {role: rank_vector(source_orders[role], size=size) for role in roles}
    return exact_order(
        sorted(
            range(size),
            key=lambda cell: (
                min(ranks[role][cell] for role in roles),
                sum(ranks[role][cell] for role in roles),
                *(ranks[role][cell] for role in roles),
                cell,
            ),
        ),
        size=size,
        label="stable wavefront",
    )


def quantiles(values: Sequence[float]) -> dict[str, float]:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        raise ValueError("A392 quantiles require values")

    def pick(q: float) -> float:
        return ordered[round(q * (len(ordered) - 1))]

    return {
        "minimum": ordered[0],
        "p25": pick(0.25),
        "median": pick(0.5),
        "p75": pick(0.75),
        "p90": pick(0.9),
        "p99": pick(0.99),
        "maximum": ordered[-1],
    }


def disjoint_parallel_schedule(
    source_orders: Mapping[str, Sequence[int]],
    role_order: Sequence[str],
    *,
    size: int,
) -> dict[str, Any]:
    roles = tuple(str(role) for role in role_order)
    if not roles or set(roles) != set(source_orders) or len(roles) != len(set(roles)):
        raise ValueError("A392 scheduler role contract differs")
    ranks = {role: rank_vector(source_orders[role], size=size) for role in roles}
    role_index = {role: index for index, role in enumerate(roles)}
    owners = [
        min(roles, key=lambda role: (ranks[role][cell], role_index[role]))
        for cell in range(size)
    ]
    lanes = {
        role: sorted(
            (cell for cell in range(size) if owners[cell] == role),
            key=lambda cell: (ranks[role][cell], cell),
        )
        for role in roles
    }
    flattened = [cell for role in roles for cell in lanes[role]]
    if len(flattened) != size or set(flattened) != set(range(size)):
        raise RuntimeError("A392 disjoint lanes do not form one complete cover")
    lane_positions = {
        role: {cell: index for index, cell in enumerate(lanes[role], 1)}
        for role in roles
    }
    serial = stable_wavefront(source_orders, roles, size=size)
    serial_ranks = rank_vector(serial, size=size)
    best_ranks: list[int] = []
    wall_depths: list[int] = []
    unique_work: list[int] = []
    serial_positions: list[int] = []
    wall_ratios: list[float] = []
    work_ratios: list[float] = []
    serial_speedups: list[float] = []
    per_cell: list[dict[str, Any]] = []
    for cell in range(size):
        owner = owners[cell]
        best = min(ranks[role][cell] for role in roles)
        depth = lane_positions[owner][cell]
        work = sum(min(depth, len(lanes[role])) for role in roles)
        serial_rank = serial_ranks[cell]
        if depth > best:
            raise RuntimeError("A392 wall-depth theorem violated")
        if work > len(roles) * best:
            raise RuntimeError("A392 total-work theorem violated")
        if serial_rank < depth:
            raise RuntimeError("A392 serial wavefront precedes owner-lane depth")
        best_ranks.append(best)
        wall_depths.append(depth)
        unique_work.append(work)
        serial_positions.append(serial_rank)
        wall_ratios.append(depth / best)
        work_ratios.append(work / (len(roles) * best))
        serial_speedups.append(serial_rank / depth)
        per_cell.append(
            {
                "cell": cell,
                "owner": owner,
                "best_source_rank_one_based": best,
                "owner_lane_depth_one_based": depth,
                "unique_prefix_groups_processed_at_discovery": work,
                "serial_wavefront_rank_one_based": serial_rank,
            }
        )
    return {
        "role_order": list(roles),
        "lane_count": len(roles),
        "cells": size,
        "ownership_rule": "minimum source rank then frozen role order",
        "lane_rule": "owner source rank then cell index",
        "partition_sizes": {role: len(lanes[role]) for role in roles},
        "owner_counts": {role: owners.count(role) for role in roles},
        "lane_orders": lanes,
        "lane_order_uint16be_sha256": {
            role: uint16be_sha256(lanes[role]) for role in roles
        },
        "owner_vector_sha256": hashlib.sha256(
            bytes(role_index[owner] for owner in owners)
        ).hexdigest(),
        "serial_wavefront_order": serial,
        "serial_wavefront_order_uint16be_sha256": uint16be_sha256(serial),
        "proof": {
            "complete_cover_cells": len(flattened),
            "duplicate_cells": len(flattened) - len(set(flattened)),
            "uncovered_cells": size - len(set(flattened)),
            "wall_depth_bound": "D_parallel(c) <= min_i R_i(c)",
            "wall_depth_violations": 0,
            "maximum_wall_depth_to_best_source_ratio": max(wall_ratios),
            "total_unique_work_bound": f"W_parallel(c) <= {len(roles)}*min_i R_i(c)",
            "total_unique_work_violations": 0,
            "maximum_total_work_to_bound_ratio": max(work_ratios),
            "serial_wavefront_not_earlier_than_parallel_depth_violations": 0,
        },
        "uniform_cell_geometry": {
            "mean_best_source_rank": statistics.fmean(best_ranks),
            "mean_parallel_wall_depth": statistics.fmean(wall_depths),
            "mean_unique_prefix_groups_at_discovery": statistics.fmean(unique_work),
            "mean_serial_wavefront_rank": statistics.fmean(serial_positions),
            "geometric_mean_serial_to_parallel_wall_speedup": math.exp(
                statistics.fmean(math.log(value) for value in serial_speedups)
            ),
            "cells_strictly_faster_in_parallel_than_serial": sum(
                serial > depth
                for serial, depth in zip(serial_positions, wall_depths, strict=True)
            ),
            "parallel_wall_depth_quantiles": quantiles(wall_depths),
            "serial_to_parallel_wall_speedup_quantiles": quantiles(serial_speedups),
        },
        "per_cell_proof": per_cell,
    }


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A392 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    scheduler = value.get("scheduler_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-disjoint-parallel-reader-scheduler-a392-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A388_source_orders_before_any_A392_scheduler_artifact_or_candidate_execution"
        or scheduler.get("cells") != CELLS
        or tuple(scheduler.get("two_lane_roles", [])) != TWO_ROLES
        or tuple(scheduler.get("three_lane_roles", [])) != THREE_ROLES
        or scheduler.get("zero_duplicate_prefixes") is not True
        or scheduler.get("complete_cover") is not True
        or boundary.get("target_labels_used") != 0
        or boundary.get("reader_refits") != 0
        or boundary.get("candidate_assignments_executed") != 0
        or boundary.get(
            "A387_A389_A391_progress_or_filter_outcomes_consumed_by_scheduler"
        )
        is not False
    ):
        raise RuntimeError("A392 frozen design semantics differ")
    for name, source_path in value["source_anchors"].items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / source_path, value["source_anchors"][f"{stem}_sha256"])
    return value


def load_source_orders() -> dict[str, list[int]]:
    anchor(A388_ORDER, A388_ORDER_SHA256)
    anchor(A388_CAUSAL, A388_CAUSAL_SHA256)
    value = json.loads(A388_ORDER.read_bytes())
    raw = value.get("source_orders", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-public-output-direct12-factor3-a388-order-v1"
        or set(raw) != set(THREE_ROLES)
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
        or value.get("A387_progress_or_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A392 A388 source semantics differ")
    return {
        role: exact_order(raw[role], size=CELLS, label=role) for role in THREE_ROLES
    }


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A392 implementation or result already exists")
    design = load_design()
    source_orders = load_source_orders()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A392 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-disjoint-parallel-reader-scheduler-a392-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A392_scheduler_materialization_or_candidate_execution",
        "design_sha256": DESIGN_SHA256,
        "scheduler_contract": design["scheduler_contract"],
        "source_order_uint16be_sha256": {
            role: uint16be_sha256(source_orders[role]) for role in THREE_ROLES
        },
        "A392_candidate_assignments_available_at_freeze": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A388_runner": anchor(A388_RUNNER, A388_RUNNER_SHA256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "A388_causal": anchor(A388_CAUSAL, A388_CAUSAL_SHA256),
            "A391_protocol": anchor(A391_PROTOCOL, A391_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A392 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-disjoint-parallel-reader-scheduler-a392-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A392_candidate_assignments_available_at_freeze") != 0
    ):
        raise RuntimeError("A392 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A392 implementation commitment differs")
    return value


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    scheduler = "A392:disjoint_parallel_reader_scheduler"
    theorem = "A392:best_reader_wall_depth_zero_duplicate_cover"
    ready = "A393:parallel_or_residual_W50_executor_ready"
    writer = CausalWriter(api_id="a392w50")
    writer._rules = []
    writer.add_rule(
        name="diverse_orders_to_disjoint_owner_partition",
        description="Minimum source-rank ownership converts complete diverse orders into pairwise disjoint lanes covering every prefix exactly once.",
        pattern=["A388_complete_complementary_W50_orders"],
        conclusion="A392_disjoint_parallel_reader_scheduler",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="owner_partition_to_exact_parallel_bounds",
        description="Owner-local rank never exceeds owner source rank; k lanes therefore preserve best-reader wall depth and use at most k times the best-reader unique work.",
        pattern=["A392_disjoint_parallel_reader_scheduler"],
        conclusion="A392_best_reader_wall_depth_zero_duplicate_cover",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="parallel_bounds_to_executor",
        description="The frozen lane lists are ready for independent complete-group executors with a shared success stop.",
        pattern=["A392_best_reader_wall_depth_zero_duplicate_cover"],
        conclusion="A393_parallel_or_residual_W50_executor_ready",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A388:complete_complementary_W50_orders",
        mechanism="minimum_rank_Voronoi_ownership_with_frozen_ties",
        outcome=scheduler,
        confidence=1.0,
        source=payload["schedule_commitment_sha256"],
        quantification=json.dumps(
            {
                name: value["partition_sizes"]
                for name, value in payload["schedules"].items()
            },
            sort_keys=True,
        ),
        evidence="all 4096 prefixes assigned exactly once in both two-lane and three-lane schedules",
        domain="target-blind full-round ChaCha20 W50 parallel scheduling",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=scheduler,
        mechanism="exact_owner_local_rank_and_unique_work_proof",
        outcome=theorem,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(
            {
                name: value["proof"] for name, value in payload["schedules"].items()
            },
            sort_keys=True,
        ),
        evidence="zero wall-depth violations, zero total-work violations, zero duplicate or uncovered prefixes",
        domain="exact multi-operator scheduler theorem",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A388:complete_complementary_W50_orders",
        mechanism="materialized_disjoint_scheduler_and_bound_chain",
        outcome=ready,
        confidence=1.0,
        source="materialized:A392_parallel_scheduler_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A392 disjoint parallel W50 scheduler",
        entities=["A388:complete_complementary_W50_orders", scheduler, theorem, ready],
    )
    writer.add_gap(
        subject=ready,
        predicate="next_required_object",
        expected_object_type="complete_group_parallel_execution_with_shared_stop",
        confidence=1.0,
        suggested_queries=[
            "Execute the disjoint owner lanes with complete W50 groups and one shared independently confirmed success stop."
        ],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a392w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A392 authentic Causal reopen gate failed")
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
            "scheduler_relation": explicit[0],
            "proof_relation": explicit[1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def materialize(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A392 result artifact already exists")
    implementation = load_implementation(expected_implementation_sha256)
    source_orders = load_source_orders()
    two_sources = {role: source_orders[role] for role in TWO_ROLES}
    three_sources = {role: source_orders[role] for role in THREE_ROLES}
    schedules = {
        "two_lane_A385_Direct12": disjoint_parallel_schedule(
            two_sources, TWO_ROLES, size=CELLS
        ),
        "three_lane_A385_Direct12_A386": disjoint_parallel_schedule(
            three_sources, THREE_ROLES, size=CELLS
        ),
    }
    essential = {
        name: {
            "role_order": value["role_order"],
            "partition_sizes": value["partition_sizes"],
            "lane_order_uint16be_sha256": value["lane_order_uint16be_sha256"],
            "owner_vector_sha256": value["owner_vector_sha256"],
            "proof": value["proof"],
        }
        for name, value in schedules.items()
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-disjoint-parallel-reader-scheduler-a392-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "EXACT_TARGET_BLIND_DISJOINT_PARALLEL_BEST_READER_DEPTH_SCHEDULER_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "A388_order_sha256": A388_ORDER_SHA256,
        "source_order_uint16be_sha256": {
            role: uint16be_sha256(source_orders[role]) for role in THREE_ROLES
        },
        "schedules": schedules,
        "candidate_assignments_executed": 0,
        "target_labels_used": 0,
        "reader_refits": 0,
        "progress_or_filter_outcomes_consumed": 0,
        "anchors": implementation["anchors"],
    }
    payload["schedule_commitment_sha256"] = canonical_sha256(essential)
    payload["measurement_sha256"] = canonical_sha256(
        {
            "schedule_commitment_sha256": payload["schedule_commitment_sha256"],
            "uniform_cell_geometry": {
                name: value["uniform_cell_geometry"]
                for name, value in schedules.items()
            },
            "candidate_assignments_executed": 0,
            "target_labels_used": 0,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    two = schedules["two_lane_A385_Direct12"]
    three = schedules["three_lane_A385_Direct12_A386"]
    atomic_bytes(
        REPORT,
        (
            "# A392 — exact disjoint parallel Reader scheduler\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Two-lane partition: **{two['partition_sizes']}**\n"
            f"- Three-lane partition: **{three['partition_sizes']}**\n"
            "- Duplicate / uncovered prefixes: **0 / 0**\n"
            "- Exact wall-depth theorem: **D_parallel(c) <= min_i R_i(c)**\n"
            "- Exact total-work theorem: **W_parallel(c) <= k min_i R_i(c)**\n"
            f"- Two-lane geometric wall speedup over serial merge: **{two['uniform_cell_geometry']['geometric_mean_serial_to_parallel_wall_speedup']:.9f}x**\n"
            f"- Three-lane geometric wall speedup over serial merge: **{three['uniform_cell_geometry']['geometric_mean_serial_to_parallel_wall_speedup']:.9f}x**\n"
            "- Candidate assignments / target labels / refits: **0 / 0 / 0**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["evidence_stage"] = value["evidence_stage"]
        payload["schedule_commitment_sha256"] = value[
            "schedule_commitment_sha256"
        ]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--materialize", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.materialize:
        if not args.expected_implementation_sha256:
            parser.error("--materialize requires --expected-implementation-sha256")
        payload = materialize(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
