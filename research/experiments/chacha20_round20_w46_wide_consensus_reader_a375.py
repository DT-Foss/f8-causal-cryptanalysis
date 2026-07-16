#!/usr/bin/env python3
"""A375: replace sparse A366 selection with a wide cross-corpus consensus Reader."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import math
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

DESIGN = CONFIGS / "chacha20_round20_w46_wide_consensus_reader_a375_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w46_wide_consensus_reader_a375_implementation_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_wide_consensus_reader_a375_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w46_wide_consensus_reader_a375.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_wide_consensus_reader_a375.sh"

A366_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_cross_corpus_invariant_reader_a366.py"
A367_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_cross_corpus_invariant_validation_a367.py"
A366_RESULT = RESULTS / "chacha20_round20_w46_cross_corpus_invariant_reader_a366_v1.json"
A367_PREPARED = RESULTS / "chacha20_round20_w46_cross_corpus_invariant_validation_a367_prepared_v1.json"
A367_RESULT = RESULTS / "chacha20_round20_w46_cross_corpus_invariant_validation_a367_v1.json"
A361_MEASUREMENT = RESULTS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_measurement_v1.json"
A368_ORDER = RESULTS / "chacha20_round20_w46_a367_reader_portfolio_sealed_a361_order_a368_v1.json"
A369_RESULT = RESULTS / "chacha20_round20_w46_a368_order_recovery_a369_v1.json"

ATTEMPT_ID = "A375"
DESIGN_SHA256 = "9781f36182718556fb1e7ef5045eb3ce5db58dd9d079fc9bc5811ae92d73318a"
A366_RUNNER_SHA256 = "c3ea91a0e5dd651a7196e6c576c889cdbdc0b420410d2fff4aaa5f6823ef310d"
A367_RUNNER_SHA256 = "23537586ed7563396e346e5428b9f96f1970d28ed1a9f102e0ec5a22ee8d5087"
A366_RESULT_SHA256 = "0a961b742c721e9ad0b09803224422c9bb03fc272695ed90b62752f24dc169c8"
A367_PREPARED_SHA256 = "26c5870671f5ca2aedddb50b4f924531b06e37a9083e1588d2cbd0128f1abf6a"
A367_RESULT_SHA256 = "bb60cb96295b7ba06d46f20ff1537287b1059e990162d3ee3dedfd8909aee568"
A361_MEASUREMENT_SHA256 = "a074afc4da9ab4476acf1f09dd752fdc9937486f4a458d8594ef7815046c89dc"

TARGETS = 128
CORPUS_TARGETS = 64
BLOCK_SIZE = 16
BLOCKS = TARGETS // BLOCK_SIZE
CELLS = 256
FEATURES = 532
MODEL_ROLES = ("wide_vote", "sparse_reciprocal", "broad_quantile", "broad_intersection")
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A375 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A367 = load_module(A367_RUNNER, "a375_a367")
A366 = A367.A366
A360 = A367.A360
A275 = A367.A275

file_sha256 = A367.file_sha256
canonical_sha256 = A367.canonical_sha256
atomic_json = A367.atomic_json
atomic_bytes = A367.atomic_bytes
relative = A367.relative
path_from_ref = A367.path_from_ref
anchor = A367.anchor


def _uniform_mean_log2_rank() -> float:
    return sum(math.log2(rank) for rank in range(1, CELLS + 1)) / CELLS


def assert_a361_still_sealed() -> None:
    if A368_ORDER.exists() or A369_RESULT.exists():
        raise RuntimeError("A375 must precede every A361 order and recovery result")


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A375 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    calibration = value.get("calibration_contract", {})
    boundary = value.get("information_boundary", {})
    models = value.get("reader_contract", {}).get("models", {})
    if (
        value.get("schema") != "chacha20-round20-w46-wide-consensus-reader-a375-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_complete_A367_rank_panel_before_any_A361_measurement_shard_read"
        or calibration.get("targets") != TARGETS
        or calibration.get("fixed_blocks") != BLOCKS
        or calibration.get("feature_universe") != FEATURES
        or tuple(models) != ("broad_intersection", "broad_quantile", "sparse_reciprocal", "wide_vote")
        or boundary.get("A367_complete_rank_panel_available") is not True
        or boundary.get("A361_compressed_measurement_shard_content_opened_at_design_freeze") is not False
        or boundary.get("A361_secret_or_true_prefix_available_to_A375") is not False
        or boundary.get("A375_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A375 frozen design semantics differ")
    for name, path_value in value["source_anchors"].items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, value["source_anchors"][f"{stem}_sha256"])
    assert_a361_still_sealed()
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A375 implementation already exists")
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise RuntimeError("A375 implementation must precede formal selection")
    design = load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A375 test and reproducer must exist before freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-wide-consensus-reader-a375-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_formal_A375_selection_A361_shard_read_order_candidate_or_prefix",
        "design_sha256": DESIGN_SHA256,
        "model_specs": design["reader_contract"]["models"],
        "A361_compressed_measurement_shard_content_opened_at_implementation_freeze": False,
        "A361_secret_or_true_prefix_available_at_implementation_freeze": False,
        "candidate_assignments_executed_at_implementation_freeze": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A366_runner": anchor(A366_RUNNER, A366_RUNNER_SHA256),
            "A367_runner": anchor(A367_RUNNER, A367_RUNNER_SHA256),
            "A366_result": anchor(A366_RESULT, A366_RESULT_SHA256),
            "A367_prepared": anchor(A367_PREPARED, A367_PREPARED_SHA256),
            "A367_result": anchor(A367_RESULT, A367_RESULT_SHA256),
            "A361_measurement_metadata": anchor(A361_MEASUREMENT, A361_MEASUREMENT_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    assert_a361_still_sealed()
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A375 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w46-wide-consensus-reader-a375-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_before_formal_A375_selection_A361_shard_read_order_candidate_or_prefix"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A361_compressed_measurement_shard_content_opened_at_implementation_freeze") is not False
        or value.get("A361_secret_or_true_prefix_available_at_implementation_freeze") is not False
        or value.get("candidate_assignments_executed_at_implementation_freeze") != 0
    ):
        raise RuntimeError("A375 frozen implementation semantics differ")
    expected = {
        "design": DESIGN,
        "A366_runner": A366_RUNNER,
        "A367_runner": A367_RUNNER,
        "A366_result": A366_RESULT,
        "A367_prepared": A367_PREPARED,
        "A367_result": A367_RESULT,
        "A361_measurement_metadata": A361_MEASUREMENT,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }
    for name, path in expected.items():
        row = value["anchors"][name]
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A375 implementation anchor differs: {name}")
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A375 implementation commitment differs")
    return value


def load_panel() -> tuple[np.ndarray, np.ndarray, list[str]]:
    anchor(A367_RESULT, A367_RESULT_SHA256)
    anchor(A367_PREPARED, A367_PREPARED_SHA256)
    old_matrices, old_truths, old_blocks = A366._load_calibration_panel()  # noqa: SLF001
    result = json.loads(A367_RESULT.read_bytes())
    labels = sorted(result["postclosure_labels"], key=lambda row: int(row["index"]))
    ledgers = sorted(result["measurement_ledger"], key=lambda row: int(row["index"]))
    if (
        result.get("attempt_id") != "A367"
        or result.get("prepared_sha256") != A367_PREPARED_SHA256
        or len(labels) != CORPUS_TARGETS
        or len(ledgers) != CORPUS_TARGETS
        or any(row.get("label_revealed_after_complete_target_cover") is not True for row in labels)
    ):
        raise RuntimeError("A375 A367 postclosure panel differs")
    new_matrices: list[np.ndarray] = []
    new_truths: list[int] = []
    for label, ledger in zip(labels, ledgers, strict=True):
        if int(label["index"]) != int(ledger["index"]):
            raise RuntimeError("A375 A367 label/measurement alignment differs")
        measurement = A367.BASE._read_measurement(  # noqa: SLF001
            path_from_ref(ledger["path"]),
            expected_prepared_sha256=A367_PREPARED_SHA256,
            ledger=ledger,
        )
        new_matrices.append(A360.target_normalize(A275._target_feature_matrix(measurement)))  # noqa: SLF001
        new_truths.append(int(label["true_high8"]))
    matrices = np.concatenate([old_matrices, np.stack(new_matrices)])
    truths = np.concatenate([old_truths, np.asarray(new_truths, dtype=np.int16)])
    blocks = [*old_blocks, "A367_validation_a", "A367_validation_b", "A367_validation_c", "A367_validation_d"]
    if (
        matrices.shape != (TARGETS, CELLS, FEATURES)
        or truths.shape != (TARGETS,)
        or len(blocks) != BLOCKS
        or not np.isfinite(matrices).all()
    ):
        raise RuntimeError("A375 calibration panel geometry differs")
    assert_a361_still_sealed()
    return matrices, truths, blocks


def exact_abs_rank_fields(matrices: np.ndarray) -> np.ndarray:
    values = np.asarray(matrices, dtype=np.float64)
    if values.shape != (TARGETS, CELLS, FEATURES):
        raise ValueError("A375 feature panel geometry differs")
    cells = np.arange(CELLS, dtype=np.int16)
    exact = np.arange(1, CELLS + 1, dtype=np.int16)
    result = np.empty((TARGETS, FEATURES, CELLS), dtype=np.int16)
    for target in range(TARGETS):
        for feature in range(FEATURES):
            order = np.lexsort((cells, -np.abs(values[target, :, feature])))
            result[target, feature, order] = exact
    return result


def field_statistics(rank_field: np.ndarray, truths: np.ndarray) -> dict[str, Any]:
    field = np.asarray(rank_field, dtype=np.int16)
    labels = np.asarray(truths, dtype=np.int16)
    if field.shape != (TARGETS, CELLS) or labels.shape != (TARGETS,):
        raise ValueError("A375 rank-field geometry differs")
    true_ranks = field[np.arange(TARGETS), labels].astype(np.int64)
    logs = np.log2(true_ranks.astype(np.float64))
    uniform = _uniform_mean_log2_rank()
    blocks = [
        float(uniform - logs[start : start + BLOCK_SIZE].mean())
        for start in range(0, TARGETS, BLOCK_SIZE)
    ]
    corpus = [
        float(uniform - logs[:CORPUS_TARGETS].mean()),
        float(uniform - logs[CORPUS_TARGETS:].mean()),
    ]
    return {
        "truth_ranks": true_ranks.tolist(),
        "fixed_block_bit_gains": blocks,
        "minimum_fixed_block_bit_gain": min(blocks),
        "positive_fixed_block_count": sum(value > 0.0 for value in blocks),
        "corpus_bit_gains": corpus,
        "balanced_two_corpus_bit_gain": min(corpus),
        "all128_bit_gain": float(uniform - logs.mean()),
        "targets_at_or_above_median_rank": int(np.count_nonzero(true_ranks <= 128)),
        "worst_rank": int(true_ranks.max()),
    }


def feature_ledger(rank_fields: np.ndarray, truths: np.ndarray) -> list[dict[str, Any]]:
    names = list(A275.FEATURE_NAMES)
    if len(names) != FEATURES or len(set(names)) != FEATURES:
        raise RuntimeError("A375 feature identity differs")
    rows = []
    for feature in range(FEATURES):
        stats = field_statistics(rank_fields[:, feature, :], truths)
        rows.append(
            {
                "feature_index": feature,
                "feature_name": names[feature],
                **{key: value for key, value in stats.items() if key != "truth_ranks"},
            }
        )
    return rows


def pool_indices(ledger: Sequence[Mapping[str, Any]], pool: str, size: int) -> list[int]:
    if len(ledger) != FEATURES or not 1 <= size <= FEATURES:
        raise ValueError("A375 pool geometry differs")
    if pool not in {"balanced_corpus_gain", "positive_block_count", "all128_gain"}:
        raise ValueError(f"A375 unknown pool {pool}")

    def key(row: Mapping[str, Any]) -> tuple[float | int, ...]:
        if pool == "balanced_corpus_gain":
            return (
                -float(row["balanced_two_corpus_bit_gain"]),
                -float(row["all128_bit_gain"]),
                -int(row["positive_fixed_block_count"]),
                -float(row["minimum_fixed_block_bit_gain"]),
                int(row["feature_index"]),
            )
        if pool == "positive_block_count":
            return (
                -int(row["positive_fixed_block_count"]),
                -float(row["minimum_fixed_block_bit_gain"]),
                -float(row["balanced_two_corpus_bit_gain"]),
                -float(row["all128_bit_gain"]),
                int(row["feature_index"]),
            )
        return (
            -float(row["all128_bit_gain"]),
            -float(row["balanced_two_corpus_bit_gain"]),
            -int(row["positive_fixed_block_count"]),
            -float(row["minimum_fixed_block_bit_gain"]),
            int(row["feature_index"]),
        )

    return [int(row["feature_index"]) for row in sorted(ledger, key=key)[:size]]


def aggregate_rank_field(
    rank_fields: np.ndarray, feature_indices: Sequence[int], aggregator: str
) -> np.ndarray:
    fields = np.asarray(rank_fields, dtype=np.int16)
    members = np.asarray([int(value) for value in feature_indices], dtype=np.int64)
    if fields.shape != (TARGETS, FEATURES, CELLS) or not len(members):
        raise ValueError("A375 aggregation geometry differs")
    if np.any(members < 0) or np.any(members >= FEATURES) or len(set(members.tolist())) != len(members):
        raise ValueError("A375 aggregation members differ")
    selected = fields[:, members, :].astype(np.float64)
    cells = np.arange(CELLS, dtype=np.int16)
    exact = np.arange(1, CELLS + 1, dtype=np.int16)
    result = np.empty((TARGETS, CELLS), dtype=np.int16)
    mean_rank = selected.mean(axis=1)
    if aggregator == "maximum_member_rank":
        primary = selected.max(axis=1)
        descending = False
    elif aggregator == "member_rank_quantile_0.75":
        primary = np.quantile(selected, 0.75, axis=1, method="linear")
        descending = False
    elif aggregator == "reciprocal_rank_sum":
        primary = (1.0 / selected).sum(axis=1)
        descending = True
    elif aggregator == "top64_vote_then_mean_rank":
        primary = (selected <= 64).sum(axis=1).astype(np.float64)
        descending = True
    else:
        raise ValueError(f"A375 unknown aggregator {aggregator}")
    for target in range(TARGETS):
        signed = -primary[target] if descending else primary[target]
        order = np.lexsort((cells, mean_rank[target], signed))
        result[target, order] = exact
    return result


def stable_gain_by_shared_xor(rank_field: np.ndarray, truths: np.ndarray) -> np.ndarray:
    field = np.asarray(rank_field, dtype=np.int16)
    labels = np.asarray(truths, dtype=np.int16)
    offsets = np.arange(CELLS, dtype=np.int16)
    mean_logs = np.zeros((BLOCKS, CELLS), dtype=np.float64)
    for target in range(TARGETS):
        shifted = np.bitwise_xor(offsets, labels[target])
        mean_logs[target // BLOCK_SIZE] += np.log2(field[target, shifted].astype(np.float64))
    mean_logs /= BLOCK_SIZE
    return np.min(_uniform_mean_log2_rank() - mean_logs, axis=0)


def correlation_panel(fields: Mapping[str, np.ndarray]) -> dict[str, float]:
    roles = list(MODEL_ROLES)
    result: dict[str, float] = {}
    for left_index, left in enumerate(roles):
        for right in roles[left_index + 1 :]:
            value = float(
                np.corrcoef(
                    fields[left].astype(np.float64).ravel(),
                    fields[right].astype(np.float64).ravel(),
                )[0, 1]
            )
            if not math.isfinite(value):
                raise RuntimeError("A375 model correlation is non-finite")
            result[f"{left}__{right}"] = value
    return result


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    boundary = "A367:sparse_cross_corpus_reader_boundary"
    panel = "A375:complete_128_target_rank_panel"
    consensus = "A375:wide_consensus_feature_pools"
    portfolio = "A375:frozen_four_reader_portfolio"
    target = "A361:still_sealed_complete_direct12_field"
    writer = CausalWriter(api_id="a375wide")
    writer._rules = []
    for name, pattern, conclusion in (
        ("boundary_to_complete_panel", [boundary], panel),
        ("panel_to_wide_consensus", [panel], consensus),
        ("consensus_to_portfolio", [consensus], portfolio),
        ("portfolio_to_sealed_target", [portfolio], target),
    ):
        writer.add_rule(
            name=name,
            description=name.replace("_", " "),
            pattern=pattern,
            conclusion=conclusion,
            confidence_modifier=1.0,
        )
    rows = (
        (boundary, "replace_sparse_feature_identity_with_complete_two_corpus_rank_panel", panel, payload["panel_summary"]),
        (panel, "deterministic_balanced_positive_block_and_all128_feature_pooling", consensus, payload["pool_summary"]),
        (consensus, "four_complementary_wide_rank_aggregators_with_eight_block_positivity", portfolio, payload["model_summary"]),
        (portfolio, "freeze_before_any_A361_compressed_shard_read", target, payload["information_boundary"]),
    )
    for trigger, mechanism, outcome, quantification in rows:
        writer.add_triplet(
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            source=payload["selection_commitment_sha256"],
            quantification=json.dumps(quantification, sort_keys=True),
            evidence=payload["evidence_stage"],
            domain="ChaCha20 R20 W46 wide consensus Reader revision",
            quality_score=1.0,
        )
    writer.add_triplet(
        trigger=boundary,
        mechanism="materialized_boundary_panel_consensus_portfolio_sealed_target_chain",
        outcome=target,
        confidence=1.0,
        source="materialized:A375_wide_consensus_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A375 wide consensus Reader revision",
        entities=[boundary, panel, consensus, portfolio, target],
    )
    writer.add_gap(
        subject=target,
        predicate="next_required_object",
        expected_object_type="A375_portfolio_scored_A361_factor4_order",
        confidence=1.0,
        suggested_queries=[
            "Apply the frozen A375 portfolio without refit to the still-sealed A361 shards and build an exact factor-four wavefront."
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
        reader.api_id != "a375wide"
        or len(explicit) != 4
        or len(all_rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 4
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A375 authentic Causal reopen gate failed")
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
            "first_relation": explicit[0],
            "terminal_relation": explicit[-1],
            "materialized_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def select(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A375 result already exists")
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    matrices, truths, block_labels = load_panel()
    fields = exact_abs_rank_fields(matrices)
    ledger = feature_ledger(fields, truths)
    model_fields: dict[str, np.ndarray] = {}
    definitions: dict[str, dict[str, Any]] = {}
    evaluations: dict[str, dict[str, Any]] = {}
    for role in MODEL_ROLES:
        spec = design["reader_contract"]["models"][role]
        members = pool_indices(ledger, str(spec["pool"]), int(spec["pool_size"]))
        rank_field = aggregate_rank_field(fields, members, str(spec["aggregator"]))
        stats = field_statistics(rank_field, truths)
        if stats["positive_fixed_block_count"] != BLOCKS or stats["minimum_fixed_block_bit_gain"] <= 0.0:
            raise RuntimeError(f"A375 frozen model did not retain eight-block positivity: {role}")
        shifted = stable_gain_by_shared_xor(rank_field, truths)
        observed = float(stats["minimum_fixed_block_bit_gain"])
        definitions[role] = {
            "name": f"{spec['pool']}::top{spec['pool_size']}::{spec['aggregator']}",
            "pool": spec["pool"],
            "pool_size": spec["pool_size"],
            "aggregator": spec["aggregator"],
            "member_feature_indices": members,
            "member_feature_names": [A275.FEATURE_NAMES[index] for index in members],
        }
        model_fields[role] = rank_field
        evaluations[role] = {
            **stats,
            "rank_field_sha256": hashlib.sha256(rank_field.tobytes()).hexdigest(),
            "fixed_shared_xor_p": float(np.count_nonzero(shifted >= observed - 1e-15) / CELLS),
        }
    correlations = correlation_panel(model_fields)
    matrix_sha = hashlib.sha256(np.ascontiguousarray(matrices, dtype="<f8").tobytes()).hexdigest()
    field_sha = hashlib.sha256(fields.tobytes()).hexdigest()
    feature_ledger_sha = canonical_sha256(ledger)
    essential = {
        "A367_result_sha256": A367_RESULT_SHA256,
        "panel_matrix_float64le_sha256": matrix_sha,
        "absolute_rank_fields_sha256": field_sha,
        "feature_ledger_sha256": feature_ledger_sha,
        "model_definitions": definitions,
        "model_evaluations": evaluations,
        "model_rank_field_correlations": correlations,
        "A361_compressed_measurement_shard_content_opened": False,
        "candidate_assignments_executed": 0,
    }
    selection_commitment = canonical_sha256(essential)
    model_summary = {
        role: {
            "minimum_fixed_block_bit_gain": evaluations[role]["minimum_fixed_block_bit_gain"],
            "balanced_two_corpus_bit_gain": evaluations[role]["balanced_two_corpus_bit_gain"],
            "all128_bit_gain": evaluations[role]["all128_bit_gain"],
            "positive_fixed_block_count": evaluations[role]["positive_fixed_block_count"],
            "targets_at_or_above_median_rank": evaluations[role]["targets_at_or_above_median_rank"],
        }
        for role in MODEL_ROLES
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-wide-consensus-reader-a375-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "POST_A367_REVISED_BEFORE_A361_SHARD_READ_WIDE_CONSENSUS_PORTFOLIO_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "selection_commitment_sha256": selection_commitment,
        "panel_summary": {
            "targets": TARGETS,
            "cells_per_target": CELLS,
            "features": FEATURES,
            "fixed_blocks": BLOCKS,
            "block_labels": block_labels,
            "panel_matrix_float64le_sha256": matrix_sha,
            "absolute_rank_fields_sha256": field_sha,
        },
        "pool_summary": {
            "feature_ledger_sha256": feature_ledger_sha,
            "feature_count": len(ledger),
            "pool_rules": design["pool_contract"],
        },
        "feature_ledger": ledger,
        "model_definitions": definitions,
        "model_evaluations": evaluations,
        "model_summary": model_summary,
        "model_rank_field_correlations": correlations,
        "information_boundary": {
            **design["information_boundary"],
            "A361_compressed_measurement_shard_content_opened_at_result_freeze": False,
            "A361_secret_or_true_prefix_available_at_result_freeze": False,
            "candidate_assignments_executed_at_result_freeze": 0,
        },
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A366_result": anchor(A366_RESULT, A366_RESULT_SHA256),
            "A367_prepared": anchor(A367_PREPARED, A367_PREPARED_SHA256),
            "A367_result": anchor(A367_RESULT, A367_RESULT_SHA256),
            "A361_measurement_metadata": anchor(A361_MEASUREMENT, A361_MEASUREMENT_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["result_sha256"] = canonical_sha256(essential)
    payload["causal"] = build_causal(payload)
    assert_a361_still_sealed()
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A375 — wide cross-corpus consensus Reader\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Complete calibration panel: **{TARGETS} targets × {CELLS} cells × {FEATURES} features**\n"
            f"- Frozen models: **{len(MODEL_ROLES)}**, each positive in all **{BLOCKS}/{BLOCKS}** fixed blocks\n"
            f"- Model summary: **{json.dumps(model_summary, sort_keys=True)}**\n"
            "- A361 compressed shards read: **zero**\n"
            "- Candidate assignments executed: **zero**\n"
            "- Authentic AI-native Causal readback: **4 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "result_available": RESULT.exists(),
        "A361_order_available": A368_ORDER.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        payload["result_file_sha256"] = file_sha256(RESULT)
        payload["result_sha256"] = value["result_sha256"]
        payload["model_summary"] = value["model_summary"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--select", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.select:
        if not args.expected_implementation_sha256:
            parser.error("--select requires --expected-implementation-sha256")
        payload = select(expected_implementation_sha256=args.expected_implementation_sha256)
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
