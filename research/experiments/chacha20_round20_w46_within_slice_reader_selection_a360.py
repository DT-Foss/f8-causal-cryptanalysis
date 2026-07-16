#!/usr/bin/env python3
"""A360: prospectively select and holdout-test a W46 within-slice Reader."""

from __future__ import annotations

import argparse
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
import zstandard
from scipy.stats import rankdata

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w46_within_slice_reader_selection_a360_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w46_within_slice_reader_selection_a360_implementation_v1.json"
)
SELECTION = RESULTS / "chacha20_round20_w46_within_slice_reader_selection_a360_frozen_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_within_slice_reader_selection_a360_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULTS / "chacha20_round20_w46_within_slice_reader_selection_a360_v1.md"
TEST = ROOT / "tests/test_chacha20_round20_w46_within_slice_reader_selection_a360.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_within_slice_reader_selection_a360.sh"

A359_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_corrected_knownkey_slice_corpus_a359.py"

ATTEMPT_ID = "A360"
DESIGN_SHA256 = "8e705b98cab70e6dbeeb8f114bc83d493b783c4cb612a842d365a12bcfb00205"
A359_PREPARED_SHA256 = "3e508df1af059116eba9d288cd55d3c34800ff8c9d9f6dc17f7989229df5372e"
SELECTION_TARGETS = tuple(range(16))
HOLDOUT_TARGETS = tuple(range(16, 32))
FEATURES = 532
CELLS = 256
TRANSFORMS = (
    "raw_z",
    "xor_laplacian",
    "xor_gradient_l2",
    "xor_gradient_maxabs",
)
ALPHAS = (0.0001, 0.001, 0.01, 0.1, 1.0, 10.0)
FULL_TOPK = (4, 8, 16, 32, 64, 128, 256, 532)
TRANSFORM_TOPK: tuple[int | str, ...] = (8, 32, "all")
SOURCE_ALPHAS = (0.1, 1.0)
CANDIDATE_READERS = 785
SECONDARY_POOL = 32
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A360 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A359 = load_module(A359_RUNNER, "a360_a359")
A275 = A359.A355.A348.A275

file_sha256 = A359.file_sha256
canonical_sha256 = A359.canonical_sha256
canonical_bytes = A359.canonical_bytes
atomic_json = A359.atomic_json
atomic_bytes = A359.atomic_bytes
relative = A359.relative
path_from_ref = A359.path_from_ref
anchor = A359.anchor
sha256 = A359.sha256


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A360 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    factory = value.get("learner_factory", {})
    selection = value.get("selection_contract", {})
    holdout = value.get("holdout_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w46-within-slice-reader-selection-a360-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A359_preparation_before_any_A359_solver_measurement_or_selection_shard"
        or factory.get("candidate_reader_count") != CANDIDATE_READERS
        or factory.get("single_feature_signed_readers") != FEATURES
        or selection.get("leave_one_target_out_folds") != len(SELECTION_TARGETS)
        or selection.get("diverse_secondary_pool") != SECONDARY_POOL
        or holdout.get("holdout_targets") != len(HOLDOUT_TARGETS)
        or holdout.get("familywise_shared_xor_offsets") != CELLS
        or boundary.get("A359_solver_measurement_started_at_design_freeze") is not False
        or boundary.get("A359_selection_measurement_shards_available_at_design_freeze") != 0
        or boundary.get("holdout_measurement_files_opened_during_selection") != 0
    ):
        raise RuntimeError("A360 frozen design semantics differ")
    sources = value["source_anchors"]
    for name, path_value in sources.items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, sources[f"{stem}_sha256"])
    return value


def _source_name(feature_name: str) -> str:
    return feature_name.split("__", 1)[0]


def _transform_name(feature_name: str) -> str:
    return feature_name.rsplit("__", 1)[1]


def _alpha_label(value: float) -> str:
    return format(float(value), ".4g")


def reader_definitions(feature_names: Sequence[str]) -> list[dict[str, Any]]:
    names = tuple(str(value) for value in feature_names)
    if len(names) != FEATURES or len(set(names)) != FEATURES:
        raise ValueError("A360 feature-name ledger differs")
    sources = sorted({_source_name(name) for name in names})
    transforms = sorted({_transform_name(name) for name in names})
    if len(sources) != 17 or tuple(transforms) != tuple(sorted(TRANSFORMS)):
        raise RuntimeError("A360 source or transform family differs")
    definitions: list[dict[str, Any]] = []
    for index, name in enumerate(names):
        definitions.append(
            {
                "name": f"single_signed::{index:03d}::{name}",
                "kind": "single_signed",
                "feature_index": index,
            }
        )
    masks = ["all"]
    masks.extend(f"transform::{transform}" for transform in TRANSFORMS)
    masks.extend(f"source::{source}" for source in sources)
    masks.extend(
        f"source_transform::{source}::{transform}" for source in sources for transform in TRANSFORMS
    )
    if len(masks) != 90 or len(set(masks)) != 90:
        raise RuntimeError("A360 mean-mask family differs")
    definitions.extend(
        {"name": f"mean_mask::{mask}", "kind": "mean_mask", "mask": mask} for mask in masks
    )
    for alpha in ALPHAS:
        for topk in FULL_TOPK:
            definitions.append(
                {
                    "name": f"studentized::all::alpha={_alpha_label(alpha)}::topk={topk}",
                    "kind": "studentized",
                    "mask": "all",
                    "alpha": alpha,
                    "topk": topk,
                }
            )
    for transform in TRANSFORMS:
        for alpha in ALPHAS:
            for topk in TRANSFORM_TOPK:
                definitions.append(
                    {
                        "name": (
                            f"studentized::transform::{transform}::"
                            f"alpha={_alpha_label(alpha)}::topk={topk}"
                        ),
                        "kind": "studentized",
                        "mask": f"transform::{transform}",
                        "alpha": alpha,
                        "topk": topk,
                    }
                )
    for source in sources:
        for alpha in SOURCE_ALPHAS:
            definitions.append(
                {
                    "name": (
                        f"studentized::source::{source}::alpha={_alpha_label(alpha)}::topk=all"
                    ),
                    "kind": "studentized",
                    "mask": f"source::{source}",
                    "alpha": alpha,
                    "topk": "all",
                }
            )
    definitions.extend(
        {"name": f"consensus::{name}", "kind": "consensus", "mode": name}
        for name in ("median_effect", "sign_vote", "stability_weighted_mean")
    )
    definitions.extend(
        {
            "name": f"covariance_lowrank::alpha={_alpha_label(alpha)}",
            "kind": "covariance_lowrank",
            "alpha": alpha,
        }
        for alpha in ALPHAS
    )
    if (
        len(definitions) != CANDIDATE_READERS
        or len({definition["name"] for definition in definitions}) != CANDIDATE_READERS
    ):
        raise RuntimeError("A360 candidate Reader family count differs")
    return definitions


def _mask_indices(mask: str, feature_names: Sequence[str]) -> np.ndarray:
    names = tuple(feature_names)
    if mask == "all":
        indices = list(range(len(names)))
    elif mask.startswith("transform::"):
        transform = mask.split("::", 1)[1]
        indices = [index for index, name in enumerate(names) if _transform_name(name) == transform]
    elif mask.startswith("source::"):
        source = mask.split("::", 1)[1]
        indices = [index for index, name in enumerate(names) if _source_name(name) == source]
    elif mask.startswith("source_transform::"):
        _, source, transform = mask.split("::", 2)
        indices = [
            index
            for index, name in enumerate(names)
            if _source_name(name) == source and _transform_name(name) == transform
        ]
    else:
        raise ValueError(f"A360 unknown mask {mask}")
    if not indices:
        raise RuntimeError(f"A360 empty mask {mask}")
    return np.asarray(indices, dtype=np.int64)


def _unit_l2(weights: np.ndarray) -> np.ndarray:
    values = np.asarray(weights, dtype=np.float64)
    if values.shape != (FEATURES,) or not np.isfinite(values).all():
        raise ValueError("A360 Reader weight vector differs")
    norm = float(np.linalg.norm(values))
    return values / norm if norm > 1e-15 else np.zeros_like(values)


def reader_weights(
    definition: Mapping[str, Any], deltas: np.ndarray, feature_names: Sequence[str]
) -> np.ndarray:
    values = np.asarray(deltas, dtype=np.float64)
    if values.ndim != 2 or values.shape[1] != FEATURES or not np.isfinite(values).all():
        raise ValueError("A360 training-effect matrix differs")
    mean = values.mean(axis=0)
    variance = values.var(axis=0)
    weights = np.zeros(FEATURES, dtype=np.float64)
    kind = definition["kind"]
    if kind == "single_signed":
        index = int(definition["feature_index"])
        weights[index] = 1.0 if mean[index] >= 0.0 else -1.0
    elif kind == "mean_mask":
        indices = _mask_indices(str(definition["mask"]), feature_names)
        weights[indices] = mean[indices]
    elif kind == "studentized":
        indices = _mask_indices(str(definition["mask"]), feature_names)
        positive = variance[indices][variance[indices] > 1e-12]
        variance_scale = float(np.median(positive)) if len(positive) else 1.0
        alpha = float(definition["alpha"])
        weights[indices] = mean[indices] / np.sqrt(
            variance[indices] + alpha * variance_scale + 1e-12
        )
        topk = definition["topk"]
        if topk != "all" and int(topk) < len(indices):
            keep_count = int(topk)
            ordered = sorted(indices.tolist(), key=lambda index: (-abs(weights[index]), index))
            keep = set(ordered[:keep_count])
            weights[[index for index in indices if index not in keep]] = 0.0
    elif kind == "consensus":
        mode = definition["mode"]
        stability = np.abs(np.sign(values).mean(axis=0))
        if mode == "median_effect":
            weights = np.median(values, axis=0)
        elif mode == "sign_vote":
            weights = np.sign(values).mean(axis=0)
        elif mode == "stability_weighted_mean":
            weights = mean * stability
        else:
            raise ValueError(f"A360 unknown consensus mode {mode}")
    elif kind == "covariance_lowrank":
        centered = values - mean
        variance_scale_values = variance[variance > 1e-12]
        variance_scale = (
            float(np.median(variance_scale_values)) if len(variance_scale_values) else 1.0
        )
        ridge = float(definition["alpha"]) * variance_scale + 1e-10
        divisor = math.sqrt(max(1, len(values) - 1))
        lowrank = centered / divisor
        system = ridge * np.eye(len(values), dtype=np.float64) + np.einsum(
            "if,jf->ij", lowrank, lowrank, optimize=False
        )
        projected_mean = np.einsum("if,f->i", lowrank, mean, optimize=False)
        solution = np.linalg.solve(system, projected_mean)
        correction = np.einsum("if,i->f", lowrank, solution, optimize=False)
        weights = (mean - correction) / ridge
    else:
        raise ValueError(f"A360 unknown Reader kind {kind}")
    return _unit_l2(weights)


def target_normalize(matrix: np.ndarray) -> np.ndarray:
    values = np.asarray(matrix, dtype=np.float64)
    if values.shape != (CELLS, FEATURES) or not np.isfinite(values).all():
        raise ValueError("A360 target feature matrix differs")
    means = values.mean(axis=0)
    scales = values.std(axis=0)
    constant = scales <= np.maximum(1e-12, np.abs(means) * 1e-12)
    scales[constant] = 1.0
    result = (values - means) / scales
    result[:, constant] = 0.0
    if not np.isfinite(result).all():
        raise RuntimeError("A360 target normalization is non-finite")
    return result


def effect_vector(matrix: np.ndarray, truth: int) -> np.ndarray:
    if not 0 <= truth < CELLS:
        raise ValueError("A360 truth outside high8 domain")
    wrong = np.delete(matrix, truth, axis=0)
    return np.asarray(matrix[truth] - wrong.mean(axis=0), dtype=np.float64)


def _rank_fields(scores: np.ndarray) -> np.ndarray:
    values = np.asarray(scores, dtype=np.float64)
    if values.ndim != 2 or values.shape[0] != CELLS or not np.isfinite(values).all():
        raise ValueError("A360 score matrix differs")
    ranks = np.asarray(rankdata(-values, method="average", axis=0), dtype=np.float64)
    if ranks.shape != values.shape or np.any(ranks < 1.0) or np.any(ranks > CELLS):
        raise RuntimeError("A360 rank field differs")
    return ranks


def _weight_matrix(
    definitions: Sequence[Mapping[str, Any]],
    deltas: np.ndarray,
    feature_names: Sequence[str],
) -> np.ndarray:
    result = np.stack(
        [reader_weights(definition, deltas, feature_names) for definition in definitions]
    )
    if result.shape != (len(definitions), FEATURES) or not np.isfinite(result).all():
        raise RuntimeError("A360 Reader weight matrix differs")
    return result


def _safe_abs_correlation(left: np.ndarray, right: np.ndarray) -> float:
    if np.std(left) <= 1e-15 or np.std(right) <= 1e-15:
        return 1.0
    value = float(np.corrcoef(left, right)[0, 1])
    return abs(value) if math.isfinite(value) else 1.0


def select_readers(
    matrices: Sequence[np.ndarray], truths: Sequence[int], feature_names: Sequence[str]
) -> dict[str, Any]:
    if len(matrices) != len(SELECTION_TARGETS) or len(truths) != len(SELECTION_TARGETS):
        raise ValueError("A360 selection geometry differs")
    definitions = reader_definitions(feature_names)
    deltas = np.stack(
        [effect_vector(matrix, int(truth)) for matrix, truth in zip(matrices, truths, strict=True)]
    )
    rank_fields = []
    for test_index, matrix in enumerate(matrices):
        training = np.delete(deltas, test_index, axis=0)
        weights = _weight_matrix(definitions, training, feature_names)
        rank_fields.append(_rank_fields(matrix @ weights.T))
    offsets = np.arange(CELLS, dtype=np.uint16)
    mean_log2_by_offset = np.zeros((CELLS, len(definitions)), dtype=np.float64)
    for fields, truth in zip(rank_fields, truths, strict=True):
        mean_log2_by_offset += np.log2(fields[np.bitwise_xor(offsets, int(truth))])
    mean_log2_by_offset /= len(matrices)
    observed = mean_log2_by_offset[0]
    truth_ranks = np.stack(
        [fields[int(truth)] for fields, truth in zip(rank_fields, truths, strict=True)]
    )
    worst = truth_ranks.max(axis=0)
    names = [definition["name"] for definition in definitions]
    primary_index = min(
        range(len(definitions)), key=lambda index: (observed[index], worst[index], names[index])
    )
    sorted_indices = sorted(
        range(len(definitions)), key=lambda index: (observed[index], worst[index], names[index])
    )
    primary_flat = np.concatenate([fields[:, primary_index] for fields in rank_fields])
    secondary_candidates = [index for index in sorted_indices if index != primary_index][
        :SECONDARY_POOL
    ]
    correlations = {
        index: _safe_abs_correlation(
            primary_flat, np.concatenate([fields[:, index] for fields in rank_fields])
        )
        for index in secondary_candidates
    }
    secondary_index = min(
        secondary_candidates,
        key=lambda index: (
            correlations[index],
            observed[index],
            worst[index],
            names[index],
        ),
    )
    all_weights = _weight_matrix(definitions, deltas, feature_names)
    uniform = sum(math.log2(rank) for rank in range(1, CELLS + 1)) / CELLS
    family_best = mean_log2_by_offset.min(axis=1)
    primary_observed = float(observed[primary_index])
    candidate_ledger = [
        {
            "index": index,
            "name": names[index],
            "leave_one_target_out_mean_log2_rank": float(observed[index]),
            "leave_one_target_out_bit_gain": float(uniform - observed[index]),
            "worst_rank": float(worst[index]),
        }
        for index in range(len(definitions))
    ]
    return {
        "definition_count": len(definitions),
        "definition_ledger_sha256": canonical_sha256(definitions),
        "definitions": definitions,
        "candidate_ledger": candidate_ledger,
        "uniform_mean_log2_rank_reference": uniform,
        "familywise_best_mean_log2_rank_by_shared_xor_offset": family_best.tolist(),
        "exact_familywise_shared_xor_p": float(
            np.count_nonzero(family_best <= primary_observed + 1e-15) / CELLS
        ),
        "primary": {
            "index": primary_index,
            "definition": definitions[primary_index],
            "leave_one_target_out_ranks": truth_ranks[:, primary_index].tolist(),
            "leave_one_target_out_mean_log2_rank": primary_observed,
            "leave_one_target_out_bit_gain": float(uniform - primary_observed),
            "weights": all_weights[primary_index].tolist(),
            "weights_sha256": canonical_sha256(all_weights[primary_index].tolist()),
        },
        "secondary": {
            "index": secondary_index,
            "definition": definitions[secondary_index],
            "leave_one_target_out_ranks": truth_ranks[:, secondary_index].tolist(),
            "leave_one_target_out_mean_log2_rank": float(observed[secondary_index]),
            "leave_one_target_out_bit_gain": float(uniform - observed[secondary_index]),
            "absolute_rank_field_spearman_to_primary": correlations[secondary_index],
            "weights": all_weights[secondary_index].tolist(),
            "weights_sha256": canonical_sha256(all_weights[secondary_index].tolist()),
        },
        "primary_secondary_absolute_rank_field_spearman": correlations[secondary_index],
    }


def _measurement_ledger(path: Path, measurement: Mapping[str, Any]) -> dict[str, Any]:
    compressed = path.read_bytes()
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    if json.loads(raw) != measurement:
        raise RuntimeError("A360 measurement ledger readback differs")
    return {
        "path": relative(path),
        "compressed_bytes": len(compressed),
        "compressed_sha256": sha256(compressed),
        "raw_bytes": len(raw),
        "raw_sha256": sha256(raw),
    }


def _load_target_panel(
    indices: Sequence[int], *, expected_prepared_sha256: str
) -> tuple[list[np.ndarray], list[int], list[dict[str, Any]]]:
    if expected_prepared_sha256 != A359_PREPARED_SHA256:
        raise RuntimeError("A360 A359 prepared hash differs from frozen design")
    A359.load_prepared(expected_prepared_sha256)
    source_rows = {row["index"]: row for row in A359.generate_rows()}
    matrices = []
    truths = []
    ledgers = []
    for index in indices:
        path = A359._measurement_path(int(index))  # noqa: SLF001
        measurement = A359._read_measurement(  # noqa: SLF001
            path, expected_prepared_sha256=expected_prepared_sha256
        )
        source = source_rows[int(index)]
        if (
            measurement["index"] != index
            or measurement["label"] != source["label"]
            or measurement["true_low4"] != source["true_low4"]
        ):
            raise RuntimeError(f"A360 target identity differs: {index}")
        matrix = target_normalize(A275._target_feature_matrix(measurement))  # noqa: SLF001
        matrices.append(matrix)
        truths.append(int(source["true_high8"]))
        ledgers.append({"index": int(index), **_measurement_ledger(path, measurement)})
    return matrices, truths, ledgers


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A360 implementation already exists")
    if any(path.exists() for path in (SELECTION, RESULT, CAUSAL, REPORT)):
        raise RuntimeError("A360 implementation must precede selection and holdout")
    load_design()
    definitions = reader_definitions(A275.FEATURE_NAMES)
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A360 test and reproducer must exist before freeze")
    available_shards = [
        index
        for index in range(32)
        if A359._measurement_path(index).exists()  # noqa: SLF001
    ]
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-within-slice-reader-selection-a360-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": (
            "frozen_after_A359_measurement_started_before_any_A359_shard_content_read_"
            "or_reader_selection"
        ),
        "measurement_shards_available_at_implementation_freeze": len(available_shards),
        "measurement_shard_indices_available_at_implementation_freeze": available_shards,
        "measurement_shard_content_read_before_implementation_freeze": False,
        "reader_selection_executed_before_implementation_freeze": False,
        "design_sha256": DESIGN_SHA256,
        "definition_ledger_sha256": canonical_sha256(definitions),
        "candidate_readers": len(definitions),
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
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
        raise RuntimeError("A360 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-within-slice-reader-selection-a360-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("candidate_readers") != CANDIDATE_READERS
        or value.get("definition_ledger_sha256")
        != canonical_sha256(reader_definitions(A275.FEATURE_NAMES))
    ):
        raise RuntimeError("A360 implementation semantics differ")
    for name, path in {
        "design": DESIGN,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }.items():
        row = value["anchors"][name]
        if row["path"] != relative(path) or row["sha256"] != file_sha256(path):
            raise RuntimeError(f"A360 implementation anchor differs: {name}")
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value["implementation_commitment_sha256"] != canonical_sha256(unsigned):
        raise RuntimeError("A360 implementation commitment differs")
    return value


def freeze_selection(
    *, expected_implementation_sha256: str, expected_prepared_sha256: str
) -> dict[str, Any]:
    if SELECTION.exists() or RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A360 selection or result already exists")
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    matrices, truths, ledgers = _load_target_panel(
        SELECTION_TARGETS, expected_prepared_sha256=expected_prepared_sha256
    )
    selection = select_readers(matrices, truths, A275.FEATURE_NAMES)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-within-slice-reader-selection-a360-frozen-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "SELECTION_ONLY_READER_FAMILY_FROZEN_BEFORE_HOLDOUT_READBACK",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A359_prepared_sha256": expected_prepared_sha256,
        "selection_target_indices": list(SELECTION_TARGETS),
        "selection_measurement_ledger": ledgers,
        "selection_measurement_sha256": canonical_sha256(ledgers),
        "reader_selection": selection,
        "holdout_measurement_files_opened": 0,
        "holdout_scores_or_ranks_available": False,
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A359_prepared": anchor(A359.PREPARED, expected_prepared_sha256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["selection_commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "implementation_commitment_sha256": payload["implementation_commitment_sha256"],
            "A359_prepared_sha256": expected_prepared_sha256,
            "selection_measurement_sha256": payload["selection_measurement_sha256"],
            "reader_selection": selection,
            "holdout_measurement_files_opened": 0,
            "holdout_scores_or_ranks_available": False,
        }
    )
    atomic_json(SELECTION, payload)
    return {
        "attempt_id": ATTEMPT_ID,
        "selection": relative(SELECTION),
        "selection_sha256": file_sha256(SELECTION),
        "selection_commitment_sha256": payload["selection_commitment_sha256"],
        "candidate_readers": selection["definition_count"],
        "primary": selection["primary"]["definition"]["name"],
        "secondary": selection["secondary"]["definition"]["name"],
        "holdout_measurement_files_opened": 0,
    }


def load_selection(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(SELECTION) != expected_sha256:
        raise RuntimeError("A360 frozen selection hash differs")
    value = json.loads(SELECTION.read_bytes())
    selection = value.get("reader_selection", {})
    if (
        value.get("schema") != "chacha20-round20-w46-within-slice-reader-selection-a360-frozen-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("holdout_measurement_files_opened") != 0
        or value.get("holdout_scores_or_ranks_available") is not False
        or selection.get("definition_count") != CANDIDATE_READERS
        or selection.get("definition_ledger_sha256")
        != canonical_sha256(reader_definitions(A275.FEATURE_NAMES))
    ):
        raise RuntimeError("A360 frozen selection semantics differ")
    for name in ("primary", "secondary"):
        weights = selection[name]["weights"]
        if len(weights) != FEATURES or selection[name]["weights_sha256"] != canonical_sha256(
            weights
        ):
            raise RuntimeError(f"A360 frozen {name} weights differ")
    for row in value["selection_measurement_ledger"]:
        path = path_from_ref(row["path"])
        if file_sha256(path) != row["compressed_sha256"]:
            raise RuntimeError("A360 selection measurement anchor differs")
    for artifact in value["anchors"].values():
        anchor(path_from_ref(artifact["path"]), artifact["sha256"])
    return value


def exact_order(scores: Sequence[float], *, descending: bool = True) -> list[int]:
    values = np.asarray(scores, dtype=np.float64)
    if values.shape != (CELLS,) or not np.isfinite(values).all():
        raise ValueError("A360 order score field differs")
    order = sorted(
        range(CELLS), key=lambda cell: ((-values[cell]) if descending else values[cell], cell)
    )
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise RuntimeError("A360 order is not a complete permutation")
    return order


def rank_vector(order: Sequence[int]) -> list[int]:
    values = [int(value) for value in order]
    if len(values) != CELLS or set(values) != set(range(CELLS)):
        raise ValueError("A360 rank-vector order differs")
    ranks = [0] * CELLS
    for rank, cell in enumerate(values, 1):
        ranks[cell] = rank
    return ranks


def equal_borda(left: Sequence[int], right: Sequence[int]) -> list[int]:
    left_ranks, right_ranks = rank_vector(left), rank_vector(right)
    return sorted(
        range(CELLS),
        key=lambda cell: (
            left_ranks[cell] + right_ranks[cell],
            min(left_ranks[cell], right_ranks[cell]),
            max(left_ranks[cell], right_ranks[cell]),
            left_ranks[cell],
            right_ranks[cell],
            cell,
        ),
    )


def min_rank_wavefront(left: Sequence[int], right: Sequence[int]) -> list[int]:
    left_ranks, right_ranks = rank_vector(left), rank_vector(right)
    return sorted(
        range(CELLS),
        key=lambda cell: (
            min(left_ranks[cell], right_ranks[cell]),
            left_ranks[cell] + right_ranks[cell],
            left_ranks[cell],
            right_ranks[cell],
            cell,
        ),
    )


def _view_statistics(
    orders: Sequence[Sequence[int]], truths: Sequence[int], low4_values: Sequence[int]
) -> dict[str, Any]:
    ranks_by_target = [rank_vector(order) for order in orders]
    true_ranks = [ranks[int(truth)] for ranks, truth in zip(ranks_by_target, truths, strict=True)]
    mean_log = sum(math.log2(rank) for rank in true_ranks) / len(true_ranks)
    uniform = sum(math.log2(rank) for rank in range(1, CELLS + 1)) / CELLS
    shifted = [
        sum(
            math.log2(ranks[int(truth) ^ offset])
            for ranks, truth in zip(ranks_by_target, truths, strict=True)
        )
        / len(truths)
        for offset in range(CELLS)
    ]
    global_group_ranks = [
        16 * (rank - 1) + int(low4) + 1 for rank, low4 in zip(true_ranks, low4_values, strict=True)
    ]
    return {
        "within_slice_ranks": true_ranks,
        "within_slice_mean_log2_rank": mean_log,
        "within_slice_uniform_mean_log2_rank_reference": uniform,
        "within_slice_mean_log2_rank_bit_gain": uniform - mean_log,
        "targets_at_or_above_median_rank_threshold": sum(rank <= 128 for rank in true_ranks),
        "shared_xor_offset_mean_log2_ranks": shifted,
        "exact_shared_xor_p": sum(value <= mean_log + 1e-15 for value in shifted) / CELLS,
        "best_shared_xor_offset": min(range(CELLS), key=shifted.__getitem__),
        "global_round_robin_group_ranks": global_group_ranks,
        "global_round_robin_geometric_mean_domain_reduction": float(
            4096
            / math.exp(sum(math.log(rank) for rank in global_group_ranks) / len(global_group_ranks))
        ),
        "global_group_rank_formula": "16*(within_rank-1)+true_low4+1",
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    source = "A360:frozen_785_reader_selection_family"
    selected = "A360:selection_only_primary_secondary_weights"
    measured = "A360:disjoint_holdout_rank_panel"
    terminal = "A360:within_slice_reader_validation_decision"
    writer = CausalWriter(api_id="a360read")
    writer._rules = []
    writer.add_rule(
        name="reader_family_to_selection_weights",
        description="Sixteen selection targets choose primary and diverse secondary definitions under leave-one-target-out ranking before any holdout shard is opened.",
        pattern=[source],
        conclusion=selected,
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="selection_weights_to_holdout_panel",
        description="The frozen weights and four derived views consume sixteen disjoint holdout targets without refit.",
        pattern=[selected],
        conclusion=measured,
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="holdout_panel_to_deployment_decision",
        description="Exact shared-XOR controls and round-robin global ranks determine whether the Reader advances to A361 deployment.",
        pattern=[measured],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger=source,
        mechanism="selection_only_leave_one_target_out_family_competition_and_diversity_rule",
        outcome=selected,
        confidence=1.0,
        source=payload["selection_sha256"],
        quantification=json.dumps(payload["selection_summary"], sort_keys=True),
        evidence="selection artifact frozen with zero holdout reads",
        domain="ChaCha20 R20 W46 within-slice Reader learning",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=selected,
        mechanism="zero_refit_disjoint_holdout_scoring_across_five_predeclared_views",
        outcome=measured,
        confidence=1.0,
        source=payload["holdout_measurement_sha256"],
        quantification=json.dumps(payload["view_summary"], sort_keys=True),
        evidence="sixteen complete target-local holdout covers",
        domain="Prospective known-key holdout validation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=measured,
        mechanism="exact_shared_xor_and_round_robin_global_rank_gate",
        outcome=terminal,
        confidence=1.0,
        source=payload["result_sha256"],
        quantification=json.dumps(payload["retention_gate"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="Deployment decision",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=source,
        mechanism="materialized_selection_holdout_deployment_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A360_reader_validation_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A360 within-slice Reader validation", entities=[source, selected, measured, terminal]
    )
    next_type = (
        "fresh_unknown_W46_round_robin_reader_deployment"
        if payload["retention_gate"]["passed"]
        else "reader_boundary_conditioned_feature_or_intervention_revision"
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=next_type,
        confidence=1.0,
        suggested_queries=[payload["retention_gate"]["next_query"]],
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
        reader.api_id != "a360read"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A360 authentic Causal reopen gate failed")
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


def validate_holdout(*, expected_selection_sha256: str) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A360 result already exists")
    design = load_design()
    selection = load_selection(expected_selection_sha256)
    matrices, truths, ledgers = _load_target_panel(
        HOLDOUT_TARGETS, expected_prepared_sha256=A359_PREPARED_SHA256
    )
    source_rows = {row["index"]: row for row in A359.generate_rows()}
    low4_values = [int(source_rows[index]["true_low4"]) for index in HOLDOUT_TARGETS]
    primary_weights = np.asarray(
        selection["reader_selection"]["primary"]["weights"], dtype=np.float64
    )
    secondary_weights = np.asarray(
        selection["reader_selection"]["secondary"]["weights"], dtype=np.float64
    )
    view_orders: dict[str, list[list[int]]] = {
        "primary_reader": [],
        "diverse_secondary_reader": [],
        "equal_borda_primary_secondary": [],
        "exact_factor2_min_rank_wavefront": [],
        "numeric_control": [],
    }
    for matrix in matrices:
        primary = exact_order(matrix @ primary_weights)
        secondary = exact_order(matrix @ secondary_weights)
        view_orders["primary_reader"].append(primary)
        view_orders["diverse_secondary_reader"].append(secondary)
        view_orders["equal_borda_primary_secondary"].append(equal_borda(primary, secondary))
        view_orders["exact_factor2_min_rank_wavefront"].append(
            min_rank_wavefront(primary, secondary)
        )
        view_orders["numeric_control"].append(list(range(CELLS)))
    evaluations = {
        name: _view_statistics(orders, truths, low4_values) for name, orders in view_orders.items()
    }
    primary = evaluations["primary_reader"]
    gate_contract = design["holdout_contract"]["primary_retention_gate"]
    passed = (
        primary["exact_shared_xor_p"] <= gate_contract["exact_shared_xor_p_maximum"]
        and primary["within_slice_mean_log2_rank_bit_gain"]
        > gate_contract["mean_log2_rank_bit_gain_minimum_exclusive"]
        and primary["targets_at_or_above_median_rank_threshold"]
        >= gate_contract["targets_at_or_above_median_rank_threshold_minimum"]
    )
    retention_gate = {
        "passed": passed,
        "contract": gate_contract,
        "observed": {
            "exact_shared_xor_p": primary["exact_shared_xor_p"],
            "within_slice_mean_log2_rank_bit_gain": primary["within_slice_mean_log2_rank_bit_gain"],
            "targets_at_or_above_median_rank_threshold": primary[
                "targets_at_or_above_median_rank_threshold"
            ],
        },
        "next_query": (
            "Deploy the frozen A360 primary Reader over all sixteen low4 slices of a fresh unknown W46 target."
            if passed
            else "Use the exact A360 per-feature and per-target boundary to revise the Reader family without rerunning A359."
        ),
    }
    view_summary = {
        name: {
            "within_slice_mean_log2_rank_bit_gain": value["within_slice_mean_log2_rank_bit_gain"],
            "exact_shared_xor_p": value["exact_shared_xor_p"],
            "global_round_robin_geometric_mean_domain_reduction": value[
                "global_round_robin_geometric_mean_domain_reduction"
            ],
        }
        for name, value in evaluations.items()
    }
    selection_summary = {
        "candidate_readers": CANDIDATE_READERS,
        "primary": selection["reader_selection"]["primary"]["definition"]["name"],
        "secondary": selection["reader_selection"]["secondary"]["definition"]["name"],
        "selection_familywise_shared_xor_p": selection["reader_selection"][
            "exact_familywise_shared_xor_p"
        ],
        "holdout_reads_before_freeze": 0,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-within-slice-reader-selection-a360-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "PROSPECTIVE_DISJOINT_HOLDOUT_WITHIN_SLICE_READER_RETAINED"
            if passed
            else "PROSPECTIVE_DISJOINT_HOLDOUT_READER_BOUNDARY_RETAINED"
        ),
        "design_sha256": DESIGN_SHA256,
        "selection_sha256": expected_selection_sha256,
        "selection_commitment_sha256": selection["selection_commitment_sha256"],
        "selection_summary": selection_summary,
        "holdout_target_indices": list(HOLDOUT_TARGETS),
        "holdout_measurement_ledger": ledgers,
        "holdout_measurement_sha256": canonical_sha256(ledgers),
        "view_evaluations": evaluations,
        "view_summary": view_summary,
        "retention_gate": retention_gate,
        "reader_refits_after_selection_freeze": 0,
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "selection": anchor(SELECTION, expected_selection_sha256),
            "A359_prepared": anchor(A359.PREPARED, A359_PREPARED_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["result_sha256"] = canonical_sha256(
        {
            "evidence_stage": payload["evidence_stage"],
            "selection_sha256": expected_selection_sha256,
            "holdout_measurement_sha256": payload["holdout_measurement_sha256"],
            "view_evaluations": evaluations,
            "retention_gate": retention_gate,
            "reader_refits_after_selection_freeze": 0,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A360 — W46 within-slice Reader selection and holdout\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Frozen candidate Readers: **{CANDIDATE_READERS}**\n"
            f"- Selection / holdout targets: **16 / 16**\n"
            f"- Primary: **{selection_summary['primary']}**\n"
            f"- Secondary: **{selection_summary['secondary']}**\n"
            f"- Primary holdout ranks: **{primary['within_slice_ranks']}**\n"
            f"- Primary holdout bit gain: **{primary['within_slice_mean_log2_rank_bit_gain']:.9f}**\n"
            f"- Primary exact shared-XOR p: **{primary['exact_shared_xor_p']:.9f}**\n"
            f"- Global round-robin geometric reduction: **{primary['global_round_robin_geometric_mean_domain_reduction']:.9f}x**\n"
            f"- Retention gate: **{passed}**\n"
            "- Reader refits after selection freeze: **0**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "implementation_sha256": file_sha256(IMPLEMENTATION) if IMPLEMENTATION.exists() else None,
        "selection_frozen": SELECTION.exists(),
        "selection_sha256": file_sha256(SELECTION) if SELECTION.exists() else None,
        "selection_shards_available": sum(
            A359._measurement_path(index).exists()
            for index in SELECTION_TARGETS  # noqa: SLF001
        ),
        "holdout_shards_available": sum(
            A359._measurement_path(index).exists()
            for index in HOLDOUT_TARGETS  # noqa: SLF001
        ),
        "result_complete": RESULT.exists(),
        "result_sha256": file_sha256(RESULT) if RESULT.exists() else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-selection", action="store_true")
    action.add_argument("--validate-holdout", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-prepared-sha256")
    parser.add_argument("--expected-selection-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_selection:
        if not args.expected_implementation_sha256 or not args.expected_prepared_sha256:
            parser.error(
                "--freeze-selection requires --expected-implementation-sha256 and "
                "--expected-prepared-sha256"
            )
        payload = freeze_selection(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_prepared_sha256=args.expected_prepared_sha256,
        )
    elif args.validate_holdout:
        if not args.expected_selection_sha256:
            parser.error("--validate-holdout requires --expected-selection-sha256")
        payload = validate_holdout(expected_selection_sha256=args.expected_selection_sha256)
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
