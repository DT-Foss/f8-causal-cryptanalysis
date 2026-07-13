#!/usr/bin/env python3
"""Fit, select, null-test, and freeze the A220 trajectory Reader."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import sys
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from pathlib import Path
from typing import Any

os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("VECLIB_MAXIMUM_THREADS", "1")

import numpy as np
import scipy

from arx_carry_leak.factorial_trajectory import (
    ATOMIC_BUNDLE_ORDER,
    BUNDLE_ORDER,
    DUAL_BUNDLE_ORDER,
    FEATURE_COUNTS,
    FEATURE_FAMILY_ORDER,
    GEOMETRY_ORDER,
    MATCHED_NULL_SEED_LABEL,
    READOUT_ORDER,
    RIDGE_LAMBDA_GRID,
    CandidateIdentity,
    PairFeatureView,
    add_one_lower_tail_p,
    deterministic_matched_permutation_pairs,
    dual_schedule_score_matrix,
    evaluate_score_matrix,
    extract_pair_feature_views,
    fit_factorial_readout,
    permute_cluster_targets,
    rank_metrics,
    readout_from_dict,
    score_readout_views,
    select_candidate,
    training_matrix,
)

ROOT = Path(__file__).parents[2]
ORCHESTRATOR = Path(__file__).resolve()
PROTOCOL = ROOT / "research/configs/chacha20_round20_factorial_trajectory_transfer_v1.json"
COLLECTOR = ROOT / "research/experiments/chacha20_round20_factorial_trajectory_collect.py"
READER_TEST = ROOT / "tests/test_chacha20_round20_factorial_trajectory_read.py"
DEFAULT_INDEX = (
    ROOT / "research/results/v1/chacha20_round20_factorial_trajectory_fit_select_v1/index.json"
)
DEFAULT_SHARD_DIRECTORY = DEFAULT_INDEX.parent / "shards"
DEFAULT_OUTPUT = ROOT / "research/results/v1/chacha20_round20_factorial_trajectory_reader_v1.json"
DEFAULT_LOCK = ROOT / ".research_sealed/chacha20_round20_factorial_trajectory_reader_v1.lock"
DEFAULT_CHECKPOINT = (
    ROOT / ".research_sealed/chacha20_round20_factorial_trajectory_reader_v1.checkpoint.json"
)

SCHEMA = "chacha20-round20-factorial-trajectory-reader-v1"
ATTEMPT_ID = "A220"
FIT_KEYS = 32
SELECTION_KEYS = 20
NULL_REPLICATES = 64
NULL_WORKERS = 2
GEOMETRY_RUN_STEMS = {
    "numeric": "numeric",
    "reflected_gray8": "reflected_gray8",
    "formula_gray8": "formula_gray8",
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def _canonical_sha256(value: Any) -> str:
    return _sha256(_canonical_bytes(value))


def _atomic_json(path: Path, value: Any, *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()
        + b"\n"
    )
    if private:
        temporary.chmod(0o600)
    temporary.replace(path)
    if private:
        path.chmod(0o600)


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A220 Reader dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@contextmanager
def _exclusive_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        path.chmod(0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("another A220 Reader process holds the launch lock") from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _load_protocol() -> tuple[dict[str, Any], str]:
    protocol_sha256 = _file_sha256(PROTOCOL)
    protocol = json.loads(PROTOCOL.read_bytes())
    anchors = protocol.get("anchors", {})
    learning = protocol.get("learning_protocol", {})
    matched = protocol.get("selection_matched_null", {})
    if (
        protocol.get("schema") != "chacha20-round20-factorial-trajectory-transfer-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or learning.get("frozen_bundle_order") != list(BUNDLE_ORDER)
        or learning.get("frozen_feature_family_order") != list(FEATURE_FAMILY_ORDER)
        or learning.get("frozen_readout_order") != list(READOUT_ORDER)
        or learning.get("ridge_lambda_grid") != list(RIDGE_LAMBDA_GRID)
        or learning.get("atomic_model_fits") != 300
        or learning.get("bundle_selection_rows") != 450
        or matched.get("replicates") != NULL_REPLICATES
        or matched.get("seed_label") != MATCHED_NULL_SEED_LABEL
        or matched.get("permutation_pairs_sha256")
        != "8e7af50c509be00878d335acc0b49c4838f74ed9ae2c96ba9ca9f6938819a588"
        or anchors.get("factorial_trajectory_reader_path")
        != "src/arx_carry_leak/factorial_trajectory.py"
        or _file_sha256(ROOT / anchors["factorial_trajectory_reader_path"])
        != anchors.get("factorial_trajectory_reader_sha256")
        or _file_sha256(ROOT / anchors["factorial_trajectory_reader_test_path"])
        != anchors.get("factorial_trajectory_reader_test_sha256")
        or anchors.get("factorial_trajectory_reader_runner_path")
        != "research/experiments/chacha20_round20_factorial_trajectory_read.py"
        or _file_sha256(ORCHESTRATOR) != anchors.get("factorial_trajectory_reader_runner_sha256")
        or anchors.get("factorial_trajectory_reader_runner_test_path")
        != "tests/test_chacha20_round20_factorial_trajectory_read.py"
        or _file_sha256(READER_TEST)
        != anchors.get("factorial_trajectory_reader_runner_test_sha256")
    ):
        raise RuntimeError("A220 frozen Reader protocol gate failed")
    return protocol, protocol_sha256


def _load_corpus(
    *, protocol: Mapping[str, Any], protocol_sha256: str, index_path: Path, shard_directory: Path
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    index = json.loads(index_path.read_bytes())
    if (
        index.get("schema") != "chacha20-round20-factorial-trajectory-fit-select-index-v1"
        or index.get("attempt_id") != ATTEMPT_ID
        or index.get("protocol_sha256") != protocol_sha256
        or index.get("completion_gates", {}).get("all_52_key_shards_complete") is not True
        or index.get("completion_gates", {}).get("all_624_fresh_solver_processes_complete")
        is not True
        or len(index.get("verified_shards", [])) != FIT_KEYS + SELECTION_KEYS
        or _file_sha256(COLLECTOR) != index.get("collector_source_sha256")
    ):
        raise RuntimeError("A220 fit/select index is incomplete or has different provenance")

    collector = _import_path(COLLECTOR, "a220_reader_frozen_collector")
    if collector._load_protocol() != dict(protocol):
        raise RuntimeError("A220 collector and Reader protocol views differ")
    design = _import_path(
        ROOT / protocol["anchors"]["factorial_design_path"], "a220_reader_factorial_design"
    )
    rows = collector._factorial_rows(protocol, design)
    entries = index["verified_shards"]
    if [entry.get("key_label") for entry in entries] != [row["label"] for row in rows]:
        raise RuntimeError("A220 index does not retain the frozen factorial label order")

    shard_root = shard_directory.resolve()
    payloads = []
    for row, entry in zip(rows, entries, strict=True):
        path = (index_path.parent / entry["relative_path"]).resolve()
        if path.parent != shard_root or path.name != f"{row['label']}.measurement.json.zst":
            raise RuntimeError("A220 index shard path escapes the frozen shard directory")
        verified = collector._verify_shard(path, expected_row=row)
        for field in (
            "measurement_sha256",
            "measurement_bytes",
            "compressed_sha256",
            "compressed_bytes",
        ):
            if verified[field] != entry[field]:
                raise RuntimeError(f"A220 index/shard {field} differs for {row['label']}")
        payload = verified["payload"]
        identity = payload.get("key_factorial_identity", {})
        if (
            identity != row
            or identity.get("suffix_split") != "fit"
            or identity.get("prefix_split") not in {"fit", "select"}
            or payload.get("information_boundary", {}).get(
                "holdout_trajectory_opened_during_fit_select_collection"
            )
            is not False
        ):
            raise RuntimeError("A220 Reader corpus crossed the fit/select information boundary")
        payloads.append(payload)
    return rows, payloads, index


def _build_feature_corpus(
    payloads: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, list[PairFeatureView]]]:
    corpus = {
        bundle: {family: [] for family in FEATURE_FAMILY_ORDER} for bundle in ATOMIC_BUNDLE_ORDER
    }
    for payload in payloads:
        runs = payload["scientific_runs"]
        for geometry in GEOMETRY_ORDER:
            stem = GEOMETRY_RUN_STEMS[geometry]
            for schedule in ("staged_retained_resolve", "one_shot"):
                bundle = f"{geometry}__{schedule}"
                forward = runs[f"{stem}_forward__{schedule}"]
                reverse = runs[f"{stem}_reverse_same_anchor__{schedule}"]
                views = extract_pair_feature_views(forward, reverse)
                for family in FEATURE_FAMILY_ORDER:
                    corpus[bundle][family].append(views[family])
    if any(
        len(corpus[bundle][family]) != FIT_KEYS + SELECTION_KEYS
        for bundle in ATOMIC_BUNDLE_ORDER
        for family in FEATURE_FAMILY_ORDER
    ):
        raise RuntimeError("A220 feature corpus is incomplete")
    return corpus


def _training_labels(target_prefixes: Sequence[int]) -> np.ndarray:
    targets = np.asarray(target_prefixes)
    if (
        targets.shape != (FIT_KEYS,)
        or not np.issubdtype(targets.dtype, np.integer)
        or np.any((targets < 0) | (targets > 255))
    ):
        raise ValueError("A220 fit targets differ from the frozen 32-key panel")
    labels = np.zeros((FIT_KEYS, 256), dtype=np.uint8)
    labels[np.arange(FIT_KEYS), targets.astype(np.int64)] = 1
    return labels.reshape(-1)


def _prepare_feature_matrices(
    corpus: Mapping[str, Mapping[str, Sequence[PairFeatureView]]],
    fit_targets: Sequence[int],
) -> tuple[
    dict[tuple[str, str], tuple[np.ndarray, tuple[str, ...]]],
    dict[tuple[str, str], Sequence[PairFeatureView]],
    dict[str, dict[str, str]],
]:
    training = {}
    selection = {}
    digests: dict[str, dict[str, str]] = {}
    for bundle in ATOMIC_BUNDLE_ORDER:
        digests[bundle] = {}
        for family in FEATURE_FAMILY_ORDER:
            views = corpus[bundle][family]
            matrix, _, names = training_matrix(views[:FIT_KEYS], fit_targets)
            selected = views[FIT_KEYS:]
            if len(selected) != SELECTION_KEYS:
                raise RuntimeError("A220 selection feature panel is incomplete")
            training[(bundle, family)] = (matrix, names)
            selection[(bundle, family)] = selected
            raw = (
                matrix.astype("<f8", copy=False).tobytes()
                + np.row_stack([view.matrix for view in selected])
                .astype("<f8", copy=False)
                .tobytes()
            )
            digests[bundle][family] = _sha256(raw)
    return training, selection, digests


def _score_sha256(scores: np.ndarray) -> str:
    values = np.asarray(scores, dtype="<f8")
    if values.shape != (SELECTION_KEYS, 256) or not np.isfinite(values).all():
        raise RuntimeError("A220 selection score matrix is malformed")
    return _sha256(values.tobytes())


def _evaluate_grid(
    *,
    training: Mapping[tuple[str, str], tuple[np.ndarray, tuple[str, ...]]],
    selection: Mapping[tuple[str, str], Sequence[PairFeatureView]],
    fit_targets: Sequence[int],
    selection_targets: Sequence[int],
    retain_grid: bool,
) -> dict[str, Any]:
    labels = _training_labels(fit_targets)
    atomic_readouts = {}
    score_matrices: dict[CandidateIdentity, np.ndarray] = {}
    metrics = {}

    for bundle in ATOMIC_BUNDLE_ORDER:
        for family in FEATURE_FAMILY_ORDER:
            matrix, names = training[(bundle, family)]
            for kind in READOUT_ORDER:
                for ridge_lambda in RIDGE_LAMBDA_GRID:
                    identity = CandidateIdentity(bundle, family, kind, ridge_lambda)
                    readout = fit_factorial_readout(
                        matrix,
                        labels,
                        kind=kind,
                        feature_family=family,
                        feature_names=names,
                        ridge_lambda=ridge_lambda,
                    )
                    scores = score_readout_views(readout, selection[(bundle, family)])
                    atomic_readouts[identity] = readout
                    score_matrices[identity] = scores
                    metrics[identity] = evaluate_score_matrix(scores, selection_targets)

    for geometry in GEOMETRY_ORDER:
        for family in FEATURE_FAMILY_ORDER:
            for kind in READOUT_ORDER:
                for ridge_lambda in RIDGE_LAMBDA_GRID:
                    staged = CandidateIdentity(
                        f"{geometry}__staged_retained_resolve", family, kind, ridge_lambda
                    )
                    one_shot = CandidateIdentity(
                        f"{geometry}__one_shot", family, kind, ridge_lambda
                    )
                    dual = CandidateIdentity(
                        f"{geometry}__dual_schedule", family, kind, ridge_lambda
                    )
                    scores = dual_schedule_score_matrix(
                        score_matrices[staged], score_matrices[one_shot]
                    )
                    score_matrices[dual] = scores
                    metrics[dual] = evaluate_score_matrix(scores, selection_targets)

    ordered_identities = [
        CandidateIdentity(bundle, family, kind, ridge_lambda)
        for bundle in BUNDLE_ORDER
        for family in FEATURE_FAMILY_ORDER
        for kind in READOUT_ORDER
        for ridge_lambda in RIDGE_LAMBDA_GRID
    ]
    if (
        len(atomic_readouts) != 300
        or len(ordered_identities) != 450
        or set(score_matrices) != set(ordered_identities)
        or set(metrics) != set(ordered_identities)
    ):
        raise RuntimeError("A220 fit/select candidate grid is not exactly 300 fits and 450 rows")
    selected, selected_metrics = select_candidate(
        [(identity, metrics[identity]) for identity in ordered_identities]
    )

    if selected.bundle_id in DUAL_BUNDLE_ORDER:
        geometry = selected.bundle_id.removesuffix("__dual_schedule")
        constituent_identities = (
            CandidateIdentity(
                f"{geometry}__staged_retained_resolve",
                selected.feature_family,
                selected.readout_kind,
                selected.ridge_lambda,
            ),
            CandidateIdentity(
                f"{geometry}__one_shot",
                selected.feature_family,
                selected.readout_kind,
                selected.ridge_lambda,
            ),
        )
    else:
        constituent_identities = (selected,)
    selected_readouts = {
        identity.bundle_id: atomic_readouts[identity].as_dict()
        for identity in constituent_identities
    }
    candidate_grid = [
        {
            **identity.as_dict(),
            "selection_metrics": dict(metrics[identity]),
            "selection_score_sha256": _score_sha256(score_matrices[identity]),
        }
        for identity in ordered_identities
    ]
    result = {
        "selected_identity": selected.as_dict(),
        "selected_metrics": dict(selected_metrics),
        "selected_score_sha256": _score_sha256(score_matrices[selected]),
        "selected_constituent_readouts": selected_readouts,
        "candidate_grid_sha256": _canonical_sha256(candidate_grid),
    }
    if retain_grid:
        result["candidate_grid"] = candidate_grid
    return result


def _null_record(
    *,
    pair: Any,
    training: Mapping[tuple[str, str], tuple[np.ndarray, tuple[str, ...]]],
    selection: Mapping[tuple[str, str], Sequence[PairFeatureView]],
    fit_cluster_ids: Sequence[str],
    fit_targets: Sequence[int],
    selection_cluster_ids: Sequence[str],
    selection_targets: Sequence[int],
) -> dict[str, Any]:
    null_fit_targets = permute_cluster_targets(
        fit_cluster_ids, fit_targets, pair.fit_cluster_permutation
    )
    null_selection_targets = permute_cluster_targets(
        selection_cluster_ids, selection_targets, pair.selection_cluster_permutation
    )
    evaluated = _evaluate_grid(
        training=training,
        selection=selection,
        fit_targets=null_fit_targets,
        selection_targets=null_selection_targets,
        retain_grid=False,
    )
    return {
        **pair.as_dict(),
        "permuted_fit_targets_sha256": _canonical_sha256(null_fit_targets),
        "permuted_selection_targets_sha256": _canonical_sha256(null_selection_targets),
        "selected_identity": evaluated["selected_identity"],
        "selected_selection_metrics": evaluated["selected_metrics"],
        "selected_score_sha256": evaluated["selected_score_sha256"],
        "candidate_grid_sha256": evaluated["candidate_grid_sha256"],
    }


def _checkpoint_identity(
    *,
    protocol_sha256: str,
    source_sha256: str,
    index_path: Path,
    feature_digests: Mapping[str, Any],
    fit_targets: Sequence[int],
    selection_targets: Sequence[int],
) -> dict[str, Any]:
    return {
        "schema": "chacha20-round20-factorial-trajectory-reader-checkpoint-v1",
        "protocol_sha256": protocol_sha256,
        "reader_runner_sha256": source_sha256,
        "fit_select_index_sha256": _file_sha256(index_path),
        "feature_matrix_sha256": dict(feature_digests),
        "fit_targets_sha256": _canonical_sha256(fit_targets),
        "selection_targets_sha256": _canonical_sha256(selection_targets),
    }


def _validate_observed_grid(observed: Any) -> None:
    if not isinstance(observed, dict) or set(observed) != {
        "selected_identity",
        "selected_metrics",
        "selected_score_sha256",
        "selected_constituent_readouts",
        "candidate_grid_sha256",
        "candidate_grid",
    }:
        raise RuntimeError("A220 Reader observed-grid checkpoint schema differs")
    expected_identities = [
        CandidateIdentity(bundle, family, kind, ridge_lambda)
        for bundle in BUNDLE_ORDER
        for family in FEATURE_FAMILY_ORDER
        for kind in READOUT_ORDER
        for ridge_lambda in RIDGE_LAMBDA_GRID
    ]
    grid = observed["candidate_grid"]
    if (
        not isinstance(grid, list)
        or len(grid) != 450
        or observed.get("candidate_grid_sha256") != _canonical_sha256(grid)
    ):
        raise RuntimeError("A220 Reader observed candidate grid is malformed")
    candidates = []
    for expected, record in zip(expected_identities, grid, strict=True):
        if not isinstance(record, dict):
            raise RuntimeError("A220 Reader candidate-grid row is malformed")
        try:
            identity = CandidateIdentity(
                str(record["bundle_id"]),
                str(record["feature_family"]),
                str(record["readout_kind"]),
                float(record["ridge_lambda"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError("A220 Reader candidate-grid identity differs") from error
        if (
            identity != expected
            or record.get("run_count") != identity.run_count
            or set(record)
            != {
                "bundle_id",
                "feature_family",
                "readout_kind",
                "ridge_lambda",
                "run_count",
                "selection_metrics",
                "selection_score_sha256",
            }
            or not isinstance(record.get("selection_metrics"), dict)
            or not isinstance(record.get("selection_score_sha256"), str)
            or len(record["selection_score_sha256"]) != 64
        ):
            raise RuntimeError("A220 Reader candidate-grid row differs")
        try:
            recomputed_metrics = rank_metrics(record["selection_metrics"]["ranks"])
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError("A220 Reader candidate-grid metrics differ") from error
        if recomputed_metrics != record["selection_metrics"]:
            raise RuntimeError("A220 Reader candidate-grid metric derivation differs")
        candidates.append((identity, record["selection_metrics"]))
    selected, selected_metrics = select_candidate(candidates)
    selected_index = expected_identities.index(selected)
    if (
        observed.get("selected_identity") != selected.as_dict()
        or observed.get("selected_metrics") != selected_metrics
        or observed.get("selected_score_sha256") != grid[selected_index]["selection_score_sha256"]
    ):
        raise RuntimeError("A220 Reader selected checkpoint candidate differs")
    if selected.bundle_id in DUAL_BUNDLE_ORDER:
        geometry = selected.bundle_id.removesuffix("__dual_schedule")
        expected_bundles = {
            f"{geometry}__staged_retained_resolve",
            f"{geometry}__one_shot",
        }
    else:
        expected_bundles = {selected.bundle_id}
    serialized = observed.get("selected_constituent_readouts")
    if not isinstance(serialized, dict) or set(serialized) != expected_bundles:
        raise RuntimeError("A220 Reader checkpoint constituent set differs")
    for value in serialized.values():
        restored = readout_from_dict(value)
        if (
            restored.feature_family != selected.feature_family
            or restored.kind != selected.readout_kind
            or restored.ridge_lambda != selected.ridge_lambda
        ):
            raise RuntimeError("A220 Reader checkpoint constituent model differs")


def _verify_selected_readout(
    observed: Mapping[str, Any],
    *,
    selection: Mapping[tuple[str, str], Sequence[PairFeatureView]],
    selection_targets: Sequence[int],
) -> None:
    selected_raw = observed["selected_identity"]
    selected = CandidateIdentity(
        str(selected_raw["bundle_id"]),
        str(selected_raw["feature_family"]),
        str(selected_raw["readout_kind"]),
        float(selected_raw["ridge_lambda"]),
    )
    serialized = observed["selected_constituent_readouts"]
    if selected.bundle_id in DUAL_BUNDLE_ORDER:
        geometry = selected.bundle_id.removesuffix("__dual_schedule")
        staged_bundle = f"{geometry}__staged_retained_resolve"
        one_shot_bundle = f"{geometry}__one_shot"
        staged = readout_from_dict(serialized[staged_bundle])
        one_shot = readout_from_dict(serialized[one_shot_bundle])
        scores = dual_schedule_score_matrix(
            score_readout_views(staged, selection[(staged_bundle, selected.feature_family)]),
            score_readout_views(one_shot, selection[(one_shot_bundle, selected.feature_family)]),
        )
    else:
        readout = readout_from_dict(serialized[selected.bundle_id])
        scores = score_readout_views(
            readout, selection[(selected.bundle_id, selected.feature_family)]
        )
    if (
        _score_sha256(scores) != observed["selected_score_sha256"]
        or evaluate_score_matrix(scores, selection_targets) != observed["selected_metrics"]
    ):
        raise RuntimeError("A220 frozen selected Reader does not reproduce its selection result")


def _load_reader_checkpoint(
    path: Path,
    *,
    identity: Mapping[str, Any],
    pairs: Sequence[Any],
) -> dict[str, Any]:
    if not path.exists():
        return {**dict(identity), "observed": None, "null_records": []}
    checkpoint = json.loads(path.read_bytes())
    if (
        set(checkpoint) != {*identity, "observed", "null_records"}
        or any(checkpoint.get(key) != value for key, value in identity.items())
        or not isinstance(checkpoint.get("null_records"), list)
    ):
        raise RuntimeError("A220 Reader checkpoint identity differs")
    observed = checkpoint.get("observed")
    if observed is not None:
        _validate_observed_grid(observed)
    elif checkpoint["null_records"]:
        raise RuntimeError("A220 Reader null checkpoint precedes the observed grid")
    expected_pairs = {pair.replicate: pair.as_dict() for pair in pairs}
    seen = set()
    for record in checkpoint["null_records"]:
        replicate = record.get("replicate") if isinstance(record, dict) else None
        if (
            not isinstance(replicate, int)
            or isinstance(replicate, bool)
            or replicate not in expected_pairs
            or replicate in seen
            or any(record.get(key) != value for key, value in expected_pairs[replicate].items())
            or set(record)
            != {
                "replicate",
                "fit_cluster_permutation",
                "selection_cluster_permutation",
                "permuted_fit_targets_sha256",
                "permuted_selection_targets_sha256",
                "selected_identity",
                "selected_selection_metrics",
                "selected_score_sha256",
                "candidate_grid_sha256",
            }
            or not isinstance(record.get("candidate_grid_sha256"), str)
            or len(record["candidate_grid_sha256"]) != 64
            or not isinstance(record.get("selected_score_sha256"), str)
            or len(record["selected_score_sha256"]) != 64
            or not isinstance(record.get("permuted_fit_targets_sha256"), str)
            or len(record["permuted_fit_targets_sha256"]) != 64
            or not isinstance(record.get("permuted_selection_targets_sha256"), str)
            or len(record["permuted_selection_targets_sha256"]) != 64
            or not isinstance(record.get("selected_selection_metrics"), dict)
        ):
            raise RuntimeError("A220 Reader null checkpoint is malformed")
        try:
            selected = record["selected_identity"]
            CandidateIdentity(
                str(selected["bundle_id"]),
                str(selected["feature_family"]),
                str(selected["readout_kind"]),
                float(selected["ridge_lambda"]),
            )
            recomputed_metrics = rank_metrics(record["selected_selection_metrics"]["ranks"])
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError("A220 Reader null checkpoint derivation differs") from error
        if (
            selected.get("run_count")
            != CandidateIdentity(
                str(selected["bundle_id"]),
                str(selected["feature_family"]),
                str(selected["readout_kind"]),
                float(selected["ridge_lambda"]),
            ).run_count
            or recomputed_metrics != record["selected_selection_metrics"]
        ):
            raise RuntimeError("A220 Reader null checkpoint metric derivation differs")
        seen.add(replicate)
    checkpoint["null_records"].sort(key=lambda record: int(record["replicate"]))
    return checkpoint


def run(
    *,
    index_path: Path = DEFAULT_INDEX,
    shard_directory: Path = DEFAULT_SHARD_DIRECTORY,
    output_path: Path = DEFAULT_OUTPUT,
    lock_path: Path = DEFAULT_LOCK,
    checkpoint_path: Path = DEFAULT_CHECKPOINT,
    null_workers: int = NULL_WORKERS,
) -> dict[str, Any]:
    """Freeze one Reader using only the completed A220 fit/select corpus."""
    if null_workers != NULL_WORKERS:
        raise ValueError("A220 null concurrency differs from the frozen two-worker plan")
    with _exclusive_lock(lock_path):
        protocol, protocol_sha256 = _load_protocol()
        source_sha256 = _file_sha256(ORCHESTRATOR)
        rows, payloads, index = _load_corpus(
            protocol=protocol,
            protocol_sha256=protocol_sha256,
            index_path=index_path,
            shard_directory=shard_directory,
        )
        fit_rows = rows[:FIT_KEYS]
        selection_rows = rows[FIT_KEYS:]
        if (
            len(fit_rows) != FIT_KEYS
            or len(selection_rows) != SELECTION_KEYS
            or any(row["prefix_split"] != "fit" for row in fit_rows)
            or any(row["prefix_split"] != "select" for row in selection_rows)
            or any(row["suffix_split"] != "fit" for row in rows)
        ):
            raise RuntimeError("A220 fit/selection panels differ from the frozen split")
        fit_targets = tuple(int(row["prefix8"]) for row in fit_rows)
        selection_targets = tuple(int(row["prefix8"]) for row in selection_rows)
        fit_cluster_ids = tuple(f"fit:{row['prefix_index']}" for row in fit_rows)
        selection_cluster_ids = tuple(f"select:{row['prefix_index']}" for row in selection_rows)

        corpus = _build_feature_corpus(payloads)
        training, selection, feature_digests = _prepare_feature_matrices(corpus, fit_targets)
        pairs = deterministic_matched_permutation_pairs(
            protocol["selection_matched_null"]["seed_label"],
            replicates=NULL_REPLICATES,
        )
        checkpoint_identity = _checkpoint_identity(
            protocol_sha256=protocol_sha256,
            source_sha256=source_sha256,
            index_path=index_path,
            feature_digests=feature_digests,
            fit_targets=fit_targets,
            selection_targets=selection_targets,
        )
        checkpoint = _load_reader_checkpoint(
            checkpoint_path, identity=checkpoint_identity, pairs=pairs
        )
        observed = checkpoint["observed"]
        if observed is None:
            observed = _evaluate_grid(
                training=training,
                selection=selection,
                fit_targets=fit_targets,
                selection_targets=selection_targets,
                retain_grid=True,
            )
            checkpoint["observed"] = observed
            _atomic_json(checkpoint_path, checkpoint, private=True)
        _verify_selected_readout(
            observed,
            selection=selection,
            selection_targets=selection_targets,
        )
        print(
            "A220 observed Reader selected "
            f"{observed['selected_identity']['bundle_id']} "
            f"mean_log2_rank={observed['selected_metrics']['mean_log2_rank']:.9f}",
            flush=True,
        )

        null_records = list(checkpoint["null_records"])
        completed_replicates = {int(record["replicate"]) for record in null_records}
        pending_pairs = [pair for pair in pairs if pair.replicate not in completed_replicates]
        pool = ThreadPoolExecutor(max_workers=NULL_WORKERS, thread_name_prefix="a220-null")
        iterator = iter(pending_pairs)
        active = {}

        def submit_next_null() -> bool:
            try:
                pair = next(iterator)
            except StopIteration:
                return False
            future = pool.submit(
                _null_record,
                pair=pair,
                training=training,
                selection=selection,
                fit_cluster_ids=fit_cluster_ids,
                fit_targets=fit_targets,
                selection_cluster_ids=selection_cluster_ids,
                selection_targets=selection_targets,
            )
            active[future] = pair.replicate
            return True

        try:
            for _ in range(NULL_WORKERS):
                submit_next_null()
            while active:
                future = next(as_completed(tuple(active)))
                active.pop(future)
                record = future.result()
                null_records.append(record)
                null_records.sort(key=lambda row: int(row["replicate"]))
                checkpoint["null_records"] = null_records
                _atomic_json(checkpoint_path, checkpoint, private=True)
                print(f"A220 matched null {record['replicate'] + 1}/64 complete", flush=True)
                submit_next_null()
        except BaseException:
            for future in active:
                future.cancel()
            raise
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
        null_records.sort(key=lambda record: int(record["replicate"]))
        if [record["replicate"] for record in null_records] != list(range(NULL_REPLICATES)):
            raise RuntimeError("A220 matched-null replicate cover differs")
        verified_checkpoint = _load_reader_checkpoint(
            checkpoint_path, identity=checkpoint_identity, pairs=pairs
        )
        if verified_checkpoint != checkpoint:
            raise RuntimeError("A220 Reader checkpoint readback differs")
        observed_statistic = float(observed["selected_metrics"]["mean_log2_rank"])
        null_statistics = [
            float(record["selected_selection_metrics"]["mean_log2_rank"]) for record in null_records
        ]
        selection_p = add_one_lower_tail_p(observed_statistic, null_statistics)

        input_manifest = [
            {
                key: entry[key]
                for key in (
                    "key_label",
                    "prefix_split",
                    "prefix_index",
                    "suffix_split",
                    "suffix_index",
                    "relative_path",
                    "measurement_sha256",
                    "measurement_bytes",
                    "compressed_sha256",
                    "compressed_bytes",
                )
            }
            for entry in index["verified_shards"]
        ]
        completion = {
            "all_52_fit_select_shards_verified": len(payloads) == 52,
            "all_624_fresh_solver_processes_in_verified_index": index["completion_gates"][
                "all_624_fresh_solver_processes_complete"
            ],
            "exactly_300_atomic_models_fit": True,
            "exactly_450_bundle_rows_evaluated": len(observed["candidate_grid"]) == 450,
            "all_64_matched_cluster_nulls_complete": len(null_records) == 64,
            "reader_resume_checkpoint_verified": len(verified_checkpoint["null_records"]) == 64,
            "one_reader_selected_and_serialized": len(observed["selected_constituent_readouts"])
            in {1, 2},
            "reader_source_unchanged": _file_sha256(ORCHESTRATOR) == source_sha256,
            "holdout_trajectory_not_opened": True,
            "future_prospective_target_not_opened": True,
        }
        if not all(value is True for value in completion.values()):
            raise RuntimeError("A220 Reader completion gate failed")
        result = {
            "schema": SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "evidence_stage": "FULLROUND_R20_FACTORIAL_READER_FROZEN_BEFORE_HOLDOUT",
            "protocol_sha256": protocol_sha256,
            "reader_runner_sha256": source_sha256,
            "reader_checkpoint_sha256": _file_sha256(checkpoint_path),
            "software_versions": {
                "python": sys.version,
                "numpy": np.__version__,
                "scipy": scipy.__version__,
            },
            "factorial_trajectory_reader_sha256": protocol["anchors"][
                "factorial_trajectory_reader_sha256"
            ],
            "ridge_backend_sha256": protocol["anchors"]["ridge_backend_sha256"],
            "collector_source_sha256": index["collector_source_sha256"],
            "fit_select_index_sha256": _file_sha256(index_path),
            "fit_select_input_manifest": input_manifest,
            "fit_select_input_manifest_sha256": _canonical_sha256(input_manifest),
            "feature_matrix_sha256": feature_digests,
            "fit_panel": {
                "labels": [row["label"] for row in fit_rows],
                "labels_sha256": _canonical_sha256([row["label"] for row in fit_rows]),
                "prefix_cluster_ids": list(fit_cluster_ids),
                "target_prefixes_sha256": _canonical_sha256(fit_targets),
                "keys": FIT_KEYS,
                "cell_rows": FIT_KEYS * 256,
            },
            "selection_panel": {
                "labels": [row["label"] for row in selection_rows],
                "labels_sha256": _canonical_sha256([row["label"] for row in selection_rows]),
                "prefix_cluster_ids": list(selection_cluster_ids),
                "target_prefixes_sha256": _canonical_sha256(selection_targets),
                "keys": SELECTION_KEYS,
                "cell_rows": SELECTION_KEYS * 256,
            },
            "grid_definition": {
                "bundle_order": list(BUNDLE_ORDER),
                "feature_family_order": list(FEATURE_FAMILY_ORDER),
                "feature_counts": dict(FEATURE_COUNTS),
                "readout_order": list(READOUT_ORDER),
                "ridge_lambda_grid": list(RIDGE_LAMBDA_GRID),
                "atomic_models": 300,
                "bundle_rows": 450,
            },
            "observed_candidate_grid": observed.pop("candidate_grid"),
            "selected_reader": observed,
            "selection_matched_null": {
                "seed_label": MATCHED_NULL_SEED_LABEL,
                "permutation_pairs_sha256": protocol["selection_matched_null"][
                    "permutation_pairs_sha256"
                ],
                "replicates": null_records,
                "observed_selected_mean_log2_rank": observed_statistic,
                "null_selected_mean_log2_ranks": null_statistics,
                "add_one_lower_tail_p": selection_p,
            },
            "information_boundary": {
                "fit_select_measurements_loaded": True,
                "holdout_measurements_loaded": False,
                "future_prospective_target_loaded": False,
                "target_labels_used_for_fit": "32_fit_prefix_labels_only",
                "target_labels_used_for_selection": "20_selection_prefix_labels_only",
                "suffix_specific_target_floor_or_key_suffix_feature_used": False,
                "reader_frozen_before_any_holdout_trajectory_process": True,
            },
            "completion_gates": completion,
        }
        if _file_sha256(ORCHESTRATOR) != source_sha256:
            raise RuntimeError("A220 Reader runner changed before output write")
        if output_path.exists():
            existing = json.loads(output_path.read_bytes())
            if existing != result:
                raise RuntimeError("A220 frozen Reader output already exists with different bytes")
        else:
            _atomic_json(output_path, result)
        reread = json.loads(output_path.read_bytes())
        if reread != result or _canonical_sha256(reread) != _canonical_sha256(result):
            raise RuntimeError("A220 frozen Reader output readback differs")
        return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    parser.add_argument("--shard-directory", type=Path, default=DEFAULT_SHARD_DIRECTORY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--null-workers", type=int, default=NULL_WORKERS)
    arguments = parser.parse_args()
    result = run(
        index_path=arguments.index,
        shard_directory=arguments.shard_directory,
        output_path=arguments.output,
        lock_path=arguments.lock,
        checkpoint_path=arguments.checkpoint,
        null_workers=arguments.null_workers,
    )
    print(
        json.dumps(
            {
                "output": str(arguments.output),
                "output_sha256": _file_sha256(arguments.output),
                "selected_reader": result["selected_reader"]["selected_identity"],
                "selection_matched_null_p": result["selection_matched_null"][
                    "add_one_lower_tail_p"
                ],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
