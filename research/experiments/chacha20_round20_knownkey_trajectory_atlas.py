#!/usr/bin/env python3
"""Fit and freeze the target-blind A218 R20 trajectory readout."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.trajectory_atlas import (
    FEATURE_FAMILY_ORDER,
    READOUT_ORDER,
    FeatureView,
    LinearReadout,
    cell_order,
    exact_rank,
    extract_feature_views,
    fit_linear_readout,
    rank_metrics,
)

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
PROTOCOL = RESEARCH / "configs/chacha20_round20_knownkey_trajectory_atlas_v1.json"
PROTOCOL_SHA256 = "037b415e25e0956a2d8b13cd0bd62a838c50dce6b831ddc8734bd03ed2ec44c7"
CORPUS = RESEARCH / "results/v1/chacha20_round20_knownkey_trajectory_corpus_v1.json"
TARGET = RESEARCH / "results/v1/chacha20_round20_target_trajectory_v1.json"
DEFAULT_OUTPUT = (
    RESEARCH / "results/v1/chacha20_round20_knownkey_trajectory_atlas_v1_prereveal.json"
)
RIDGE_GRID = (0.01, 0.1, 1.0, 10.0, 100.0)
NULL_REPLICATES = 64
NULL_SEED_LABEL = "f8-causal:A218:selection-matched-complete-key-null:v1"


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


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    )
    temporary.replace(path)


def _load_artifact(path: Path, schema: str) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if (
        value.get("schema") != schema
        or value.get("attempt_id") != "A218"
        or value.get("protocol_sha256") != PROTOCOL_SHA256
        or value.get("complete") is not True
        or value.get("secret_file_or_target_label_read") is not False
    ):
        raise RuntimeError(f"A218 input artifact identity failed: {path}")
    return value


def _feature_hash(view: FeatureView) -> str:
    return _sha256(
        _canonical_bytes(list(view.names)) + np.asarray(view.matrix, dtype="<f8").tobytes()
    )


def _prepare_challenges(rows: Sequence[dict[str, Any]], *, known: bool) -> list[dict[str, Any]]:
    prepared = []
    for row in rows:
        views = extract_feature_views(row["trajectories"])
        material: dict[str, Any] = {
            "split": row.get("split"),
            "index": row.get("index"),
            "label": row["label"],
            "views": views,
            "feature_sha256": {
                family: _feature_hash(views[family]) for family in FEATURE_FAMILY_ORDER
            },
        }
        if known:
            low20 = int(row["known_low20"])
            if row["target_prefix8"] != f"{low20 >> 12:08b}":
                raise RuntimeError("A218 known challenge label differs")
            material["target_prefix"] = low20 >> 12
        prepared.append(material)
    return prepared


def _training_matrix(
    challenges: Sequence[dict[str, Any]],
    *,
    family: str,
    target_prefixes: Sequence[int],
) -> tuple[np.ndarray, np.ndarray, tuple[str, ...]]:
    if len(challenges) != len(target_prefixes):
        raise ValueError("A218 target-prefix override length differs")
    names = challenges[0]["views"][family].names
    matrices = []
    labels = []
    for challenge, target in zip(challenges, target_prefixes, strict=True):
        view = challenge["views"][family]
        if view.names != names or target < 0 or target >= 256:
            raise RuntimeError("A218 training feature identity differs")
        target_labels = np.zeros(256, dtype=np.uint8)
        target_labels[int(target)] = 1
        matrices.append(view.matrix)
        labels.append(target_labels)
    return np.vstack(matrices), np.concatenate(labels), names


def _evaluate(
    model: LinearReadout,
    challenges: Sequence[dict[str, Any]],
    target_prefixes: Sequence[int],
) -> dict[str, Any]:
    if len(challenges) != len(target_prefixes):
        raise ValueError("A218 validation label override length differs")
    ranks = [
        exact_rank(
            model.scores(challenge["views"][model.feature_family].matrix),
            int(target),
        )
        for challenge, target in zip(challenges, target_prefixes, strict=True)
    ]
    return rank_metrics(ranks)


def _selection_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    metrics = row["validation"]
    return (
        float(metrics["mean_log2_rank"]),
        float(metrics["median_rank"]),
        -int(metrics["hit_at_16"]),
        -float(metrics["mean_reciprocal_rank"]),
        int(row["feature_count"]),
        FEATURE_FAMILY_ORDER.index(row["feature_family"]),
        READOUT_ORDER.index(row["readout"]),
        RIDGE_GRID.index(float(row["ridge_lambda"])),
    )


def _fit_grid(
    training: Sequence[dict[str, Any]],
    validation: Sequence[dict[str, Any]],
    *,
    training_prefixes: Sequence[int],
    validation_prefixes: Sequence[int],
) -> tuple[list[dict[str, Any]], dict[str, Any], LinearReadout]:
    rows: list[dict[str, Any]] = []
    models: dict[tuple[str, str, float], LinearReadout] = {}
    for family in FEATURE_FAMILY_ORDER:
        matrix, labels, names = _training_matrix(
            training,
            family=family,
            target_prefixes=training_prefixes,
        )
        for kind in READOUT_ORDER:
            for ridge_lambda in RIDGE_GRID:
                model = fit_linear_readout(
                    matrix,
                    labels,
                    kind=kind,
                    feature_family=family,
                    feature_names=names,
                    ridge_lambda=ridge_lambda,
                )
                models[(family, kind, ridge_lambda)] = model
                rows.append(
                    {
                        "feature_family": family,
                        "feature_count": len(names),
                        "readout": kind,
                        "ridge_lambda": ridge_lambda,
                        "validation": _evaluate(model, validation, validation_prefixes),
                        "model_diagnostics": dict(model.diagnostics),
                    }
                )
    selected = min(rows, key=_selection_key)
    identity = (
        selected["feature_family"],
        selected["readout"],
        float(selected["ridge_lambda"]),
    )
    return rows, selected, models[identity]


def _null_permutations() -> list[tuple[list[int], list[int]]]:
    seed = int.from_bytes(hashlib.shake_256(NULL_SEED_LABEL.encode()).digest(16), "little")
    rng = np.random.default_rng(seed)
    identity_train = np.arange(16)
    identity_validation = np.arange(8)
    observed: set[tuple[tuple[int, ...], tuple[int, ...]]] = set()
    rows = []
    while len(rows) < NULL_REPLICATES:
        train = rng.permutation(16)
        validation = rng.permutation(8)
        key = (tuple(int(value) for value in train), tuple(int(value) for value in validation))
        if (
            np.array_equal(train, identity_train)
            or np.array_equal(validation, identity_validation)
            or key in observed
        ):
            continue
        observed.add(key)
        rows.append((list(key[0]), list(key[1])))
    return rows


def _verify_existing(path: Path, corpus_sha: str, target_sha: str) -> dict[str, Any]:
    payload = json.loads(path.read_bytes())
    measurement = {key: payload[key] for key in payload["measurement_hash_scope"]}
    if (
        payload.get("schema") != "chacha20-round20-knownkey-trajectory-atlas-prereveal-v1"
        or payload.get("protocol_sha256") != PROTOCOL_SHA256
        or payload.get("corpus_sha256") != corpus_sha
        or payload.get("target_trajectory_sha256") != target_sha
        or payload.get("secret_file_or_target_label_read") is not False
        or payload.get("measurement_sha256") != _canonical_sha256(measurement)
    ):
        raise RuntimeError("existing A218 prereveal artifact fails gates")
    return payload


def run(output: Path) -> dict[str, Any]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A218 frozen protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    learning = protocol["learning_protocol"]
    null_protocol = protocol["selection_matched_null"]
    if (
        tuple(learning["ridge_lambda_grid"]) != RIDGE_GRID
        or null_protocol["replicates"] != NULL_REPLICATES
        or null_protocol["seed_label"] != NULL_SEED_LABEL
    ):
        raise RuntimeError("A218 learning constants differ from frozen protocol")
    corpus_sha = _file_sha256(CORPUS)
    target_sha = _file_sha256(TARGET)
    if output.exists():
        return _verify_existing(output, corpus_sha, target_sha)

    corpus = _load_artifact(CORPUS, "chacha20-round20-knownkey-trajectory-corpus-v1")
    target_artifact = _load_artifact(TARGET, "chacha20-round20-target-trajectory-v1")
    if (
        corpus["public_target_sha256"] != target_artifact["public_target_sha256"]
        or corpus["target_commitment_sha256"] != target_artifact["target_commitment_sha256"]
        or len(corpus["challenges"]) != 24
        or len(target_artifact["challenges"]) != 1
    ):
        raise RuntimeError("A218 corpus and target trajectory identities differ")

    known = _prepare_challenges(corpus["challenges"], known=True)
    training = [row for row in known if row["split"] == "train"]
    validation = [row for row in known if row["split"] == "validation"]
    target = _prepare_challenges(target_artifact["challenges"], known=False)[0]
    if len(training) != 16 or len(validation) != 8:
        raise RuntimeError("A218 key split differs")
    training_prefixes = [int(row["target_prefix"]) for row in training]
    validation_prefixes = [int(row["target_prefix"]) for row in validation]

    print("A218 fit observed complete grid", flush=True)
    observed_grid, selected, selected_model = _fit_grid(
        training,
        validation,
        training_prefixes=training_prefixes,
        validation_prefixes=validation_prefixes,
    )
    null_rows = []
    for null_index, (train_permutation, validation_permutation) in enumerate(_null_permutations()):
        print(f"A218 selection-matched null {null_index + 1:02d}/{NULL_REPLICATES}", flush=True)
        null_training = [training_prefixes[index] for index in train_permutation]
        null_validation = [validation_prefixes[index] for index in validation_permutation]
        grid, null_selected, _ = _fit_grid(
            training,
            validation,
            training_prefixes=null_training,
            validation_prefixes=null_validation,
        )
        null_rows.append(
            {
                "null_index": null_index,
                "training_key_permutation": train_permutation,
                "validation_key_permutation": validation_permutation,
                "changed_training_prefix_labels": sum(
                    left != right
                    for left, right in zip(training_prefixes, null_training, strict=True)
                ),
                "changed_validation_prefix_labels": sum(
                    left != right
                    for left, right in zip(validation_prefixes, null_validation, strict=True)
                ),
                "selection_grid": grid,
                "selected": null_selected,
            }
        )
    observed_statistic = float(selected["validation"]["mean_log2_rank"])
    lower_tail = (
        1
        + sum(
            float(row["selected"]["validation"]["mean_log2_rank"]) <= observed_statistic
            for row in null_rows
        )
    ) / (NULL_REPLICATES + 1)
    null_summary = {
        "replicates": NULL_REPLICATES,
        "rows": null_rows,
        "observed_selected_mean_log2_rank": observed_statistic,
        "lower_tail_plus_one_p": lower_tail,
        "all_complete_key_units_preserved": True,
        "full_candidate_selection_repeated": True,
    }

    target_view = target["views"][selected_model.feature_family]
    target_scores = selected_model.scores(target_view.matrix)
    order = cell_order(target_scores)
    target_readout = {
        "selected_feature_family": selected_model.feature_family,
        "selected_readout": selected_model.kind,
        "selected_ridge_lambda": selected_model.ridge_lambda,
        "all_feature_view_sha256": target["feature_sha256"],
        "selected_feature_matrix_sha256": _feature_hash(target_view),
        "cell_scores_float64le_sha256": _sha256(np.asarray(target_scores, dtype="<f8").tobytes()),
        "complete_cell_order": [int(value) for value in order],
        "complete_cell_order_uint8_sha256": _sha256(np.asarray(order, dtype=np.uint8).tobytes()),
        "top_64_prefixes": [f"{int(value):08b}" for value in order[:64]],
    }
    feature_manifests = {
        "training": [
            {
                "label": row["label"],
                "feature_sha256": row["feature_sha256"],
            }
            for row in training
        ],
        "validation": [
            {
                "label": row["label"],
                "feature_sha256": row["feature_sha256"],
            }
            for row in validation
        ],
        "target": target["feature_sha256"],
    }
    payload = {
        "schema": "chacha20-round20-knownkey-trajectory-atlas-prereveal-v1",
        "attempt_id": "A218",
        "evidence_stage": "FULLROUND_R20_TRAJECTORY_ATLAS_PREREVEAL_FROZEN",
        "protocol_sha256": PROTOCOL_SHA256,
        "corpus_path": str(CORPUS.relative_to(ROOT)),
        "corpus_sha256": corpus_sha,
        "corpus_measurement_sha256": corpus["measurement_sha256"],
        "target_trajectory_path": str(TARGET.relative_to(ROOT)),
        "target_trajectory_sha256": target_sha,
        "target_trajectory_measurement_sha256": target_artifact["measurement_sha256"],
        "public_target_sha256": corpus["public_target_sha256"],
        "target_commitment_sha256": corpus["target_commitment_sha256"],
        "feature_manifests": feature_manifests,
        "observed_selection_grid": observed_grid,
        "selected": selected,
        "selected_model": selected_model.as_dict(),
        "selection_matched_null": null_summary,
        "target_readout": target_readout,
        "secret_file_or_target_label_read": False,
        "target_rank_known_at_prereveal": False,
        "target_solver_executed": False,
    }
    payload["measurement_hash_scope"] = [
        "feature_manifests",
        "observed_selection_grid",
        "selected",
        "selected_model",
        "selection_matched_null",
        "target_readout",
    ]
    payload["measurement_sha256"] = _canonical_sha256(
        {key: payload[key] for key in payload["measurement_hash_scope"]}
    )
    _atomic_json(output, payload)
    return _verify_existing(output, corpus_sha, target_sha)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args()
    payload = run(arguments.output)
    print(
        json.dumps(
            {
                "output": str(arguments.output),
                "output_sha256": _file_sha256(arguments.output),
                "measurement_sha256": payload["measurement_sha256"],
                "selected": payload["selected"],
                "selection_matched_null_p": payload["selection_matched_null"][
                    "lower_tail_plus_one_p"
                ],
                "target_cell_order_sha256": payload["target_readout"][
                    "complete_cell_order_uint8_sha256"
                ],
                "target_rank_known_at_prereveal": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
