#!/usr/bin/env python3
"""A216N: selection-matched phase-label null confirmation for A216."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import zipfile
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader, ExactRule

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
PROTOCOL_PATH = (
    RESEARCH
    / "configs/chacha20_round20_multifrequency_selection_matched_null_v1.json"
)
PROTOCOL_SHA256 = "3f1d74666165432a4bebd9e559deb5dc619c573fa77c937fc3084efcb5e0f351"
A216_RESULT_PATH = (
    RESEARCH / "results/v1/chacha20_round20_multifrequency_group_readout_v1.json"
)
A216_RESULT_SHA256 = "f85eb6034123b4aa5cae6114e35565bb3e613800f4102f04ae631edbc6e380da"
A216_PREREVEAL_PATH = (
    RESEARCH
    / "results/v1/chacha20_round20_multifrequency_group_readout_v1_prereveal.json"
)
A216_PREREVEAL_SHA256 = "f0eee4aecb4f691ebb05fc03515b4b27e88d594d70d3eb1b269ea6d9a8fadb99"
A216_MEASUREMENT_PATH = (
    RESEARCH
    / "results/v1/chacha20_round20_multifrequency_group_readout_v1_measurements.npz"
)
A216_MEASUREMENT_SHA256 = "aa931bca62098372f0dd56655e43cbd2380127c50eaa75256006e72c4fe32b85"
A216_MEASUREMENT_PAYLOAD_SHA256 = (
    "a5afb58487f4847a240be90b2e75f765005b098fadd8464a40c271c6392106c8"
)

ATTEMPT_ID = "A216N-CHACHA20-R20-MULTIFREQ-SELECTION-MATCHED-NULL-V1"
SCHEMA = "chacha20-round20-multifrequency-selection-matched-null-v1"
REPRESENTATIONS = (
    "raw_output_bits_pm1",
    "adjacent_block_xor_bits_pm1",
    "per_block_byte_histograms",
    "per_block_bit_rfft_magnitudes",
)
SHRINKAGES = (0.0, 0.25, 0.5, 0.75, 0.9)
GROUP_COUNT = 5
CLASS_COUNT = 16
PERMUTATIONS = 64


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_sha256(value: Any) -> str:
    return _sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    )


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_write(
        path,
        (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(),
    )


def _load_protocol() -> dict[str, Any]:
    if _file_sha256(PROTOCOL_PATH) != PROTOCOL_SHA256:
        raise RuntimeError("A216N protocol hash differs")
    protocol = json.loads(PROTOCOL_PATH.read_bytes())
    if (
        protocol.get("schema")
        != "chacha20-round20-multifrequency-selection-matched-null-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or tuple(protocol.get("representations_in_fixed_order", ())) != REPRESENTATIONS
        or tuple(protocol.get("shrinkages_in_fixed_order", ())) != SHRINKAGES
        or protocol.get("null", {}).get("permutations") != PERMUTATIONS
    ):
        raise RuntimeError("A216N protocol identity gate failed")
    return protocol


def _output_bytes(outputs: np.ndarray) -> np.ndarray:
    return np.ascontiguousarray(outputs.astype("<u4", copy=False)).view(np.uint8).reshape(
        len(outputs), 8, 64
    )


def _feature_representations(outputs: np.ndarray) -> dict[str, np.ndarray]:
    blocks = _output_bytes(outputs)
    bits = np.unpackbits(blocks, axis=2, bitorder="little").astype(np.float32)
    pm1 = bits * 2.0 - 1.0
    adjacent_bytes = blocks[:, :-1] ^ blocks[:, 1:]
    adjacent_bits = np.unpackbits(
        adjacent_bytes, axis=2, bitorder="little"
    ).astype(np.float32)

    low = blocks & np.uint8(0x0F)
    high = blocks >> np.uint8(4)
    histograms = np.empty((len(outputs), 8, 2, 16), dtype=np.float32)
    for block in range(8):
        for half, nibbles in enumerate((low[:, block], high[:, block])):
            for value in range(16):
                histograms[:, block, half, value] = np.count_nonzero(
                    nibbles == value, axis=1
                ) / 64.0
    spectrum = np.abs(np.fft.rfft(pm1, axis=2)).astype(np.float32)
    return {
        "raw_output_bits_pm1": pm1.reshape(len(outputs), -1),
        "adjacent_block_xor_bits_pm1": (adjacent_bits * 2.0 - 1.0).reshape(
            len(outputs), -1
        ),
        "per_block_byte_histograms": histograms.reshape(len(outputs), -1),
        "per_block_bit_rfft_magnitudes": spectrum.reshape(len(outputs), -1),
    }


def _labels(keys: np.ndarray, group: int) -> np.ndarray:
    return ((keys >> np.uint32(4 * group)) & np.uint32(0x0F)).astype(np.uint8)


def _standardized_features(
    measurement: Any,
    prereveal: dict[str, Any],
) -> tuple[dict[str, np.ndarray], dict[str, np.ndarray]]:
    training_raw = _feature_representations(measurement["training_outputs"])
    validation_raw = _feature_representations(measurement["validation_outputs"])
    training: dict[str, np.ndarray] = {}
    validation: dict[str, np.ndarray] = {}
    for representation in REPRESENTATIONS:
        mean = measurement[f"{representation}__mean"].astype(np.float32, copy=True)
        scale = measurement[f"{representation}__scale"].astype(np.float32, copy=True)
        retained = scale > 1e-8
        train = (
            training_raw[representation][:, retained] - mean[retained]
        ) / scale[retained]
        valid = (
            validation_raw[representation][:, retained] - mean[retained]
        ) / scale[retained]
        train = np.ascontiguousarray(train, dtype=np.float32)
        valid = np.ascontiguousarray(valid, dtype=np.float32)
        manifest = prereveal["standardization"][representation]
        exact_standardization_replay = (
            _sha256(train.astype("<f4", copy=False).tobytes())
            == manifest["training_standardized_sha256"]
            and _sha256(valid.astype("<f4", copy=False).tobytes())
            == manifest["validation_standardized_sha256"]
        )
        # NumPy's real FFT is allowed to differ by a few float32 ULPs across
        # Accelerate processes. The frozen mean/scale arrays remain byte-anchored
        # in A216's NPZ; additionally gate a fresh semantic reconstruction here.
        fft_semantic_replay = representation == "per_block_bit_rfft_magnitudes" and (
            np.allclose(
                training_raw[representation].mean(axis=0, dtype=np.float64),
                mean,
                atol=2e-6,
                rtol=1e-7,
            )
            and np.allclose(
                training_raw[representation].std(axis=0, dtype=np.float64),
                scale,
                atol=2e-6,
                rtol=1e-7,
            )
        )
        if (
            train.shape[1] != manifest["retained_dimensions"]
            or not (exact_standardization_replay or fft_semantic_replay)
        ):
            raise RuntimeError(f"A216N {representation} standardization replay differs")
        training[representation] = train
        validation[representation] = valid
    return training, validation


def _load_frozen_inputs() -> tuple[
    dict[str, Any],
    dict[str, Any],
    np.ndarray,
    np.ndarray,
    dict[str, np.ndarray],
    dict[str, np.ndarray],
]:
    if (
        _file_sha256(A216_RESULT_PATH) != A216_RESULT_SHA256
        or _file_sha256(A216_PREREVEAL_PATH) != A216_PREREVEAL_SHA256
        or _file_sha256(A216_MEASUREMENT_PATH) != A216_MEASUREMENT_SHA256
    ):
        raise RuntimeError("A216N frozen A216 artifact anchor differs")
    result = json.loads(A216_RESULT_PATH.read_bytes())
    prereveal = json.loads(A216_PREREVEAL_PATH.read_bytes())
    if (
        result.get("measurement_sha256") != A216_MEASUREMENT_PAYLOAD_SHA256
        or result.get("prereveal_sha256") != A216_PREREVEAL_SHA256
        or result.get("prereveal") != prereveal
        or result.get("target_rank") != 1_041_965
    ):
        raise RuntimeError("A216N frozen A216 semantic anchor differs")
    with np.load(A216_MEASUREMENT_PATH, allow_pickle=False) as measurement:
        training_keys = measurement["training_low20"].astype(np.uint32, copy=True)
        validation_keys = measurement["validation_low20"].astype(np.uint32, copy=True)
        training, validation = _standardized_features(measurement, prereveal)
    if (
        len(training_keys) != 5404
        or len(validation_keys) != 1024
        or np.intersect1d(training_keys, validation_keys).size
    ):
        raise RuntimeError("A216N key-disjoint ledger gate failed")
    return result, prereveal, training_keys, validation_keys, training, validation


def _class_means(features: np.ndarray, labels: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    counts = np.bincount(labels, minlength=CLASS_COUNT).astype(np.int64)
    if np.any(counts == 0):
        raise RuntimeError("A216N class bank has an empty phase class")
    means = np.empty((CLASS_COUNT, features.shape[1]), dtype=np.float32)
    for label in range(CLASS_COUNT):
        means[label] = features[labels == label].mean(axis=0)
    return means, counts


def _all_shrinkage_scores(
    training: np.ndarray,
    validation: np.ndarray,
    training_labels: np.ndarray,
) -> tuple[list[np.ndarray], np.ndarray]:
    """Derive five exact MSE score banks from one class-mean cross-product."""
    if (
        training.ndim != 2
        or validation.ndim != 2
        or training.shape[1] != validation.shape[1]
        or len(training_labels) != len(training)
        or training.shape[1] == 0
    ):
        raise ValueError("A216N score operands have incompatible dimensions")
    means32, counts = _class_means(training, training_labels)
    global32 = training.mean(axis=0)
    x = np.ascontiguousarray(validation, dtype=np.float64)
    means = np.ascontiguousarray(means32, dtype=np.float64)
    global_mean = np.ascontiguousarray(global32, dtype=np.float64)
    if (
        not np.all(np.isfinite(x))
        or not np.all(np.isfinite(means))
        or not np.all(np.isfinite(global_mean))
    ):
        raise RuntimeError("A216N score operands contain non-finite values")

    x_norm = np.einsum("ij,ij->i", x, x)[:, None]
    class_cross = np.einsum("ij,kj->ik", x, means, optimize=False)
    global_cross = np.einsum("ij,j->i", x, global_mean, optimize=False)[:, None]
    class_norm = np.einsum("ij,ij->i", means, means)[None, :]
    global_norm = float(np.einsum("i,i->", global_mean, global_mean))
    class_global = np.einsum("ij,j->i", means, global_mean)[None, :]

    banks: list[np.ndarray] = []
    for shrinkage in SHRINKAGES:
        retained = 1.0 - shrinkage
        cross = retained * class_cross + shrinkage * global_cross
        prototype_norm = (
            retained * retained * class_norm
            + 2.0 * retained * shrinkage * class_global
            + shrinkage * shrinkage * global_norm
        )
        scores = -(x_norm - 2.0 * cross + prototype_norm) / x.shape[1]
        if not np.all(np.isfinite(scores)):
            raise RuntimeError("A216N score matrix contains non-finite values")
        banks.append(scores)
    return banks, counts


def _rank_metrics(scores: np.ndarray, labels: np.ndarray) -> dict[str, Any]:
    candidates = np.arange(CLASS_COUNT, dtype=np.int16)
    true_scores = scores[np.arange(len(scores)), labels]
    ranks = 1 + np.sum(scores > true_scores[:, None], axis=1) + np.sum(
        (scores == true_scores[:, None]) & (candidates[None, :] < labels[:, None]),
        axis=1,
    )
    predicted = np.argmax(scores, axis=1).astype(np.uint8)
    return {
        "top1_accuracy": float(np.mean(predicted == labels)),
        "mean_rank": float(np.mean(ranks)),
        "median_rank": float(np.median(ranks)),
        "mean_reciprocal_rank": float(np.mean(1.0 / ranks)),
        "predicted_class_uint8_sha256": _sha256(predicted.tobytes()),
        "true_class_rank_uint8_sha256": _sha256(ranks.astype(np.uint8).tobytes()),
    }


def _select_group(
    training: dict[str, np.ndarray],
    validation: dict[str, np.ndarray],
    training_labels: np.ndarray,
    validation_labels: np.ndarray,
    group: int,
) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for representation_index, representation in enumerate(REPRESENTATIONS):
        score_banks, counts = _all_shrinkage_scores(
            training[representation], validation[representation], training_labels
        )
        for shrinkage_index, scores in enumerate(score_banks):
            candidates.append(
                {
                    "group": group,
                    "representation": representation,
                    "representation_index": representation_index,
                    "shrinkage": SHRINKAGES[shrinkage_index],
                    "shrinkage_index": shrinkage_index,
                    "class_counts": counts.tolist(),
                    "validation": _rank_metrics(scores, validation_labels),
                }
            )
    return min(
        candidates,
        key=lambda row: (
            -row["validation"]["top1_accuracy"],
            row["validation"]["mean_rank"],
            row["representation_index"],
            row["shrinkage_index"],
        ),
    )


def _observed_replay(
    a216_result: dict[str, Any],
    training_keys: np.ndarray,
    validation_keys: np.ndarray,
    training: dict[str, np.ndarray],
    validation: dict[str, np.ndarray],
) -> list[dict[str, Any]]:
    observed = [
        _select_group(
            training,
            validation,
            _labels(training_keys, group),
            _labels(validation_keys, group),
            group,
        )
        for group in range(GROUP_COUNT)
    ]
    anchored = a216_result["prereveal"]["selected_models"]
    for replay, original in zip(observed, anchored, strict=True):
        replay_comparable = {
            key: replay[key]
            for key in (
                "group",
                "representation",
                "representation_index",
                "shrinkage",
                "shrinkage_index",
                "class_counts",
                "validation",
            )
        }
        original_comparable = {
            key: original[key]
            for key in replay_comparable
        }
        if replay_comparable != original_comparable:
            raise RuntimeError(f"A216N observed A216 replay differs for group {replay['group']}")
    return observed


def _selection_matched_null(
    training_keys: np.ndarray,
    validation_keys: np.ndarray,
    training: dict[str, np.ndarray],
    validation: dict[str, np.ndarray],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for permutation in range(PERMUTATIONS):
        selected: list[dict[str, Any]] = []
        for group in range(GROUP_COUNT):
            shuffled = _labels(training_keys, group).copy()
            np.random.default_rng(0xA216100 + 257 * permutation + group).shuffle(
                shuffled
            )
            selected.append(
                _select_group(
                    training,
                    validation,
                    shuffled,
                    _labels(validation_keys, group),
                    group,
                )
            )
        group_top1 = [row["validation"]["top1_accuracy"] for row in selected]
        rows.append(
            {
                "permutation": permutation,
                "selected_models": selected,
                "group_top1_accuracies": group_top1,
                "macro_top1_accuracy": float(np.mean(group_top1)),
            }
        )
    return rows


def _upper_tail_add_one(observed: float, nulls: list[float]) -> dict[str, Any]:
    exceedances = sum(value >= observed for value in nulls)
    return {
        "observed": observed,
        "minimum_null": min(nulls),
        "maximum_null": max(nulls),
        "strictly_beats_all_nulls": observed > max(nulls),
        "null_greater_or_equal_observed": exceedances,
        "add_one_upper_tail_p_value": (1 + exceedances) / (1 + len(nulls)),
        "permutations": len(nulls),
    }


def _statistics(
    observed: list[dict[str, Any]], null_rows: list[dict[str, Any]]
) -> dict[str, Any]:
    observed_groups = [row["validation"]["top1_accuracy"] for row in observed]
    groups = []
    for group in range(GROUP_COUNT):
        groups.append(
            {
                "group": group,
                **_upper_tail_add_one(
                    observed_groups[group],
                    [row["group_top1_accuracies"][group] for row in null_rows],
                ),
            }
        )
    return {
        "groups": groups,
        "macro": _upper_tail_add_one(
            float(np.mean(observed_groups)),
            [row["macro_top1_accuracy"] for row in null_rows],
        ),
    }


def _evidence_stage(statistics: dict[str, Any]) -> str:
    if statistics["macro"]["strictly_beats_all_nulls"]:
        return "SELECTION_MATCHED_MULTIFREQUENCY_TRANSFER_CONFIRMED"
    if any(row["strictly_beats_all_nulls"] for row in statistics["groups"]):
        return "GROUP_SPECIFIC_SELECTION_MATCHED_MULTIFREQUENCY_TRANSFER_CONFIRMED"
    return "MULTIFREQUENCY_MODEL_SELECTION_EXPLAINED"


def _save_measurement(
    path: Path,
    observed: list[dict[str, Any]],
    null_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    group_top1 = np.asarray(
        [row["group_top1_accuracies"] for row in null_rows], dtype=np.float64
    )
    group_mean_rank = np.asarray(
        [
            [model["validation"]["mean_rank"] for model in row["selected_models"]]
            for row in null_rows
        ],
        dtype=np.float64,
    )
    representation = np.asarray(
        [
            [model["representation_index"] for model in row["selected_models"]]
            for row in null_rows
        ],
        dtype=np.uint8,
    )
    shrinkage = np.asarray(
        [
            [model["shrinkage_index"] for model in row["selected_models"]]
            for row in null_rows
        ],
        dtype=np.uint8,
    )
    arrays = {
        "null_group_top1": group_top1,
        "null_macro_top1": group_top1.mean(axis=1),
        "null_group_mean_rank": group_mean_rank,
        "null_selected_representation_index": representation,
        "null_selected_shrinkage_index": shrinkage,
        "observed_group_top1": np.asarray(
            [row["validation"]["top1_accuracy"] for row in observed], dtype=np.float64
        ),
        "observed_group_mean_rank": np.asarray(
            [row["validation"]["mean_rank"] for row in observed], dtype=np.float64
        ),
    }
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, mode="w", compression=zipfile.ZIP_STORED) as bundle:
        for name in sorted(arrays):
            array = io.BytesIO()
            np.lib.format.write_array(array, arrays[name], allow_pickle=False)
            member = zipfile.ZipInfo(f"{name}.npy", date_time=(1980, 1, 1, 0, 0, 0))
            member.compress_type = zipfile.ZIP_STORED
            member.external_attr = 0o600 << 16
            bundle.writestr(member, array.getvalue())
    _atomic_write(path, archive.getvalue())
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": _file_sha256(path)}


def _causal_graph(payload: dict[str, Any], output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_round20_multifrequency_selection_matched_null",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "protocol_sha256": PROTOCOL_SHA256,
            "A216_result_sha256": A216_RESULT_SHA256,
            "permutations": PERMUTATIONS,
        },
    )
    builder.add_rule(
        ExactRule(
            name="selection_pressure_matched_null_decision",
            first="replays_complete_4x5_selection_on_each_label_permutation",
            second="compares_observed_to_optimized_null_maxima",
            conclusion="decides_whether_A216_signal_survives_selection_matching",
        )
    )
    builder.add_triplet(
        edge_id="a216n-complete-selection-replay",
        trigger="A216:frozen_multifrequency_group_discovery",
        mechanism="replays_complete_4x5_selection_on_each_label_permutation",
        outcome="A216N:64_selection_matched_null_optimizers",
        confidence=1.0,
        evidence_kind="exact_post_discovery_selection_bias_control",
        source=f"measurement:sha256:{payload['measurement_artifact']['sha256']}",
        attrs={
            "permutations": PERMUTATIONS,
            "models_per_group_per_permutation": 20,
            "observed_replay_exact": payload["observed_replay_exact"],
        },
    )
    builder.add_triplet(
        edge_id="a216n-selection-matched-decision",
        trigger="A216N:64_selection_matched_null_optimizers",
        mechanism="compares_observed_to_optimized_null_maxima",
        outcome=f"A216N:{payload['evidence_stage']}",
        confidence=1.0,
        evidence_kind="exact_add_one_permutation_test",
        source=f"measurement:sha256:{payload['measurement_artifact']['sha256']}",
        provenance=["a216n-complete-selection-replay"],
        attrs={
            "macro_observed": payload["selection_matched_statistics"]["macro"][
                "observed"
            ],
            "macro_null_maximum": payload["selection_matched_statistics"]["macro"][
                "maximum_null"
            ],
            "macro_p_value": payload["selection_matched_statistics"]["macro"][
                "add_one_upper_tail_p_value"
            ],
        },
    )
    builder.infer_exact_closure(max_hops=4)
    stats = builder.save(output)
    reader = CryptoCausalReader(output)
    if not reader.verify_provenance() or reader.graph_sha256 != stats["graph_sha256"]:
        raise RuntimeError("A216N Causal Reader provenance gate failed")
    return {**stats, "reader_verified": True}


def _report(payload: dict[str, Any], output: Path) -> None:
    macro = payload["selection_matched_statistics"]["macro"]
    lines = [
        "# ChaCha20 R20 multi-frequency selection-matched null (A216N)",
        "",
        f"**Evidence stage:** `{payload['evidence_stage']}`",
        "",
        "A216N is a post-discovery bias-control for A216. It repeats the complete "
        "four-representation by five-shrinkage optimizer independently for every "
        "group under each of 64 deterministic training-label permutations. Thus the "
        "null receives exactly the same validation-set model-selection opportunity as "
        "the observed statistic.",
        "",
        "| Statistic | Observed | Null maximum | Add-one p | Beats all nulls |",
        "|---|---:|---:|---:|---:|",
        f"| Macro | {macro['observed']:.8f} | {macro['maximum_null']:.8f} | "
        f"{macro['add_one_upper_tail_p_value']:.8f} | "
        f"{macro['strictly_beats_all_nulls']} |",
    ]
    for group in payload["selection_matched_statistics"]["groups"]:
        lines.append(
            f"| Group {group['group']} | {group['observed']:.8f} | "
            f"{group['maximum_null']:.8f} | "
            f"{group['add_one_upper_tail_p_value']:.8f} | "
            f"{group['strictly_beats_all_nulls']} |"
        )
    lines.extend(
        [
            "",
            "The unpermuted optimized replay reproduces every A216 selected model, "
            "top-1/mean-rank metric, predicted-class hash, and true-rank hash exactly. "
            "No target output or target label is evaluated in A216N.",
            "",
            "A216's public target rank remains 1,041,965 / 1,048,576 and therefore "
            "remains a standard-output rank boundary regardless of this validation-only "
            "selection-control outcome.",
            "",
            f"- Protocol SHA-256: `{PROTOCOL_SHA256}`",
            f"- A216 result anchor: `{A216_RESULT_SHA256}`",
            f"- Measurement SHA-256: `{payload['measurement_artifact']['sha256']}`",
            f"- Result measurement payload SHA-256: `{payload['measurement_sha256']}`",
            f"- Causal graph SHA-256: `{payload['causal_artifact']['graph_sha256']}`",
        ]
    )
    _atomic_write(output, ("\n".join(lines) + "\n").encode())


def run(
    *,
    measurement_output: Path,
    output: Path,
    causal_output: Path,
    report_output: Path,
) -> dict[str, Any]:
    protocol = _load_protocol()
    a216_result, _a216_prereveal, training_keys, validation_keys, training, validation = (
        _load_frozen_inputs()
    )
    observed = _observed_replay(
        a216_result, training_keys, validation_keys, training, validation
    )
    null_rows = _selection_matched_null(
        training_keys, validation_keys, training, validation
    )
    statistics = _statistics(observed, null_rows)
    stage = _evidence_stage(statistics)
    measurement = _save_measurement(measurement_output, observed, null_rows)
    measurement_payload = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "anchors": protocol["anchors"],
        "target_evaluation_performed": False,
        "A216_target_rank_retained_boundary": a216_result["target_rank"],
        "observed_replay_exact": True,
        "observed_selected_models": observed,
        "selection_matched_null": {
            "permutations": PERMUTATIONS,
            "models_optimized_per_group_per_permutation": len(REPRESENTATIONS)
            * len(SHRINKAGES),
            "rows": null_rows,
        },
        "selection_matched_statistics": statistics,
        "measurement_artifact": measurement,
        "evidence_stage": stage,
    }
    measurement_sha256 = _canonical_sha256(measurement_payload)
    payload = {**measurement_payload, "measurement_sha256": measurement_sha256}
    payload["causal_artifact"] = _causal_graph(payload, causal_output)
    _atomic_json(output, payload)
    _report(payload, report_output)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--measurement-output",
        type=Path,
        default=RESEARCH
        / "results/v1/chacha20_round20_multifrequency_selection_matched_null_v1_measurements.npz",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=RESEARCH
        / "results/v1/chacha20_round20_multifrequency_selection_matched_null_v1.json",
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=RESEARCH
        / "results/v1/chacha20_round20_multifrequency_selection_matched_null_v1.causal",
    )
    parser.add_argument(
        "--report-output",
        type=Path,
        default=RESEARCH
        / "reports/CAUSAL_CHACHA20_ROUND20_MULTIFREQUENCY_SELECTION_MATCHED_NULL_V1.md",
    )
    args = parser.parse_args()
    payload = run(
        measurement_output=args.measurement_output,
        output=args.output,
        causal_output=args.causal_output,
        report_output=args.report_output,
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "evidence_stage": payload["evidence_stage"],
                "macro": payload["selection_matched_statistics"]["macro"],
                "measurement_sha256": payload["measurement_sha256"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
