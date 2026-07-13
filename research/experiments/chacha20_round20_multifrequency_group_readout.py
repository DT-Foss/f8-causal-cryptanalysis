#!/usr/bin/env python3
"""A216: O1 multi-frequency group readout on standard R20 outputs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.chacha_trace import trace_chacha20_batch_words
from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader, ExactRule

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
PROTOCOL_PATH = RESEARCH / "configs/chacha20_round20_multifrequency_group_readout_v1.json"
PROTOCOL_SHA256 = "ea006add56f38767892bd2981db1829d546c535af305e3281c92a1ac67f7e803"
A215_MEASUREMENT_PATH = (
    RESEARCH / "results/v1/chacha20_round20_key_contrast_mobius_atlas_v1_measurements.npz"
)
A215_MEASUREMENT_SHA256 = "882ae2504851f1bac1f2350f8c160dba6cddd5b03afc4eb09f2252fc9b8cb5ff"
A215_PREREVEAL_PATH = (
    RESEARCH / "results/v1/chacha20_round20_key_contrast_mobius_atlas_v1_prereveal.json"
)
A215_PREREVEAL_SHA256 = "aad591b55094f50497ebf19c0399bfae2c6e33c8d1e3c3cfdae764ef50813839"
A215_RESULT_PATH = RESEARCH / "results/v1/chacha20_round20_key_contrast_mobius_atlas_v1.json"
A215_RESULT_SHA256 = "85448ceec849c8d65f088efd1abdf156c0b9f9f57145429e292606bec6fe9700"
CHALLENGE_PATH = (
    RESEARCH / "pilots/chacha20_round20_partition_v1/phase2_split18_10s/config.json"
)

ATTEMPT_ID = "A216-CHACHA20-R20-MULTIFREQ-GROUP-READOUT-V1"
SCHEMA = "chacha20-round20-multifrequency-group-readout-v1"
PREREVEAL_SCHEMA = "chacha20-round20-multifrequency-group-readout-prereveal-v1"
REPRESENTATIONS = (
    "raw_output_bits_pm1",
    "adjacent_block_xor_bits_pm1",
    "per_block_byte_histograms",
    "per_block_bit_rfft_magnitudes",
)
SHRINKAGES = (0.0, 0.25, 0.5, 0.75, 0.9)
GROUP_COUNT = 5
CLASS_COUNT = 16
RANK_CHALLENGES = 16


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
        raise RuntimeError("A216 protocol hash differs")
    protocol = json.loads(PROTOCOL_PATH.read_bytes())
    operator = protocol.get("group_operator", {})
    controls = protocol.get("controls", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-multifrequency-group-readout-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or tuple(protocol.get("representations_in_fixed_order", ())) != REPRESENTATIONS
        or operator.get("classes_per_group") != CLASS_COUNT
        or operator.get("harmonics") != list(range(16))
        or controls.get("phase_label_permutations") != 64
    ):
        raise RuntimeError("A216 protocol identity gate failed")
    return protocol


def _load_public() -> dict[str, Any]:
    public = json.loads(CHALLENGE_PATH.read_bytes())["public_challenge"]
    if (
        public.get("rounds") != 20
        or public.get("block_count") != 8
        or public.get("unknown_key_word0_low_bits") != 20
    ):
        raise RuntimeError("A216 public challenge semantic gate failed")
    return public


def _load_ledgers() -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    if (
        _file_sha256(A215_MEASUREMENT_PATH) != A215_MEASUREMENT_SHA256
        or _file_sha256(A215_PREREVEAL_PATH) != A215_PREREVEAL_SHA256
    ):
        raise RuntimeError("A216 A215 ledger anchor differs")
    prereveal = json.loads(A215_PREREVEAL_PATH.read_bytes())
    with np.load(A215_MEASUREMENT_PATH, allow_pickle=False) as measurement:
        training = measurement["training_low20"].astype(np.uint32, copy=True)
        validation = measurement["holdout_low20"].astype(np.uint32, copy=True)
    if (
        len(training) != 5404
        or len(validation) != 1024
        or _sha256(training.astype("<u4").tobytes())
        != prereveal["training_low20_uint32_le_sha256"]
        or _sha256(validation.astype("<u4").tobytes())
        != prereveal["holdout_low20_uint32_le_sha256"]
        or np.intersect1d(training, validation).size
    ):
        raise RuntimeError("A216 key-disjoint ledger gate failed")
    return training, validation, prereveal


def _key_words(low20: np.ndarray, public: dict[str, Any]) -> np.ndarray:
    keys = np.empty((len(low20), 8), dtype=np.uint32)
    keys[:, 0] = np.uint32(public["known_key_word0_upper12"]) | low20
    keys[:, 1:] = np.asarray(public["known_key_words_1_through_7"], dtype=np.uint32)
    return keys


def _output_corpus(
    training: np.ndarray, validation: np.ndarray, public: dict[str, Any]
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    low20 = np.concatenate((training, validation))
    counters = (
        np.uint32(public["counter_start"]) + np.arange(8, dtype=np.uint32)
    ).astype(np.uint32)
    batch = trace_chacha20_batch_words(
        key_words=_key_words(low20, public),
        counters=counters,
        nonce_words=np.asarray(public["nonce_words"], dtype=np.uint32),
        rounds=20,
        mode="factual",
        selected_trace_blocks=[],
        chunk_size=512,
    )
    outputs = batch.block_states.copy()
    raw = np.ascontiguousarray(outputs.astype("<u4", copy=False)).tobytes()
    return outputs[: len(training)], outputs[len(training) :], {
        "keys": len(outputs),
        "blocks_per_key": 8,
        "output_bits_per_key": 4096,
        "bytes": len(raw),
        "sha256": _sha256(raw),
    }


def _output_bytes(outputs: np.ndarray) -> np.ndarray:
    return np.ascontiguousarray(outputs.astype("<u4", copy=False)).view(np.uint8).reshape(
        len(outputs), 8, 64
    )


def _feature_representations(outputs: np.ndarray) -> dict[str, np.ndarray]:
    blocks = _output_bytes(outputs)
    bits = np.unpackbits(blocks, axis=2, bitorder="little").astype(np.float32)
    pm1 = bits * 2.0 - 1.0
    raw = pm1.reshape(len(outputs), -1)
    adjacent_bytes = blocks[:, :-1] ^ blocks[:, 1:]
    adjacent_bits = np.unpackbits(
        adjacent_bytes, axis=2, bitorder="little"
    ).astype(np.float32)
    adjacent = (adjacent_bits * 2.0 - 1.0).reshape(len(outputs), -1)

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
        "raw_output_bits_pm1": raw,
        "adjacent_block_xor_bits_pm1": adjacent,
        "per_block_byte_histograms": histograms.reshape(len(outputs), -1),
        "per_block_bit_rfft_magnitudes": spectrum.reshape(len(outputs), -1),
    }


def _standardize(
    training: np.ndarray, validation: np.ndarray
) -> tuple[np.ndarray, np.ndarray, dict[str, Any], np.ndarray, np.ndarray]:
    mean = training.mean(axis=0, dtype=np.float64).astype(np.float32)
    scale = training.std(axis=0, dtype=np.float64).astype(np.float32)
    retained = scale > 1e-8
    if not np.any(retained):
        raise RuntimeError("A216 representation has no variable coordinates")
    mean_retained = mean[retained]
    scale_retained = scale[retained]
    train = (training[:, retained] - mean_retained) / scale_retained
    valid = (validation[:, retained] - mean_retained) / scale_retained
    manifest = {
        "input_dimensions": training.shape[1],
        "retained_dimensions": int(np.count_nonzero(retained)),
        "mean_float32_le_sha256": _sha256(mean_retained.astype("<f4").tobytes()),
        "scale_float32_le_sha256": _sha256(scale_retained.astype("<f4").tobytes()),
        "retained_mask_sha256": _sha256(np.packbits(retained).tobytes()),
        "training_standardized_sha256": _sha256(
            np.ascontiguousarray(train.astype("<f4", copy=False)).tobytes()
        ),
        "validation_standardized_sha256": _sha256(
            np.ascontiguousarray(valid.astype("<f4", copy=False)).tobytes()
        ),
    }
    return train.astype(np.float32), valid.astype(np.float32), manifest, mean, scale


def _labels(keys: np.ndarray, group: int) -> np.ndarray:
    return ((keys >> np.uint32(4 * group)) & np.uint32(0x0F)).astype(np.uint8)


def _class_means(features: np.ndarray, labels: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    means = np.empty((CLASS_COUNT, features.shape[1]), dtype=np.float32)
    counts = np.bincount(labels, minlength=CLASS_COUNT).astype(np.int64)
    if np.any(counts == 0):
        raise RuntimeError("A216 class bank has an empty phase class")
    for label in range(CLASS_COUNT):
        means[label] = features[labels == label].mean(axis=0)
    return means, counts


def _character_bank(class_means: np.ndarray) -> tuple[np.ndarray, float]:
    bank = np.fft.fft(class_means.astype(np.float64), axis=0) / CLASS_COUNT
    reconstructed = np.fft.ifft(bank * CLASS_COUNT, axis=0).real
    error = float(np.max(np.abs(reconstructed - class_means)))
    if error > 1e-10:
        raise RuntimeError("A216 inverse DFT character-bank identity failed")
    return bank, error


def _scores(features: np.ndarray, prototypes: np.ndarray) -> np.ndarray:
    if (
        features.ndim != 2
        or prototypes.ndim != 2
        or features.shape[1] != prototypes.shape[1]
        or features.shape[1] == 0
    ):
        raise ValueError("A216 score operands have incompatible dimensions")
    # NumPy/Accelerate can emit spurious floating-point exceptions for the
    # float32 F-contiguous validation matrices produced by boolean indexing.
    # The protocol is a Euclidean prototype score, so make its numerical
    # realization explicit and stable: C-contiguous float64 operands throughout.
    x = np.ascontiguousarray(features, dtype=np.float64)
    p = np.ascontiguousarray(prototypes, dtype=np.float64)
    if not np.all(np.isfinite(x)) or not np.all(np.isfinite(p)):
        raise RuntimeError("A216 score operands contain non-finite values")
    x_norm = np.einsum("ij,ij->i", x, x)[:, None]
    p_norm = np.einsum("ij,ij->i", p, p)[None, :]
    cross = np.einsum("ij,kj->ik", x, p, optimize=False)
    scores = -(x_norm - 2.0 * cross + p_norm) / x.shape[1]
    if not np.all(np.isfinite(scores)):
        raise RuntimeError("A216 score matrix contains non-finite values")
    return scores


def _rank_metrics(scores: np.ndarray, labels: np.ndarray) -> dict[str, Any]:
    candidates = np.arange(CLASS_COUNT, dtype=np.int16)
    true_scores = scores[np.arange(len(scores)), labels]
    ranks = 1 + np.sum(scores > true_scores[:, None], axis=1) + np.sum(
        (scores == true_scores[:, None]) & (candidates[None, :] < labels[:, None]), axis=1
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


def _single_harmonic_prototypes(bank: np.ndarray) -> np.ndarray:
    phases = np.exp(2j * np.pi * np.arange(CLASS_COUNT) / CLASS_COUNT)
    reconstructed = bank[0][None, :] + (
        phases[:, None] * bank[1][None, :]
        + np.conjugate(phases[:, None] * bank[1][None, :])
    )
    return reconstructed.real.astype(np.float32)


def _fit_select(
    train_features: dict[str, np.ndarray],
    validation_features: dict[str, np.ndarray],
    training_keys: np.ndarray,
    validation_keys: np.ndarray,
) -> tuple[dict[str, Any], dict[str, np.ndarray], dict[str, Any]]:
    all_models: list[dict[str, Any]] = []
    arrays: dict[str, np.ndarray] = {}
    standardization: dict[str, Any] = {}
    standardized_train: dict[str, np.ndarray] = {}
    standardized_validation: dict[str, np.ndarray] = {}
    for representation in REPRESENTATIONS:
        train, valid, manifest, mean, scale = _standardize(
            train_features[representation], validation_features[representation]
        )
        standardized_train[representation] = train
        standardized_validation[representation] = valid
        standardization[representation] = manifest
        arrays[f"{representation}__mean"] = mean
        arrays[f"{representation}__scale"] = scale

    for group in range(GROUP_COUNT):
        training_labels = _labels(training_keys, group)
        validation_labels = _labels(validation_keys, group)
        for representation_index, representation in enumerate(REPRESENTATIONS):
            train = standardized_train[representation]
            valid = standardized_validation[representation]
            means, counts = _class_means(train, training_labels)
            bank, reconstruction_error = _character_bank(means)
            arrays[f"g{group}__{representation}__class_means"] = means
            arrays[f"g{group}__{representation}__character_bank_real"] = bank.real.astype(
                np.float32
            )
            arrays[f"g{group}__{representation}__character_bank_imag"] = bank.imag.astype(
                np.float32
            )
            global_mean = train.mean(axis=0)
            for shrinkage_index, shrinkage in enumerate(SHRINKAGES):
                prototypes = (
                    (1.0 - shrinkage) * means + shrinkage * global_mean[None, :]
                ).astype(np.float32)
                scores = _scores(valid, prototypes)
                metrics = _rank_metrics(scores, validation_labels)
                all_models.append(
                    {
                        "group": group,
                        "representation": representation,
                        "representation_index": representation_index,
                        "shrinkage": shrinkage,
                        "shrinkage_index": shrinkage_index,
                        "class_counts": counts.tolist(),
                        "inverse_DFT_maximum_absolute_error": reconstruction_error,
                        "validation": metrics,
                    }
                )

    selected = []
    selected_prototypes: dict[str, np.ndarray] = {}
    selected_scores: dict[str, np.ndarray] = {}
    controls = {"single_harmonic": [], "wrong_group": [], "random_operator": []}
    for group in range(GROUP_COUNT):
        candidates = [row for row in all_models if row["group"] == group]
        best = min(
            candidates,
            key=lambda row: (
                -row["validation"]["top1_accuracy"],
                row["validation"]["mean_rank"],
                row["representation_index"],
                row["shrinkage_index"],
            ),
        )
        selected.append(best)
        representation = best["representation"]
        means = arrays[f"g{group}__{representation}__class_means"]
        global_mean = standardized_train[representation].mean(axis=0)
        prototypes = (
            (1.0 - best["shrinkage"]) * means
            + best["shrinkage"] * global_mean[None, :]
        ).astype(np.float32)
        selected_prototypes[str(group)] = prototypes
        scores = _scores(standardized_validation[representation], prototypes)
        selected_scores[str(group)] = scores

        bank = arrays[f"g{group}__{representation}__character_bank_real"].astype(
            np.float64
        ) + 1j * arrays[
            f"g{group}__{representation}__character_bank_imag"
        ].astype(np.float64)
        harmonic = _single_harmonic_prototypes(bank)
        harmonic = (
            (1.0 - best["shrinkage"]) * harmonic
            + best["shrinkage"] * global_mean[None, :]
        ).astype(np.float32)
        controls["single_harmonic"].append(
            {
                "group": group,
                **_rank_metrics(
                    _scores(standardized_validation[representation], harmonic),
                    _labels(validation_keys, group),
                ),
            }
        )
        rng = np.random.default_rng(0xA216000 + group)
        random_prototypes = rng.choice(
            np.asarray([-1.0, 1.0], dtype=np.float32),
            size=prototypes.shape,
        )
        controls["random_operator"].append(
            {
                "group": group,
                **_rank_metrics(
                    _scores(standardized_validation[representation], random_prototypes),
                    _labels(validation_keys, group),
                ),
            }
        )

    for group in range(GROUP_COUNT):
        source_group = (group + 1) % GROUP_COUNT
        source = selected[source_group]
        representation = source["representation"]
        controls["wrong_group"].append(
            {
                "requested_group": group,
                "source_group": source_group,
                **_rank_metrics(
                    _scores(
                        standardized_validation[representation],
                        selected_prototypes[str(source_group)],
                    ),
                    _labels(validation_keys, group),
                ),
            }
        )
    state = {
        "standardized_train": standardized_train,
        "standardized_validation": standardized_validation,
        "selected_prototypes": selected_prototypes,
        "selected_scores": selected_scores,
    }
    return {
        "standardization": standardization,
        "all_models": all_models,
        "selected": selected,
        "controls": controls,
    }, arrays, state


def _null_bank(
    selected: list[dict[str, Any]],
    state: dict[str, Any],
    training_keys: np.ndarray,
    validation_keys: np.ndarray,
) -> dict[str, Any]:
    per_permutation = []
    for permutation in range(64):
        group_accuracies = []
        for group, model in enumerate(selected):
            representation = model["representation"]
            train = state["standardized_train"][representation]
            valid = state["standardized_validation"][representation]
            labels = _labels(training_keys, group).copy()
            np.random.default_rng(0xA216100 + 257 * permutation + group).shuffle(labels)
            means, _counts = _class_means(train, labels)
            global_mean = train.mean(axis=0)
            prototypes = (
                (1.0 - model["shrinkage"]) * means
                + model["shrinkage"] * global_mean[None, :]
            ).astype(np.float32)
            metrics = _rank_metrics(
                _scores(valid, prototypes), _labels(validation_keys, group)
            )
            group_accuracies.append(metrics["top1_accuracy"])
        per_permutation.append(
            {
                "permutation": permutation,
                "group_accuracies": group_accuracies,
                "macro_accuracy": float(np.mean(group_accuracies)),
            }
        )
    observed_groups = [row["validation"]["top1_accuracy"] for row in selected]
    observed_macro = float(np.mean(observed_groups))
    null_macros = [row["macro_accuracy"] for row in per_permutation]
    maximum_null_by_group = [
        max(row["group_accuracies"][group] for row in per_permutation)
        for group in range(GROUP_COUNT)
    ]
    return {
        "permutations": 64,
        "observed_group_accuracies": observed_groups,
        "observed_macro_accuracy": observed_macro,
        "minimum_null_macro_accuracy": min(null_macros),
        "maximum_null_macro_accuracy": max(null_macros),
        "beats_all_nulls": observed_macro > max(null_macros),
        "maximum_null_accuracy_by_group": maximum_null_by_group,
        "observed_beats_all_nulls_by_group": [
            observed_groups[group] > maximum_null_by_group[group]
            for group in range(GROUP_COUNT)
        ],
        "per_permutation": per_permutation,
    }


def _joint_validation(
    selected_scores: dict[str, np.ndarray], validation_keys: np.ndarray
) -> dict[str, Any]:
    predictions = np.stack(
        [np.argmax(selected_scores[str(group)], axis=1) for group in range(GROUP_COUNT)],
        axis=1,
    ).astype(np.uint8)
    actual = np.stack(
        [_labels(validation_keys, group) for group in range(GROUP_COUNT)], axis=1
    )
    return {
        "all_five_groups_top1": int(np.count_nonzero(np.all(predictions == actual, axis=1))),
        "validation_keys": len(validation_keys),
        "mean_correct_groups_per_key": float(np.mean(np.sum(predictions == actual, axis=1))),
        "predicted_groups_uint8_sha256": _sha256(predictions.tobytes()),
    }


def _candidate_scores(group_scores: list[np.ndarray]) -> np.ndarray:
    candidates = np.arange(1 << 20, dtype=np.uint32)
    total = np.zeros(len(candidates), dtype=np.float64)
    for group, scores in enumerate(group_scores):
        standardized = (scores - np.mean(scores)) / (np.std(scores) + 1e-12)
        labels = (candidates >> np.uint32(4 * group)) & np.uint32(0x0F)
        total += standardized[labels]
    return total


def _exact_rank(scores: np.ndarray, candidate: int) -> int:
    target = scores[candidate]
    keys = np.arange(len(scores), dtype=np.uint32)
    return 1 + int(np.count_nonzero(scores > target)) + int(
        np.count_nonzero((scores == target) & (keys < candidate))
    )


def _complete_rank_challenges(
    selected_scores: dict[str, np.ndarray], validation_keys: np.ndarray
) -> list[dict[str, Any]]:
    rows = []
    for challenge in range(RANK_CHALLENGES):
        group_scores = [selected_scores[str(group)][challenge] for group in range(GROUP_COUNT)]
        scores = _candidate_scores(group_scores)
        key = int(validation_keys[challenge])
        rows.append(
            {
                "challenge": challenge,
                "rank": _exact_rank(scores, key),
                "true_candidate_score": float(scores[key]),
                "candidate_scores_float64_le_sha256": _sha256(
                    scores.astype("<f8").tobytes()
                ),
            }
        )
    return rows


def _save_measurement(path: Path, arrays: dict[str, np.ndarray], **extra: np.ndarray) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        np.savez(stream, **arrays, **extra)
    temporary.replace(path)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": _file_sha256(path)}


def _postseal_target() -> tuple[int, dict[str, Any]]:
    if _file_sha256(A215_RESULT_PATH) != A215_RESULT_SHA256:
        raise RuntimeError("A216 postseal A215 result hash differs")
    result = json.loads(A215_RESULT_PATH.read_bytes())
    target = int(result["target_reveal"]["target_low20"])
    if target != 0xE4934 or result["target_reveal"]["target_reveal_after_prereveal"] is not True:
        raise RuntimeError("A216 postseal target reveal differs")
    return target, {
        "source_result_sha256": A215_RESULT_SHA256,
        "target_reveal_after_A216_prereveal": True,
    }


def _target_features(public: dict[str, Any]) -> dict[str, np.ndarray]:
    outputs = np.asarray(public["target_words"], dtype=np.uint32)[None, ...]
    return _feature_representations(outputs)


def _target_group_scores(
    public: dict[str, Any],
    selected: list[dict[str, Any]],
    arrays: dict[str, np.ndarray],
    prototypes: dict[str, np.ndarray],
) -> list[np.ndarray]:
    raw = _target_features(public)
    scores = []
    for group, model in enumerate(selected):
        representation = model["representation"]
        mean = arrays[f"{representation}__mean"]
        scale = arrays[f"{representation}__scale"]
        retained = scale > 1e-8
        target = (raw[representation][:, retained] - mean[retained]) / scale[retained]
        scores.append(_scores(target.astype(np.float32), prototypes[str(group)])[0])
    return scores


def _evidence_stage(null: dict[str, Any], target_rank: int, selected: list[dict[str, Any]]) -> str:
    if null["beats_all_nulls"] and target_rank <= 1024:
        return "FULLROUND_MULTIFREQUENCY_GROUP_RANK_TRANSFER"
    if null["beats_all_nulls"] and target_rank < (1 << 19):
        return "FULLROUND_MULTIFREQUENCY_GROUP_ENRICHMENT"
    group_hits = sum(null["observed_beats_all_nulls_by_group"])
    if group_hits:
        return "GROUP_SPECIFIC_MULTIFREQUENCY_TRANSFER"
    return "MULTIFREQUENCY_STANDARD_OUTPUT_GROUP_REPRESENTATION_BOUNDARY"


def _causal_graph(payload: dict[str, Any], output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_round20_multifrequency_group_readout",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "protocol_sha256": PROTOCOL_SHA256,
            "prereveal_sha256": payload["prereveal_sha256"],
            "O1_commit": payload["prereveal"]["O1_transfer"]["commit"],
        },
    )
    builder.add_rule(
        ExactRule(
            name="fourier_group_scores_to_domain_rank",
            first="constructs_complete_Z16_character_banks",
            second="sums_five_target_blind_group_scores",
            conclusion="tests_multifrequency_fullround_rank_transfer",
        )
    )
    builder.add_triplet(
        edge_id="a216-o1-character-bank",
        trigger="A216:5404_known_training_keys_plus_1024_disjoint_validation_keys",
        mechanism="constructs_complete_Z16_character_banks",
        outcome="A216:sealed_group_operators_and_nulls",
        confidence=1.0,
        evidence_kind="exact_DFT_character_bank_with_key_disjoint_selection",
        source=f"measurement:sha256:{payload['measurement_sha256']}",
        attrs={
            "inverse_DFT_maximum_error": payload["prereveal"][
                "inverse_DFT_maximum_absolute_error"
            ],
            "validation_macro_accuracy": payload["prereveal"]["phase_label_null"][
                "observed_macro_accuracy"
            ],
        },
    )
    builder.add_triplet(
        edge_id="a216-complete-rank",
        trigger="A216:sealed_group_operators_and_nulls",
        mechanism="sums_five_target_blind_group_scores",
        outcome=f"A216:{payload['evidence_stage']}",
        confidence=1.0,
        evidence_kind="postseal_complete_2pow20_standard_output_rank",
        source=f"measurement:sha256:{payload['measurement_sha256']}",
        provenance=["a216-o1-character-bank"],
        attrs={"target_rank": payload["target_rank"]},
    )
    builder.infer_exact_closure(max_hops=4)
    stats = builder.save(output)
    reader = CryptoCausalReader(output)
    if not reader.verify_provenance() or reader.graph_sha256 != stats["graph_sha256"]:
        raise RuntimeError("A216 Causal Reader gate failed")
    return {**stats, "reader_verified": True}


def _report(payload: dict[str, Any], output: Path) -> None:
    null = payload["prereveal"]["phase_label_null"]
    lines = [
        "# ChaCha20 R20 multi-frequency group readout (A216)",
        "",
        f"**Evidence stage:** `{payload['evidence_stage']}`",
        "",
        "A216 transfers O1's multi-frequency write into five complete Z16 Fourier "
        "character banks, one for each four-bit group. Model selection and 64 "
        "phase-label nulls use only 1,024 disjoint known-key holdouts; the standard "
        "eight-block R20 target is scored after the prereveal is written.",
        "",
        "| Group | Representation | Shrinkage | Validation top-1 | Mean rank |",
        "|---:|---|---:|---:|---:|",
    ]
    for row in payload["prereveal"]["selected_models"]:
        lines.append(
            f"| {row['group']} | `{row['representation']}` | {row['shrinkage']:.2f} | "
            f"{row['validation']['top1_accuracy']:.6f} | {row['validation']['mean_rank']:.4f} |"
        )
    lines.extend(
        [
            "",
            f"- Validation macro top-1: `{null['observed_macro_accuracy']:.6f}`",
            f"- Maximum of 64 label-null macros: `{null['maximum_null_macro_accuracy']:.6f}`",
            f"- Beats all label nulls: `{null['beats_all_nulls']}`",
            f"- Public R20 target rank: `{payload['target_rank']:,}` / 1,048,576",
            f"- Postseal target: `0x{payload['target_reveal']['target_low20']:05x}`",
            "",
            "The complete 16-harmonic bank is an exact coordinate transform of the "
            "class prototypes; it is not counted as 16 independent observations. The "
            "experiment tests whether those target-blind class means transfer, not whether "
            "Fourier notation alone creates information.",
            "",
            f"- Protocol SHA-256: `{PROTOCOL_SHA256}`",
            f"- Prereveal SHA-256: `{payload['prereveal_sha256']}`",
            f"- Measurement SHA-256: `{payload['measurement_artifact']['sha256']}`",
            f"- Causal graph SHA-256: `{payload['causal_artifact']['graph_sha256']}`",
        ]
    )
    _atomic_write(output, ("\n".join(lines) + "\n").encode())


def run(
    *,
    prereveal_output: Path,
    measurement_output: Path,
    output: Path,
    causal_output: Path,
    report_output: Path,
) -> dict[str, Any]:
    protocol = _load_protocol()
    public = _load_public()
    training_keys, validation_keys, _a215 = _load_ledgers()
    training_outputs, validation_outputs, corpus = _output_corpus(
        training_keys, validation_keys, public
    )
    training_features = _feature_representations(training_outputs)
    validation_features = _feature_representations(validation_outputs)
    fit, arrays, state = _fit_select(
        training_features,
        validation_features,
        training_keys,
        validation_keys,
    )
    selected = fit["selected"]
    null = _null_bank(selected, state, training_keys, validation_keys)
    joint = _joint_validation(state["selected_scores"], validation_keys)
    validation_ranks = _complete_rank_challenges(
        state["selected_scores"], validation_keys
    )
    measurement = _save_measurement(
        measurement_output,
        arrays,
        training_low20=training_keys,
        validation_low20=validation_keys,
        training_outputs=training_outputs,
        validation_outputs=validation_outputs,
        **{
            f"selected_prototypes_g{group}": state["selected_prototypes"][str(group)]
            for group in range(GROUP_COUNT)
        },
    )
    maximum_inverse_error = max(
        row["inverse_DFT_maximum_absolute_error"] for row in fit["all_models"]
    )
    prereveal = {
        "schema": PREREVEAL_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "target_key_available": False,
        "target_output_used_for_selection": False,
        "O1_transfer": protocol["anchors"]["O1"],
        "output_corpus": corpus,
        "measurement_artifact": measurement,
        "standardization": fit["standardization"],
        "inverse_DFT_maximum_absolute_error": maximum_inverse_error,
        "selected_models": selected,
        "controls": fit["controls"],
        "phase_label_null": null,
        "joint_validation": joint,
        "validation_complete_domain_ranks": validation_ranks,
        "all_models_target_blind_and_sealed": True,
    }
    _atomic_json(prereveal_output, prereveal)
    prereveal_sha256 = _file_sha256(prereveal_output)
    if json.loads(prereveal_output.read_bytes()) != prereveal:
        raise RuntimeError("A216 prereveal atomic readback differs")

    target_low20, reveal = _postseal_target()
    target_scores = _target_group_scores(
        public, selected, arrays, state["selected_prototypes"]
    )
    candidate_scores = _candidate_scores(target_scores)
    target_rank = _exact_rank(candidate_scores, target_low20)
    stage = _evidence_stage(null, target_rank, selected)
    measurement_payload = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "prereveal_sha256": prereveal_sha256,
        "prereveal": prereveal,
        "measurement_artifact": measurement,
        "target_reveal": {
            **reveal,
            "target_low20": target_low20,
            "target_low20_hex": f"0x{target_low20:05x}",
        },
        "target_group_scores": [row.tolist() for row in target_scores],
        "target_rank": target_rank,
        "target_candidate_score": float(candidate_scores[target_low20]),
        "candidate_scores_float64_le_sha256": _sha256(
            candidate_scores.astype("<f8").tobytes()
        ),
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
        "--prereveal-output",
        type=Path,
        default=RESEARCH
        / "results/v1/chacha20_round20_multifrequency_group_readout_v1_prereveal.json",
    )
    parser.add_argument(
        "--measurement-output",
        type=Path,
        default=RESEARCH
        / "results/v1/chacha20_round20_multifrequency_group_readout_v1_measurements.npz",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=RESEARCH / "results/v1/chacha20_round20_multifrequency_group_readout_v1.json",
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=RESEARCH / "results/v1/chacha20_round20_multifrequency_group_readout_v1.causal",
    )
    parser.add_argument(
        "--report-output",
        type=Path,
        default=RESEARCH / "reports/CAUSAL_CHACHA20_ROUND20_MULTIFREQUENCY_GROUP_READOUT_V1.md",
    )
    args = parser.parse_args()
    payload = run(
        prereveal_output=args.prereveal_output,
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
                "target_rank": payload["target_rank"],
                "measurement_sha256": payload["measurement_sha256"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
