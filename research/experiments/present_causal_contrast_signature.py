#!/usr/bin/env python3
"""Direct ciphertext-pair causal profiles for validated PRESENT-80 prefixes.

The graph contains only a compact profile derived from factual ciphertext
differences and BvN-repaired counterfactual pairings.  Holdout classification
is reconstructed solely by ``CryptoCausalReader``.
"""
from __future__ import annotations

import argparse
import itertools
import hashlib
import json
import re
from pathlib import Path

import numpy as np

from arx_carry_leak.bvn import route_ensemble, verify_routes
from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader
from arx_carry_leak.nano_ciphers import (
    _present_encrypt,
    _present_inverse_permutation,
    _present_inverse_sbox_layer,
    _present_key_schedule_80,
)

_KAT = 0x5579C1387B228445
_TRIGGER = re.compile(r":class_(.+)$")
_OUTCOME = re.compile(r":contrast_feature_(\d+)$")


def _validate_primitive() -> None:
    if _present_encrypt(0, _present_key_schedule_80(0, 31), 31) != _KAT:
        raise RuntimeError("PRESENT-80 official zero-vector gate failed")


def _view(ciphertext: int, final_round_key: int, output_view: str) -> int:
    if output_view == "ciphertext":
        return ciphertext
    state = ciphertext ^ final_round_key
    if output_view == "post_sbox":
        return _present_inverse_permutation(state)
    if output_view == "pre_sbox":
        return _present_inverse_sbox_layer(_present_inverse_permutation(state))
    raise ValueError(f"unknown output view: {output_view}")


def _blocks(key: int, values: np.ndarray, rounds: int, output_view: str) -> np.ndarray:
    rks = _present_key_schedule_80(key, rounds)
    out = np.empty((len(values), 8), dtype=np.uint8)
    for index, value in enumerate(values):
        ciphertext = _present_encrypt(int(value), rks, rounds)
        out[index] = np.frombuffer(_view(ciphertext, rks[rounds], output_view).to_bytes(8, "big"), dtype=np.uint8)
    return out


def _profile(delta: np.ndarray, mode: str, feature_unit: str, nibble_pairs: list[tuple[int, int]] | None) -> np.ndarray:
    features: list[float] = []
    if feature_unit == "byte":
        columns = [delta[:, column] for column in range(delta.shape[1])]
        alphabet, entropy_max = 256, 8.0
    elif feature_unit == "nibble":
        columns = [((delta[:, column] >> shift) & 0xF) for column in range(delta.shape[1]) for shift in (4, 0)]
        alphabet, entropy_max = 16, 4.0
    elif feature_unit == "nibble-pair":
        if not nibble_pairs:
            raise ValueError("nibble-pair features require an explicit pair list")
        nibbles = np.stack([((delta[:, column] >> shift) & 0xF) for column in range(delta.shape[1]) for shift in (4, 0)], axis=1)
        columns = [((nibbles[:, left] << 4) | nibbles[:, right]) for left, right in nibble_pairs]
        alphabet, entropy_max = 256, 8.0
    else:
        raise ValueError(f"unknown feature unit: {feature_unit}")
    for values in columns:
        if mode == "entropy":
            counts = np.bincount(values, minlength=alphabet)
            p = counts[counts > 0] / len(values)
            features.append(entropy_max + float(np.sum(p * np.log2(p))))
        elif mode == "bitbias":
            bits = np.unpackbits(values[:, None], axis=1)[:, -int(np.log2(alphabet)):]
            features.append(float(np.mean(np.abs(bits.mean(axis=0) - 0.5))))
        elif mode == "collision":
            counts = np.bincount(values, minlength=alphabet)
            features.append(float(np.sum(counts * (counts - 1)) / (len(values) * (len(values) - 1))))
        else:
            raise ValueError(f"unknown profile mode: {mode}")
    return np.asarray(features)


def _contrast(a: np.ndarray, b: np.ndarray, routes: int, seed: int, mode: str, feature_unit: str, nibble_pairs: list[tuple[int, int]] | None) -> np.ndarray:
    factual = _profile(a ^ b, mode, feature_unit, nibble_pairs)
    repairs = route_ensemble(len(b), routes, seed)
    check = verify_routes(repairs)
    if not check["all_bijective"] or check["forbidden_alignments"]:
        raise RuntimeError("invalid BvN repair routes")
    return factual - np.mean([_profile(a ^ b[route], mode, feature_unit, nibble_pairs) for route in repairs], axis=0)


def _base_values(rng: np.random.Generator, pairs: int, mode: str, seed: int) -> np.ndarray:
    if mode == "random":
        return rng.integers(0, 2**64, size=pairs, dtype=np.uint64)
    if mode == "counter":
        return (np.arange(pairs, dtype=np.uint64) + np.uint64(seed << 17))
    if mode == "mixed":
        return rng.integers(0, 2**64, size=pairs, dtype=np.uint64) ^ np.arange(pairs, dtype=np.uint64)
    raise ValueError(f"unknown base mode: {mode}")


def _changed(values: np.ndarray, position: int, difference_mode: str) -> np.ndarray:
    if difference_mode == "bit":
        return values ^ np.uint64(1 << position)
    if difference_mode == "byte":
        return values ^ np.uint64(0xFF << (8 * position))
    raise ValueError(f"unknown difference mode: {difference_mode}")


def _build_graph(path: Path, parameters: dict, means: dict[str, np.ndarray], sds: dict[str, np.ndarray], train_hash: str) -> dict:
    builder = CryptoCausalBuilder(
        experiment="present_causal_contrast_signature",
        parameters={
            **parameters,
            "train_output_sha256": train_hash,
            "direct_output_causal_graph": True,
            "causal_header": {
                "codec": "factual-minus-BvN-repairing-output-profile",
                "stage_chain": [
                    "PRESENT80_prefix_ciphertext_pairs", "chosen_plaintext_xor",
                    "factual_ciphertext_xor_delta", "shared_BvN_repair_counterfactuals",
                    "per_byte_profile_contrast", "causal_zlib", "reader_reverse_round_query",
                ],
                "writer_model_forbidden_at_holdout": True,
            },
        },
    )
    for label in means:
        for index, (mean, sd) in enumerate(zip(means[label], sds[label], strict=True)):
            builder.add_triplet(
                edge_id=f"{label}-feature{index}", trigger=f"present80:class_{label}",
                mechanism="factual_minus_repairing_output_profile_compressed",
                outcome=f"present80:contrast_feature_{index}",
                confidence=min(.999, max(0.0, 1 - np.exp(-abs(mean) / (sd + 1e-12)))),
                evidence_kind="direct_cipher_output_interventional_profile",
                source="embedded_train_output_hash", attrs={"mean": float(mean), "sd": float(sd)},
            )
    stats = builder.save(path)
    if not CryptoCausalReader(path).verify_provenance():
        raise RuntimeError("reader provenance verification failed")
    return stats


def _read_model(reader: CryptoCausalReader, labels: list[str], width: int) -> tuple[dict[str, np.ndarray], dict[str, np.ndarray]]:
    means = {label: np.zeros(width) for label in labels}
    sds = {label: np.zeros(width) for label in labels}
    found = 0
    for edge in reader.triplets(include_inferred=False):
        trigger, outcome = _TRIGGER.search(edge["trigger"]), _OUTCOME.search(edge["outcome"])
        if trigger and outcome and trigger.group(1) in means:
            label, index = trigger.group(1), int(outcome.group(1))
            means[label][index] = edge["attrs"]["mean"]
            sds[label][index] = max(edge["attrs"]["sd"], 1e-9)
            found += 1
    if found != len(labels) * width:
        raise RuntimeError(f"reader model incomplete: found {found}")
    return means, sds


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--rounds", type=int, nargs="+", default=list(range(24, 32)))
    parser.add_argument("--positions", type=int, nargs="+", default=[0, 7, 31, 63])
    parser.add_argument("--holdout-positions", type=int, nargs="+", default=[1, 8, 32, 62])
    parser.add_argument("--difference-mode", choices=["bit", "byte"], default="bit")
    parser.add_argument("--profile", choices=["entropy", "bitbias", "collision"], default="entropy")
    parser.add_argument("--feature-unit", choices=["byte", "nibble", "nibble-pair"], default="byte")
    parser.add_argument("--nibble-pairs", nargs="+", help="Ordered feature pairs as LEFT:RIGHT; default for nibble-pair is all 120 unordered pairs")
    parser.add_argument("--output-view", choices=["ciphertext", "post_sbox", "pre_sbox"], default="ciphertext")
    parser.add_argument("--feature-indices", type=int, nargs="+", help="Frozen output-byte features retained in the written causal graph")
    parser.add_argument("--base-mode", choices=["random", "counter", "mixed"], default="random")
    parser.add_argument("--holdout-base-mode", choices=["random", "counter", "mixed"])
    parser.add_argument("--pairs", type=int, default=10_000)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--train-seeds", type=int, default=5)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--seed-base", type=int, default=73885001)
    args = parser.parse_args()
    limit = 64 if args.difference_mode == "bit" else 8
    if not 1 <= args.train_seeds < args.seeds or any(x < 0 or x >= limit for x in set(args.positions) | set(args.holdout_positions)):
        raise ValueError("invalid seeds or difference positions")
    if args.nibble_pairs and args.feature_unit != "nibble-pair":
        raise ValueError("--nibble-pairs requires --feature-unit nibble-pair")
    if args.feature_unit == "nibble-pair":
        raw_pairs = args.nibble_pairs or [f"{left}:{right}" for left, right in itertools.combinations(range(16), 2)]
        try:
            nibble_pairs = [tuple(int(part) for part in value.split(":")) for value in raw_pairs]
        except ValueError as exc:
            raise ValueError("nibble pairs must be LEFT:RIGHT") from exc
        if any(len(pair) != 2 or pair[0] < 0 or pair[1] < 0 or pair[0] >= 16 or pair[1] >= 16 or pair[0] == pair[1] for pair in nibble_pairs):
            raise ValueError("nibble pair endpoints must be distinct positions in 0..15")
        if len(set(nibble_pairs)) != len(nibble_pairs):
            raise ValueError("nibble pairs must be distinct")
    else:
        nibble_pairs = None
    feature_width = 8 if args.feature_unit == "byte" else (16 if args.feature_unit == "nibble" else len(nibble_pairs))
    if args.feature_indices is not None and (not args.feature_indices or any(x < 0 or x >= feature_width for x in args.feature_indices)):
        raise ValueError(f"feature indices must be distinct {args.feature_unit} positions in 0..{feature_width - 1}")
    if args.feature_indices is not None and len(set(args.feature_indices)) != len(args.feature_indices):
        raise ValueError("feature indices must be distinct")
    _validate_primitive()
    labels = [f"r{rounds}" for rounds in args.rounds]
    train = {label: [] for label in labels}; evaluation = {label: [] for label in labels}
    all_positions = sorted(set(args.positions) | set(args.holdout_positions))
    for seed_index in range(args.seeds):
        seed = args.seed_base + 1009 * seed_index
        rng = np.random.default_rng(seed)
        key = int.from_bytes(rng.bytes(10), "big")
        train_values = _base_values(rng, args.pairs, args.base_mode, seed)
        eval_values = train_values if args.holdout_base_mode is None else _base_values(rng, args.pairs, args.holdout_base_mode, seed ^ 0x9E37)
        for rounds, label in zip(args.rounds, labels, strict=True):
            print(f"present80 causal seed={seed} rounds={rounds}", flush=True)
            first_train = _blocks(key, train_values, rounds, args.output_view)
            first_eval = _blocks(key, eval_values, rounds, args.output_view)
            for position in all_positions:
                values = train_values if position in args.positions else eval_values
                first = first_train if position in args.positions else first_eval
                feature = _contrast(first, _blocks(key, _changed(values, position, args.difference_mode), rounds, args.output_view), args.routes, seed ^ position, args.profile, args.feature_unit, nibble_pairs)
                if position in args.positions: train[label].append(feature)
                if position in args.holdout_positions: evaluation[label].append(feature)
    split = args.train_seeds * len(args.positions); eval_split = args.train_seeds * len(args.holdout_positions)
    selected = args.feature_indices if args.feature_indices is not None else list(range(feature_width))
    train = {label: [feature[selected] for feature in values] for label, values in train.items()}
    evaluation = {label: [feature[selected] for feature in values] for label, values in evaluation.items()}
    means = {label: np.mean(train[label][:split], axis=0) for label in labels}
    pooled = np.std(np.concatenate([train[label][:split] for label in labels]), axis=0, ddof=1) + 1e-9
    sds = {label: pooled.copy() for label in labels}
    train_hash = hashlib.sha256(np.asarray([train[label][:split] for label in labels]).tobytes()).hexdigest()
    parameters = {"rounds": args.rounds, "positions": args.positions, "holdout_positions": args.holdout_positions, "difference_mode": args.difference_mode, "profile": args.profile, "feature_unit": args.feature_unit, "nibble_pairs": nibble_pairs, "output_view": args.output_view, "feature_indices": selected, "base_mode": args.base_mode, "holdout_base_mode": args.holdout_base_mode or args.base_mode, "pairs_per_seed": args.pairs, "train_seeds": args.train_seeds, "repairing_routes": args.routes, "route_mode": "bvn", "repair_route_seed_strategy": "shared_per_seed_plaintext_difference_across_round_classes", "variance_mode": "pooled", "primitive_gate": "PRESENT-80 zero-key/zero-plaintext -> 5579c1387b228445"}
    causal = _build_graph(args.causal_output, parameters, means, sds, train_hash)
    reader_means, reader_sds = _read_model(CryptoCausalReader(args.causal_output), labels, len(selected))
    trials = []
    for label in labels:
        for feature in evaluation[label][eval_split:]:
            scores = {candidate: float(-.5 * np.sum(((feature - reader_means[candidate]) / reader_sds[candidate]) ** 2 + 2 * np.log(reader_sds[candidate]))) for candidate in labels}
            predicted = max(scores, key=scores.get)
            trials.append({"actual": label, "predicted": predicted, "correct": predicted == label, "scores": scores})
    per_class = {label: {"correct": sum(t["correct"] for t in trials if t["actual"] == label), "total": sum(t["actual"] == label for t in trials)} for label in labels}
    for value in per_class.values(): value["accuracy"] = value["correct"] / max(value["total"], 1)
    payload = {"schema": "present80-causal-contrast-signature-v1", "parameters": parameters, "causal": causal, "overall_accuracy": float(np.mean([trial["correct"] for trial in trials])), "chance": 1 / len(labels), "per_class": per_class, "trials": trials, "scope": "known-key chosen-plaintext PRESENT-80 prefix output class query; not key recovery, a ciphertext-only distinguisher, or a full-round security claim"}
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_bytes(raw)
    print(json.dumps({"output": str(args.output), "sha256": hashlib.sha256(raw).hexdigest(), "overall_accuracy": payload["overall_accuracy"], "per_class": per_class}, indent=2))


if __name__ == "__main__": main()
