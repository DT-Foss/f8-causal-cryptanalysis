#!/usr/bin/env python3
"""Reverse-infer AES prefix round/representation from causal-compressed output deltas."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.atlas import aes_inverse_linear_layer, aes_inverse_shift_rows, aes_prefix_batch
from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _represent(first: np.ndarray, second: np.ndarray, rounds: int, representation: str) -> np.ndarray:
    if representation == "identity":
        return first ^ second
    return (aes_inverse_shift_rows if rounds == 10 else aes_inverse_linear_layer)(first) ^ (aes_inverse_shift_rows if rounds == 10 else aes_inverse_linear_layer)(second)


def _fit(rows: dict[str, list[np.ndarray]], labels: list[str], bins: int) -> tuple[dict[str, np.ndarray], np.ndarray]:
    shift = 8 - int(np.log2(bins))
    counts = {label: np.stack([np.bincount((np.concatenate(rows[label]) >> shift)[:, byte], minlength=bins) for byte in range(16)]).astype(float) for label in labels}
    total = np.sum(np.stack(list(counts.values())), axis=0)
    background = (total + 1.0) / (total.sum(axis=1, keepdims=True) + bins)
    return {label: (counts[label] + 1.0) / (counts[label].sum(axis=1, keepdims=True) + bins) for label in labels}, background


def _build(path: Path, condition: str, parameters: dict[str, Any], model: dict[str, np.ndarray], background: np.ndarray, rows_hash: str) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="aes_round_causal_signature", parameters={**parameters, "condition": condition, "delta_train_rows_sha256": rows_hash, "direct_output_causal_graph": True, "causal_header": {"codec": "round-signature", "stage_chain": ["paired_cipher_outputs", "xor_delta", "optional_public_linear_projection", "quantized_conditional_signature", "causal_zlib", "reader_reverse_round_query"], "writer_model_forbidden_at_holdout": True}})
    for label, probability in model.items():
        for byte in range(16):
            for value in range(probability.shape[1]):
                log_lift = float(np.log(probability[byte, value] / background[byte, value]))
                builder.add_triplet(edge_id=f"{condition}-{label}-d{byte}b{value}", trigger=f"{condition}:class_{label}", mechanism="empirical_delta_round_signature_compressed", outcome=f"{condition}:delta_byte_{byte}:bin_{value}", confidence=min(0.999, max(0.0, 1.0 - np.exp(-max(log_lift, 0.0)))), evidence_kind="direct_cipher_output_batch_signature", source="embedded_delta_train_rows_hash", attrs={"log_lift": log_lift, "probability": float(probability[byte, value]), "background_probability": float(background[byte, value])})
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets()) != len(model) * 16 * next(iter(model.values())).shape[1]:
        raise RuntimeError("round signature graph reader round-trip failed")
    return stats


_CLASS_RE = re.compile(r":class_(.+)$")
_OUTCOME_RE = re.compile(r":delta_byte_(\d+):bin_(\d+)$")


def _reader_model(reader: CryptoCausalReader, labels: list[str], bins: int) -> dict[str, np.ndarray]:
    model = {label: np.zeros((16, bins), dtype=float) for label in labels}
    recovered = 0
    for edge in reader.triplets(include_inferred=False):
        label_match, outcome_match = _CLASS_RE.search(edge["trigger"]), _OUTCOME_RE.search(edge["outcome"])
        if label_match is None or outcome_match is None:
            continue
        label = label_match.group(1)
        if label in model:
            byte, value = map(int, outcome_match.groups())
            model[label][byte, value] = float(edge["attrs"]["log_lift"])
            recovered += 1
    if recovered != len(labels) * 16 * bins:
        raise RuntimeError("reader failed to reconstruct full round signature")
    return model


def _classify(model: dict[str, np.ndarray], delta: np.ndarray, bins: int) -> tuple[str, dict[str, float]]:
    values = delta >> (8 - int(np.log2(bins)))
    scores = {label: float(sum(table[byte, values[:, byte]].sum() for byte in range(16))) for label, table in model.items()}
    return max(scores, key=scores.get), scores


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--rounds", type=int, nargs="+", default=[3, 4, 10])
    parser.add_argument("--representations", choices=["identity", "peel-final-linear"], nargs="+", default=["identity", "peel-final-linear"])
    parser.add_argument("--bits", type=int, nargs="+", default=[0, 31, 64, 127])
    parser.add_argument("--pairs", type=int, default=5000)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--train-seeds", type=int, default=5)
    parser.add_argument("--bins", type=int, default=4)
    parser.add_argument("--seed-base", type=int, default=1685001)
    args = parser.parse_args()
    if args.train_seeds < 1 or args.train_seeds >= args.seeds:
        raise ValueError("train-seeds must be in [1,seeds)")
    labels = [f"r{rounds}-{representation}" for rounds in args.rounds for representation in args.representations]
    rows: dict[str, list[np.ndarray]] = {label: [] for label in labels}
    batch_labels: list[tuple[str, np.ndarray]] = []
    for seed_index in range(args.seeds):
        seed = args.seed_base + 1009 * seed_index
        rng = np.random.default_rng(seed)
        key = rng.integers(0, 256, size=16, dtype=np.uint8)
        plaintexts = rng.integers(0, 256, size=(args.pairs, 16), dtype=np.uint8)
        for rounds in args.rounds:
            print(f"aes round causal signature seed={seed} rounds={rounds}", flush=True)
            first = aes_prefix_batch(key, plaintexts, rounds)
            for bit in args.bits:
                paired = plaintexts.copy()
                paired[:, bit // 8] ^= np.uint8(1 << (bit % 8))
                second = aes_prefix_batch(key, paired, rounds)
                for representation in args.representations:
                    label = f"r{rounds}-{representation}"
                    delta = _represent(first, second, rounds, representation)
                    rows[label].append(delta)
                    batch_labels.append((label, delta))
    train = {label: rows[label][:args.train_seeds * len(args.bits)] for label in labels}
    model, background = _fit(train, labels, args.bins)
    train_hash = hashlib.sha256(b"".join(np.concatenate(train[label]).tobytes() for label in labels)).hexdigest()
    parameters = {"rounds": args.rounds, "representations": args.representations, "bits": args.bits, "bins": args.bins, "train_seeds": args.train_seeds, "pairs_per_seed": args.pairs}
    stats = _build(args.causal_output, "aes-round-output-signature", parameters, model, background, train_hash)
    reader = CryptoCausalReader(args.causal_output)
    reader_model = _reader_model(reader, labels, args.bins)
    holdout_start = args.train_seeds * len(args.bits)
    trials = []
    for label in labels:
        for delta in rows[label][holdout_start:]:
            predicted, scores = _classify(reader_model, delta, args.bins)
            trials.append({"actual": label, "predicted": predicted, "correct": predicted == label, "scores": scores})
    per_class = {label: {"correct": sum(trial["correct"] for trial in trials if trial["actual"] == label), "total": sum(trial["actual"] == label for trial in trials)} for label in labels}
    for row in per_class.values(): row["accuracy"] = row["correct"] / max(row["total"], 1)
    payload = {"schema": "aes-round-causal-signature-v1", "parameters": parameters, "environment": {"python": sys.version, "numpy": np.__version__}, "causal": stats, "holdout_trials": trials, "overall_accuracy": float(np.mean([trial["correct"] for trial in trials])), "chance": 1.0 / len(labels), "per_class": per_class, "scope": "reader-only reverse classification of output-generating reduced-round class; not key recovery or a full-AES break"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.write_bytes(encoded)
    print(json.dumps({"output": str(args.output), "sha256": hashlib.sha256(encoded).hexdigest(), "overall_accuracy": payload["overall_accuracy"], "per_class": per_class}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
