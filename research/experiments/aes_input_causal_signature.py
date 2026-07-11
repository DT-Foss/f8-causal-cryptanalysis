#!/usr/bin/env python3
"""Causally compress paired AES output batches into reverse input-bit signatures."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
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
    transform = aes_inverse_shift_rows if rounds == 10 else aes_inverse_linear_layer
    return transform(first) ^ transform(second)


def _model(deltas: dict[int, list[np.ndarray]], bits: list[int], bins: int) -> tuple[dict[int, np.ndarray], np.ndarray]:
    shift = 8 - int(np.log2(bins))
    counts = {}
    for bit in bits:
        matrix = np.concatenate(deltas[bit]) >> shift
        counts[bit] = np.stack([np.bincount(matrix[:, byte], minlength=bins) for byte in range(matrix.shape[1])]).astype(float)
    total = np.sum(np.stack([counts[bit] for bit in bits]), axis=0)
    background = (total + 1.0) / (total.sum(axis=1, keepdims=True) + bins)
    probabilities = {bit: (counts[bit] + 1.0) / (counts[bit].sum(axis=1, keepdims=True) + bins) for bit in bits}
    return probabilities, background


def _classify(probabilities: dict[int, np.ndarray], background: np.ndarray, deltas: np.ndarray, bins: int) -> tuple[int, dict[int, float]]:
    shift = 8 - int(np.log2(bins))
    values = deltas >> shift
    scores = {}
    for bit, probability in probabilities.items():
        score = 0.0
        for byte in range(values.shape[1]):
            score += float(np.log(probability[byte, values[:, byte]] / background[byte, values[:, byte]]).sum())
        scores[bit] = score
    return max(scores, key=scores.get), scores


_INPUT_RE = re.compile(r":input_xor_bit_(\d+)$")
_DELTA_RE = re.compile(r":delta_byte_(\d+):bin_(\d+)$")


def _reader_score_model(reader: CryptoCausalReader, bits: list[int], width: int, bins: int) -> dict[int, np.ndarray]:
    """Reconstruct the complete compressed likelihood model from .causal."""
    model = {bit: np.zeros((width, bins), dtype=float) for bit in bits}
    recovered = 0
    for edge in reader.triplets(include_inferred=False):
        trigger = _INPUT_RE.search(edge["trigger"])
        outcome = _DELTA_RE.search(edge["outcome"])
        if trigger is None or outcome is None:
            continue
        bit = int(trigger.group(1))
        byte, value = map(int, outcome.groups())
        if bit in model:
            model[bit][byte, value] = float(edge["attrs"]["log_lift"])
            recovered += 1
    expected = len(bits) * width * bins
    if recovered != expected:
        raise RuntimeError(f"reader recovered {recovered} signature edges, expected {expected}")
    return model


def _classify_from_reader(model: dict[int, np.ndarray], deltas: np.ndarray, bins: int) -> tuple[int, dict[int, float]]:
    shift = 8 - int(np.log2(bins))
    values = deltas >> shift
    scores = {bit: float(sum(model[bit][byte, values[:, byte]].sum() for byte in range(values.shape[1]))) for bit in model}
    return max(scores, key=scores.get), scores


def _build_graph(path: Path, *, condition: str, parameters: dict[str, Any], probabilities: dict[int, np.ndarray], background: np.ndarray, bits: list[int], rows_hash: str, per_bit_edges: int, header_label: str) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="aes_input_causal_signature", parameters={**parameters, "condition": condition, "delta_train_rows_sha256": rows_hash, "direct_output_causal_graph": True, "causal_header": {"label": header_label, "codec": "conditional-output-signature", "stage_chain": ["paired_cipher_outputs", "xor_delta", "quantize", "conditional_log_lift", "causal_zlib_serialization", "reader_reverse_batch_query"], "writer_model_forbidden_at_holdout": True}})
    for bit in bits:
        candidates = []
        for byte in range(probabilities[bit].shape[0]):
            for value in range(probabilities[bit].shape[1]):
                log_lift = float(np.log(probabilities[bit][byte, value] / background[byte, value]))
                candidates.append((log_lift, byte, value))
        selected = sorted(candidates, reverse=True) if per_bit_edges == 0 else sorted(candidates, reverse=True)[:per_bit_edges]
        for rank, (log_lift, byte, value) in enumerate(selected):
            builder.add_triplet(
                edge_id=f"{condition}-bit{bit}-d{byte}b{value}",
                trigger=f"{condition}:input_xor_bit_{bit}",
                mechanism="empirical_delta_signature_compressed",
                outcome=f"{condition}:delta_byte_{byte}:bin_{value}",
                confidence=min(0.999, max(0.0, 1.0 - np.exp(-max(log_lift, 0.0)))),
                evidence_kind="direct_cipher_output_batch_signature",
                source="embedded_delta_train_rows_hash",
                attrs={"log_lift": log_lift, "probability": float(probabilities[bit][byte, value]), "background_probability": float(background[byte, value]), "rank_within_trigger": rank},
            )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if len(reader.triplets()) != stats["triplets"] or not reader.verify_provenance():
        raise RuntimeError("causal signature graph failed reader round-trip")
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-dir", type=Path, required=True)
    parser.add_argument("--rounds", type=int, nargs="+", default=[3, 4, 10])
    parser.add_argument("--representations", nargs="+", choices=["identity", "peel-final-linear"], default=["identity", "peel-final-linear"])
    parser.add_argument("--bits", type=int, nargs="+", default=[0, 31, 64, 127])
    parser.add_argument("--pairs", type=int, default=5000)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--train-seeds", type=int, default=5)
    parser.add_argument("--bins", type=int, default=16)
    parser.add_argument("--edges-per-bit", type=int, default=0, help="0 stores the full signature; positive values retain only top edges")
    parser.add_argument("--header-label", default="output-causal-signature-v2")
    parser.add_argument("--seed-base", type=int, default=885001)
    args = parser.parse_args()
    if args.train_seeds < 1 or args.train_seeds >= args.seeds or any(bit < 0 or bit >= 128 for bit in args.bits):
        raise ValueError("train-seeds must be in [1,seeds) and bits in [0,127]")
    data: dict[tuple[int, str], dict[int, list[np.ndarray]]] = {(rounds, representation): {bit: [] for bit in args.bits} for rounds in args.rounds for representation in args.representations}
    for seed_index in range(args.seeds):
        seed = args.seed_base + 1009 * seed_index
        rng = np.random.default_rng(seed)
        key = rng.integers(0, 256, size=16, dtype=np.uint8)
        plaintexts = rng.integers(0, 256, size=(args.pairs, 16), dtype=np.uint8)
        for rounds in args.rounds:
            print(f"aes output causal signature seed={seed} rounds={rounds}", flush=True)
            first = aes_prefix_batch(key, plaintexts, rounds)
            for bit in args.bits:
                paired_plaintexts = plaintexts.copy()
                paired_plaintexts[:, bit // 8] ^= np.uint8(1 << (bit % 8))
                second = aes_prefix_batch(key, paired_plaintexts, rounds)
                for representation in args.representations:
                    data[rounds, representation][bit].append(_represent(first, second, rounds, representation))
    args.causal_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for (rounds, representation), per_bit in data.items():
        train = {bit: rows[:args.train_seeds] for bit, rows in per_bit.items()}
        probabilities, background = _model(train, args.bits, args.bins)
        condition = f"aes-r{rounds}-{representation}-input-signature"
        train_hash = hashlib.sha256(b"".join(np.concatenate(train[bit]).tobytes() for bit in args.bits)).hexdigest()
        causal_path = args.causal_dir / f"{condition}.causal"
        stats = _build_graph(causal_path, condition=condition, parameters={"rounds": rounds, "representation": representation, "bits": args.bits, "bins": args.bins, "train_seeds": args.train_seeds, "pairs_per_seed": args.pairs}, probabilities=probabilities, background=background, bits=args.bits, rows_hash=train_hash, per_bit_edges=args.edges_per_bit, header_label=args.header_label)
        # Open the graph and use its independently reconstructed numerical model
        # for reverse batch inference, rather than reusing a writer-only object.
        reader = CryptoCausalReader(causal_path)
        if reader.graph["parameters"]["delta_train_rows_sha256"] != train_hash:
            raise RuntimeError("reader did not recover embedded output provenance")
        reader_model = _reader_score_model(reader, args.bits, 16, args.bins)
        trials = []
        for bit in args.bits:
            for heldout in per_bit[bit][args.train_seeds:]:
                predicted, scores = _classify_from_reader(reader_model, heldout, args.bins)
                trials.append({"actual_input_bit": bit, "predicted_input_bit": predicted, "correct": predicted == bit, "margin": float(scores[predicted] - max(value for key, value in scores.items() if key != predicted)), "scores": scores})
        accuracy = float(np.mean([trial["correct"] for trial in trials]))
        results.append({"rounds": rounds, "representation": representation, "causal_path": str(causal_path), "causal": stats, "holdout_trials": trials, "holdout_accuracy": accuracy, "chance_accuracy": 1.0 / len(args.bits), "accuracy_lift_over_chance": accuracy * len(args.bits)})
    payload = {"schema": "aes-input-causal-signature-v1", "parameters": {key: value for key, value in vars(args).items() if key not in {"output", "causal_dir"}}, "environment": {"python": sys.version, "numpy": np.__version__, "platform": platform.platform()}, "results": results, "scope": "direct cipher-output causal compression plus heldout reverse input-bit batch inference; not key recovery or full-AES attack"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.write_bytes(encoded)
    print(json.dumps({"output": str(args.output), "sha256": hashlib.sha256(encoded).hexdigest(), "conditions": len(results), "accuracies": [row["holdout_accuracy"] for row in results]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
