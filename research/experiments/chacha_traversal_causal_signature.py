#!/usr/bin/env python3
"""Direct adjacent-output causal graphs across ChaCha counter traversals.

Each graph compresses *cipher outputs*, not counter metadata: consecutive
outputs under one explicitly named counter geometry form factual pairs, while
BvN bijections create same-multiset repairing pairs.  The default cyclic
topology gives factual source and destination the exact same output multiset;
the legacy open-path topology is retained only as an explicit ablation.  The resulting per-byte
entropy-contrast profile is stored in a ``.causal`` graph, re-opened, and used
by the reader-reconstructed model to classify held-out output batches by round.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

import numpy as np

from arx_carry_leak.atlas import chacha_counter_blocks
from arx_carry_leak.bvn import route_ensemble, verify_routes
from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _bit_reverse32(values: np.ndarray) -> np.ndarray:
    value = values.astype(np.uint32, copy=True)
    value = ((value & 0x55555555) << 1) | ((value >> 1) & 0x55555555)
    value = ((value & 0x33333333) << 2) | ((value >> 2) & 0x33333333)
    value = ((value & 0x0F0F0F0F) << 4) | ((value >> 4) & 0x0F0F0F0F)
    value = ((value & 0x00FF00FF) << 8) | ((value >> 8) & 0x00FF00FF)
    return ((value << 16) | (value >> 16)).astype(np.uint32)


def _counters(name: str, count: int, seed: int) -> np.ndarray:
    base = np.arange(count, dtype=np.uint32)
    if name == "sequential":
        return base
    if name == "gray":
        return base ^ (base >> np.uint32(1))
    if name == "bit-reversal":
        return _bit_reverse32(base)
    if name == "affine":
        # Odd multiplier makes this a permutation of the uint32 ring.
        return (np.uint64(1664525) * base.astype(np.uint64) + np.uint64(seed | 1)).astype(np.uint32)
    if name == "random-permutation":
        return np.random.default_rng(seed ^ 0xC0A51C).permutation(base)
    raise ValueError(f"unknown traversal: {name}")


def _entropy_deficits(delta: np.ndarray) -> np.ndarray:
    values = []
    for index in range(delta.shape[1]):
        counts = np.bincount(delta[:, index], minlength=256)
        probabilities = counts[counts > 0] / len(delta)
        values.append(8.0 + float(np.sum(probabilities * np.log2(probabilities))))
    return np.asarray(values)


def _contrast(first: np.ndarray, second: np.ndarray, routes: int, seed: int) -> np.ndarray:
    factual = _entropy_deficits(first ^ second)
    permutations = route_ensemble(len(second), routes, seed)
    route_check = verify_routes(permutations)
    if not route_check["all_bijective"] or route_check["forbidden_alignments"]:
        raise RuntimeError("invalid BvN repairing routes")
    repaired = np.stack([_entropy_deficits(first ^ second[route]) for route in permutations])
    return factual - repaired.mean(axis=0)


def _build(path: Path, traversal: str, params: dict, means: dict, sds: dict, train_hash: str) -> dict:
    builder = CryptoCausalBuilder(
        experiment="chacha_traversal_causal_signature",
        parameters={
            **params,
            "traversal": traversal,
            "train_output_sha256": train_hash,
            "direct_output_causal_graph": True,
            "causal_header": {
                "codec": "adjacent-output-factual-minus-repairing-contrast-profile",
                "stage_chain": [
                    f"{traversal}_counter_ordered_cipher_outputs",
                    f"{params['pair_topology']}_adjacent_factual_xor_delta",
                    "BvN_row_repair_counterfactuals",
                    "per_byte_entropy_contrast",
                    "causal_zlib",
                    "reader_reverse_round_query",
                ],
                "writer_model_forbidden_at_holdout": True,
            },
        },
    )
    for label in means:
        for index, (mean, sd) in enumerate(zip(means[label], sds[label], strict=True)):
            builder.add_triplet(
                edge_id=f"{traversal}-{label}-f{index}",
                trigger=f"traversal:{traversal}:class_{label}",
                mechanism="adjacent_output_factual_minus_repairing_profile_compressed",
                outcome=f"traversal:{traversal}:entropy_contrast_byte_{index}",
                confidence=min(0.999, max(0.0, 1.0 - np.exp(-abs(mean) / (sd + 1e-12)))),
                evidence_kind="direct_cipher_output_interventional_profile",
                source="embedded_train_output_hash",
                attrs={"mean": float(mean), "sd": float(sd)},
            )
    stats = builder.save(path)
    if not CryptoCausalReader(path).verify_provenance():
        raise RuntimeError("saved traversal graph failed reader provenance")
    return stats


_TRIGGER = re.compile(r":class_(.+)$")
_OUTCOME = re.compile(r":entropy_contrast_byte_(\d+)$")


def _reader_model(reader: CryptoCausalReader, labels: list[str]) -> tuple[dict, dict]:
    means = {label: np.zeros(64) for label in labels}
    sds = {label: np.zeros(64) for label in labels}
    count = 0
    for edge in reader.triplets(include_inferred=False):
        trigger, outcome = _TRIGGER.search(edge["trigger"]), _OUTCOME.search(edge["outcome"])
        if trigger is None or outcome is None or trigger.group(1) not in means:
            continue
        label, index = trigger.group(1), int(outcome.group(1))
        means[label][index] = edge["attrs"]["mean"]
        sds[label][index] = max(edge["attrs"]["sd"], 1e-9)
        count += 1
    if count != len(labels) * 64:
        raise RuntimeError("reader did not reconstruct every traversal profile node")
    return means, sds


def _classify(means: dict, sds: dict, feature: np.ndarray) -> tuple[str, dict]:
    scores = {
        label: float(-0.5 * np.sum(((feature - means[label]) / sds[label]) ** 2 + 2 * np.log(sds[label])))
        for label in means
    }
    return max(scores, key=scores.get), scores


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-directory", type=Path, required=True)
    parser.add_argument("--rounds", type=int, nargs="+", default=[2, 3, 20])
    parser.add_argument("--traversals", nargs="+", choices=["sequential", "gray", "bit-reversal", "affine", "random-permutation"], default=["sequential", "gray", "bit-reversal", "affine", "random-permutation"])
    parser.add_argument("--pairs", type=int, default=5000)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--train-seeds", type=int, default=5)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--pair-topology", choices=["cycle", "path"], default="cycle")
    parser.add_argument("--seed-base", type=int, default=4585001)
    args = parser.parse_args()
    if args.pairs < 3 or not 1 <= args.train_seeds < args.seeds:
        raise ValueError("pairs must be >= 3 and train-seeds must split seeds")

    labels = [f"r{rounds}" for rounds in args.rounds]
    params = {"rounds": args.rounds, "pairs_per_seed": args.pairs, "train_seeds": args.train_seeds, "repairing_routes": args.routes, "route_mode": "bvn", "repair_route_seed_strategy": "shared_per_seed_traversal_across_round_classes", "pair_topology": args.pair_topology}
    records = {}
    for traversal in args.traversals:
        data = {label: [] for label in labels}
        for seed_index in range(args.seeds):
            seed = args.seed_base + 1009 * seed_index
            counters = _counters(traversal, args.pairs, seed)
            for rounds, label in zip(args.rounds, labels, strict=True):
                print(f"traversal causal traversal={traversal} seed={seed} rounds={rounds}", flush=True)
                outputs = chacha_counter_blocks(counters, rounds, seed)
                if args.pair_topology == "cycle":
                    source, destination = outputs, np.roll(outputs, -1, axis=0)
                else:
                    source, destination = outputs[:-1], outputs[1:]
                data[label].append(_contrast(source, destination, args.routes, seed ^ sum(traversal.encode())))
        means = {label: np.mean(data[label][:args.train_seeds], axis=0) for label in labels}
        sds = {label: np.std(data[label][:args.train_seeds], axis=0, ddof=1) + 1e-9 for label in labels}
        train_hash = hashlib.sha256(np.asarray([data[label][:args.train_seeds] for label in labels]).tobytes()).hexdigest()
        causal_path = args.causal_directory / f"chacha_traversal_causal_{traversal}_v1.causal"
        causal = _build(causal_path, traversal, params, means, sds, train_hash)
        reader_means, reader_sds = _reader_model(CryptoCausalReader(causal_path), labels)
        trials = []
        for label in labels:
            for feature in data[label][args.train_seeds:]:
                predicted, scores = _classify(reader_means, reader_sds, feature)
                trials.append({"actual": label, "predicted": predicted, "correct": predicted == label, "scores": scores})
        per_class = {label: {"correct": sum(row["correct"] for row in trials if row["actual"] == label), "total": sum(row["actual"] == label for row in trials)} for label in labels}
        for row in per_class.values():
            row["accuracy"] = row["correct"] / max(row["total"], 1)
        records[traversal] = {"causal": causal, "overall_accuracy": float(np.mean([row["correct"] for row in trials])), "per_class": per_class, "trials": trials}
    payload = {"schema": "chacha-traversal-causal-signature-v1", "parameters": {**params, "traversals": args.traversals}, "chance": 1 / len(labels), "results": records, "scope": "direct adjacent cipher-output causal compression over explicit counter traversals and reader-only reverse reduced-round query; not key recovery"}
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded)
    print(json.dumps({"output": str(args.output), "sha256": hashlib.sha256(encoded).hexdigest(), "results": {name: value["per_class"] for name, value in records.items()}}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
