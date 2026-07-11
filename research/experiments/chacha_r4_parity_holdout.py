#!/usr/bin/env python3
"""Disjoint-key holdout for frozen ChaCha R4 pair-parity features."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

import numpy as np
from scipy.stats import rankdata

from arx_carry_leak.atlas import chacha_counter_blocks, exact_sign_flip_test
from arx_carry_leak.crypto_causal import CryptoCausalBuilder


def _features(difference: np.ndarray, candidates: list[dict[str, Any]]) -> np.ndarray:
    bits = np.unpackbits(difference, axis=1, bitorder="little")
    columns = []
    for candidate in candidates:
        parity = bits[:, candidate["first"]] ^ bits[:, candidate["second"]]
        columns.append(1.0 - 2.0 * parity.astype(float))
    return np.column_stack(columns)


def _auc(real: np.ndarray, null: np.ndarray) -> float:
    combined = np.concatenate([real, null])
    ranks = rankdata(combined, method="average")
    n = len(real)
    u = ranks[:n].sum() - n * (n + 1) / 2.0
    return float(u / (n * len(null)))


def _bh(rows: list[dict[str, Any]]) -> None:
    order = sorted(range(len(rows)), key=lambda index: rows[index]["exact_test"]["two_sided_p"])
    adjusted = 1.0
    for reverse_rank, index in enumerate(reversed(order), start=1):
        rank = len(rows) - reverse_rank + 1
        p = rows[index]["exact_test"]["two_sided_p"]
        adjusted = min(adjusted, p * len(rows) / rank)
        rows[index]["bh_q"] = float(adjusted)


def _run(config: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    candidates = config["candidates"]
    weights = np.sign([candidate["training_effect"] for candidate in candidates])
    per_feature = [[] for _ in candidates]
    ensemble_effects = []
    ensemble_aucs = []
    per_seed = []
    for seed_index in range(args.seeds):
        seed = args.seed_base + 1009 * seed_index
        rng = np.random.default_rng(seed ^ 0xA0C)
        counters = rng.integers(0, 2**32, size=args.pairs, dtype=np.uint32)
        first = chacha_counter_blocks(counters, config["rounds"], seed)
        second = chacha_counter_blocks(
            counters ^ np.uint32(1 << config["counter_bit"]), config["rounds"], seed
        )
        real = _features(first ^ second, candidates)
        real_mean = real.mean(axis=0)
        real_score = np.sum(real * weights[None, :], axis=1) / len(weights)
        control_means = []
        control_scores = []
        for _ in range(args.routes):
            null = _features(first ^ second[rng.permutation(args.pairs)], candidates)
            control_means.append(null.mean(axis=0))
            control_scores.append(np.sum(null * weights[None, :], axis=1) / len(weights))
        control_mean = np.mean(control_means, axis=0)
        effects = real_mean - control_mean
        for index, effect in enumerate(effects):
            per_feature[index].append(float(effect))
        null_score_mean = float(np.mean([score.mean() for score in control_scores]))
        ensemble_effect = float(real_score.mean() - null_score_mean)
        ensemble_effects.append(ensemble_effect)
        auc = _auc(real_score, control_scores[0])
        ensemble_aucs.append(auc)
        per_seed.append(
            {
                "seed": seed,
                "feature_effects": [float(value) for value in effects],
                "ensemble_effect": ensemble_effect,
                "ensemble_auc_vs_first_repairing": auc,
            }
        )
        print(f"parity holdout seed={seed}", flush=True)
    feature_rows = []
    for index, (candidate, values) in enumerate(zip(candidates, per_feature, strict=True)):
        test = exact_sign_flip_test(values)
        feature_rows.append(
            {
                "candidate_index": index,
                **candidate,
                "holdout_effect_values": values,
                "holdout_effect_mean": float(np.mean(values)),
                "same_direction_as_training": bool(np.sign(np.mean(values)) == np.sign(candidate["training_effect"])),
                "exact_test": test,
            }
        )
    _bh(feature_rows)
    ensemble_test = exact_sign_flip_test(ensemble_effects)
    return {
        "features": feature_rows,
        "ensemble": {
            "weights": [int(value) for value in weights],
            "effect_values": ensemble_effects,
            "effect_mean": float(np.mean(ensemble_effects)),
            "exact_test": ensemble_test,
            "auc_values": ensemble_aucs,
            "auc_mean": float(np.mean(ensemble_aucs)),
            "auc_exact_test_vs_half": exact_sign_flip_test(
                [value - 0.5 for value in ensemble_aucs]
            ),
        },
        "gates": {
            "bh_significant_features": sum(row["bh_q"] <= 0.05 for row in feature_rows),
            "directionally_replicated_features": sum(row["same_direction_as_training"] for row in feature_rows),
            "ensemble_two_sided_p": ensemble_test["two_sided_p"],
        },
        "per_seed": per_seed,
    }


def _graph(result: dict[str, Any], parameters: dict[str, Any], source: str, output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="chacha_r4_parity_holdout", parameters=parameters)
    for row in result["features"]:
        builder.add_triplet(
            edge_id=f"feature-{row['candidate_index']}",
            trigger=f"diff_bit_{row['first']}_xor_diff_bit_{row['second']}",
            mechanism="frozen_pair_parity_on_disjoint_keys",
            outcome="real_pairing_vs_repairing_expectation",
            confidence=1.0 - float(row["bh_q"]),
            evidence_kind="independent_holdout",
            source=source,
            attrs=row,
        )
    ensemble = result["ensemble"]
    builder.add_triplet(
        edge_id="frozen-parity-ensemble",
        trigger="frozen_training_sign_weighted_parities",
        mechanism="cross_key_linear_inference_score",
        outcome="real_pairing_vs_repairing_classification",
        confidence=1.0 - float(ensemble["exact_test"]["two_sided_p"]),
        evidence_kind="independent_holdout_ensemble",
        source=source,
        attrs=ensemble,
    )
    return builder.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--pairs", type=int, default=100000)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--routes", type=int, default=32)
    parser.add_argument("--seed-base", type=int, default=60000)
    args = parser.parse_args()
    if args.pairs < 5000 or args.seeds < 3 or args.routes < 3:
        raise ValueError("pairs >= 5000, seeds >= 3 and routes >= 3 required")
    config = json.loads(args.config.read_text())
    discovery = Path(config["source_discovery"])
    if hashlib.sha256(discovery.read_bytes()).hexdigest() != config["source_discovery_sha256"]:
        raise RuntimeError("frozen discovery hash mismatch")
    parameters = {
        "config": str(args.config),
        "config_sha256": hashlib.sha256(args.config.read_bytes()).hexdigest(),
        "pairs": args.pairs,
        "seeds": args.seeds,
        "routes": args.routes,
        "seed_base": args.seed_base,
        "rounds": config["rounds"],
        "counter_bit": config["counter_bit"],
    }
    result = _run(config, args)
    payload = {
        "schema_version": 1,
        "experiment": "chacha_r4_parity_holdout",
        "parameters": parameters,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "numpy": np.__version__,
        },
        "result": result,
        "scope_note": "Disjoint-key holdout of frozen R4 parity features; no feature selection occurs here.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    source = "sha256:" + hashlib.sha256(args.output.read_bytes()).hexdigest()
    stats = _graph(result, parameters, source, args.causal_output)
    print(f"wrote {args.output}")
    print(f"wrote {args.causal_output} ({stats['triplets']} triplets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
