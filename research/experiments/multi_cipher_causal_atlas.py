#!/usr/bin/env python3
"""Null-corrected information atlas across cipher rounds and PQC outputs.

The atlas deliberately keeps two output-level views separate:

* layout fingerprint: observed row order minus arbitrary row permutation;
* operation-order fingerprint: observed minus whole-operation permutation.

For fixed-width classical generators an operation is one 32-byte row, except
ChaCha where the two halves of a 64-byte block remain grouped.  PQC operations
retain all complete rows of one ciphertext or signature as a group.  Neither
view is called an internal-round causal effect for APIs that expose outputs only.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import itertools
import json
import math
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import matplotlib
import numpy as np

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from arx_carry_leak.atlas import (
    aes_counter_blocks,
    cosine_similarity,
    exact_sign_flip_test,
    permutation_control,
    positional_entropy,
    rows32,
    sequential_delta_heatmap,
)
from arx_carry_leak.ciphers import get_generator
from arx_carry_leak.crypto_causal import CryptoCausalBuilder
from arx_carry_leak.live_casi_v091.ciphers import generate_chacha_stream
from arx_carry_leak.nano_ciphers import NANO_CIPHER_REGISTRY


@dataclass(frozen=True)
class Target:
    name: str
    family: str
    mode: str
    rounds: int | None = None
    module: str | None = None
    kind: str | None = None


TARGETS = {
    target.name: target
    for target in (
        Target("random_bytes", "null", "random"),
        Target("chacha_r1", "ChaCha20/ARX-stream", "chacha", 1),
        Target("chacha_r2", "ChaCha20/ARX-stream", "chacha", 2),
        Target("chacha_r3", "ChaCha20/ARX-stream", "chacha", 3),
        Target("chacha_r4", "ChaCha20/ARX-stream", "chacha", 4),
        Target("chacha_r20", "ChaCha20/ARX-stream", "chacha", 20),
        Target("aes_r1", "AES-128/SPN", "aes", 1),
        Target("aes_r2", "AES-128/SPN", "aes", 2),
        Target("aes_r3", "AES-128/SPN", "aes", 3),
        Target("aes_r4", "AES-128/SPN", "aes", 4),
        Target("aes_r10", "AES-128/SPN", "aes", 10),
        Target("simon32_r8", "SIMON32/64/Feistel", "nano", 8),
        Target("simon32_r32", "SIMON32/64/Feistel", "nano", 32),
        Target("threefish256_r72", "Threefish-256/ARX", "threefish", 72),
        Target("mlkem512", "ML-KEM", "pqc", module="pqcrypto.kem.ml_kem_512", kind="kem"),
        Target("mlkem768", "ML-KEM", "pqc", module="pqcrypto.kem.ml_kem_768", kind="kem"),
        Target("mldsa44", "ML-DSA", "pqc", module="pqcrypto.sign.ml_dsa_44", kind="sign"),
        Target("hqc128", "HQC", "pqc", module="pqcrypto.kem.hqc_128", kind="kem"),
    )
}

DEFAULT_TARGETS = list(TARGETS)


def _aes_rows(count: int, rounds: int, seed: int) -> np.ndarray:
    return aes_counter_blocks(count * 2, rounds, seed).reshape(count, 32)


def _pqc_groups(target: Target, rows: int, seed: int) -> tuple[list[np.ndarray], bool]:
    if target.module is None or target.kind is None:
        raise RuntimeError("incomplete PQC target")
    module = importlib.import_module(target.module)
    public_key, secret_key = module.generate_keypair()
    groups: list[np.ndarray] = []
    verified = False
    index = 0
    while sum(len(group) for group in groups) < rows:
        if target.kind == "kem":
            output, shared = module.encrypt(public_key)
            if index == 0:
                verified = module.decrypt(secret_key, output) == shared
        else:
            message = hashlib.sha256(f"{seed}:{index}".encode()).digest() * 2
            output = module.sign(secret_key, message)
            if index == 0:
                verified = bool(module.verify(public_key, message, output))
        group = rows32(output)
        if len(group):
            groups.append(group)
        index += 1
    if not verified:
        raise RuntimeError(f"{target.name} functional gate failed")
    return groups, verified


def _collect(target: Target, rows: int, seed: int) -> tuple[np.ndarray, list[np.ndarray], dict[str, Any]]:
    if target.mode == "random":
        matrix = np.random.default_rng(seed).integers(0, 256, size=(rows, 32), dtype=np.uint8)
        return matrix, [row[None, :] for row in matrix], {"replay_class": "exact"}
    if target.mode == "chacha":
        raw = generate_chacha_stream(rows, rounds=int(target.rounds), seed=seed)
        matrix = rows32(raw, limit=rows)
        groups = [matrix[index : index + 2] for index in range(0, len(matrix), 2)]
        return matrix, groups, {"replay_class": "exact", "rows_per_block": 2}
    if target.mode == "aes":
        matrix = _aes_rows(rows, int(target.rounds), seed)
        return matrix, [row[None, :] for row in matrix], {
            "replay_class": "exact",
            "reduced_round_semantics": "prefix; MixColumns retained in rounds 1..9",
        }
    if target.mode == "nano":
        raw = NANO_CIPHER_REGISTRY["simon32_64"]["gen"](rows, int(target.rounds), seed)
        matrix = rows32(raw, limit=rows)
        return matrix, [row[None, :] for row in matrix], {"replay_class": "exact"}
    if target.mode == "threefish":
        raw, width, metadata = get_generator("threefish256")(rows, int(target.rounds), seed)
        if width != 32:
            raise RuntimeError("unexpected Threefish block width")
        matrix = rows32(raw, limit=rows)
        return matrix, [row[None, :] for row in matrix], {
            "replay_class": "exact",
            "generator_metadata": metadata,
        }
    if target.mode == "pqc":
        groups, verified = _pqc_groups(target, rows, seed)
        matrix = np.vstack(groups)[:rows]
        retained: list[np.ndarray] = []
        remaining = rows
        for group in groups:
            if remaining <= 0:
                break
            retained.append(group[:remaining])
            remaining -= len(retained[-1])
        return matrix, retained, {
            "replay_class": "statistical; backend randomness is OS-provided",
            "functional_gate": verified,
            "operations": len(retained),
            "rows_per_operation": [len(group) for group in retained],
        }
    raise ValueError(f"unsupported mode {target.mode}")


def _group_controls(
    groups: list[np.ndarray], *, rows: int, shift: int, permutations: int, seed: int
) -> np.ndarray:
    rng = np.random.default_rng(seed)
    controls = []
    for _ in range(permutations):
        order = rng.permutation(len(groups))
        matrix = np.vstack([groups[index] for index in order])[:rows]
        controls.append(sequential_delta_heatmap(matrix, shift=shift))
    return np.stack(controls)


def _matrix_payload(matrix: np.ndarray) -> list[list[float]]:
    return [[float(value) for value in row] for row in matrix]


def _summary(values: list[float]) -> dict[str, Any]:
    return {
        "values": values,
        "mean": float(np.mean(values)),
        "sample_sd_ddof1": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
        "minimum": float(np.min(values)),
        "maximum": float(np.max(values)),
    }


def _target_run(target: Target, args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    seed_data = []
    layout_excesses = []
    order_excesses = []
    row_residuals = []
    observed_means = []
    row_control_means = []
    group_control_means = []
    entropy_profiles = []
    for seed_index in range(args.seeds):
        seed = 42 + 1009 * seed_index
        matrix, groups, collection = _collect(target, args.rows, seed)
        row_control = permutation_control(
            matrix, shift=args.shift, permutations=args.permutations, seed=seed ^ 0xA71A5
        )
        group_controls = _group_controls(
            groups,
            rows=len(matrix),
            shift=args.shift,
            permutations=args.permutations,
            seed=seed ^ 0xB0A7D,
        )
        group_mean = group_controls.mean(axis=0)
        observed = row_control["observed"]
        layout_excess = row_control["excess"]
        order_excess = observed - group_mean
        entropy = positional_entropy(matrix)
        layout_excesses.append(layout_excess)
        order_excesses.append(order_excess)
        row_residuals.append(row_control["control_matrices"] - row_control["control_mean"])
        observed_means.append(float(observed.mean()))
        row_control_means.append(float(row_control["control_mean"].mean()))
        group_control_means.append(float(group_mean.mean()))
        entropy_profiles.append(entropy)
        seed_data.append(
            {
                "seed": seed,
                "collection": collection,
                "observed_mean_mi": float(observed.mean()),
                "row_permutation_mean_mi": float(row_control["control_mean"].mean()),
                "operation_permutation_mean_mi": float(group_mean.mean()),
                "layout_excess_mean_mi": float(layout_excess.mean()),
                "operation_order_excess_mean_mi": float(order_excess.mean()),
                "layout_excess_l2": float(np.linalg.norm(layout_excess)),
                "operation_order_excess_l2": float(np.linalg.norm(order_excess)),
                "mean_byte_entropy": float(entropy.mean()),
                "minimum_byte_entropy": float(entropy.min()),
            }
        )
    layout = np.mean(layout_excesses, axis=0)
    order = np.mean(order_excesses, axis=0)
    aggregate = {
        "observed_mean_mi": _summary(observed_means),
        "row_permutation_mean_mi": _summary(row_control_means),
        "operation_permutation_mean_mi": _summary(group_control_means),
        "observed_vs_row_permutation": exact_sign_flip_test(
            list(np.asarray(observed_means) - np.asarray(row_control_means))
        ),
        "observed_vs_operation_permutation": exact_sign_flip_test(
            list(np.asarray(observed_means) - np.asarray(group_control_means))
        ),
        "mean_entropy_profile": [float(value) for value in np.mean(entropy_profiles, axis=0)],
        "layout_excess_mean_matrix": _matrix_payload(layout),
        "operation_order_excess_mean_matrix": _matrix_payload(order),
        "layout_excess_mean_mi": float(layout.mean()),
        "layout_excess_maximum_mi": float(layout.max()),
        "layout_excess_minimum_mi": float(layout.min()),
        "operation_order_excess_mean_mi": float(order.mean()),
        "operation_order_excess_maximum_mi": float(order.max()),
    }
    result = {
        "target": target.name,
        "family": target.family,
        "mode": target.mode,
        "rounds": target.rounds,
        "per_seed": seed_data,
        "aggregate": aggregate,
    }
    working = {
        "layout": layout,
        "order": order,
        "seed_layouts": np.stack(layout_excesses),
        "row_residuals": np.stack(row_residuals),
    }
    return result, working


def _bh_adjust(rows: list[dict[str, Any]], key: str = "null_two_sided_p") -> None:
    order = sorted(range(len(rows)), key=lambda index: rows[index][key])
    adjusted = 1.0
    for reverse_rank, index in enumerate(reversed(order), start=1):
        rank = len(rows) - reverse_rank + 1
        adjusted = min(adjusted, rows[index][key] * len(rows) / rank)
        rows[index]["bh_q"] = float(adjusted)


def _similarities(
    names: list[str], working: dict[str, dict[str, Any]], draws: int, seed: int
) -> list[dict[str, Any]]:
    rng = np.random.default_rng(seed)
    rows = []
    for left_index, left in enumerate(names):
        for right in names[left_index + 1 :]:
            observed = cosine_similarity(working[left]["layout"], working[right]["layout"])
            null = []
            left_residuals = working[left]["row_residuals"]
            right_residuals = working[right]["row_residuals"]
            for _ in range(draws):
                left_draw = np.mean(
                    [seed_rows[rng.integers(len(seed_rows))] for seed_rows in left_residuals], axis=0
                )
                right_draw = np.mean(
                    [seed_rows[rng.integers(len(seed_rows))] for seed_rows in right_residuals], axis=0
                )
                null.append(cosine_similarity(left_draw, right_draw))
            null_array = np.asarray(null)
            p = float((1 + np.count_nonzero(np.abs(null_array) >= abs(observed))) / (draws + 1))
            rows.append(
                {
                    "left": left,
                    "right": right,
                    "layout_cosine_similarity": observed,
                    "null_mean": float(null_array.mean()),
                    "null_sd_ddof1": float(null_array.std(ddof=1)),
                    "null_draws": draws,
                    "null_two_sided_p": p,
                }
            )
    _bh_adjust(rows)
    return rows


def _plot_atlas(names: list[str], working: dict[str, dict[str, Any]], destination: Path) -> None:
    columns = 4
    rows = math.ceil(len(names) / columns)
    figure, axes = plt.subplots(rows, columns, figsize=(4.2 * columns, 3.6 * rows), squeeze=False)
    limit = max(float(np.max(np.abs(working[name]["layout"]))) for name in names)
    for axis, name in zip(axes.ravel(), names, strict=False):
        image = axis.imshow(working[name]["layout"], cmap="coolwarm", vmin=-limit, vmax=limit)
        axis.set_title(name)
        axis.set_xlabel("delta byte j")
        axis.set_ylabel("source byte i")
    for axis in axes.ravel()[len(names) :]:
        axis.axis("off")
    figure.colorbar(image, ax=list(axes.ravel()), shrink=0.65, label="MI excess over row permutation (bits)")
    figure.suptitle("Multi-cipher null-corrected layout fingerprints")
    destination.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(destination, dpi=160, bbox_inches="tight", metadata={"Creator": "arx-carry-leak"})
    plt.close(figure)


def _plot_similarity(
    names: list[str], similarities: list[dict[str, Any]], destination: Path
) -> None:
    matrix = np.eye(len(names))
    positions = {name: index for index, name in enumerate(names)}
    for row in similarities:
        i, j = positions[row["left"]], positions[row["right"]]
        matrix[i, j] = matrix[j, i] = row["layout_cosine_similarity"]
    size = max(9, 0.65 * len(names))
    figure, axis = plt.subplots(figsize=(size, size))
    image = axis.imshow(matrix, cmap="coolwarm", vmin=-1, vmax=1)
    axis.set_xticks(range(len(names)), labels=names, rotation=90)
    axis.set_yticks(range(len(names)), labels=names)
    figure.colorbar(image, ax=axis, label="cosine similarity")
    axis.set_title("Similarity of null-corrected layout fingerprints")
    figure.savefig(destination, dpi=160, bbox_inches="tight", metadata={"Creator": "arx-carry-leak"})
    plt.close(figure)


def _graph(
    results: list[dict[str, Any]], similarities: list[dict[str, Any]], parameters: dict[str, Any], source: str, output: Path
) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="multi_cipher_causal_atlas", parameters=parameters)
    for result in results:
        target = result["target"]
        test = result["aggregate"]["observed_vs_row_permutation"]
        builder.add_triplet(
            edge_id=f"{target}-layout-fingerprint",
            trigger=f"{target}:ordered_32_byte_output_rows",
            mechanism="quantized_sequential_delta_information",
            outcome="layout_fingerprint_vs_row_permutation",
            confidence=1.0 - float(test["two_sided_p"]),
            evidence_kind="paired_exact_sign_flip_test",
            source=source,
            attrs={
                **test,
                "mean_excess_mi": result["aggregate"]["layout_excess_mean_mi"],
                "scope": "output layout; not automatically an internal mechanism",
            },
        )
    for row in similarities:
        if row["bh_q"] <= 0.05:
            builder.add_triplet(
                edge_id=f"similarity-{row['left']}-{row['right']}",
                trigger=f"{row['left']}:layout_fingerprint",
                mechanism="null_corrected_cosine_similarity",
                outcome=f"{row['right']}:layout_fingerprint",
                confidence=1.0 - float(row["bh_q"]),
                evidence_kind="row_permutation_residual_null",
                source=source,
                attrs=row,
            )
    return builder.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--figure-prefix", type=Path, required=True)
    parser.add_argument("--rows", type=int, default=4000)
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--permutations", type=int, default=8)
    parser.add_argument("--similarity-null-draws", type=int, default=999)
    parser.add_argument("--shift", type=int, default=5)
    parser.add_argument("--targets", nargs="*", default=DEFAULT_TARGETS)
    args = parser.parse_args()
    if args.rows < 1000 or args.seeds < 3 or args.permutations < 3 or args.similarity_null_draws < 99:
        raise ValueError("rows >= 1000, seeds >= 3, permutations >= 3, null draws >= 99 required")
    unknown = sorted(set(args.targets) - set(TARGETS))
    if unknown:
        raise ValueError(f"unknown targets: {', '.join(unknown)}")
    names = list(dict.fromkeys(args.targets))
    parameters = {
        "rows": args.rows,
        "seeds": args.seeds,
        "permutations": args.permutations,
        "similarity_null_draws": args.similarity_null_draws,
        "shift": args.shift,
        "targets": names,
    }
    results = []
    working = {}
    for name in names:
        print(f"atlas: {name}", flush=True)
        result, arrays = _target_run(TARGETS[name], args)
        results.append(result)
        working[name] = arrays
    similarities = _similarities(names, working, args.similarity_null_draws, 0xA71A5)
    atlas_figure = args.figure_prefix.with_name(args.figure_prefix.name + "_fingerprints.png")
    similarity_figure = args.figure_prefix.with_name(args.figure_prefix.name + "_similarity.png")
    _plot_atlas(names, working, atlas_figure)
    _plot_similarity(names, similarities, similarity_figure)
    payload = {
        "schema_version": 1,
        "experiment": "multi_cipher_causal_atlas",
        "parameters": parameters,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "numpy": np.__version__,
            "matplotlib": matplotlib.__version__,
            "pqcrypto": importlib.metadata.version("pqcrypto"),
        },
        "definitions": {
            "heatmap": "I(row_t[i] >> shift; ((row_t[j] XOR row_t+1[j]) >> shift))",
            "layout_fingerprint": "observed heatmap minus arbitrary-row-permutation mean",
            "operation_order_fingerprint": "observed heatmap minus whole-operation-permutation mean",
            "similarity_null": "cosine compared with independently sampled row-permutation residual fingerprints",
        },
        "results": results,
        "similarities": similarities,
        "figures": [str(atlas_figure), str(similarity_figure)],
        "scope_note": (
            "This atlas discovers and compares output-level motifs. A similarity or layout effect is not by itself "
            "a cryptographic distinguisher, an internal causal mechanism, or a security break. PQC replay is "
            "statistical because the backend obtains cryptographic randomness from the operating system."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    source = "sha256:" + hashlib.sha256(args.output.read_bytes()).hexdigest()
    stats = _graph(results, similarities, parameters, source, args.causal_output)
    print(f"wrote {args.output}")
    print(f"wrote {args.causal_output} ({stats['triplets']} triplets)")
    print(f"wrote {atlas_figure}")
    print(f"wrote {similarity_figure}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
