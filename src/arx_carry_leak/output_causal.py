"""Derive compact, reversible causal graphs directly from paired cipher outputs.

The graph nodes are quantized observed bytes, not experiment labels.  An edge
encodes an empirical conditional transition from a source-output byte/bin to a
paired-output-difference byte/bin, measured against row-repairing routes.
"""

from __future__ import annotations

from collections import defaultdict
import re
from typing import Any

import numpy as np

from .crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _validate_rows(source: np.ndarray, outcome: np.ndarray, bins: int) -> None:
    if source.shape != outcome.shape or source.ndim != 2 or source.dtype != np.uint8 or outcome.dtype != np.uint8:
        raise ValueError("source and outcome must be equally shaped uint8 matrices")
    if len(source) < 32:
        raise ValueError("at least 32 paired rows are required")
    if bins < 2 or bins > 256 or bins & (bins - 1):
        raise ValueError("bins must be a power of two in [2, 256]")


def derive_edges(
    source: np.ndarray,
    outcome: np.ndarray,
    *,
    bins: int = 16,
    routes: int = 8,
    seed: int = 0,
    max_edges: int = 256,
    exclude_diagonal: bool = False,
) -> list[dict[str, Any]]:
    """Find output-bin transitions exceeding exact row-repairing controls.

    ``outcome`` is normally an XOR difference.  The only compression here is
    quantization plus retaining the strongest measured conditional edges; raw
    row hashes and all edge counts remain embedded in the artifact metadata.
    """
    _validate_rows(source, outcome, bins)
    if routes < 2:
        raise ValueError("at least two repair routes are required")
    shift = 8 - int(np.log2(bins))
    source_bins = source >> shift
    outcome_bins = outcome >> shift
    rng = np.random.default_rng(seed)
    candidates: list[dict[str, Any]] = []
    for source_byte in range(source.shape[1]):
        left = source_bins[:, source_byte]
        for outcome_byte in range(outcome.shape[1]):
            if exclude_diagonal and source_byte == outcome_byte:
                continue
            right = outcome_bins[:, outcome_byte]
            actual = np.bincount(left.astype(np.int64) * bins + right, minlength=bins * bins).reshape(bins, bins)
            controls = []
            for _ in range(routes):
                routed = outcome_bins[rng.permutation(len(outcome_bins)), outcome_byte]
                controls.append(np.bincount(left.astype(np.int64) * bins + routed, minlength=bins * bins).reshape(bins, bins))
            control = np.stack(controls)
            mean = control.mean(axis=0)
            sd = control.std(axis=0, ddof=1)
            difference = actual - mean
            z = np.zeros_like(difference, dtype=float)
            nondegenerate = sd > 1e-12
            z[nondegenerate] = difference[nondegenerate] / sd[nondegenerate]
            # One strongest positive observed bin transition per byte-pair;
            # this avoids selecting every correlated bin of the same relation.
            flat = int(np.argmax(z))
            source_bin, outcome_bin = divmod(flat, bins)
            observed = float(actual[source_bin, outcome_bin])
            control_values = control[:, source_bin, outcome_bin]
            empirical_upper_p = float((1 + np.sum(control_values >= observed)) / (routes + 1))
            if difference[source_bin, outcome_bin] <= 0 or not nondegenerate[source_bin, outcome_bin]:
                continue
            marginal = float(actual[:, outcome_bin].sum() / len(source))
            conditional = observed / max(float(actual[source_bin].sum()), 1.0)
            candidates.append({
                "source_byte": source_byte,
                "source_bin": source_bin,
                "outcome_byte": outcome_byte,
                "outcome_bin": outcome_bin,
                "observed_count": int(observed),
                "control_mean_count": float(mean[source_bin, outcome_bin]),
                "control_sd_count": float(sd[source_bin, outcome_bin]),
                "excess_count": float(difference[source_bin, outcome_bin]),
                "route_z": float(z[source_bin, outcome_bin]),
                "empirical_upper_p": empirical_upper_p,
                "conditional_probability": float(conditional),
                "marginal_probability": marginal,
                "lift": float(conditional / max(marginal, 1e-12)),
            })
    candidates.sort(key=lambda row: (-row["route_z"], -row["excess_count"], row["source_byte"], row["outcome_byte"]))
    return candidates[:max_edges]


def save_output_graph(
    path: str,
    *,
    experiment: str,
    condition: str,
    parameters: dict[str, Any],
    source: np.ndarray,
    outcome: np.ndarray,
    edges: list[dict[str, Any]],
) -> dict[str, Any]:
    """Serialize direct cipher-output transitions into the native .causal graph."""
    builder = CryptoCausalBuilder(
        experiment=experiment,
        parameters={
            **parameters,
            "condition": condition,
            "source_rows_sha256": __import__("hashlib").sha256(source.tobytes()).hexdigest(),
            "outcome_rows_sha256": __import__("hashlib").sha256(outcome.tobytes()).hexdigest(),
            "direct_output_causal_graph": True,
        },
    )
    for edge in edges:
        builder.add_triplet(
            edge_id=f"{condition}-s{edge['source_byte']}b{edge['source_bin']}-d{edge['outcome_byte']}b{edge['outcome_bin']}",
            trigger=f"{condition}:source_byte_{edge['source_byte']}:bin_{edge['source_bin']}",
            mechanism="empirical_output_transition_compressed",
            outcome=f"{condition}:delta_byte_{edge['outcome_byte']}:bin_{edge['outcome_bin']}",
            confidence=1.0 - edge["empirical_upper_p"],
            evidence_kind="direct_cipher_output_pairing_vs_repairing",
            source="embedded_cipher_output_row_hashes",
            attrs=edge,
        )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if len(reader.triplets()) != len(edges) or not reader.verify_provenance():
        raise RuntimeError("direct output causal graph failed reader round-trip")
    stats["reader_roundtrip"] = {"triplets": len(reader.triplets()), "graph_sha256": reader.graph_sha256}
    return stats


def reverse_rank(reader: CryptoCausalReader, *, condition: str, observed_delta: np.ndarray, bins: int = 16) -> list[dict[str, Any]]:
    """Rank source-output bins that explain an observed differential row.

    This is graph-level reverse inference over observed output relations, not a
    key or plaintext recovery algorithm.
    """
    if observed_delta.ndim != 1 or observed_delta.dtype != np.uint8:
        raise ValueError("observed_delta must be a one-dimensional uint8 row")
    shift = 8 - int(np.log2(bins))
    wanted = {f"{condition}:delta_byte_{index}:bin_{int(value >> shift)}" for index, value in enumerate(observed_delta)}
    scores: dict[str, float] = defaultdict(float)
    evidence: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in reader.triplets(include_inferred=False):
        if edge["outcome"] not in wanted:
            continue
        attrs = edge["attrs"]
        score = float(attrs["route_z"]) * np.log2(max(float(attrs["lift"]), 1.0))
        scores[edge["trigger"]] += score
        evidence[edge["trigger"]].append({"outcome": edge["outcome"], "score": score, "lift": attrs["lift"], "route_z": attrs["route_z"]})
    return [
        {"source": source, "score": score, "support": sorted(evidence[source], key=lambda item: -item["score"])}
        for source, score in sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    ]


_SOURCE_RE = re.compile(r":source_byte_(\d+):bin_(\d+)$")


def evaluate_holdout(
    reader: CryptoCausalReader,
    *,
    condition: str,
    source: np.ndarray,
    outcome: np.ndarray,
    bins: int = 16,
    routes: int = 16,
    seed: int = 0,
) -> dict[str, Any]:
    """Evaluate graph edges and reverse bin inference on unseen output rows."""
    _validate_rows(source, outcome, bins)
    shift = 8 - int(np.log2(bins))
    edges = reader.triplets(include_inferred=False)
    rng = np.random.default_rng(seed)
    edge_effects = []
    for edge in edges:
        attrs = edge["attrs"]
        i, x, j, y = (int(attrs[key]) for key in ("source_byte", "source_bin", "outcome_byte", "outcome_bin"))
        actual = float(np.sum((source[:, i] >> shift == x) & (outcome[:, j] >> shift == y)))
        controls = []
        for _ in range(routes):
            routed = outcome[rng.permutation(len(outcome)), j] >> shift
            controls.append(float(np.sum((source[:, i] >> shift == x) & (routed == y))) )
        edge_effects.append(actual - float(np.mean(controls)))
    hits = baselines = covered = 0
    for row_source, row_outcome in zip(source, outcome, strict=True):
        ranked = reverse_rank(reader, condition=condition, observed_delta=row_outcome, bins=bins)
        if not ranked:
            continue
        match = _SOURCE_RE.search(ranked[0]["source"])
        if match is None:
            continue
        byte, bin_value = map(int, match.groups())
        covered += 1
        hits += int((row_source[byte] >> shift) == bin_value)
        baselines += int(np.mean(source[:, byte] >> shift == bin_value) * 1_000_000)
    baseline_rate = baselines / max(covered * 1_000_000, 1)
    return {
        "edges": len(edges),
        "mean_edge_excess_count": float(np.mean(edge_effects)) if edge_effects else 0.0,
        "edge_effects": edge_effects,
        "reverse_coverage": covered / len(source),
        "reverse_top1_hit_rate": hits / max(covered, 1),
        "reverse_marginal_baseline_rate": baseline_rate,
        "reverse_lift_over_marginal": (hits / max(covered, 1)) / max(baseline_rate, 1e-12),
    }
