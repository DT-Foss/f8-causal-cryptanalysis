"""Selection-corrected rank overlay for independent R20 readers.

Each reader contributes only its already out-of-fold 256-candidate score
vector.  Score scales are removed by a within-row descending midrank map.  The
complete ternary coefficient family {-1, 0, +1}^R minus the zero vector is
searched, and the identical search is repeated for every shared XOR label
offset.  The resulting exact p-value therefore includes coefficient and subset
selection rather than treating the best overlay as preselected.
"""

from __future__ import annotations

import hashlib
import itertools
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np


def _candidate_midranks(scores: Sequence[float]) -> np.ndarray:
    values = np.asarray(scores, dtype=np.float64)
    if values.shape != (256,) or not np.isfinite(values).all():
        raise ValueError("rank-overlay score vector geometry differs")
    order = np.argsort(-values, kind="stable")
    ranks = np.empty(256, dtype=np.float64)
    start = 0
    while start < 256:
        stop = start + 1
        value = values[order[start]]
        while stop < 256 and values[order[stop]] == value:
            stop += 1
        midrank = 1.0 + start + 0.5 * (stop - start - 1)
        ranks[order[start:stop]] = midrank
        start = stop
    return ranks


def _centered_rank_score(scores: Sequence[float]) -> np.ndarray:
    ranks = _candidate_midranks(scores)
    return ((128.5 - ranks) / 127.5).astype(np.float32)


def _prefix_index(label: str) -> int:
    marker = "_p"
    start = label.find(marker)
    if start < 0 or start + 4 > len(label):
        raise ValueError(f"rank-overlay label lacks prefix index: {label}")
    value = label[start + 2 : start + 4]
    if not value.isdigit():
        raise ValueError(f"rank-overlay prefix index differs: {label}")
    return int(value)


@dataclass(frozen=True)
class RankOverlayCorpus:
    reader_ids: tuple[str, ...]
    labels: tuple[str, ...]
    true_prefixes: np.ndarray
    prefix_groups: np.ndarray
    rank_scores: np.ndarray


def build_rank_overlay_corpus(
    reader_rows: Mapping[str, Sequence[Mapping[str, Any]]],
) -> RankOverlayCorpus:
    if len(reader_rows) < 2:
        raise ValueError("rank overlay requires at least two readers")
    reader_ids = tuple(reader_rows)
    normalized: dict[str, dict[str, Mapping[str, Any]]] = {}
    for reader_id, rows in reader_rows.items():
        by_label = {str(row["label"]): row for row in rows}
        if len(rows) != 20 or len(by_label) != 20:
            raise ValueError(f"rank-overlay reader cover differs: {reader_id}")
        normalized[reader_id] = by_label
    labels = tuple(sorted(normalized[reader_ids[0]]))
    if any(tuple(sorted(normalized[reader_id])) != labels for reader_id in reader_ids):
        raise ValueError("rank-overlay reader labels differ")
    true_prefixes = []
    groups = []
    rank_scores = np.empty((20, len(reader_ids), 256), dtype=np.float32)
    for row_index, label in enumerate(labels):
        truths = {
            int(normalized[reader_id][label]["true_prefix"])
            for reader_id in reader_ids
        }
        if len(truths) != 1:
            raise ValueError(f"rank-overlay true prefix differs: {label}")
        true_prefix = truths.pop()
        if not 0 <= true_prefix < 256:
            raise ValueError("rank-overlay true prefix is outside one byte")
        true_prefixes.append(true_prefix)
        groups.append(_prefix_index(label))
        for reader_index, reader_id in enumerate(reader_ids):
            rank_scores[row_index, reader_index] = _centered_rank_score(
                normalized[reader_id][label]["scores"]
            )
    if sorted(set(groups)) != [0, 1, 2, 3, 4] or any(
        groups.count(group) != 4 for group in range(5)
    ):
        raise ValueError("rank-overlay prefix group geometry differs")
    return RankOverlayCorpus(
        reader_ids=reader_ids,
        labels=labels,
        true_prefixes=np.asarray(true_prefixes, dtype=np.uint8),
        prefix_groups=np.asarray(groups, dtype=np.uint8),
        rank_scores=rank_scores,
    )


def ternary_coefficient_modes(reader_count: int) -> tuple[tuple[int, ...], ...]:
    if reader_count < 2 or reader_count > 10:
        raise ValueError("rank-overlay reader count differs")
    return tuple(
        mode
        for mode in itertools.product((-1, 0, 1), repeat=reader_count)
        if any(mode)
    )


def _combined_candidate_ranks(
    corpus: RankOverlayCorpus,
    coefficients: Sequence[int],
) -> tuple[np.ndarray, np.ndarray]:
    weights = np.asarray(coefficients, dtype=np.float64)
    if weights.shape != (len(corpus.reader_ids),) or not np.any(weights):
        raise ValueError("rank-overlay coefficient geometry differs")
    scores = np.tensordot(corpus.rank_scores, weights, axes=(1, 0))
    scores /= float(np.abs(weights).sum())
    ranks = np.vstack([_candidate_midranks(row) for row in scores])
    return scores, ranks


def selection_corrected_rank_overlay(
    corpus: RankOverlayCorpus,
) -> dict[str, Any]:
    modes = ternary_coefficient_modes(len(corpus.reader_ids))
    mode_curves = np.empty((len(modes), 256), dtype=np.float64)
    mode_offset_zero_fold_means = []
    selected_scores: np.ndarray | None = None
    selected_ranks: np.ndarray | None = None
    selected_mode_index = -1
    selected_observed = math.inf
    offsets = np.arange(256, dtype=np.uint16)
    for mode_index, mode in enumerate(modes):
        scores, ranks = _combined_candidate_ranks(corpus, mode)
        row_indices = np.arange(20)[:, None]
        candidate_indices = np.bitwise_xor(
            corpus.true_prefixes.astype(np.uint16)[:, None], offsets[None, :]
        )
        selected = ranks[row_indices, candidate_indices]
        curve = np.log2(selected).mean(axis=0)
        mode_curves[mode_index] = curve
        fold_means = [
            float(
                np.log2(
                    ranks[corpus.prefix_groups == group][
                        np.arange(4),
                        corpus.true_prefixes[corpus.prefix_groups == group],
                    ]
                ).mean()
            )
            for group in range(5)
        ]
        mode_offset_zero_fold_means.append(fold_means)
        observed = float(curve[0])
        if (observed, mode) < (
            selected_observed,
            modes[selected_mode_index] if selected_mode_index >= 0 else mode,
        ):
            selected_observed = observed
            selected_mode_index = mode_index
            selected_scores = scores
            selected_ranks = ranks
    assert selected_scores is not None and selected_ranks is not None
    selection_curve = mode_curves.min(axis=0)
    exact_p = float(np.count_nonzero(selection_curve <= selected_observed + 1e-15) / 256.0)
    uniform = sum(math.log2(rank) for rank in range(1, 257)) / 256.0
    selected_mode = modes[selected_mode_index]
    selected_fold_means = mode_offset_zero_fold_means[selected_mode_index]
    rows = []
    for index, label in enumerate(corpus.labels):
        rows.append(
            {
                "label": label,
                "prefix_index": int(corpus.prefix_groups[index]),
                "true_prefix": int(corpus.true_prefixes[index]),
                "midrank": float(
                    selected_ranks[index, int(corpus.true_prefixes[index])]
                ),
                "scores": selected_scores[index].tolist(),
            }
        )
    return {
        "reader_ids": list(corpus.reader_ids),
        "mode_family": "complete_nonzero_ternary_coefficients",
        "mode_count": len(modes),
        "selected_coefficients": list(selected_mode),
        "selected_readers": [
            {"reader_id": reader_id, "coefficient": coefficient}
            for reader_id, coefficient in zip(corpus.reader_ids, selected_mode, strict=True)
            if coefficient
        ],
        "mean_log2_rank": selected_observed,
        "uniform_mean_log2_rank_reference": uniform,
        "mean_log2_rank_bit_gain": uniform - selected_observed,
        "outer_prefix_fold_mean_log2_ranks": selected_fold_means,
        "outer_prefix_folds_with_positive_bit_gain": sum(
            uniform - value > 0.0 for value in selected_fold_means
        ),
        "outer_holdout_rows": rows,
        "selected_mode_shared_xor_curve": mode_curves[selected_mode_index].tolist(),
        "selection_corrected_shared_xor_curve": selection_curve.tolist(),
        "selection_corrected_exact_shared_xor_p": exact_p,
        "selection_corrected_best_xor_offset": int(np.argmin(selection_curve)),
        "observed_offset": 0,
        "mode_ledger_sha256": hashlib.sha256(
            np.asarray(modes, dtype=np.int8).tobytes()
        ).hexdigest(),
        "mode_curves_float64le_sha256": hashlib.sha256(
            mode_curves.astype("<f8").tobytes()
        ).hexdigest(),
    }
