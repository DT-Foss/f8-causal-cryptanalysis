"""Transparent paired-trajectory features and linear readouts for A220."""

from __future__ import annotations

import hashlib
import itertools
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np
from scipy.stats import rankdata

from arx_carry_leak.key_atlas import fit_ridge_logistic

ELIGIBLE_CHANNELS = ("decisions", "search_propagations", "redundant_clauses_delta")
FEATURE_FAMILY_ORDER = (
    "P1_dense_local",
    "P2_dense_cross",
    "P3_dense_cube",
    "P4_dense_path",
    "P5_dense_all",
)
FEATURE_COUNTS = {
    "P1_dense_local": 12,
    "P2_dense_cross": 24,
    "P3_dense_cube": 36,
    "P4_dense_path": 48,
    "P5_dense_all": 60,
}
READOUT_ORDER = ("ridge_logistic", "gram_wiener_fisher")
RIDGE_LAMBDA_GRID = (0.01, 0.1, 1.0, 10.0, 100.0)
GEOMETRY_ORDER = ("numeric", "reflected_gray8", "formula_gray8")
SCHEDULE_ORDER = ("staged_retained_resolve", "one_shot")
ATOMIC_BUNDLE_ORDER = tuple(
    f"{geometry}__{schedule}" for geometry in GEOMETRY_ORDER for schedule in SCHEDULE_ORDER
)
DUAL_BUNDLE_ORDER = tuple(f"{geometry}__dual_schedule" for geometry in GEOMETRY_ORDER)
BUNDLE_ORDER = (*ATOMIC_BUNDLE_ORDER, *DUAL_BUNDLE_ORDER)
MATCHED_NULL_SEED_LABEL = "f8-causal:A220:selection-matched-prefix-cluster-null:v1"
EXPECTED_MATCHED_NULL_PERMUTATION_SHA256 = (
    "8e7af50c509be00878d335acc0b49c4838f74ed9ae2c96ba9ca9f6938819a588"
)


@dataclass(frozen=True)
class PairFeatureView:
    names: tuple[str, ...]
    matrix: np.ndarray


@dataclass(frozen=True)
class CandidateIdentity:
    bundle_id: str
    feature_family: str
    readout_kind: str
    ridge_lambda: float

    def __post_init__(self) -> None:
        if (
            self.bundle_id not in BUNDLE_ORDER
            or self.feature_family not in FEATURE_FAMILY_ORDER
            or self.readout_kind not in READOUT_ORDER
            or self.ridge_lambda not in RIDGE_LAMBDA_GRID
        ):
            raise ValueError("A220 candidate identity differs from the frozen grid")

    @property
    def run_count(self) -> int:
        return 4 if self.bundle_id in DUAL_BUNDLE_ORDER else 2

    def as_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "feature_family": self.feature_family,
            "readout_kind": self.readout_kind,
            "ridge_lambda": self.ridge_lambda,
            "run_count": self.run_count,
        }


@dataclass(frozen=True)
class MatchedPermutationPair:
    replicate: int
    fit_cluster_permutation: tuple[int, ...]
    selection_cluster_permutation: tuple[int, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "replicate": self.replicate,
            "fit_cluster_permutation": list(self.fit_cluster_permutation),
            "selection_cluster_permutation": list(self.selection_cluster_permutation),
        }


@dataclass(frozen=True)
class FactorialLinearReadout:
    kind: str
    feature_family: str
    feature_names: tuple[str, ...]
    means: tuple[float, ...]
    scales: tuple[float, ...]
    intercept: float
    coefficients: tuple[float, ...]
    ridge_lambda: float
    diagnostics: Mapping[str, Any]

    def __post_init__(self) -> None:
        width = FEATURE_COUNTS.get(self.feature_family)
        numeric = np.asarray(
            [*self.means, *self.scales, self.intercept, *self.coefficients],
            dtype=np.float64,
        )
        if (
            self.kind not in READOUT_ORDER
            or width is None
            or len(self.feature_names) != width
            or len(set(self.feature_names)) != width
            or len(self.means) != width
            or len(self.scales) != width
            or len(self.coefficients) != width
            or numeric.shape != (3 * width + 1,)
            or not np.isfinite(numeric).all()
            or np.any(np.asarray(self.scales) <= 0.0)
            or not np.isfinite(self.ridge_lambda)
            or self.ridge_lambda <= 0.0
            or not isinstance(self.diagnostics, Mapping)
        ):
            raise ValueError("A220 serialized readout is malformed")

    def scores(self, matrix: np.ndarray) -> np.ndarray:
        values = np.asarray(matrix, dtype=np.float64)
        if values.ndim != 2 or values.shape[1] != len(self.feature_names):
            raise ValueError("A220 feature matrix differs from fitted readout")
        standardized = (values - np.asarray(self.means)) / np.asarray(self.scales)
        result = self.intercept + np.einsum(
            "ij,j->i", standardized, np.asarray(self.coefficients), optimize=False
        )
        if not np.isfinite(result).all():
            raise RuntimeError("A220 readout produced non-finite scores")
        return result

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "feature_family": self.feature_family,
            "feature_names": list(self.feature_names),
            "means": list(self.means),
            "scales": list(self.scales),
            "intercept": self.intercept,
            "coefficients": list(self.coefficients),
            "ridge_lambda": self.ridge_lambda,
            "diagnostics": dict(self.diagnostics),
        }


def readout_from_dict(value: Mapping[str, Any]) -> FactorialLinearReadout:
    required = {
        "kind",
        "feature_family",
        "feature_names",
        "means",
        "scales",
        "intercept",
        "coefficients",
        "ridge_lambda",
        "diagnostics",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        raise ValueError("A220 serialized readout schema differs")
    return FactorialLinearReadout(
        kind=str(value["kind"]),
        feature_family=str(value["feature_family"]),
        feature_names=tuple(str(name) for name in value["feature_names"]),
        means=tuple(float(item) for item in value["means"]),
        scales=tuple(float(item) for item in value["scales"]),
        intercept=float(value["intercept"]),
        coefficients=tuple(float(item) for item in value["coefficients"]),
        ridge_lambda=float(value["ridge_lambda"]),
        diagnostics=dict(value["diagnostics"]),
    )


def _average_ranks(values: np.ndarray) -> np.ndarray:
    return np.asarray(rankdata(values, method="average"), dtype=np.float64)


def centered_score_ranks(scores: np.ndarray) -> np.ndarray:
    values = np.asarray(scores, dtype=np.float64)
    if values.shape != (256,) or not np.isfinite(values).all():
        raise ValueError("A220 bundle score vector must contain 256 finite values")
    return 2.0 * (_average_ranks(values) - 1.0) / 255.0 - 1.0


def dual_schedule_scores(left: np.ndarray, right: np.ndarray) -> np.ndarray:
    return 0.5 * (centered_score_ranks(left) + centered_score_ranks(right))


def dual_schedule_score_matrix(left: np.ndarray, right: np.ndarray) -> np.ndarray:
    left_values = np.asarray(left, dtype=np.float64)
    right_values = np.asarray(right, dtype=np.float64)
    if (
        left_values.ndim != 2
        or left_values.shape[0] == 0
        or left_values.shape[1:] != (256,)
        or right_values.shape != left_values.shape
        or not np.isfinite(left_values).all()
        or not np.isfinite(right_values).all()
    ):
        raise ValueError("A220 dual-schedule key-score matrices differ")
    return np.row_stack(
        [
            dual_schedule_scores(left_row, right_row)
            for left_row, right_row in zip(left_values, right_values, strict=True)
        ]
    )


def add_one_lower_tail_p(observed: float, null_statistics: Sequence[float]) -> float:
    values = np.asarray(null_statistics, dtype=np.float64)
    if (
        not math.isfinite(observed)
        or values.ndim != 1
        or len(values) == 0
        or not np.isfinite(values).all()
    ):
        raise ValueError("invalid A220 matched-null statistics")
    return float((1 + np.count_nonzero(values <= observed)) / (len(values) + 1))


def exact_lower_tail_p(
    observed: float, permutation_statistics: Sequence[float], *, expected_count: int = 120
) -> float:
    values = np.asarray(permutation_statistics, dtype=np.float64)
    if (
        not math.isfinite(observed)
        or expected_count <= 0
        or values.shape != (expected_count,)
        or not np.isfinite(values).all()
    ):
        raise ValueError("invalid A220 exact-null statistics")
    count = int(np.count_nonzero(values <= observed))
    if count == 0:
        raise ValueError("A220 exact null does not contain the identity observation")
    return float(count / expected_count)


def exact_rank(scores: np.ndarray, target_prefix: int) -> int:
    """Rank descending scores with the frozen ascending-prefix tie break."""
    values = np.asarray(scores, dtype=np.float64)
    if (
        values.shape != (256,)
        or not np.isfinite(values).all()
        or not isinstance(target_prefix, int)
        or isinstance(target_prefix, bool)
        or not 0 <= target_prefix < 256
    ):
        raise ValueError("invalid A220 prefix-rank input")
    target = values[target_prefix]
    prefixes = np.arange(256)
    return (
        1
        + int(np.count_nonzero(values > target))
        + int(np.count_nonzero((values == target) & (prefixes < target_prefix)))
    )


def rank_metrics(ranks: Sequence[int]) -> dict[str, Any]:
    values = np.asarray(ranks)
    if (
        values.ndim != 1
        or len(values) == 0
        or not np.issubdtype(values.dtype, np.integer)
        or np.any((values < 1) | (values > 256))
    ):
        raise ValueError("invalid A220 rank collection")
    integers = values.astype(np.int64, copy=False)
    result: dict[str, Any] = {
        "ranks": [int(value) for value in integers],
        "mean_log2_rank": float(np.mean(np.log2(integers))),
        "median_rank": float(np.median(integers)),
        "mean_rank": float(np.mean(integers)),
        "mean_reciprocal_rank": float(np.mean(1.0 / integers)),
    }
    for cutoff in (1, 8, 16, 32, 64):
        result[f"hit_at_{cutoff}"] = float(np.mean(integers <= cutoff))
    return result


def evaluate_score_matrix(scores: np.ndarray, target_prefixes: Sequence[int]) -> dict[str, Any]:
    values = np.asarray(scores, dtype=np.float64)
    if values.shape != (len(target_prefixes), 256) or not np.isfinite(values).all():
        raise ValueError("invalid A220 key-score matrix")
    return rank_metrics(
        [exact_rank(row, target) for row, target in zip(values, target_prefixes, strict=True)]
    )


def score_readout_views(
    readout: FactorialLinearReadout, views: Sequence[PairFeatureView]
) -> np.ndarray:
    if not views:
        raise ValueError("A220 readout requires at least one key view")
    rows = []
    for view in views:
        if view.names != readout.feature_names:
            raise ValueError("A220 key view differs from frozen readout")
        rows.append(readout.scores(view.matrix))
    result = np.row_stack(rows)
    if result.shape != (len(views), 256) or not np.isfinite(result).all():
        raise RuntimeError("A220 readout key-score matrix is malformed")
    return result


def candidate_selection_key(
    identity: CandidateIdentity, metrics: Mapping[str, Any]
) -> tuple[Any, ...]:
    required = {
        "mean_log2_rank",
        "median_rank",
        "hit_at_16",
        "mean_reciprocal_rank",
    }
    if not required.issubset(metrics):
        raise ValueError("A220 candidate selection metrics are incomplete")
    numeric = {name: float(metrics[name]) for name in required}
    if not all(math.isfinite(value) for value in numeric.values()):
        raise ValueError("A220 candidate selection metrics are non-finite")
    return (
        numeric["mean_log2_rank"],
        numeric["median_rank"],
        -numeric["hit_at_16"],
        -numeric["mean_reciprocal_rank"],
        identity.run_count,
        FEATURE_COUNTS[identity.feature_family],
        BUNDLE_ORDER.index(identity.bundle_id),
        FEATURE_FAMILY_ORDER.index(identity.feature_family),
        READOUT_ORDER.index(identity.readout_kind),
        RIDGE_LAMBDA_GRID.index(identity.ridge_lambda),
    )


def select_candidate(
    candidates: Sequence[tuple[CandidateIdentity, Mapping[str, Any]]],
) -> tuple[CandidateIdentity, Mapping[str, Any]]:
    if not candidates:
        raise ValueError("A220 selection grid is empty")
    identities = [identity for identity, _ in candidates]
    if len(set(identities)) != len(identities):
        raise ValueError("A220 selection grid contains duplicate candidates")
    return min(
        candidates,
        key=lambda candidate: candidate_selection_key(candidate[0], candidate[1]),
    )


def _hash_uniform_index(seed: str, domain: str, counter: int, upper: int) -> int:
    if not seed or not domain or counter < 0 or upper <= 0:
        raise ValueError("invalid A220 hash-index request")
    space = 1 << 256
    acceptance_limit = space - (space % upper)
    nonce = 0
    while True:
        material = f"{seed}\x00{domain}\x00{counter}\x00{nonce}".encode()
        value = int.from_bytes(hashlib.sha256(material).digest(), "big")
        if value < acceptance_limit:
            return value % upper
        nonce += 1


def deterministic_matched_permutation_pairs(
    seed_label: str, *, replicates: int = 64
) -> tuple[MatchedPermutationPair, ...]:
    if not isinstance(seed_label, str) or not seed_label or not 1 <= replicates <= 1024:
        raise ValueError("invalid A220 matched-null request")
    fit = tuple(
        permutation
        for permutation in itertools.permutations(range(8))
        if permutation != tuple(range(8))
    )
    selection = tuple(
        permutation
        for permutation in itertools.permutations(range(5))
        if permutation != tuple(range(5))
    )
    if replicates > len(fit) * len(selection):
        raise ValueError("A220 matched-null requests too many unique permutation pairs")
    result = []
    seen: set[tuple[tuple[int, ...], tuple[int, ...]]] = set()
    counter = 0
    while len(result) < replicates:
        fit_permutation = fit[
            _hash_uniform_index(seed_label, "fit-prefix-clusters", counter, len(fit))
        ]
        selection_permutation = selection[
            _hash_uniform_index(seed_label, "selection-prefix-clusters", counter, len(selection))
        ]
        pair = (fit_permutation, selection_permutation)
        counter += 1
        if pair in seen:
            continue
        seen.add(pair)
        result.append(
            MatchedPermutationPair(
                replicate=len(result),
                fit_cluster_permutation=fit_permutation,
                selection_cluster_permutation=selection_permutation,
            )
        )
    pairs = tuple(result)
    if seed_label == MATCHED_NULL_SEED_LABEL and replicates == 64:
        raw = json.dumps(
            [pair.as_dict() for pair in pairs],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
        if hashlib.sha256(raw).hexdigest() != EXPECTED_MATCHED_NULL_PERMUTATION_SHA256:
            raise RuntimeError("A220 matched-null permutation digest differs")
    return pairs


def permute_cluster_targets(
    cluster_ids: Sequence[str],
    target_prefixes: Sequence[int],
    permutation: Sequence[int],
    *,
    replicates_per_cluster: int = 4,
) -> tuple[int, ...]:
    if (
        not cluster_ids
        or len(cluster_ids) != len(target_prefixes)
        or replicates_per_cluster <= 0
        or any(not isinstance(cluster, str) or not cluster for cluster in cluster_ids)
    ):
        raise ValueError("invalid A220 matched-null cluster table")
    clusters = tuple(dict.fromkeys(cluster_ids))
    if len(permutation) != len(clusters) or set(permutation) != set(range(len(clusters))):
        raise ValueError("invalid A220 cluster-label permutation")
    target_by_cluster: list[int] = []
    for cluster in clusters:
        positions = [index for index, value in enumerate(cluster_ids) if value == cluster]
        observed = {target_prefixes[index] for index in positions}
        if len(positions) != replicates_per_cluster or len(observed) != 1:
            raise ValueError("A220 prefix clusters do not retain intact suffix replicates")
        target = observed.pop()
        if not isinstance(target, int) or isinstance(target, bool) or not 0 <= target < 256:
            raise ValueError("invalid A220 prefix-cluster target")
        target_by_cluster.append(target)
    if len(set(target_by_cluster)) != len(target_by_cluster):
        raise ValueError("A220 prefix clusters do not have unique labels")
    replacement = {
        cluster: target_by_cluster[permutation[index]] for index, cluster in enumerate(clusters)
    }
    result = tuple(replacement[cluster] for cluster in cluster_ids)
    if sorted(result) != sorted(int(value) for value in target_prefixes):
        raise RuntimeError("A220 cluster permutation changed the target-label multiset")
    return result


def _aligned_cells(trajectory: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    cells = trajectory.get("cells")
    if not isinstance(cells, list) or len(cells) != 256:
        raise ValueError("A220 trajectory must contain 256 cells")
    by_prefix: dict[int, Mapping[str, Any]] = {}
    for cell in cells:
        if not isinstance(cell, Mapping):
            raise ValueError("A220 trajectory cell is malformed")
        prefix = cell.get("prefix8")
        if (
            not isinstance(prefix, str)
            or len(prefix) != 8
            or set(prefix) - {"0", "1"}
            or int(prefix, 2) in by_prefix
        ):
            raise ValueError("A220 trajectory prefix cover is malformed")
        by_prefix[int(prefix, 2)] = cell
    if set(by_prefix) != set(range(256)):
        raise ValueError("A220 trajectory prefix cover is incomplete")
    return [by_prefix[prefix] for prefix in range(256)]


def _channel_matrix(trajectory: Mapping[str, Any]) -> np.ndarray:
    matrix = np.empty((256, len(ELIGIBLE_CHANNELS)), dtype=np.float64)
    for index, cell in enumerate(_aligned_cells(trajectory)):
        metrics = cell.get("metrics_delta")
        redundant = cell.get("redundant_clauses_delta")
        if (
            not isinstance(metrics, list)
            or len(metrics) != 3
            or any(not isinstance(value, int) or isinstance(value, bool) for value in metrics)
            or metrics[1] < 0
            or metrics[2] < 0
            or not isinstance(redundant, int)
            or isinstance(redundant, bool)
        ):
            raise ValueError("A220 eligible trajectory channel is malformed")
        matrix[index, 0] = np.log1p(metrics[1])
        matrix[index, 1] = np.log1p(metrics[2])
        matrix[index, 2] = np.sign(redundant) * np.log1p(abs(redundant))
    if not np.isfinite(matrix).all():
        raise RuntimeError("A220 channel transform produced non-finite values")
    return matrix


def _zscore(matrix: np.ndarray) -> np.ndarray:
    means = matrix.mean(axis=0)
    scales = matrix.std(axis=0)
    constant = scales <= np.maximum(1e-12, np.abs(means) * 1e-12)
    safe = scales.copy()
    safe[constant] = 1.0
    result = (matrix - means) / safe
    result[:, constant] = 0.0
    return result


def _centered_column_ranks(matrix: np.ndarray) -> np.ndarray:
    result = np.empty_like(matrix, dtype=np.float64)
    for column in range(matrix.shape[1]):
        result[:, column] = 2.0 * (_average_ranks(matrix[:, column]) - 1.0) / 255.0 - 1.0
    return result


def _operator_order(trajectory: Mapping[str, Any]) -> tuple[np.ndarray, np.ndarray]:
    raw = trajectory.get("order")
    if (
        not isinstance(raw, list)
        or len(raw) != 256
        or any(
            not isinstance(prefix, str) or len(prefix) != 8 or bool(set(prefix) - {"0", "1"})
            for prefix in raw
        )
    ):
        raise ValueError("A220 operator order is malformed")
    order = np.asarray([int(prefix, 2) for prefix in raw], dtype=np.int64)
    if set(order.tolist()) != set(range(256)):
        raise ValueError("A220 operator order is not a complete prefix permutation")
    position = np.empty(256, dtype=np.int64)
    position[order] = np.arange(256)
    return order, position


def _hypercube_residual(matrix: np.ndarray) -> np.ndarray:
    result = np.empty_like(matrix)
    for prefix in range(256):
        neighbors = [prefix ^ (1 << bit) for bit in range(8)]
        result[prefix] = matrix[prefix] - matrix[neighbors].mean(axis=0)
    return result


def _path_gradients(
    matrix: np.ndarray, trajectory: Mapping[str, Any]
) -> tuple[np.ndarray, np.ndarray]:
    order, position = _operator_order(trajectory)
    predecessor = order[(position - 1) % 256]
    successor = order[(position + 1) % 256]
    return matrix - matrix[predecessor], matrix - matrix[successor]


def extract_pair_feature_views(
    forward: Mapping[str, Any], reverse: Mapping[str, Any]
) -> dict[str, PairFeatureView]:
    """Build the five frozen A220 feature families for one direction pair."""
    trajectories = {"forward": forward, "reverse": reverse}
    local_parts: list[np.ndarray] = []
    local_names: list[str] = []
    views: dict[str, dict[str, np.ndarray]] = {}
    for direction, trajectory in trajectories.items():
        transformed = _channel_matrix(trajectory)
        views[direction] = {
            "z": _zscore(transformed),
            "rank": _centered_column_ranks(transformed),
        }
        for view in ("z", "rank"):
            local_parts.append(views[direction][view])
            local_names.extend(f"{direction}.{view}.{channel}" for channel in ELIGIBLE_CHANNELS)
    local = np.column_stack(local_parts)

    cross_parts: list[np.ndarray] = []
    cross_names: list[str] = []
    root2 = np.sqrt(2.0)
    for view in ("z", "rank"):
        left, right = views["forward"][view], views["reverse"][view]
        cross_parts.extend(((left + right) / root2, (left - right) / root2))
        cross_names.extend(f"direction.{view}.sum.{channel}" for channel in ELIGIBLE_CHANNELS)
        cross_names.extend(
            f"direction.{view}.difference.{channel}" for channel in ELIGIBLE_CHANNELS
        )
    cross = np.column_stack(cross_parts)
    cube = _hypercube_residual(local)
    cube_names = [f"cube_h1.{name}" for name in local_names]

    path_parts: list[np.ndarray] = []
    path_names: list[str] = []
    width = 2 * len(ELIGIBLE_CHANNELS)
    for direction_index, (direction, trajectory) in enumerate(trajectories.items()):
        direction_local = local[:, direction_index * width : (direction_index + 1) * width]
        predecessor, successor = _path_gradients(direction_local, trajectory)
        path_parts.extend((predecessor, successor))
        names = [
            f"{direction}.{view}.{channel}"
            for view in ("z", "rank")
            for channel in ELIGIBLE_CHANNELS
        ]
        path_names.extend(f"path_predecessor.{name}" for name in names)
        path_names.extend(f"path_successor.{name}" for name in names)
    path = np.column_stack(path_parts)

    components = {
        "local": (local, local_names),
        "cross": (cross, cross_names),
        "cube": (cube, cube_names),
        "path": (path, path_names),
    }
    layouts = {
        "P1_dense_local": ("local",),
        "P2_dense_cross": ("local", "cross"),
        "P3_dense_cube": ("local", "cross", "cube"),
        "P4_dense_path": ("local", "cross", "path"),
        "P5_dense_all": ("local", "cross", "cube", "path"),
    }
    result: dict[str, PairFeatureView] = {}
    for family in FEATURE_FAMILY_ORDER:
        selected = layouts[family]
        matrix = np.column_stack([components[name][0] for name in selected])
        names = tuple(feature for name in selected for feature in components[name][1])
        if (
            matrix.shape != (256, FEATURE_COUNTS[family])
            or len(names) != FEATURE_COUNTS[family]
            or len(set(names)) != len(names)
            or not np.isfinite(matrix).all()
        ):
            raise RuntimeError(f"A220 feature family {family} is malformed")
        result[family] = PairFeatureView(names=names, matrix=matrix)
    return result


def training_matrix(
    views: Sequence[PairFeatureView], target_prefixes: Sequence[int]
) -> tuple[np.ndarray, np.ndarray, tuple[str, ...]]:
    if not views or len(views) != len(target_prefixes):
        raise ValueError("A220 training views and target prefixes differ")
    names = views[0].names
    matrices = []
    labels = []
    for view, target in zip(views, target_prefixes, strict=True):
        if (
            view.names != names
            or len(set(view.names)) != len(names)
            or view.matrix.shape != (256, len(names))
            or not np.isfinite(view.matrix).all()
            or not isinstance(target, int)
            or isinstance(target, bool)
            or not 0 <= target < 256
        ):
            raise ValueError("A220 training feature identity differs")
        target_labels = np.zeros(256, dtype=np.uint8)
        target_labels[int(target)] = 1
        matrices.append(view.matrix)
        labels.append(target_labels)
    return np.row_stack(matrices), np.concatenate(labels), names


def _standardization(values: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    means = values.mean(axis=0)
    scales = values.std(axis=0)
    constant = scales <= np.maximum(1e-10, np.abs(means) * 1e-10)
    scales[constant] = 1.0
    standardized = (values - means) / scales
    standardized[:, constant] = 0.0
    return standardized, means, scales


def fit_factorial_readout(
    matrix: np.ndarray,
    labels: np.ndarray,
    *,
    kind: str,
    feature_family: str,
    feature_names: Sequence[str],
    ridge_lambda: float,
) -> FactorialLinearReadout:
    values = np.asarray(matrix, dtype=np.float64)
    raw_targets = np.asarray(labels)
    targets = np.asarray(labels, dtype=np.uint8)
    expected_width = FEATURE_COUNTS.get(feature_family)
    if (
        kind not in READOUT_ORDER
        or expected_width is None
        or values.ndim != 2
        or values.shape[1] != expected_width
        or len(feature_names) != expected_width
        or len(set(feature_names)) != expected_width
        or raw_targets.shape != (len(values),)
        or not (
            np.issubdtype(raw_targets.dtype, np.integer)
            or np.issubdtype(raw_targets.dtype, np.bool_)
        )
        or np.any((raw_targets != 0) & (raw_targets != 1))
        or targets.shape != (len(values),)
        or set(np.unique(targets)) != {0, 1}
        or not np.isfinite(values).all()
        or not np.isfinite(ridge_lambda)
        or ridge_lambda <= 0
    ):
        raise ValueError("invalid A220 readout training data")
    if kind == "ridge_logistic":
        fitted = fit_ridge_logistic(
            values,
            targets,
            feature_names=feature_names,
            ridge_lambda=ridge_lambda,
        )
        return FactorialLinearReadout(
            kind=kind,
            feature_family=feature_family,
            feature_names=tuple(feature_names),
            means=fitted.means,
            scales=fitted.scales,
            intercept=fitted.intercept,
            coefficients=fitted.coefficients,
            ridge_lambda=ridge_lambda,
            diagnostics={
                "optimizer_iterations": fitted.optimizer_iterations,
                "optimizer_gradient_norm": fitted.optimizer_gradient_norm,
                "positive_rows": int(targets.sum()),
                "negative_rows": int(len(targets) - targets.sum()),
            },
        )

    standardized, means, scales = _standardization(values)
    positive = standardized[targets == 1]
    negative = standardized[targets == 0]
    if len(positive) < 2 or len(negative) < 2:
        raise ValueError("A220 Gram/Wiener readout requires at least two rows per class")
    positive_mean, negative_mean = positive.mean(axis=0), negative.mean(axis=0)
    positive_centered = positive - positive_mean
    negative_centered = negative - negative_mean
    covariance = 0.5 * (
        np.einsum("ni,nj->ij", positive_centered, positive_centered, optimize=False)
        / (len(positive) - 1)
        + np.einsum("ni,nj->ij", negative_centered, negative_centered, optimize=False)
        / (len(negative) - 1)
    )
    system = covariance + ridge_lambda * np.eye(values.shape[1])
    contrast = positive_mean - negative_mean
    coefficients = np.linalg.solve(system, contrast)
    intercept = -0.5 * float(
        np.einsum("i,i->", positive_mean + negative_mean, coefficients, optimize=False)
    )
    residual = np.einsum("ij,j->i", system, coefficients, optimize=False) - contrast
    condition = float(np.linalg.cond(system))
    if not np.isfinite(coefficients).all() or not np.isfinite(condition):
        raise RuntimeError("A220 Gram/Wiener readout is non-finite")
    return FactorialLinearReadout(
        kind=kind,
        feature_family=feature_family,
        feature_names=tuple(feature_names),
        means=tuple(float(value) for value in means),
        scales=tuple(float(value) for value in scales),
        intercept=intercept,
        coefficients=tuple(float(value) for value in coefficients),
        ridge_lambda=ridge_lambda,
        diagnostics={
            "linear_system_condition_number": condition,
            "linear_system_residual_l2": float(np.linalg.norm(residual)),
            "positive_rows": len(positive),
            "negative_rows": len(negative),
        },
    )
