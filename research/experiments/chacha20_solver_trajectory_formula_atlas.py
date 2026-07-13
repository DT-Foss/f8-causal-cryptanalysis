#!/usr/bin/env python3
"""Transfer formula-atlas operators to retained CaDiCaL learning trajectories."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader

ATTEMPT_ID = "A212"
SCHEMA = "chacha20-solver-trajectory-formula-atlas-v1"
PROTOCOL_SCHEMA = "chacha20-solver-trajectory-formula-atlas-protocol-v1"
PROTOCOL_FILENAME = "chacha20_solver_trajectory_formula_atlas_v1.json"
PROTOCOL_SHA256 = "d74edc91d2e02e4512c8798d71c4d7af457295c350d5abd561d1de4691e5de96"
RESULT_FILENAME = "chacha20_solver_trajectory_formula_atlas_v1.json"
CAUSAL_FILENAME = "chacha20_solver_trajectory_formula_atlas_v1.causal"

CHANNELS = (
    "conflicts",
    "decisions",
    "search_propagations",
    "active_variables",
    "redundant_clauses",
    "irredundant_clauses",
)
METRIC_DELTA_CHANNELS = CHANNELS[:3]
STATE_CHANNELS = CHANNELS[3:]
CONTEXT_ORDER = (
    "A210_numeric_reset_local",
    "A210_gray_reset_local",
    "A211_numeric_retained_global",
    "A211_gray_retained_global",
)
MODE_BY_CONTEXT = {
    "A210_numeric_reset_local": "numeric_incremental",
    "A210_gray_reset_local": "gray_incremental",
    "A211_numeric_retained_global": "numeric_global_incremental",
    "A211_gray_retained_global": "reflected_gray8_global_incremental",
}
T01_NULL_REPLICATES = 4096
T02_NULL_REPLICATES = 512
RIDGE_LAMBDA = 1e-3
ROOT_TOLERANCE = 1e-8
HALF_LIFE_CELLS = 32.0


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


def _q(value: float, digits: int = 12) -> float:
    rounded = round(float(value), digits)
    return 0.0 if rounded == 0.0 else rounded


def _q_array(values: np.ndarray, digits: int = 12) -> list[Any]:
    array = np.asarray(values)
    if np.iscomplexobj(array):
        raise TypeError("complex arrays require _complex_rows")
    return np.round(array.astype(np.float64), digits).tolist()


def _complex_rows(values: np.ndarray, digits: int = 12) -> list[dict[str, float]]:
    return [
        {"real": _q(complex(value).real, digits), "imag": _q(complex(value).imag, digits)}
        for value in np.asarray(values).ravel()
    ]


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _seed(label: str) -> int:
    material = f"f8-causal/A212/{PROTOCOL_SHA256}/{label}".encode()
    return int.from_bytes(hashlib.shake_256(material).digest(16), "big")


def _load_protocol_and_anchors(results_dir: Path) -> dict[str, Any]:
    research_root = Path(__file__).parents[1]
    repo_root = research_root.parent
    protocol_path = research_root / "configs" / PROTOCOL_FILENAME
    if _file_sha256(protocol_path) != PROTOCOL_SHA256:
        raise RuntimeError("A212 frozen protocol hash differs")
    protocol = json.loads(protocol_path.read_bytes())
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A210_A211_before_any_A212_operator_measurement_or_future_round_transfer"
        or boundary.get("A210_and_A211_outcomes_known_before_protocol_freeze") is not True
        or boundary.get("A212_is_claimed_as_prospective_for_A210_or_A211") is not False
        or boundary.get("A212_operator_values_used_before_protocol_freeze") is not False
        or boundary.get("future_R11_or_R20_solver_outcomes_used") is not False
        or boundary.get("hidden_key_assignment_fields_accessed_or_used_by_A212") is not False
        or boundary.get("known_SAT_prefix_used_in_feature_fit_or_schedule_score") is not False
        or boundary.get("solver_execution_in_A212") is not False
    ):
        raise RuntimeError("A212 protocol identity or information-boundary gate failed")
    if tuple(protocol.get("observed_channels", ())) != CHANNELS:
        raise RuntimeError("A212 channel registry differs")

    anchors: dict[str, Any] = {}
    for name, identity in protocol["anchors"].items():
        path = repo_root / identity["path"]
        if not path.is_file() or _file_sha256(path) != identity["sha256"]:
            raise RuntimeError(f"A212 anchor hash differs: {name}")
        if path.suffix == ".json":
            anchors[name] = json.loads(path.read_bytes())
        elif path.suffix == ".causal":
            reader = CryptoCausalReader(path)
            if reader.file_sha256 != identity["sha256"] or not reader.verify_provenance():
                raise RuntimeError(f"A212 Causal anchor gate failed: {name}")
            anchors[name] = {
                "file_sha256": reader.file_sha256,
                "graph_sha256": reader.graph_sha256,
                "explicit_triplets": len(reader.triplets(include_inferred=False)),
            }
        else:
            anchors[name] = {"file_sha256": identity["sha256"]}

    a199 = anchors["A199_result"]
    a210 = anchors["A210_result"]
    a211 = anchors["A211_result"]
    if (
        a199.get("evidence_stage")
        != protocol["anchors"]["A199_result"]["required_evidence_stage"]
        or a210.get("evidence_stage")
        != protocol["anchors"]["A210_result"]["required_evidence_stage"]
        or a211.get("evidence_stage")
        != protocol["anchors"]["A211_result"]["required_evidence_stage"]
    ):
        raise RuntimeError("A212 retained evidence-stage gate failed")
    a210_rows = a210.get("execution", {}).get("observations", [])
    a211_rows = a211.get("execution", {}).get("observations", [])
    if len(a210_rows) != 512 or len(a211_rows) != 512:
        raise RuntimeError("A212 complete trajectory anchor length failed")
    if any(row.get("status") != "unknown" for row in a210_rows):
        raise RuntimeError("A212 A210 schedule source must contain only UNKNOWN rows")
    if sum(row.get("status") == "sat" for row in a211_rows) != 2:
        raise RuntimeError("A212 A211 retained two-mode SAT anchor differs")
    return {"protocol": protocol, "anchors": anchors, "results_dir": str(results_dir)}


def _row_feature(row: dict[str, Any]) -> np.ndarray:
    delta = row.get("metrics_delta", {})
    raw = [delta.get(name) for name in METRIC_DELTA_CHANNELS]
    raw.extend(row.get(name) for name in STATE_CHANNELS)
    if any(not isinstance(value, int | float) or value < 0 for value in raw):
        raise RuntimeError("A212 trajectory row has an invalid observed channel")
    values = np.asarray(raw, dtype=np.float64)
    transformed = np.log1p(values)
    if not np.isfinite(transformed).all():
        raise RuntimeError("A212 non-finite log1p feature")
    return transformed


def _context_payload(
    *,
    key: str,
    rows: list[dict[str, Any]],
    operator_segments: np.ndarray,
    cumulant_segments: list[np.ndarray],
    prefixes: list[str],
) -> dict[str, Any]:
    flat = np.vstack([_row_feature(row) for row in rows])
    mean = flat.mean(axis=0)
    scale = flat.std(axis=0)
    if np.any(scale <= 0) or not np.isfinite(scale).all():
        raise RuntimeError(f"A212 zero/nonfinite scale in {key}")
    standardized = (flat - mean) / scale
    index_by_prefix = {row["prefix8"]: index for index, row in enumerate(rows)}
    if len(index_by_prefix) != 256 or sorted(index_by_prefix) != [f"{i:08b}" for i in range(256)]:
        raise RuntimeError(f"A212 prefix cover failed in {key}")

    standardized_by_row_id = {id(row): standardized[index] for index, row in enumerate(rows)}
    standardized_operator = np.empty_like(operator_segments, dtype=np.float64)
    cursor = 0
    for segment_index in range(operator_segments.shape[0]):
        for cell_index in range(operator_segments.shape[1]):
            standardized_operator[segment_index, cell_index] = standardized[cursor]
            cursor += 1
    if cursor != len(rows):
        raise RuntimeError(f"A212 segment flattening failed in {key}")

    standardized_cumulants: list[np.ndarray] = []
    if key.startswith("A210"):
        cursor = 0
        for segment in cumulant_segments:
            count = segment.shape[0]
            standardized_cumulants.append(standardized[cursor : cursor + count])
            cursor += count
        if cursor != len(rows):
            raise RuntimeError(f"A212 A210 cumulant segmentation failed in {key}")
    else:
        standardized_cumulants = [standardized]

    return {
        "key": key,
        "mode": MODE_BY_CONTEXT[key],
        "rows": rows,
        "prefixes": prefixes,
        "raw": flat,
        "standardized": standardized,
        "operator_segments": standardized_operator,
        "cumulant_segments": standardized_cumulants,
        "mean": mean,
        "scale": scale,
        "index_by_prefix": index_by_prefix,
        "standardized_by_row_id": standardized_by_row_id,
    }


def _build_contexts(a210: dict[str, Any], a211: dict[str, Any]) -> dict[str, dict[str, Any]]:
    contexts: dict[str, dict[str, Any]] = {}
    a210_rows = a210["execution"]["observations"]
    for key in CONTEXT_ORDER[:2]:
        mode = MODE_BY_CONTEXT[key]
        selected = [row for row in a210_rows if row["mode"] == mode]
        groups: list[list[dict[str, Any]]] = []
        for parent in (f"{value:05b}" for value in range(32)):
            group = sorted(
                (row for row in selected if row["parent_prefix5"] == parent),
                key=lambda row: row["child_index"],
            )
            if len(group) != 8 or [row["child_index"] for row in group] != list(range(8)):
                raise RuntimeError(f"A212 A210 child order failed for {key}/{parent}")
            groups.append(group)
        rows = [row for group in groups for row in group]
        segments = np.asarray(
            [[_row_feature(row) for row in group] for group in groups], dtype=np.float64
        )
        contexts[key] = _context_payload(
            key=key,
            rows=rows,
            operator_segments=segments,
            cumulant_segments=[segment for segment in segments],
            prefixes=[row["prefix8"] for row in rows],
        )

    a211_rows = a211["execution"]["observations"]
    for key in CONTEXT_ORDER[2:]:
        mode = MODE_BY_CONTEXT[key]
        rows = sorted(
            (row for row in a211_rows if row["mode"] == mode),
            key=lambda row: row["cell_index"],
        )
        if len(rows) != 256 or [row["cell_index"] for row in rows] != list(range(256)):
            raise RuntimeError(f"A212 A211 cell order failed for {key}")
        raw = np.vstack([_row_feature(row) for row in rows])
        segments = raw.reshape(8, 32, len(CHANNELS))
        contexts[key] = _context_payload(
            key=key,
            rows=rows,
            operator_segments=segments,
            cumulant_segments=[raw],
            prefixes=[row["prefix8"] for row in rows],
        )
    return contexts


def _fit_transition(x: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, dict[str, Any]]:
    gram = x.T @ x
    regularized = gram + RIDGE_LAMBDA * np.eye(x.shape[1])
    operator = (np.linalg.solve(regularized, x.T @ y)).T
    predicted = x @ operator.T
    denominator = max(float(np.linalg.norm(y)), np.finfo(float).tiny)
    residual = float(np.linalg.norm(predicted - y) / denominator)
    singular = np.linalg.svd(operator, compute_uv=False)
    spectral = float(singular[0])
    if spectral <= 0 or not np.isfinite(operator).all():
        raise RuntimeError("A212 invalid fitted transition operator")
    return operator, {
        "samples": int(x.shape[0]),
        "relative_fit_residual": _q(residual),
        "spectral_norm": _q(spectral),
        "condition_number_regularized_gram": _q(float(np.linalg.cond(regularized))),
    }


def _context_operators(context: dict[str, Any]) -> tuple[np.ndarray, list[dict[str, Any]]]:
    segments = context["operator_segments"]
    matrices: list[np.ndarray] = []
    fits: list[dict[str, Any]] = []
    if context["key"].startswith("A210"):
        for position in range(7):
            operator, fit = _fit_transition(segments[:, position, :], segments[:, position + 1, :])
            fit.update({"operator_index": position, "geometry": "pooled_child_position"})
            matrices.append(operator)
            fits.append(fit)
    else:
        for bin_index, segment in enumerate(segments):
            operator, fit = _fit_transition(segment[:-1], segment[1:])
            fit.update({"operator_index": bin_index, "geometry": "ordered_32_cell_bin"})
            matrices.append(operator)
            fits.append(fit)
    return np.asarray(matrices), fits


def _ordered_product(operators: np.ndarray, order: Sequence[int]) -> np.ndarray:
    product = np.eye(operators.shape[1])
    for index in order:
        product = operators[index] @ product
    return product


def _relative_frobenius(left: np.ndarray, right: np.ndarray) -> float:
    denominator = max(
        float(np.linalg.norm(left)), float(np.linalg.norm(right)), np.finfo(float).tiny
    )
    return float(np.linalg.norm(left - right) / denominator)


def _commutator_rows(operators: np.ndarray, lag: int) -> tuple[list[float], float]:
    rows: list[float] = []
    maximum_adjoint_error = 0.0
    for index in range(len(operators) - lag):
        left = operators[index]
        right = operators[index + lag]
        commutator = right @ left - left @ right
        denominator = max(
            float(np.linalg.norm(right @ left)) + float(np.linalg.norm(left @ right)),
            np.finfo(float).tiny,
        )
        rows.append(float(np.linalg.norm(commutator) / denominator))
        adjoint_commutator = left.T @ right.T - right.T @ left.T
        maximum_adjoint_error = max(
            maximum_adjoint_error,
            float(np.max(np.abs(commutator.T - adjoint_commutator))),
        )
    return rows, maximum_adjoint_error


def _t01(contexts: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], dict[str, np.ndarray]]:
    output: dict[str, Any] = {}
    normalized_by_context: dict[str, np.ndarray] = {}
    all_gates = True
    retained_global: list[str] = []
    lower_tail_discoveries: list[str] = []
    for key in CONTEXT_ORDER:
        raw_operators, fits = _context_operators(contexts[key])
        spectral = np.asarray([np.linalg.svd(matrix, compute_uv=False)[0] for matrix in raw_operators])
        normalized = raw_operators / spectral[:, None, None]
        normalized_by_context[key] = normalized
        count = len(normalized)
        chronological = _ordered_product(normalized, range(count))
        reversed_product = _ordered_product(normalized, reversed(range(count)))
        observed = _relative_frobenius(chronological, reversed_product)
        rng = np.random.default_rng(_seed(f"T01/{key}"))
        null = np.empty(T01_NULL_REPLICATES, dtype=np.float64)
        for replicate in range(T01_NULL_REPLICATES):
            order = rng.permutation(count).tolist()
            null[replicate] = _relative_frobenius(
                _ordered_product(normalized, order),
                _ordered_product(normalized, reversed(order)),
            )
        threshold = float(np.quantile(null, 0.975, method="higher"))
        lower_threshold = float(np.quantile(null, 0.025, method="lower"))
        empirical_p = float((1 + np.count_nonzero(null >= observed)) / (len(null) + 1))
        empirical_lower_p = float(
            (1 + np.count_nonzero(null <= observed)) / (len(null) + 1)
        )
        adjacent, adjoint1 = _commutator_rows(normalized, 1)
        lag2, adjoint2 = _commutator_rows(normalized, 2)
        gate = bool(
            np.isfinite(normalized).all()
            and np.all(spectral > 0)
            and max(adjoint1, adjoint2) <= 1e-10
        )
        prediction = bool(observed > threshold and empirical_p <= 0.025)
        if key.startswith("A211") and prediction:
            retained_global.append(key)
        lower_discovery = bool(observed < lower_threshold and empirical_lower_p <= 0.025)
        if lower_discovery:
            lower_tail_discoveries.append(key)
        all_gates = all_gates and gate
        output[key] = {
            "operator_count": count,
            "fits": fits,
            "raw_operator_sha256": _sha256(raw_operators.astype("<f8").tobytes()),
            "normalized_operator_sha256": _sha256(normalized.astype("<f8").tobytes()),
            "normalized_operators": _q_array(normalized),
            "chronological_product_sha256": _sha256(chronological.astype("<f8").tobytes()),
            "reversed_product_sha256": _sha256(reversed_product.astype("<f8").tobytes()),
            "chronological_reverse_relative_frobenius": _q(observed),
            "order_null": {
                "replicates": T01_NULL_REPLICATES,
                "mean": _q(float(null.mean())),
                "lower_2_5_percentile": _q(lower_threshold),
                "upper_97_5_percentile": _q(threshold),
                "empirical_lower_p_value": _q(empirical_lower_p),
                "empirical_upper_p_value": _q(empirical_p),
                "values_sha256": _sha256(null.astype("<f8").tobytes()),
            },
            "adjacent_commutators": [_q(value) for value in adjacent],
            "lag2_commutators": [_q(value) for value in lag2],
            "maximum_adjoint_identity_error": _q(max(adjoint1, adjoint2), 15),
            "operator_gate_passed": gate,
            "order_prediction_retained": prediction,
            "posthoc_lower_tail_order_coherence_discovery": lower_discovery,
        }
    return {
        "transfer_family": "T01",
        "contexts": output,
        "all_operator_gates_passed": all_gates,
        "retained_global_contexts": retained_global,
        "posthoc_lower_tail_order_coherence_discovery_contexts": lower_tail_discoveries,
        "prediction_retained": bool(all_gates and retained_global),
    }, normalized_by_context


def _triplet_tensor(segments: list[np.ndarray]) -> tuple[np.ndarray, int]:
    tensor = np.zeros((len(CHANNELS),) * 3, dtype=np.float64)
    samples = 0
    for segment in segments:
        if len(segment) < 3:
            continue
        left, center, right = segment[:-2], segment[1:-1], segment[2:]
        tensor += np.einsum("ni,nj,nk->ijk", left, center, right, optimize=True)
        samples += len(left)
    if samples <= 0:
        raise RuntimeError("A212 triplet context has no samples")
    return tensor / samples, samples


def _marginals_equal(left: list[np.ndarray], right: list[np.ndarray]) -> bool:
    if len(left) != len(right):
        return False
    return all(
        np.array_equal(np.sort(a, axis=0), np.sort(b, axis=0))
        for a, b in zip(left, right, strict=True)
    )


def _null_segments(
    segments: list[np.ndarray], *, kind: str, rng: np.random.Generator
) -> list[np.ndarray]:
    transformed: list[np.ndarray] = []
    for segment in segments:
        target = np.empty_like(segment)
        for channel in range(segment.shape[1]):
            if kind == "permutation":
                target[:, channel] = segment[rng.permutation(len(segment)), channel]
            elif kind == "circular_shift":
                shift = int(rng.integers(0, len(segment)))
                target[:, channel] = np.roll(segment[:, channel], shift)
            else:
                raise ValueError(kind)
        transformed.append(target)
    return transformed


def _holm_adjust(rows: list[tuple[str, float]]) -> dict[str, float]:
    ordered = sorted(rows, key=lambda row: (row[1], row[0]))
    adjusted: dict[str, float] = {}
    running = 0.0
    total = len(ordered)
    for rank, (name, value) in enumerate(ordered):
        candidate = min(1.0, (total - rank) * value)
        running = max(running, candidate)
        adjusted[name] = running
    return adjusted


def _t02(contexts: dict[str, dict[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    raw_tests: list[tuple[str, float]] = []
    all_marginals = True
    for key in CONTEXT_ORDER:
        segments = contexts[key]["cumulant_segments"]
        observed_tensor, samples = _triplet_tensor(segments)
        observed = {
            "l2_norm": float(np.linalg.norm(observed_tensor)),
            "maximum_absolute_entry": float(np.max(np.abs(observed_tensor))),
        }
        null_payload: dict[str, Any] = {}
        for kind in ("permutation", "circular_shift"):
            rng = np.random.default_rng(_seed(f"T02/{key}/{kind}"))
            values = np.empty((T02_NULL_REPLICATES, 2), dtype=np.float64)
            marginals = True
            for replicate in range(T02_NULL_REPLICATES):
                shuffled = _null_segments(segments, kind=kind, rng=rng)
                marginals = marginals and _marginals_equal(segments, shuffled)
                tensor, null_samples = _triplet_tensor(shuffled)
                if null_samples != samples:
                    raise RuntimeError("A212 null sample count changed")
                values[replicate, 0] = np.linalg.norm(tensor)
                values[replicate, 1] = np.max(np.abs(tensor))
            all_marginals = all_marginals and marginals
            stats: dict[str, Any] = {}
            for index, statistic in enumerate(("l2_norm", "maximum_absolute_entry")):
                raw_p = float(
                    (1 + np.count_nonzero(values[:, index] >= observed[statistic]))
                    / (T02_NULL_REPLICATES + 1)
                )
                test_id = f"{key}/{kind}/{statistic}"
                raw_tests.append((test_id, raw_p))
                stats[statistic] = {
                    "mean": _q(float(values[:, index].mean())),
                    "upper_97_5_percentile": _q(
                        float(np.quantile(values[:, index], 0.975, method="higher"))
                    ),
                    "empirical_upper_p_value": _q(raw_p),
                    "test_id": test_id,
                }
            null_payload[kind] = {
                "replicates": T02_NULL_REPLICATES,
                "marginals_preserved_exactly": marginals,
                "values_sha256": _sha256(values.astype("<f8").tobytes()),
                "statistics": stats,
            }
        output[key] = {
            "triplet_samples": samples,
            "tensor_sha256": _sha256(observed_tensor.astype("<f8").tobytes()),
            "observed": {name: _q(value) for name, value in observed.items()},
            "nulls": null_payload,
        }

    adjusted = _holm_adjust(raw_tests)
    retained_contexts: list[dict[str, str]] = []
    for key in CONTEXT_ORDER:
        for kind in ("permutation", "circular_shift"):
            for statistic in ("l2_norm", "maximum_absolute_entry"):
                row = output[key]["nulls"][kind]["statistics"][statistic]
                row["holm_adjusted_p_value"] = _q(adjusted[row["test_id"]])
        for statistic in ("l2_norm", "maximum_absolute_entry"):
            if all(
                output[key]["nulls"][kind]["statistics"][statistic][
                    "holm_adjusted_p_value"
                ]
                <= 0.05
                for kind in ("permutation", "circular_shift")
            ):
                retained_contexts.append({"context": key, "statistic": statistic})
    return {
        "transfer_family": "T02",
        "lags": [0, 1, 2],
        "tensor_shape": [len(CHANNELS)] * 3,
        "multiple_testing": "Holm_over_16_predeclared_tests",
        "all_null_marginals_preserved_exactly": all_marginals,
        "contexts": output,
        "retained_context_statistics": retained_contexts,
        "prediction_retained": bool(all_marginals and retained_contexts),
    }


def _root_residual(coefficients: np.ndarray, root: complex) -> float:
    degree = len(coefficients) - 1
    scale = sum(
        abs(coefficient) * max(1.0, abs(root)) ** (degree - index)
        for index, coefficient in enumerate(coefficients)
    )
    return float(abs(np.polyval(coefficients, root)) / max(scale, np.finfo(float).tiny))


def _t03(normalized_by_context: dict[str, np.ndarray]) -> dict[str, Any]:
    diagnostics: list[dict[str, Any]] = []
    maximum_reconstruction = 0.0
    maximum_root_residual = 0.0
    for key in CONTEXT_ORDER:
        for index, operator in enumerate(normalized_by_context[key]):
            characteristic = np.poly(operator)
            derivative = np.polyder(characteristic)
            roots = np.roots(derivative)
            reconstructed = derivative[0] * np.poly(roots)
            reconstruction = float(
                np.linalg.norm(reconstructed - derivative)
                / max(float(np.linalg.norm(derivative)), np.finfo(float).tiny)
            )
            residual = max((_root_residual(derivative, root) for root in roots), default=0.0)
            eigenvalues = np.linalg.eigvals(operator)
            gate = reconstruction <= ROOT_TOLERANCE and residual <= ROOT_TOLERANCE
            maximum_reconstruction = max(maximum_reconstruction, reconstruction)
            maximum_root_residual = max(maximum_root_residual, residual)
            diagnostics.append(
                {
                    "context": key,
                    "operator_index": index,
                    "eigenvalues": _complex_rows(eigenvalues),
                    "characteristic_derivative_roots": _complex_rows(roots),
                    "characteristic_coefficients": _complex_rows(characteristic),
                    "derivative_coefficients": _complex_rows(derivative),
                    "coefficient_reconstruction_relative_error": _q(reconstruction, 15),
                    "maximum_root_residual_relative": _q(residual, 15),
                    "spectral_radius": _q(float(np.max(np.abs(eigenvalues)))),
                    "critical_radius_maximum": _q(float(np.max(np.abs(roots)))),
                    "gate_passed": gate,
                }
            )
    return {
        "transfer_family": "T03",
        "diagnostic_count": len(diagnostics),
        "diagnostics": diagnostics,
        "maximum_coefficient_reconstruction_relative_error": _q(
            maximum_reconstruction, 15
        ),
        "maximum_root_residual_relative": _q(maximum_root_residual, 15),
        "all_operator_gates_passed": all(row["gate_passed"] for row in diagnostics),
        "prediction_retained": all(row["gate_passed"] for row in diagnostics),
    }


def _aligned_pair(
    contexts: dict[str, dict[str, Any]], left_key: str, right_key: str
) -> dict[str, Any]:
    prefixes = [f"{value:08b}" for value in range(256)]
    left_context, right_context = contexts[left_key], contexts[right_key]
    left_rows = [left_context["rows"][left_context["index_by_prefix"][prefix]] for prefix in prefixes]
    right_rows = [
        right_context["rows"][right_context["index_by_prefix"][prefix]] for prefix in prefixes
    ]
    left = np.vstack([_row_feature(row) for row in left_rows])
    right = np.vstack([_row_feature(row) for row in right_rows])
    pooled = np.vstack([left, right])
    mean = pooled.mean(axis=0)
    scale = pooled.std(axis=0)
    if np.any(scale <= 0):
        raise RuntimeError("A212 cross-copy zero scale")
    left_z, right_z = (left - mean) / scale, (right - mean) / scale
    physical_sum = (left_z + right_z) / math.sqrt(2.0)
    signed_difference = (left_z - right_z) / math.sqrt(2.0)
    swapped_sum = (right_z + left_z) / math.sqrt(2.0)
    swapped_difference = (right_z - left_z) / math.sqrt(2.0)
    sum_error = float(np.max(np.abs(physical_sum - swapped_sum)))
    difference_error = float(np.max(np.abs(signed_difference + swapped_difference)))
    eligible = np.asarray(
        [left_row["status"] == right_row["status"] == "unknown" for left_row, right_row in zip(left_rows, right_rows, strict=True)]
    )
    ratio = np.linalg.norm(signed_difference, axis=1) / np.maximum(
        np.linalg.norm(physical_sum, axis=1), np.finfo(float).tiny
    )
    rankings = sorted(
        (
            {"prefix8": prefixes[index], "difference_over_sum": _q(ratio[index])}
            for index in range(256)
            if eligible[index]
        ),
        key=lambda row: (-row["difference_over_sum"], row["prefix8"]),
    )
    return {
        "prefixes": prefixes,
        "left_rows": left_rows,
        "right_rows": right_rows,
        "left": left,
        "right": right,
        "left_z": left_z,
        "right_z": right_z,
        "physical_sum": physical_sum,
        "signed_difference": signed_difference,
        "eligible": eligible,
        "ratio": ratio,
        "payload": {
            "left_context": left_key,
            "right_context": right_key,
            "aligned_prefix_count": 256,
            "eligible_unknown_pair_count": int(eligible.sum()),
            "excluded_non_unknown_pair_count": int((~eligible).sum()),
            "physical_sum_copy_swap_error": _q(sum_error, 15),
            "signed_difference_copy_swap_error": _q(difference_error, 15),
            "difference_over_sum_summary_eligible": {
                "minimum": _q(float(ratio[eligible].min())),
                "mean": _q(float(ratio[eligible].mean())),
                "maximum": _q(float(ratio[eligible].max())),
            },
            "top16_difference_over_sum": rankings[:16],
            "aligned_raw_sha256": _sha256(np.stack([left, right]).astype("<f8").tobytes()),
            "sum_sha256": _sha256(physical_sum.astype("<f8").tobytes()),
            "difference_sha256": _sha256(signed_difference.astype("<f8").tobytes()),
        },
    }


def _t05(contexts: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    pairs = {
        "A210_reset_local": _aligned_pair(
            contexts, "A210_numeric_reset_local", "A210_gray_reset_local"
        ),
        "A211_retained_global": _aligned_pair(
            contexts, "A211_numeric_retained_global", "A211_gray_retained_global"
        ),
    }
    prediction = all(
        pair["payload"]["physical_sum_copy_swap_error"] <= 1e-12
        and pair["payload"]["signed_difference_copy_swap_error"] <= 1e-12
        for pair in pairs.values()
    ) and pairs["A210_reset_local"]["payload"]["eligible_unknown_pair_count"] == 256
    return {
        "transfer_family": "T05",
        "pairs": {name: pair["payload"] for name, pair in pairs.items()},
        "schedule_source": "A210_reset_local_only",
        "status_or_model_fields_used_as_features": False,
        "prediction_retained": prediction,
    }, pairs


def _orient_vector(vector: np.ndarray) -> np.ndarray:
    result = vector.copy()
    pivot = int(np.argmax(np.abs(result)))
    if result[pivot] < 0:
        result *= -1.0
    return result


def _cross_copy_diagnostic(pair: dict[str, Any]) -> tuple[dict[str, Any], np.ndarray]:
    left = pair["left_z"] - pair["left_z"].mean(axis=0)
    right = pair["right_z"] - pair["right_z"].mean(axis=0)
    left_norm = np.linalg.norm(left, axis=0)
    right_norm = np.linalg.norm(right, axis=0)
    if np.any(left_norm <= 0) or np.any(right_norm <= 0):
        raise RuntimeError("A212 cross-copy normalization failed")
    normalized_left = left / left_norm
    normalized_right = right / right_norm
    cross = np.einsum("ni,nj->ij", normalized_left, normalized_right, optimize=False)
    u, singular, vt = np.linalg.svd(cross, full_matrices=True)
    u0, v0 = _orient_vector(u[:, 0]), _orient_vector(vt.T[:, 0])
    weights = (u0**2 + v0**2) / 2.0
    weights /= weights.sum()
    gram = cross.T @ cross
    eigenvalues, eigenvectors = np.linalg.eigh(gram)
    epsilon = max(1e-12, float(eigenvalues[-1]) * 1e-8)
    regularized_eigenvalues = eigenvalues + epsilon
    hamiltonian_eigenvalues = -np.log(regularized_eigenvalues)
    hamiltonian = eigenvectors @ np.diag(hamiltonian_eigenvalues) @ eigenvectors.T
    reconstructed = eigenvectors @ np.diag(
        np.exp(-hamiltonian_eigenvalues)
    ) @ eigenvectors.T
    regularized = gram + epsilon * np.eye(len(CHANNELS))
    reconstruction_error = float(
        np.linalg.norm(reconstructed - regularized)
        / max(float(np.linalg.norm(regularized)), np.finfo(float).tiny)
    )
    swapped_singular = np.linalg.svd(cross.T, compute_uv=False)
    swap_error = float(np.max(np.abs(singular - swapped_singular)))
    gate = bool(
        np.isfinite(hamiltonian).all()
        and reconstruction_error <= ROOT_TOLERANCE
        and swap_error <= ROOT_TOLERANCE
    )
    return {
        "cross_matrix": _q_array(cross),
        "cross_matrix_sha256": _sha256(cross.astype("<f8").tobytes()),
        "singular_values": [_q(value) for value in singular],
        "effective_rank_1e_10": int(np.count_nonzero(singular > singular[0] * 1e-10)),
        "first_mode_weights": {
            channel: _q(weights[index]) for index, channel in enumerate(CHANNELS)
        },
        "regularization_epsilon": _q(epsilon, 15),
        "regularized_gram_eigenvalues": [_q(value) for value in regularized_eigenvalues],
        "negative_matrix_log": _q_array(hamiltonian),
        "matrix_log_reconstruction_relative_error": _q(reconstruction_error, 15),
        "copy_swap_singular_value_error": _q(swap_error, 15),
        "gate_passed": gate,
    }, weights


def _t06(pairs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, np.ndarray]]:
    output: dict[str, Any] = {}
    weights: dict[str, np.ndarray] = {}
    for name in ("A210_reset_local", "A211_retained_global"):
        output[name], weights[name] = _cross_copy_diagnostic(pairs[name])
    return {
        "transfer_family": "T06",
        "pairs": output,
        "all_matrix_log_gates_passed": all(row["gate_passed"] for row in output.values()),
        "prediction_retained": all(row["gate_passed"] for row in output.values()),
    }, weights


def _hamming(left: int, right: int) -> int:
    return (left ^ right).bit_count()


def _permuted_gray(bit_permutation: tuple[int, ...], direction: int) -> np.ndarray:
    values = np.arange(256, dtype=np.uint16)
    gray = values ^ (values >> 1)
    mapped = np.zeros(256, dtype=np.uint16)
    for source, target in enumerate(bit_permutation):
        mapped |= ((gray >> source) & 1) << target
    return mapped if direction == 0 else mapped[::-1]


def _prospective_schedule(
    pair: dict[str, Any], weights: np.ndarray
) -> dict[str, Any]:
    if pair["payload"]["eligible_unknown_pair_count"] != 256:
        raise RuntimeError("A212 schedule source includes a terminal row")
    left, right = pair["left"], pair["right"]
    scale = np.median(np.vstack([left, right]), axis=0)
    if np.any(scale <= 0):
        raise RuntimeError("A212 positive schedule scale failed")
    left_positive, right_positive = left / scale, right / scale
    physical_sum = (left_positive + right_positive) / math.sqrt(2.0)
    signed_difference = (left_positive - right_positive) / math.sqrt(2.0)
    sum_energy = np.sqrt(np.sum(weights[None, :] * physical_sum**2, axis=1))
    difference_energy = np.sqrt(
        np.sum(weights[None, :] * signed_difference**2, axis=1)
    )
    ratio = difference_energy / np.maximum(sum_energy, np.finfo(float).tiny)
    score = sum_energy * (1.0 + ratio)
    start_prefix = int(np.flatnonzero(score == score.max())[0])
    discount = np.exp(-math.log(2.0) * np.arange(256) / HALF_LIFE_CELLS)

    best_objective = -math.inf
    best_identity: tuple[tuple[int, ...], int] | None = None
    best_order: np.ndarray | None = None
    for permutation in itertools.permutations(range(8)):
        for direction in (0, 1):
            base = _permuted_gray(permutation, direction)
            order = base ^ np.uint16(int(base[0]) ^ start_prefix)
            objective = float(np.dot(discount, score[order]))
            identity = (permutation, direction)
            if objective > best_objective + 1e-12 or (
                abs(objective - best_objective) <= 1e-12
                and (best_identity is None or identity < best_identity)
            ):
                best_objective = objective
                best_identity = identity
                best_order = order.copy()
    if best_identity is None or best_order is None:
        raise RuntimeError("A212 Gray Hamiltonian search returned no path")

    standard = _permuted_gray(tuple(range(8)), 0)
    standard ^= np.uint16(int(standard[0]) ^ start_prefix)
    standard_objective = float(np.dot(discount, score[standard]))
    numeric = np.arange(256, dtype=np.uint16)
    numeric_objective = float(np.dot(discount, score[numeric]))
    hamming = [_hamming(int(best_order[index]), int(best_order[index + 1])) for index in range(255)]
    exact_cover = sorted(best_order.astype(int).tolist()) == list(range(256))
    hamiltonian = all(distance == 1 for distance in hamming)
    score_rows = [
        {
            "prefix8": f"{value:08b}",
            "weighted_positive_sum_energy": _q(sum_energy[value]),
            "weighted_difference_energy": _q(difference_energy[value]),
            "weighted_difference_over_sum": _q(ratio[value]),
            "schedule_score": _q(score[value]),
        }
        for value in range(256)
    ]
    return {
        "source": "A210_reset_local_all_UNKNOWN_rows",
        "channel_scale": {name: _q(scale[index]) for index, name in enumerate(CHANNELS)},
        "channel_weights": {name: _q(weights[index]) for index, name in enumerate(CHANNELS)},
        "score_rows": score_rows,
        "score_rows_sha256": _canonical_sha256(score_rows),
        "start_prefix8": f"{start_prefix:08b}",
        "selected_bit_permutation_source_to_target": list(best_identity[0]),
        "selected_direction": "forward" if best_identity[1] == 0 else "reverse",
        "formula_gray8_order": [f"{int(value):08b}" for value in best_order],
        "formula_gray8_order_sha256": _sha256(best_order.astype(np.uint8).tobytes()),
        "standard_gray8_same_start_order_sha256": _sha256(
            standard.astype(np.uint8).tobytes()
        ),
        "discount_half_life_cells": HALF_LIFE_CELLS,
        "discounted_objectives": {
            "formula_gray8": _q(best_objective),
            "standard_gray8_same_start": _q(standard_objective),
            "numeric": _q(numeric_objective),
            "formula_over_standard_ratio": _q(best_objective / standard_objective),
        },
        "complete_256_prefix_permutation": exact_cover,
        "adjacent_hamming_histogram": {
            str(distance): hamming.count(distance) for distance in sorted(set(hamming))
        },
        "gray8_Hamiltonian_path": hamiltonian,
        "status_or_model_field_used": False,
        "future_solver_outcome_used": False,
        "prediction_retained": bool(
            exact_cover and hamiltonian and best_objective > standard_objective + 1e-12
        ),
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_solver_trajectory_formula_atlas",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "contexts": 4,
            "channels": len(CHANNELS),
            "trajectory_rows": 1024,
            "solver_processes": 0,
        },
    )
    rows = [
        (
            "a212-formula-anchor",
            "A199:T01_T02_T03_T05_public_operator_atlas",
            "transfer_predeclared_formula_families_to_solver_trajectories",
            "A212:retrospective_solver_operator_program",
            "formula_transfer_anchor",
            payload["anchors_sha256"],
            [],
            {"protocol_sha256": PROTOCOL_SHA256},
        ),
        (
            "a212-local-anchor",
            "A210:64_reset_local_incremental_runs",
            "extract_six_status_blind_observed_channels",
            "A212:two_reset_local_trajectories",
            "retained_local_learning_anchor",
            payload["anchors"]["A210_result_sha256"],
            [],
            {"contexts": CONTEXT_ORDER[:2]},
        ),
        (
            "a212-global-anchor",
            "A211:two_complete_retained_global_runs",
            "extract_six_status_blind_observed_channels",
            "A212:two_retained_global_trajectories",
            "retained_global_learning_anchor",
            payload["anchors"]["A211_result_sha256"],
            [],
            {"contexts": CONTEXT_ORDER[2:]},
        ),
        (
            "a212-t01",
            "A212:four_normalized_transition_operator_sequences",
            "compare_chronological_reverse_commutator_and_order_null_products",
            "A212:T01_solver_order_result",
            "ordered_solver_transition_transfer",
            payload["T01_sha256"],
            ["a212-formula-anchor", "a212-local-anchor", "a212-global-anchor"],
            {"retained_global_contexts": payload["T01"]["retained_global_contexts"]},
        ),
        (
            "a212-t02",
            "A212:four_centered_solver_channel_trajectories",
            "measure_lag_0_1_2_cumulants_against_two_marginal_preserving_nulls",
            "A212:T02_triplet_result",
            "solver_triplet_cumulant_transfer",
            payload["T02_sha256"],
            ["a212-formula-anchor", "a212-local-anchor", "a212-global-anchor"],
            {"retained": payload["T02"]["retained_context_statistics"]},
        ),
        (
            "a212-t03",
            "A212:all_T01_normalized_transition_operators",
            "reconstruct_characteristic_derivative_roots_with_residual_gates",
            "A212:T03_critical_root_result",
            "solver_characteristic_derivative_transfer",
            payload["T03_sha256"],
            ["a212-t01"],
            {"diagnostics": payload["T03"]["diagnostic_count"]},
        ),
        (
            "a212-t05",
            "A212:numeric_and_Gray_channels_aligned_by_prefix",
            "construct_physical_sum_and_signed_difference_with_copy_swap_control",
            "A212:T05_order_sensitive_channel_result",
            "solver_z2_sum_difference_transfer",
            payload["T05_sha256"],
            ["a212-local-anchor", "a212-global-anchor"],
            {"schedule_source": payload["T05"]["schedule_source"]},
        ),
        (
            "a212-t06",
            "A212:T05_aligned_cross_copy_channels",
            "compute_cross_copy_SVD_and_regularized_matrix_log",
            "A212:T06_latent_coupling_result",
            "solver_cross_copy_SVD_matrix_log_transfer",
            payload["T06_sha256"],
            ["a212-t05"],
            {"all_gates": payload["T06"]["all_matrix_log_gates_passed"]},
        ),
        (
            "a212-schedule",
            "A212:A210_target_independent_T05_T06_scores",
            "search_all_bit_permuted_bidirectional_Gray8_paths",
            "A212:prospectively_frozen_formula_Gray8_schedule",
            "target_independent_solver_schedule_derivation",
            payload["prospective_schedule_sha256"],
            ["a212-t05", "a212-t06"],
            {
                "order_sha256": payload["prospective_schedule"][
                    "formula_gray8_order_sha256"
                ],
                "future_targets": ["R11", "R20"],
            },
        ),
    ]
    for edge_id, trigger, mechanism, outcome, kind, source, provenance, attrs in rows:
        builder.add_triplet(
            edge_id=edge_id,
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            evidence_kind=kind,
            source=source,
            provenance=provenance,
            attrs=attrs,
        )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = CryptoCausalReader(path)
    explicit = reader.triplets(include_inferred=False)
    if len(explicit) != len(rows) or not reader.verify_provenance():
        raise RuntimeError("A212 native Causal Reader provenance gate failed")
    return {
        "stats": stats,
        "explicit_triplets": len(explicit),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def analyze(results_dir: Path) -> dict[str, Any]:
    analysis = _load_protocol_and_anchors(results_dir)
    anchors = analysis["anchors"]
    contexts = _build_contexts(anchors["A210_result"], anchors["A211_result"])
    return {
        "protocol_sha256": PROTOCOL_SHA256,
        "context_rows": {key: len(contexts[key]["rows"]) for key in CONTEXT_ORDER},
        "solver_execution_started": False,
        "output_written": False,
    }


def run(*, results_dir: Path, output: Path, causal_output: Path) -> dict[str, Any]:
    analysis = _load_protocol_and_anchors(results_dir)
    protocol, anchors = analysis["protocol"], analysis["anchors"]
    contexts = _build_contexts(anchors["A210_result"], anchors["A211_result"])
    t01, operators = _t01(contexts)
    t02 = _t02(contexts)
    t03 = _t03(operators)
    t05, pairs = _t05(contexts)
    t06, weights = _t06(pairs)
    schedule = _prospective_schedule(pairs["A210_reset_local"], weights["A210_reset_local"])
    predictions = {
        "T01_ordered_products": t01["prediction_retained"],
        "T02_triplet_cumulants": t02["prediction_retained"],
        "T03_derivative_root_gates": t03["prediction_retained"],
        "T05_sum_difference_controls": t05["prediction_retained"],
        "T06_cross_copy_matrix_log": t06["prediction_retained"],
        "formula_Gray8_schedule": schedule["prediction_retained"],
    }
    evidence_stage = (
        "SOLVER_TRAJECTORY_FORMULA_ATLAS_AND_SCHEDULE_RETAINED"
        if all(predictions.values())
        else "SOLVER_TRAJECTORY_FORMULA_ATLAS_MIXED_BOUNDARY_RETAINED"
    )
    anchor_payload = {
        "formula_source_reaudit_sha256": protocol["anchors"]["formula_source_reaudit"][
            "sha256"
        ],
        "A199_result_sha256": protocol["anchors"]["A199_result"]["sha256"],
        "A199_causal_sha256": protocol["anchors"]["A199_causal"]["sha256"],
        "A210_result_sha256": protocol["anchors"]["A210_result"]["sha256"],
        "A210_causal_sha256": protocol["anchors"]["A210_causal"]["sha256"],
        "A211_result_sha256": protocol["anchors"]["A211_result"]["sha256"],
        "A211_causal_sha256": protocol["anchors"]["A211_causal"]["sha256"],
    }
    context_manifest = {
        key: {
            "mode": contexts[key]["mode"],
            "rows": len(contexts[key]["rows"]),
            "operator_segments": list(contexts[key]["operator_segments"].shape[:2]),
            "cumulant_segments": [len(segment) for segment in contexts[key]["cumulant_segments"]],
            "feature_mean": {
                channel: _q(contexts[key]["mean"][index])
                for index, channel in enumerate(CHANNELS)
            },
            "feature_scale": {
                channel: _q(contexts[key]["scale"][index])
                for index, channel in enumerate(CHANNELS)
            },
            "raw_feature_sha256": _sha256(contexts[key]["raw"].astype("<f8").tobytes()),
        }
        for key in CONTEXT_ORDER
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "The complete A210/A211 solver trajectories support a six-channel formula "
            "operator atlas and freeze a target-independent complete Gray8 Hamiltonian "
            "schedule for future round transfers."
        ),
        "scope": (
            "Retrospective mechanism analysis of retained R10 solver telemetry and "
            "prospective schedule derivation for later R11/R20 experiments; A212 "
            "launches no cipher solver and accesses no hidden assignment field."
        ),
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": protocol["protocol_state"],
            "information_boundary": protocol["information_boundary"],
            "prediction_registry": protocol["prediction_registry"],
        },
        "anchors": anchor_payload,
        "anchors_sha256": _canonical_sha256(anchor_payload),
        "channels": list(CHANNELS),
        "context_manifest": context_manifest,
        "context_manifest_sha256": _canonical_sha256(context_manifest),
        "T01": t01,
        "T01_sha256": _canonical_sha256(t01),
        "T02": t02,
        "T02_sha256": _canonical_sha256(t02),
        "T03": t03,
        "T03_sha256": _canonical_sha256(t03),
        "T05": t05,
        "T05_sha256": _canonical_sha256(t05),
        "T06": t06,
        "T06_sha256": _canonical_sha256(t06),
        "prospective_schedule": schedule,
        "prospective_schedule_sha256": _canonical_sha256(schedule),
        "predictions_retained": predictions,
        "solver_execution": {
            "solver_processes_started": 0,
            "future_R11_or_R20_outcomes_used": False,
            "status_labels_used_as_features": False,
            "model_or_assignment_fields_accessed": False,
        },
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _atomic_write(output, raw)
    reader = CryptoCausalReader(causal_output)
    if (
        _file_sha256(output) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A212 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "predictions": predictions,
        "formula_gray8_order_sha256": schedule["formula_gray8_order_sha256"],
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    research_root = Path(__file__).parents[1]
    parser.add_argument("--results-dir", type=Path, default=research_root / "results" / "v1")
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument(
        "--output", type=Path, default=research_root / "results" / "v1" / RESULT_FILENAME
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=research_root / "results" / "v1" / CAUSAL_FILENAME,
    )
    args = parser.parse_args(argv)
    if args.analyze_only:
        summary = analyze(args.results_dir.resolve())
    else:
        summary = run(
            results_dir=args.results_dir.resolve(),
            output=args.output.resolve(),
            causal_output=args.causal_output.resolve(),
        )
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
