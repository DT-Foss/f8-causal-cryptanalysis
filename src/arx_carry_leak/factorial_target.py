"""Label-free application of one frozen A220 Reader to a prospective target."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

import numpy as np

from arx_carry_leak.factorial_holdout import (
    _constituent_bundle_ids,
    _pair_view,
    _selected_reader_identity,
    selected_bundle_run_ids,
)
from arx_carry_leak.factorial_trajectory import (
    ATOMIC_BUNDLE_ORDER,
    dual_schedule_scores,
    readout_from_dict,
)


def _float64_sha256(values: np.ndarray) -> str:
    array = np.ascontiguousarray(np.asarray(values, dtype="<f8"))
    return hashlib.sha256(array.tobytes()).hexdigest()


def _uint8_sha256(values: np.ndarray) -> str:
    array = np.ascontiguousarray(np.asarray(values, dtype=np.uint8))
    return hashlib.sha256(array.tobytes()).hexdigest()


def score_label_free_target(
    selected_reader: Mapping[str, Any], scientific_runs: Mapping[str, Any]
) -> dict[str, Any]:
    """Return a complete frozen-Reader prefix order without any target label.

    The function has no file, solver, key-label, commitment, or reveal input.
    It accepts only the serialized Reader and exactly its selected public
    trajectory runs.  Scores descend; exact ties use ascending prefix integer.
    """

    identity = _selected_reader_identity(selected_reader)
    expected_run_ids = selected_bundle_run_ids(identity.bundle_id)
    if not isinstance(scientific_runs, Mapping) or set(scientific_runs) != set(
        expected_run_ids
    ):
        raise ValueError("A220 prospective target selected-run cover differs")
    raw_readouts = selected_reader["selected_constituent_readouts"]
    constituents = _constituent_bundle_ids(identity)
    if not isinstance(raw_readouts, Mapping) or set(raw_readouts) != set(constituents):
        raise ValueError("A220 prospective target constituent Reader set differs")

    scores_by_constituent = {}
    for bundle_id in constituents:
        readout = readout_from_dict(raw_readouts[bundle_id])
        if (
            readout.feature_family != identity.feature_family
            or readout.kind != identity.readout_kind
            or readout.ridge_lambda != identity.ridge_lambda
        ):
            raise ValueError("A220 prospective target Reader identity differs")
        view = _pair_view(
            scientific_runs,
            bundle_id=bundle_id,
            feature_family=identity.feature_family,
        )
        scores_by_constituent[bundle_id] = readout.scores(view.matrix)

    if identity.bundle_id in ATOMIC_BUNDLE_ORDER:
        scores = scores_by_constituent[identity.bundle_id]
    else:
        scores = dual_schedule_scores(
            scores_by_constituent[constituents[0]],
            scores_by_constituent[constituents[1]],
        )
    values = np.asarray(scores, dtype=np.float64)
    if values.shape != (256,) or not np.isfinite(values).all():
        raise RuntimeError("A220 prospective target score vector is malformed")
    prefixes = np.arange(256, dtype=np.int64)
    order = np.lexsort((prefixes, -values))
    if order.shape != (256,) or set(order.tolist()) != set(range(256)):
        raise RuntimeError("A220 prospective target prefix order is malformed")
    return {
        "selected_identity": identity.as_dict(),
        "selected_run_ids": list(expected_run_ids),
        "constituent_bundle_ids": list(constituents),
        "target_label_or_secret_used": False,
        "score_vector_float64_le_sha256": _float64_sha256(values),
        "complete_prefix_order": [int(value) for value in order],
        "complete_prefix_order_uint8_sha256": _uint8_sha256(order),
        "top_1_prefix": int(order[0]),
        "top_8_prefixes": [int(value) for value in order[:8]],
        "top_16_prefixes": [int(value) for value in order[:16]],
        "top_32_prefixes": [int(value) for value in order[:32]],
        "top_64_prefixes": [int(value) for value in order[:64]],
    }
