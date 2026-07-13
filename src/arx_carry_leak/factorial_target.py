"""Label-free application of one frozen A220 Reader to a prospective target."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
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
    centered_score_ranks,
    dual_schedule_scores,
    readout_from_dict,
)

FORBIDDEN_TARGET_FIELD_NAMES = frozenset(
    {
        "correct_prefix",
        "known_low20",
        "low20",
        "low20_hex",
        "model_bits_bit0_through_bit19",
        "recovered_unknown_low20",
        "recovered_unknown_low20_hex",
        "salt",
        "salt_hex",
        "secret",
        "secret_low20",
        "target_label",
        "target_prefix8",
        "true_prefix8",
        "true_prefix_rank",
        "unknown_assignment",
        "unknown_assignment_bits_bit0_through_bit19",
    }
)

BLOCK_OBSERVATION_FIELDS = frozenset(
    {
        "counter_block_index",
        "counter_value",
        "public_challenge_sha256",
        "target_block_words_sha256",
        "launch_manifest_sha256",
        "measurement_sha256",
        "scientific_runs_sha256",
        "scientific_runs",
    }
)


class ProspectiveTargetModelObserved(RuntimeError):
    """Signal that trajectory collection itself produced a SAT model."""


def _float64_sha256(values: np.ndarray) -> str:
    array = np.ascontiguousarray(np.asarray(values, dtype="<f8"))
    return hashlib.sha256(array.tobytes()).hexdigest()


def _uint8_sha256(values: np.ndarray) -> str:
    array = np.ascontiguousarray(np.asarray(values, dtype=np.uint8))
    return hashlib.sha256(array.tobytes()).hexdigest()


def _canonical_sha256(value: Any) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _selected_reader_binding(selected_reader: Mapping[str, Any]) -> dict[str, str]:
    """Bind the complete Reader input and its executable readout payload."""

    return {
        "selected_reader_canonical_sha256": _canonical_sha256(selected_reader),
        "selected_readout_sha256": _canonical_sha256(
            {
                "selected_identity": selected_reader.get("selected_identity"),
                "selected_constituent_readouts": selected_reader.get(
                    "selected_constituent_readouts"
                ),
                "selected_score_sha256": selected_reader.get("selected_score_sha256"),
            }
        ),
    }


def _require_sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"A220 prospective target {label} is not a lowercase SHA-256 digest")
    return value


def _forbidden_target_field_paths(value: Any, *, path: str) -> tuple[str, ...]:
    """Locate explicit reveal/label fields without interpreting their values."""

    found: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if isinstance(key, str) and key.casefold() in FORBIDDEN_TARGET_FIELD_NAMES:
                found.append(child_path)
            found.extend(_forbidden_target_field_paths(child, path=child_path))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            found.extend(_forbidden_target_field_paths(child, path=f"{path}[{index}]"))
    return tuple(sorted(found))


def _require_label_free_inputs(
    selected_reader: Mapping[str, Any], scientific_runs: Mapping[str, Any]
) -> None:
    forbidden = (
        *_forbidden_target_field_paths(selected_reader, path="selected_reader"),
        *_forbidden_target_field_paths(scientific_runs, path="scientific_runs"),
    )
    if forbidden:
        raise ValueError(
            "A220 prospective target input contains forbidden reveal/label fields: "
            + ", ".join(forbidden)
        )


def project_label_free_reader_runs(
    scientific_runs: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Project raw solver trajectories onto the exact frozen Reader channels.

    The projection deliberately excludes statuses, stages, assumptions, models,
    timings, and provenance.  A non-empty model is surfaced as a separate direct
    recovery event and may never enter the prospective ordering computation.
    """

    if not isinstance(scientific_runs, Mapping) or not scientific_runs:
        raise ValueError("A220 prospective target scientific-run mapping is empty")
    result: dict[str, dict[str, Any]] = {}
    for run_id, run in scientific_runs.items():
        if not isinstance(run_id, str) or not run_id or not isinstance(run, Mapping):
            raise ValueError("A220 prospective target scientific-run identity differs")
        order = run.get("order")
        cells = run.get("cells")
        if (
            not isinstance(order, list)
            or len(order) != 256
            or any(
                not isinstance(prefix, str) or len(prefix) != 8 or bool(set(prefix) - {"0", "1"})
                for prefix in order
            )
            or len(set(order)) != 256
            or not isinstance(cells, list)
            or len(cells) != 256
        ):
            raise ValueError("A220 prospective target trajectory geometry differs")
        forbidden_paths = _forbidden_target_field_paths(run, path=f"scientific_runs.{run_id}")
        model_paths = [
            path for path in forbidden_paths if path.endswith(".model_bits_bit0_through_bit19")
        ]
        other_forbidden = sorted(set(forbidden_paths) - set(model_paths))
        if other_forbidden:
            raise ValueError(
                "A220 prospective target raw trajectory contains forbidden reveal/label fields: "
                + ", ".join(other_forbidden)
            )
        for path in model_paths:
            cursor: Any = run
            relative = path.removeprefix(f"scientific_runs.{run_id}.")
            for component in relative.split("."):
                if "[" in component:
                    name, raw_index = component[:-1].split("[", 1)
                    if name:
                        cursor = cursor[name]
                    cursor = cursor[int(raw_index)]
                else:
                    cursor = cursor[component]
            if cursor not in (None, [], ()):
                raise ProspectiveTargetModelObserved(
                    "prospective target trajectory produced a SAT model before ordering"
                )
        projected_cells = []
        for index, cell in enumerate(cells):
            if not isinstance(cell, Mapping):
                raise ValueError("A220 prospective target cell schema differs")
            prefix = cell.get("prefix8")
            metrics = cell.get("metrics_delta")
            redundant = cell.get("redundant_clauses_delta")
            if (
                prefix != order[index]
                or not isinstance(metrics, list)
                or len(metrics) != 3
                or any(not isinstance(value, int) or isinstance(value, bool) for value in metrics)
                or metrics[1] < 0
                or metrics[2] < 0
                or not isinstance(redundant, int)
                or isinstance(redundant, bool)
            ):
                raise ValueError("A220 prospective target Reader channel differs")
            projected_cells.append(
                {
                    "prefix8": prefix,
                    "metrics_delta": list(metrics),
                    "redundant_clauses_delta": redundant,
                }
            )
        result[run_id] = {
            "mode": str(run.get("mode")),
            "order": list(order),
            "cells": projected_cells,
        }
    _require_label_free_inputs({}, result)
    return result


def _complete_order_payload(values: np.ndarray) -> dict[str, Any]:
    scores = np.asarray(values, dtype=np.float64)
    if scores.shape != (256,) or not np.isfinite(scores).all():
        raise RuntimeError("A220 prospective target score vector is malformed")
    prefixes = np.arange(256, dtype=np.int64)
    order = np.lexsort((prefixes, -scores))
    if order.shape != (256,) or set(order.tolist()) != set(range(256)):
        raise RuntimeError("A220 prospective target prefix order is malformed")
    return {
        "score_vector_prefix_order": list(range(256)),
        "score_vector_float64": [float(value) for value in scores],
        "score_vector_float64_le_sha256": _float64_sha256(scores),
        "complete_prefix_order": [int(value) for value in order],
        "complete_prefix_order_uint8_sha256": _uint8_sha256(order),
        "top_1_prefix": int(order[0]),
        "top_8_prefixes": [int(value) for value in order[:8]],
        "top_16_prefixes": [int(value) for value in order[:16]],
        "top_32_prefixes": [int(value) for value in order[:32]],
        "top_64_prefixes": [int(value) for value in order[:64]],
    }


def score_label_free_target(
    selected_reader: Mapping[str, Any], scientific_runs: Mapping[str, Any]
) -> dict[str, Any]:
    """Return a complete frozen-Reader prefix order without any target label.

    The function has no file, solver, key-label, commitment, or reveal input.
    It accepts only the serialized Reader and exactly its selected public
    trajectory runs.  Scores descend; exact ties use ascending prefix integer.
    """

    _require_label_free_inputs(selected_reader, scientific_runs)
    projected_runs = project_label_free_reader_runs(scientific_runs)
    if projected_runs != scientific_runs:
        raise ValueError("A220 prospective target Reader received non-projected run fields")
    identity = _selected_reader_identity(selected_reader)
    reader_binding = _selected_reader_binding(selected_reader)
    expected_run_ids = selected_bundle_run_ids(identity.bundle_id)
    if not isinstance(scientific_runs, Mapping) or set(scientific_runs) != set(expected_run_ids):
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
            projected_runs,
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
    return {
        "selected_identity": identity.as_dict(),
        **reader_binding,
        "scientific_runs_canonical_sha256": _canonical_sha256(projected_runs),
        "selected_run_ids": list(expected_run_ids),
        "constituent_bundle_ids": list(constituents),
        "target_label_or_secret_used": False,
        "recursive_reveal_label_field_gate_passed": True,
        **_complete_order_payload(values),
    }


def score_label_free_target_ensemble(
    selected_reader: Mapping[str, Any],
    block_observations: Mapping[int, Mapping[str, Any]],
) -> dict[str, Any]:
    """Overlay eight independently observed counter-block score fields.

    Each block is scored by the same byte-frozen Reader.  Raw score scales may
    differ across blocks, so the registered ensemble averages centered within-
    block score ranks.  No block is selected, weighted, or dropped by outcome.
    """

    if (
        not isinstance(block_observations, Mapping)
        or any(type(block) is not int for block in block_observations)
        or set(block_observations) != set(range(8))
    ):
        raise ValueError("A220 prospective target ensemble requires blocks zero through seven")
    forbidden = _forbidden_target_field_paths(block_observations, path="block_observations")
    if forbidden:
        raise ValueError(
            "A220 prospective target ensemble contains forbidden reveal/label fields: "
            + ", ".join(forbidden)
        )
    block_manifests = []
    run_maps = {}
    for block in range(8):
        observation = block_observations[block]
        if not isinstance(observation, Mapping) or set(observation) != BLOCK_OBSERVATION_FIELDS:
            raise ValueError("A220 prospective target ensemble block schema differs")
        index = observation.get("counter_block_index")
        counter = observation.get("counter_value")
        runs = observation.get("scientific_runs")
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or index != block
            or not isinstance(counter, int)
            or isinstance(counter, bool)
            or not 0 <= counter < (1 << 32)
            or not isinstance(runs, Mapping)
        ):
            raise ValueError("A220 prospective target ensemble block identity differs")
        manifest = {
            "counter_block_index": block,
            "counter_value": counter,
            "public_challenge_sha256": _require_sha256(
                observation.get("public_challenge_sha256"), "public challenge hash"
            ),
            "target_block_words_sha256": _require_sha256(
                observation.get("target_block_words_sha256"), "target block hash"
            ),
            "launch_manifest_sha256": _require_sha256(
                observation.get("launch_manifest_sha256"), "launch manifest hash"
            ),
            "measurement_sha256": _require_sha256(
                observation.get("measurement_sha256"), "measurement hash"
            ),
            "scientific_runs_sha256": _require_sha256(
                observation.get("scientific_runs_sha256"), "scientific-run hash"
            ),
        }
        if manifest["scientific_runs_sha256"] != _canonical_sha256(runs):
            raise ValueError("A220 prospective target ensemble scientific-run hash differs")
        block_manifests.append(manifest)
        run_maps[block] = runs
    challenge_hashes = {row["public_challenge_sha256"] for row in block_manifests}
    start_counter = block_manifests[0]["counter_value"]
    if len(challenge_hashes) != 1 or any(
        row["counter_value"] != (start_counter + row["counter_block_index"]) & 0xFFFFFFFF
        for row in block_manifests
    ):
        raise ValueError("A220 prospective target ensemble counter/challenge sequence differs")
    block_results = {
        block: score_label_free_target(selected_reader, run_maps[block]) for block in range(8)
    }
    identities = [result["selected_identity"] for result in block_results.values()]
    reader_hashes = [
        result["selected_reader_canonical_sha256"] for result in block_results.values()
    ]
    readout_hashes = [result["selected_readout_sha256"] for result in block_results.values()]
    run_sets = [result["selected_run_ids"] for result in block_results.values()]
    if (
        any(identity != identities[0] for identity in identities[1:])
        or any(runs != run_sets[0] for runs in run_sets[1:])
        or any(value != reader_hashes[0] for value in reader_hashes[1:])
        or any(value != readout_hashes[0] for value in readout_hashes[1:])
    ):
        raise RuntimeError("A220 prospective target ensemble Reader identity differs")
    block_scores = np.row_stack(
        [
            np.asarray(block_results[block]["score_vector_float64"], dtype=np.float64)
            for block in range(8)
        ]
    )
    if block_scores.shape != (8, 256) or not np.isfinite(block_scores).all():
        raise RuntimeError("A220 prospective target ensemble score matrix differs")
    centered = np.row_stack([centered_score_ranks(row) for row in block_scores])
    aggregate = centered.mean(axis=0)
    return {
        "schema": "chacha20-round20-factorial-target-eight-block-ensemble-v1",
        "selected_identity": identities[0],
        "selected_reader_canonical_sha256": reader_hashes[0],
        "selected_readout_sha256": readout_hashes[0],
        "selected_run_ids_per_block": run_sets[0],
        "block_indices": list(range(8)),
        "counter_values": [row["counter_value"] for row in block_manifests],
        "public_challenge_sha256": block_manifests[0]["public_challenge_sha256"],
        "ordered_block_input_manifest": block_manifests,
        "ordered_block_input_manifest_sha256": _canonical_sha256(block_manifests),
        "aggregation": "mean_centered_score_rank_across_all_eight_counter_blocks",
        "block_selection_weighting_or_dropping_performed": False,
        "target_label_or_secret_used": False,
        "recursive_reveal_label_field_gate_passed": True,
        "per_block_score_vector_float64_le_sha256": [
            block_results[block]["score_vector_float64_le_sha256"] for block in range(8)
        ],
        "per_block_complete_prefix_order_uint8_sha256": [
            block_results[block]["complete_prefix_order_uint8_sha256"] for block in range(8)
        ],
        "centered_rank_matrix_float64_le_sha256": _float64_sha256(centered),
        **_complete_order_payload(aggregate),
    }
