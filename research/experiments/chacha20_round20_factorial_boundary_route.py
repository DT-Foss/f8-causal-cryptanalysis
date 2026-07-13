#!/usr/bin/env python3
"""Finalize the pre-outcome A220B mechanistic route after A220 evaluation."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from arx_carry_leak.crypto_causal import (
    CryptoCausalBuilder,
    CryptoCausalReader,
    ExactRule,
)
from arx_carry_leak.factorial_boundary import (
    PANEL_ORDER,
    UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2,
    localize_factorial_boundary,
)
from arx_carry_leak.factorial_holdout import selected_bundle_run_ids

ROOT = Path(__file__).parents[2]
ATTEMPT_ID = "A220B"
SCHEMA = "chacha20-round20-factorial-boundary-route-v1"
PROTOCOL = ROOT / "research/configs/chacha20_round20_factorial_boundary_router_v1.json"
A220_RESULT = ROOT / "research/results/v1/chacha20_round20_factorial_trajectory_transfer_v1.json"
READER = ROOT / "research/results/v1/chacha20_round20_factorial_trajectory_reader_freeze_v1.json"
DEFAULT_OUTPUT = ROOT / "research/results/v1/chacha20_round20_factorial_boundary_route_v1.json"
DEFAULT_CAUSAL = ROOT / "research/results/v1/chacha20_round20_factorial_boundary_route_v1.causal"
DEFAULT_REPORT = ROOT / "research/results/v1/chacha20_round20_factorial_boundary_route_v1.md"

A220_READER_TOP_FIELDS = frozenset(
    {
        "schema",
        "attempt_id",
        "evidence_stage",
        "protocol_sha256",
        "reader_runner_sha256",
        "reader_checkpoint_sha256",
        "software_versions",
        "factorial_trajectory_reader_sha256",
        "ridge_backend_sha256",
        "collector_source_sha256",
        "fit_select_index_sha256",
        "fit_select_input_manifest",
        "fit_select_input_manifest_sha256",
        "feature_matrix_sha256",
        "fit_panel",
        "selection_panel",
        "grid_definition",
        "observed_candidate_grid",
        "selected_reader",
        "selection_matched_null",
        "information_boundary",
        "completion_gates",
    }
)
A220_READER_COMPLETION = {
    "all_52_fit_select_shards_verified": True,
    "all_624_fresh_solver_processes_in_verified_index": True,
    "exactly_300_atomic_models_fit": True,
    "exactly_450_bundle_rows_evaluated": True,
    "all_64_matched_cluster_nulls_complete": True,
    "reader_resume_checkpoint_verified": True,
    "one_reader_selected_and_serialized": True,
    "reader_source_unchanged": True,
    "holdout_trajectory_not_opened": True,
    "future_prospective_target_not_opened": True,
}
A220_READER_BOUNDARY = {
    "fit_select_measurements_loaded": True,
    "holdout_measurements_loaded": False,
    "future_prospective_target_loaded": False,
    "target_labels_used_for_fit": "32_fit_prefix_labels_only",
    "target_labels_used_for_selection": "20_selection_prefix_labels_only",
    "suffix_specific_target_floor_or_key_suffix_feature_used": False,
    "reader_frozen_before_any_holdout_trajectory_process": True,
}
A220_RESULT_COMPLETION = {
    "verified_loader_was_the_only_holdout_input_path": True,
    "all_92_holdout_shards_reconstructively_verified": True,
    "exact_selected_two_or_four_fresh_runs_per_key": True,
    "reader_and_launch_frozen_before_holdout": True,
    "reader_refit_or_reselection_performed": False,
    "threshold_or_feature_adaptation_performed": False,
    "all_four_frozen_panels_evaluated": True,
    "complete_120_permutation_primary_null_evaluated": True,
    "future_prospective_target_opened": False,
    "source_reader_launch_index_and_input_shards_unchanged": True,
    "public_reconstructive_verification_supported": True,
    "sealed_execution_provenance_embedded_in_verified_shards": True,
}
A220_RESULT_BOUNDARY = {
    "stage": "A220_HOLDOUT_FINALIZATION",
    "fit_select_corpus_loaded_by_finalizer": False,
    "holdout_corpus_source": "collector_load_verified_holdout_corpus_only",
    "holdout_labels_used_only_as_fixed_reader_rank_targets_and_exact_cluster_null_labels": True,
    "reader_refit_reselected_or_modified": False,
    "feature_family_bundle_readout_or_threshold_changed": False,
    "suffix_specific_target_floor_or_suffix_feature_used": False,
    "future_prospective_target_generated_or_opened": False,
    "A220_contains_a_prospective_target_or_recovery_claim": False,
}
FORBIDDEN_EXTRA_FIELDS = frozenset(
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
        "unknown_assignment",
        "unknown_assignment_bits_bit0_through_bit19",
    }
)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def _canonical_sha256(value: Any) -> str:
    return _sha256(_canonical_bytes(value))


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
        + b"\n"
    )


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    root = ROOT.resolve()
    return resolved.relative_to(root).as_posix() if resolved.is_relative_to(root) else str(resolved)


def _finite(value: Any, label: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
    ):
        raise RuntimeError(f"A220B {label} is not finite")
    return float(value)


def _require_digest(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RuntimeError(f"A220B {label} is not a lowercase SHA-256 digest")
    return value


def _forbidden_field_paths(value: Any, *, path: str) -> tuple[str, ...]:
    found = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if isinstance(key, str) and key.casefold() in FORBIDDEN_EXTRA_FIELDS:
                found.append(child_path)
            found.extend(_forbidden_field_paths(child, path=child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_forbidden_field_paths(child, path=f"{path}[{index}]"))
    return tuple(sorted(found))


def _load_protocol() -> tuple[dict[str, Any], str]:
    raw = PROTOCOL.read_bytes()
    protocol = json.loads(raw)
    protocol_sha256 = _sha256(raw)
    anchors = protocol.get("anchors")
    boundary = protocol.get("information_boundary")
    if (
        protocol.get("schema") != "chacha20-round20-factorial-boundary-router-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or not isinstance(anchors, Mapping)
        or not isinstance(boundary, Mapping)
        or boundary.get("A220_holdout_outcome_opened_before_freeze") is not False
        or boundary.get("raw_trajectory_or_target_label_input_permitted") is not False
        or boundary.get("retention_rule_threshold_or_reader_change_permitted") is not False
    ):
        raise RuntimeError("A220B frozen protocol gate failed")
    for path_key, hash_key in (
        ("A220_protocol_path", "A220_protocol_sha256"),
        ("A220_holdout_evaluator_path", "A220_holdout_evaluator_sha256"),
        ("router_source_path", "router_source_sha256"),
        ("router_source_test_path", "router_source_test_sha256"),
        ("router_runner_path", "router_runner_sha256"),
        ("router_runner_test_path", "router_runner_test_sha256"),
    ):
        path = ROOT / str(anchors[path_key])
        if _file_sha256(path) != anchors[hash_key]:
            raise RuntimeError(f"A220B source anchor drift: {path_key}")
    return protocol, protocol_sha256


def _selected_readout_sha256(reader: Mapping[str, Any]) -> str:
    selected = reader.get("selected_reader")
    if not isinstance(selected, Mapping):
        raise RuntimeError("A220B Reader selected payload differs")
    return _canonical_sha256(
        {
            "selected_identity": selected.get("selected_identity"),
            "selected_constituent_readouts": selected.get("selected_constituent_readouts"),
            "selected_score_sha256": selected.get("selected_score_sha256"),
        }
    )


def _validate_inputs(
    result: Mapping[str, Any], reader: Mapping[str, Any], protocol: Mapping[str, Any]
) -> tuple[float, dict[str, float], bool, dict[str, Any], str]:
    evaluation = result.get("evaluation")
    selected = reader.get("selected_reader")
    result_selected = result.get("selected_reader")
    anchors = protocol.get("anchors")
    forbidden = (
        *_forbidden_field_paths(result, path="A220_result"),
        *_forbidden_field_paths(reader, path="A220_reader"),
    )
    if forbidden:
        raise RuntimeError("A220B input contains forbidden extra fields: " + ", ".join(forbidden))
    if (
        not isinstance(evaluation, Mapping)
        or not isinstance(selected, Mapping)
        or not isinstance(result_selected, Mapping)
        or not isinstance(anchors, Mapping)
    ):
        raise RuntimeError("A220B final A220 evaluation or Reader differs")
    retained_stage = "FULLROUND_R20_FACTORIAL_TRAJECTORY_HOLDOUT_TRANSFER"
    boundary_stage = "FULLROUND_R20_FACTORIAL_TRAJECTORY_PROBE_SPECIFIC_BOUNDARY"
    a220_protocol_path = anchors.get("A220_protocol_path")
    a220_protocol_sha = _require_digest(anchors.get("A220_protocol_sha256"), "A220 protocol anchor")
    evaluator_path = anchors.get("A220_holdout_evaluator_path")
    evaluator_sha = _require_digest(
        anchors.get("A220_holdout_evaluator_sha256"), "A220 evaluator anchor"
    )
    readout_sha = _selected_readout_sha256(reader)
    identity = selected.get("selected_identity")
    selected_fields = {
        "selected_identity",
        "selected_metrics",
        "selected_score_sha256",
        "selected_constituent_readouts",
        "candidate_grid_sha256",
    }
    if (
        result.get("schema") != "chacha20-round20-factorial-trajectory-transfer-v1"
        or result.get("attempt_id") != "A220"
        or result.get("evidence_stage") not in {retained_stage, boundary_stage}
        or result.get("protocol_path") != a220_protocol_path
        or result.get("protocol_sha256") != a220_protocol_sha
        or result.get("holdout_evaluator_path") != evaluator_path
        or result.get("holdout_evaluator_sha256") != evaluator_sha
        or result.get("reader_path") != _display_path(READER)
        or result.get("measurement_sha256")
        != _canonical_sha256(
            {
                key: value
                for key, value in result.items()
                if key not in {"measurement_sha256", "causal_artifact"}
            }
        )
        or evaluation.get("evaluation_sha256")
        != _canonical_sha256(
            {key: value for key, value in evaluation.items() if key != "evaluation_sha256"}
        )
        or reader.get("schema") != "chacha20-round20-factorial-trajectory-reader-v1"
        or set(reader) != A220_READER_TOP_FIELDS
        or reader.get("attempt_id") != "A220"
        or reader.get("protocol_sha256") != a220_protocol_sha
        or reader.get("evidence_stage") != "FULLROUND_R20_FACTORIAL_READER_FROZEN_BEFORE_HOLDOUT"
        or reader.get("completion_gates") != A220_READER_COMPLETION
        or reader.get("information_boundary") != A220_READER_BOUNDARY
        or result.get("reader_artifact_sha256") != _file_sha256(READER)
        or set(selected) != selected_fields
        or not isinstance(identity, Mapping)
        or result_selected.get("selected_identity") != identity
        or result_selected.get("selected_identity_sha256") != _canonical_sha256(identity)
        or result_selected.get("selected_readout_sha256") != readout_sha
        or evaluation.get("selected_identity") != identity
        or evaluation.get("selected_run_ids") != result_selected.get("selected_run_ids")
    ):
        raise RuntimeError("A220B A220-result/Reader/hash binding failed")
    try:
        expected_run_ids = list(selected_bundle_run_ids(str(identity["bundle_id"])))
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError("A220B selected Reader bundle differs") from error
    if (
        result_selected.get("selected_run_ids") != expected_run_ids
        or identity.get("run_count") != len(expected_run_ids)
        or not isinstance(selected.get("selected_constituent_readouts"), Mapping)
        or _require_digest(selected.get("selected_score_sha256"), "selected score hash")
        != selected.get("selected_score_sha256")
        or _require_digest(selected.get("candidate_grid_sha256"), "candidate grid hash")
        != selected.get("candidate_grid_sha256")
    ):
        raise RuntimeError("A220B selected Reader run/readout binding failed")
    reader_metrics = selected.get("selected_metrics")
    panel_metrics = evaluation.get("panel_metrics")
    primary = evaluation.get("primary_exact_cluster_null")
    if (
        not isinstance(reader_metrics, Mapping)
        or not isinstance(panel_metrics, Mapping)
        or set(panel_metrics) != set(PANEL_ORDER)
        or not isinstance(primary, Mapping)
        or not isinstance(primary.get("retained"), bool)
    ):
        raise RuntimeError("A220B metric schema differs")
    selection = _finite(reader_metrics.get("mean_log2_rank"), "selection mean")
    expected_counts = {
        "fit_by_confirm": 32,
        "select_by_confirm": 20,
        "confirm_by_fit": 20,
        "confirm_by_confirm": 20,
    }
    panels = {}
    for panel in PANEL_ORDER:
        metrics = panel_metrics[panel]
        ranks = metrics.get("ranks") if isinstance(metrics, Mapping) else None
        mean = metrics.get("mean_log2_rank") if isinstance(metrics, Mapping) else None
        if (
            not isinstance(ranks, list)
            or len(ranks) != expected_counts[panel]
            or any(
                not isinstance(rank, int) or isinstance(rank, bool) or not 1 <= rank <= 256
                for rank in ranks
            )
        ):
            raise RuntimeError("A220B panel rank cover differs")
        value = _finite(mean, f"{panel} mean")
        recomputed = sum(math.log2(rank) for rank in ranks) / len(ranks)
        if not math.isclose(value, recomputed, rel_tol=0.0, abs_tol=1e-12):
            raise RuntimeError("A220B panel mean/ranks differ")
        panels[panel] = value
    retained = bool(primary["retained"])
    observed_metrics = primary.get("observed_metrics")
    observed = _finite(
        observed_metrics.get("mean_log2_rank") if isinstance(observed_metrics, Mapping) else None,
        "primary mean",
    )
    records = primary.get("permutation_records")
    if (
        observed_metrics != panel_metrics["confirm_by_confirm"]
        or not isinstance(records, list)
        or len(records) != 120
    ):
        raise RuntimeError("A220B primary observed metric/permutation cover differs")
    statistics = []
    for index, (record, permutation) in enumerate(
        zip(records, itertools.permutations(range(5)), strict=True)
    ):
        statistic = record.get("mean_log2_rank") if isinstance(record, Mapping) else None
        if (
            not isinstance(record, Mapping)
            or set(record)
            != {
                "permutation_index",
                "cluster_permutation",
                "target_prefix_order_sha256",
                "mean_log2_rank",
            }
            or record.get("permutation_index") != index
            or record.get("cluster_permutation") != list(permutation)
        ):
            raise RuntimeError("A220B primary permutation identity differs")
        _require_digest(record.get("target_prefix_order_sha256"), "permutation target hash")
        statistics.append(_finite(statistic, "permutation statistic"))
    if statistics[0] != observed:
        raise RuntimeError("A220B identity permutation statistic differs")
    expected_p = sum(value <= observed for value in statistics) / 120
    p_value = _finite(primary.get("exact_lower_tail_p"), "primary p")
    bit_gain = UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2 - observed
    expected_retained = expected_p <= 0.05 and observed < UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2
    completion = result.get("completion_gates")
    boundary = result.get("information_boundary")
    if (
        observed != panels["confirm_by_confirm"]
        or retained is not expected_retained
        or (result.get("evidence_stage") == retained_stage) is not retained
        or evaluation.get("evidence_stage") != result.get("evidence_stage")
        or primary.get("panel") != "confirm_by_confirm"
        or primary.get("prefix_clusters") != 5
        or primary.get("suffix_replicates_per_cluster") != 4
        or primary.get("permutation_statistics_sha256") != _canonical_sha256(statistics)
        or p_value != expected_p
        or not 1 / 120 <= p_value <= 1.0
        or primary.get("retention_threshold") != 0.05
        or primary.get("uniform_random_rank_expected_mean_log2")
        != UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2
        or primary.get("observed_bit_gain_over_uniform_mean_log2") != bit_gain
        or primary.get("geometric_rank_concentration_factor") != float(2.0**bit_gain)
        or completion != A220_RESULT_COMPLETION
        or boundary != A220_RESULT_BOUNDARY
    ):
        raise RuntimeError("A220B registered retention/boundary gate failed")
    return selection, panels, retained, dict(identity), readout_sha


def _causal_bytes(
    *,
    measurement_sha256: str,
    localization: Mapping[str, Any],
    protocol_sha256: str,
) -> tuple[bytes, dict[str, Any]]:
    driver = str(localization["selected_driver"])
    probe = str(localization["next_probe"]["probe"])
    builder = CryptoCausalBuilder(
        experiment="chacha20_round20_factorial_boundary_route",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "protocol_sha256": protocol_sha256,
            "measurement_sha256": measurement_sha256,
            "evidence_status": localization["evidence_status"],
            "selected_driver": driver,
            "next_probe": probe,
            "fuzzy_matching": False,
        },
    )
    builder.add_rule(
        ExactRule(
            name="factorial_localization_to_frozen_probe",
            first="exact_factorial_contrast_decomposition",
            second="preoutcome_mechanism_routing",
            conclusion="mechanism_localized_next_experiment",
        )
    )
    builder.add_triplet(
        edge_id="a220b-1-factorial-localization",
        trigger="A220:four_frozen_holdout_panels_finalized",
        mechanism="exact_factorial_contrast_decomposition",
        outcome=f"A220B:driver:{driver}",
        confidence=1.0,
        evidence_kind="predeclared_two_factor_mean_log2_rank_contrasts",
        source=f"measurement:sha256:{measurement_sha256}",
        attrs={
            "effects": localization["factorial_effects_mean_log2_rank"],
            "significance_claim_added": False,
            "registered_retention_rule_changed": False,
        },
    )
    builder.add_triplet(
        edge_id="a220b-2-frozen-route",
        trigger=f"A220B:driver:{driver}",
        mechanism="preoutcome_mechanism_routing",
        outcome=f"A220B:next_probe:{probe}",
        confidence=1.0,
        evidence_kind="frozen_before_holdout_outcome_routing_table",
        source=f"protocol:sha256:{protocol_sha256}",
        provenance=["a220b-1-factorial-localization"],
        attrs={"next_probe": dict(localization["next_probe"])},
    )
    inferred = builder.infer_exact_closure(max_hops=2)
    if len(inferred) != 1:
        raise RuntimeError("A220B exact Causal closure differs")
    with tempfile.TemporaryDirectory(prefix="a220b-causal-") as temporary:
        path = Path(temporary) / "route.causal"
        stats = builder.save(path)
        raw = path.read_bytes()
        reader = CryptoCausalReader(path)
        if (
            not reader.verify_provenance()
            or reader.graph_sha256 != stats["graph_sha256"]
            or len(reader.triplets(include_inferred=False)) != 2
            or len(reader.triplets(include_inferred=True)) != 3
        ):
            raise RuntimeError("A220B Causal Reader gate failed")
    return raw, {
        "bytes": len(raw),
        "file_sha256": _sha256(raw),
        "graph_sha256": stats["graph_sha256"],
        "explicit_triplets": 2,
        "inferred_triplets": 1,
        "reader_verified": True,
    }


def _report_bytes(payload: Mapping[str, Any]) -> bytes:
    localization = payload["localization"]
    effects = localization["factorial_effects_mean_log2_rank"]
    lines = [
        "# ChaCha20 R20 Factorial Mechanism Route (A220B)",
        "",
        f"**Evidence status:** `{localization['evidence_status']}`",
        "",
        "The routing rule was frozen before the A220 holdout outcome. It does not alter the "
        "registered retention decision; it turns either branch into the next fixed experiment.",
        "",
        "## Exact mean-log2-rank effects",
        "",
        *[f"- {name}: `{value:.12g}`" for name, value in effects.items()],
        "",
        f"- Selected driver: `{localization['selected_driver']}`",
        f"- Next probe: `{localization['next_probe']['probe']}`",
        f"- Mechanism: {localization['next_probe']['mechanism']}",
        "",
        "## Reproduction",
        "",
        "```bash",
        "PYTHONPATH=src .venv/bin/python research/experiments/"
        "chacha20_round20_factorial_boundary_route.py",
        "```",
        "",
        f"- Protocol SHA-256: `{payload['protocol_sha256']}`",
        f"- Measurement SHA-256: `{payload['measurement_sha256']}`",
        f"- Causal graph SHA-256: `{payload['causal_artifact']['graph_sha256']}`",
    ]
    return ("\n".join(lines) + "\n").encode()


def _commit_exact(artifacts: Mapping[Path, bytes]) -> None:
    if any(path.exists() and path.read_bytes() != raw for path, raw in artifacts.items()):
        raise RuntimeError("A220B conflicting final artifact exists")
    if all(path.exists() for path in artifacts):
        return
    temporaries: dict[Path, Path] = {}
    try:
        for path, raw in artifacts.items():
            if path.exists():
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(f".{path.name}.tmp")
            if temporary.exists():
                if (
                    not temporary.is_file()
                    or temporary.is_symlink()
                    or temporary.read_bytes() != raw
                ):
                    raise RuntimeError("A220B conflicting temporary artifact exists")
                with temporary.open("rb") as handle:
                    os.fsync(handle.fileno())
            else:
                with temporary.open("xb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
            temporaries[path] = temporary
        for path, temporary in temporaries.items():
            os.replace(temporary, path)
            descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        for temporary in temporaries.values():
            temporary.unlink(missing_ok=True)


def run(
    *,
    output: Path = DEFAULT_OUTPUT,
    causal_output: Path = DEFAULT_CAUSAL,
    report_output: Path = DEFAULT_REPORT,
) -> dict[str, Any]:
    paths = [output.resolve(), causal_output.resolve(), report_output.resolve()]
    if len(set(paths)) != 3:
        raise RuntimeError("A220B JSON/Causal/report output paths must be pairwise distinct")
    protocol, protocol_sha256 = _load_protocol()
    result_raw = A220_RESULT.read_bytes()
    reader_raw = READER.read_bytes()
    result = json.loads(result_raw)
    reader = json.loads(reader_raw)
    selection, panels, retained, identity, readout_sha = _validate_inputs(result, reader, protocol)
    localization = localize_factorial_boundary(
        selection_mean_log2_rank=selection,
        panel_mean_log2_ranks=panels,
        primary_retained=retained,
    )
    measurement = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FULLROUND_R20_FACTORIAL_MECHANISM_ROUTE_FROZEN",
        "protocol_path": _display_path(PROTOCOL),
        "protocol_sha256": protocol_sha256,
        "A220_result_path": _display_path(A220_RESULT),
        "A220_result_sha256": _sha256(result_raw),
        "authoritative_reader_path": _display_path(READER),
        "authoritative_reader_sha256": _sha256(reader_raw),
        "selected_reader_identity": identity,
        "selected_readout_sha256": readout_sha,
        "localization": localization,
        "information_boundary": {
            "raw_holdout_trajectory_loaded": False,
            "known_key_holdout_aggregate_metrics_loaded": True,
            "prospective_target_key_or_label_loaded": False,
            "reader_refit_or_reselection_performed": False,
            "registered_retention_rule_changed": False,
            "routing_rule_frozen_before_A220_holdout_outcome": True,
        },
    }
    measurement_sha256 = _canonical_sha256(measurement)
    causal_raw, causal_meta = _causal_bytes(
        measurement_sha256=measurement_sha256,
        localization=localization,
        protocol_sha256=protocol_sha256,
    )
    causal_meta["path"] = _display_path(causal_output)
    payload = {
        **measurement,
        "measurement_sha256": measurement_sha256,
        "causal_artifact": causal_meta,
    }
    raw = _json_bytes(payload)
    report_raw = _report_bytes(payload)
    if _sha256(result_raw) != _file_sha256(A220_RESULT) or _sha256(reader_raw) != _file_sha256(
        READER
    ):
        raise RuntimeError("A220B source inputs changed during localization")
    _commit_exact({output: raw, causal_output: causal_raw, report_output: report_raw})
    reread = json.loads(output.read_bytes())
    causal_reader = CryptoCausalReader(causal_output)
    if (
        reread != payload
        or causal_reader.file_sha256 != causal_meta["file_sha256"]
        or causal_reader.graph_sha256 != causal_meta["graph_sha256"]
        or not causal_reader.verify_provenance()
        or report_output.read_bytes() != report_raw
    ):
        raise RuntimeError("A220B final readback differs")
    return reread


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--causal-output", type=Path, default=DEFAULT_CAUSAL)
    parser.add_argument("--report-output", type=Path, default=DEFAULT_REPORT)
    arguments = parser.parse_args()
    result = run(
        output=arguments.output,
        causal_output=arguments.causal_output,
        report_output=arguments.report_output,
    )
    print(
        json.dumps(
            {
                "output": str(arguments.output),
                "measurement_sha256": result["measurement_sha256"],
                "evidence_status": result["localization"]["evidence_status"],
                "selected_driver": result["localization"]["selected_driver"],
                "next_probe": result["localization"]["next_probe"]["probe"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
