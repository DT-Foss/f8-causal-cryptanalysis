from __future__ import annotations

import copy
import hashlib
import importlib.util
import itertools
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "research/experiments/chacha20_round20_factorial_boundary_route.py"


def _load():
    spec = importlib.util.spec_from_file_location("a220b_boundary_route_test", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load()


def _reader() -> dict[str, Any]:
    identity = {
        "bundle_id": "numeric__one_shot",
        "feature_family": "P1_dense_local",
        "readout_kind": "ridge_logistic",
        "ridge_lambda": 0.1,
        "run_count": 2,
    }
    readout = {
        "kind": "ridge_logistic",
        "feature_family": "P1_dense_local",
        "feature_names": [f"f{index}" for index in range(12)],
        "means": [0.0] * 12,
        "scales": [1.0] * 12,
        "intercept": 0.0,
        "coefficients": [0.0] * 12,
        "ridge_lambda": 0.1,
        "diagnostics": {"fixture": True},
    }
    return {
        "schema": "chacha20-round20-factorial-trajectory-reader-v1",
        "attempt_id": "A220",
        "evidence_stage": "FULLROUND_R20_FACTORIAL_READER_FROZEN_BEFORE_HOLDOUT",
        "protocol_sha256": _protocol()["anchors"]["A220_protocol_sha256"],
        "reader_runner_sha256": "01" * 32,
        "reader_checkpoint_sha256": "02" * 32,
        "software_versions": {},
        "factorial_trajectory_reader_sha256": "03" * 32,
        "ridge_backend_sha256": "04" * 32,
        "collector_source_sha256": "05" * 32,
        "fit_select_index_sha256": "06" * 32,
        "fit_select_input_manifest": [],
        "fit_select_input_manifest_sha256": "07" * 32,
        "feature_matrix_sha256": "08" * 32,
        "fit_panel": {},
        "selection_panel": {},
        "grid_definition": {},
        "observed_candidate_grid": [],
        "selected_reader": {
            "selected_identity": identity,
            "selected_metrics": {
                "mean_log2_rank": 3.0,
                "ranks": [8] * 20,
            },
            "selected_constituent_readouts": {"numeric__one_shot": readout},
            "selected_score_sha256": "11" * 32,
            "candidate_grid_sha256": "22" * 32,
        },
        "selection_matched_null": {},
        "information_boundary": copy.deepcopy(MODULE.A220_READER_BOUNDARY),
        "completion_gates": copy.deepcopy(MODULE.A220_READER_COMPLETION),
    }


def _protocol() -> dict[str, Any]:
    return json.loads(MODULE.PROTOCOL.read_bytes())


def _metrics(count: int, mean_log2_rank: int) -> dict[str, Any]:
    rank = 1 << mean_log2_rank
    return {"mean_log2_rank": float(mean_log2_rank), "ranks": [rank] * count}


def _evaluation(*, retained: bool) -> dict[str, Any]:
    panels = {
        "fit_by_confirm": _metrics(32, 3),
        "select_by_confirm": _metrics(20, 3),
        "confirm_by_fit": _metrics(20, 3 if retained else 5),
        "confirm_by_confirm": _metrics(20, 3 if retained else 6),
    }
    primary_mean = panels["confirm_by_confirm"]["mean_log2_rank"]
    records = []
    for index, permutation in enumerate(itertools.permutations(range(5))):
        statistic = (
            primary_mean + (0.0 if index == 0 else 1.0)
            if retained
            else primary_mean + (0.0 if index < 60 else 1.0)
        )
        records.append(
            {
                "permutation_index": index,
                "cluster_permutation": list(permutation),
                "target_prefix_order_sha256": hashlib.sha256(bytes(permutation)).hexdigest(),
                "mean_log2_rank": statistic,
            }
        )
    statistics = [record["mean_log2_rank"] for record in records]
    bit_gain = MODULE.UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2 - primary_mean
    primary = {
        "retained": retained,
        "exact_lower_tail_p": 1 / 120 if retained else 0.5,
        "retention_threshold": 0.05,
        "uniform_random_rank_expected_mean_log2": 6.578110496969589,
        "panel": "confirm_by_confirm",
        "prefix_clusters": 5,
        "suffix_replicates_per_cluster": 4,
        "observed_metrics": panels["confirm_by_confirm"],
        "observed_bit_gain_over_uniform_mean_log2": bit_gain,
        "geometric_rank_concentration_factor": float(2.0**bit_gain),
        "permutation_records": records,
        "permutation_statistics_sha256": MODULE._canonical_sha256(statistics),
    }
    identity = _reader_identity()
    run_ids = list(MODULE.selected_bundle_run_ids(identity["bundle_id"]))
    evaluation = {
        "selected_identity": identity,
        "selected_run_ids": run_ids,
        "panel_metrics": panels,
        "primary_exact_cluster_null": primary,
        "evidence_stage": (
            "FULLROUND_R20_FACTORIAL_TRAJECTORY_HOLDOUT_TRANSFER"
            if retained
            else "FULLROUND_R20_FACTORIAL_TRAJECTORY_PROBE_SPECIFIC_BOUNDARY"
        ),
    }
    evaluation["evaluation_sha256"] = MODULE._canonical_sha256(evaluation)
    return evaluation


def _reader_identity() -> dict[str, Any]:
    return {
        "bundle_id": "numeric__one_shot",
        "feature_family": "P1_dense_local",
        "readout_kind": "ridge_logistic",
        "ridge_lambda": 0.1,
        "run_count": 2,
    }


def _result(reader: dict[str, Any], reader_path: Path, *, retained: bool) -> dict[str, Any]:
    selected = reader["selected_reader"]
    evaluation = _evaluation(retained=retained)
    measurement = {
        "schema": "chacha20-round20-factorial-trajectory-transfer-v1",
        "attempt_id": "A220",
        "evidence_stage": evaluation["evidence_stage"],
        "protocol_path": _protocol()["anchors"]["A220_protocol_path"],
        "protocol_sha256": _protocol()["anchors"]["A220_protocol_sha256"],
        "reader_path": MODULE._display_path(reader_path),
        "reader_artifact_sha256": hashlib.sha256(reader_path.read_bytes()).hexdigest(),
        "holdout_evaluator_path": _protocol()["anchors"]["A220_holdout_evaluator_path"],
        "holdout_evaluator_sha256": _protocol()["anchors"]["A220_holdout_evaluator_sha256"],
        "selected_reader": {
            "selected_identity": selected["selected_identity"],
            "selected_identity_sha256": MODULE._canonical_sha256(selected["selected_identity"]),
            "selected_readout_sha256": MODULE._selected_readout_sha256(reader),
            "selected_run_ids": list(
                MODULE.selected_bundle_run_ids(selected["selected_identity"]["bundle_id"])
            ),
        },
        "evaluation": evaluation,
        "completion_gates": copy.deepcopy(MODULE.A220_RESULT_COMPLETION),
        "information_boundary": copy.deepcopy(MODULE.A220_RESULT_BOUNDARY),
    }
    return {**measurement, "measurement_sha256": MODULE._canonical_sha256(measurement)}


@pytest.fixture()
def artifact_pair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    reader_path = tmp_path / "reader.json"
    result_path = tmp_path / "result.json"
    reader = _reader()
    reader_path.write_text(json.dumps(reader, sort_keys=True))
    monkeypatch.setattr(MODULE, "READER", reader_path)
    monkeypatch.setattr(MODULE, "A220_RESULT", result_path)
    return reader, reader_path, result_path, _protocol()


@pytest.mark.parametrize("retained", [False, True])
def test_final_input_gate_accepts_both_registered_branches(artifact_pair, retained: bool) -> None:
    reader, reader_path, _, protocol = artifact_pair
    result = _result(reader, reader_path, retained=retained)
    selection, panels, observed_retained, identity, readout_sha = MODULE._validate_inputs(
        result, reader, protocol
    )
    assert selection == 3.0
    assert set(panels) == set(MODULE.PANEL_ORDER)
    assert observed_retained is retained
    assert identity == reader["selected_reader"]["selected_identity"]
    assert readout_sha == MODULE._selected_readout_sha256(reader)


@pytest.mark.parametrize(
    "mutation",
    [
        "outer_hash",
        "evaluation_hash",
        "reader_hash",
        "reader_identity",
        "primary_p",
        "primary_mean",
        "completion",
        "boundary",
    ],
)
def test_final_input_gate_rejects_mutation(artifact_pair, mutation: str) -> None:
    reader, reader_path, _, protocol = artifact_pair
    result = _result(reader, reader_path, retained=False)
    if mutation == "outer_hash":
        result["measurement_sha256"] = "00" * 32
    elif mutation == "evaluation_hash":
        result["evaluation"]["evaluation_sha256"] = "00" * 32
    elif mutation == "reader_hash":
        result["reader_artifact_sha256"] = "00" * 32
    elif mutation == "reader_identity":
        result["selected_reader"]["selected_identity"]["ridge_lambda"] = 10.0
    elif mutation == "primary_p":
        result["evaluation"]["primary_exact_cluster_null"]["exact_lower_tail_p"] = 0.01
    elif mutation == "primary_mean":
        result["evaluation"]["primary_exact_cluster_null"]["observed_metrics"]["mean_log2_rank"] = (
            5.0
        )
    elif mutation == "completion":
        result["completion_gates"]["complete_120_permutation_primary_null_evaluated"] = False
    else:
        result["information_boundary"]["future_prospective_target_generated_or_opened"] = True
    if mutation not in {"outer_hash", "evaluation_hash"}:
        evaluation = result["evaluation"]
        evaluation["evaluation_sha256"] = MODULE._canonical_sha256(
            {key: value for key, value in evaluation.items() if key != "evaluation_sha256"}
        )
        result["measurement_sha256"] = MODULE._canonical_sha256(
            {key: value for key, value in result.items() if key != "measurement_sha256"}
        )
    with pytest.raises(RuntimeError):
        MODULE._validate_inputs(result, reader, protocol)


def _rehash_result(result: dict[str, Any]) -> None:
    evaluation = result["evaluation"]
    evaluation["evaluation_sha256"] = MODULE._canonical_sha256(
        {key: value for key, value in evaluation.items() if key != "evaluation_sha256"}
    )
    result["measurement_sha256"] = MODULE._canonical_sha256(
        {key: value for key, value in result.items() if key != "measurement_sha256"}
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "result_protocol",
        "result_evaluator_path",
        "result_evaluator_hash",
        "reader_attempt",
        "reader_protocol",
        "reader_completion",
        "selected_run_ids",
        "result_secret_extra",
        "reader_secret_extra",
        "duplicate_permutation",
        "statistics_hash",
    ],
)
def test_final_gate_rejects_self_rehashed_provenance_or_secret_mutation(
    artifact_pair, mutation: str
) -> None:
    reader, reader_path, _, protocol = artifact_pair
    result = _result(reader, reader_path, retained=False)
    if mutation == "result_protocol":
        result["protocol_sha256"] = "90" * 32
    elif mutation == "result_evaluator_path":
        result["holdout_evaluator_path"] = "research/experiments/forged.py"
    elif mutation == "result_evaluator_hash":
        result["holdout_evaluator_sha256"] = "91" * 32
    elif mutation == "reader_attempt":
        reader["attempt_id"] = "A220-forged"
    elif mutation == "reader_protocol":
        reader["protocol_sha256"] = "92" * 32
    elif mutation == "reader_completion":
        reader["completion_gates"]["one_reader_selected_and_serialized"] = False
    elif mutation == "selected_run_ids":
        result["selected_reader"]["selected_run_ids"].reverse()
        result["evaluation"]["selected_run_ids"].reverse()
    elif mutation == "result_secret_extra":
        result["target_prefix8"] = 7
    elif mutation == "reader_secret_extra":
        reader["selected_reader"]["selected_constituent_readouts"]["numeric__one_shot"][
            "diagnostics"
        ]["low20"] = 7
    elif mutation == "duplicate_permutation":
        result["evaluation"]["primary_exact_cluster_null"]["permutation_records"][1][
            "cluster_permutation"
        ] = [0, 1, 2, 3, 4]
    else:
        result["evaluation"]["primary_exact_cluster_null"]["permutation_statistics_sha256"] = (
            "93" * 32
        )
    if mutation.startswith("reader_"):
        reader_path.write_text(json.dumps(reader, sort_keys=True))
        result["reader_artifact_sha256"] = hashlib.sha256(reader_path.read_bytes()).hexdigest()
        result["selected_reader"]["selected_readout_sha256"] = MODULE._selected_readout_sha256(
            reader
        )
    _rehash_result(result)
    with pytest.raises(RuntimeError):
        MODULE._validate_inputs(result, reader, protocol)


@pytest.mark.parametrize("p_value", [-1.0, 0.0, 1.1, 0.12345])
def test_final_gate_reconstructs_exact_p_instead_of_trusting_value(
    artifact_pair, p_value: float
) -> None:
    reader, reader_path, _, protocol = artifact_pair
    result = _result(reader, reader_path, retained=False)
    result["evaluation"]["primary_exact_cluster_null"]["exact_lower_tail_p"] = p_value
    _rehash_result(result)
    with pytest.raises(RuntimeError):
        MODULE._validate_inputs(result, reader, protocol)


def test_causal_graph_is_exact_and_reader_verified(tmp_path: Path) -> None:
    localization = MODULE.localize_factorial_boundary(
        selection_mean_log2_rank=3.0,
        panel_mean_log2_ranks={
            "fit_by_confirm": 3.0,
            "select_by_confirm": 3.0,
            "confirm_by_fit": 5.0,
            "confirm_by_confirm": 6.0,
        },
        primary_retained=False,
    )
    raw, meta = MODULE._causal_bytes(
        measurement_sha256="33" * 32,
        localization=localization,
        protocol_sha256="44" * 32,
    )
    assert meta["explicit_triplets"] == 2
    assert meta["inferred_triplets"] == 1
    path = tmp_path / "route.causal"
    path.write_bytes(raw)
    reader = MODULE.CryptoCausalReader(path)
    assert reader.verify_provenance()
    assert reader.file_sha256 == meta["file_sha256"]


def test_atomic_artifact_commit_is_idempotent_and_conflict_safe(tmp_path: Path) -> None:
    paths = {tmp_path / "a": b"alpha", tmp_path / "b": b"beta"}
    MODULE._commit_exact(paths)
    MODULE._commit_exact(paths)
    assert {path.read_bytes() for path in paths} == {b"alpha", b"beta"}
    with pytest.raises(RuntimeError):
        MODULE._commit_exact({tmp_path / "a": b"changed", tmp_path / "b": b"beta"})
    (tmp_path / "b").unlink()
    MODULE._commit_exact(paths)
    assert (tmp_path / "b").read_bytes() == b"beta"


def test_atomic_artifact_commit_resumes_exact_temporary(tmp_path: Path) -> None:
    first = tmp_path / "a"
    second = tmp_path / "b"
    first.write_bytes(b"alpha")
    second_tmp = tmp_path / ".b.tmp"
    second_tmp.write_bytes(b"beta")
    MODULE._commit_exact({first: b"alpha", second: b"beta"})
    assert second.read_bytes() == b"beta"
    assert not second_tmp.exists()


@pytest.mark.parametrize("collision", ["json_causal", "json_report", "causal_report"])
def test_runner_rejects_output_path_alias_before_any_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, collision: str
) -> None:
    output = tmp_path / "route.json"
    causal = tmp_path / "route.causal"
    report = tmp_path / "route.md"
    if collision == "json_causal":
        causal = output
    elif collision == "json_report":
        report = output
    else:
        report = causal
    monkeypatch.setattr(
        MODULE,
        "_load_protocol",
        lambda: (_ for _ in ()).throw(AssertionError("protocol opened before path preflight")),
    )
    with pytest.raises(RuntimeError, match="pairwise distinct"):
        MODULE.run(output=output, causal_output=causal, report_output=report)
    assert not output.exists()
    assert not causal.exists()
    assert not report.exists()


@pytest.mark.parametrize("retained", [False, True])
def test_complete_runner_writes_reproducible_json_causal_and_report(
    artifact_pair,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    retained: bool,
) -> None:
    reader, reader_path, result_path, protocol = artifact_pair
    result = _result(reader, reader_path, retained=retained)
    result_path.write_text(json.dumps(result, sort_keys=True))
    protocol_sha = hashlib.sha256(MODULE.PROTOCOL.read_bytes()).hexdigest()
    monkeypatch.setattr(MODULE, "_load_protocol", lambda: (protocol, protocol_sha))
    output = tmp_path / "route.json"
    causal = tmp_path / "route.causal"
    report = tmp_path / "route.md"
    first = MODULE.run(output=output, causal_output=causal, report_output=report)
    first_bytes = (output.read_bytes(), causal.read_bytes(), report.read_bytes())
    second = MODULE.run(output=output, causal_output=causal, report_output=report)
    assert first == second
    assert first_bytes == (output.read_bytes(), causal.read_bytes(), report.read_bytes())
    assert first["localization"]["evidence_status"] == (
        "RETAINED_RESULT" if retained else "NEW_BOUNDARY"
    )
    assert first["information_boundary"]["known_key_holdout_aggregate_metrics_loaded"] is True
    assert first["information_boundary"]["prospective_target_key_or_label_loaded"] is False


def test_source_has_no_target_secret_or_raw_holdout_loader() -> None:
    text = SOURCE.read_text()
    assert ".research_sealed" not in text
    assert ".load_verified_holdout_corpus(" not in text
    assert "target_commit" not in text
    assert "ranked_target" not in text
    assert "prospective_target_key_or_label_loaded" in text
