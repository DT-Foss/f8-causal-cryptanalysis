from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import numpy as np
import pytest

from arx_carry_leak import factorial_holdout as holdout
from arx_carry_leak.crypto_causal import CryptoCausalReader
from arx_carry_leak.factorial_trajectory import CandidateIdentity, PairFeatureView

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research/experiments/chacha20_round20_factorial_trajectory_holdout_evaluate.py"
PROTOCOL = ROOT / "research/configs/chacha20_round20_factorial_trajectory_transfer_v1.json"


def _load_runner() -> Any:
    spec = importlib.util.spec_from_file_location("test_a220_holdout_evaluator", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load_runner()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()
    return _sha256(raw)


def _rows() -> list[dict[str, Any]]:
    result = []
    panels = (
        ("fit", "confirm", 8),
        ("select", "confirm", 5),
        ("confirm", "fit", 5),
        ("confirm", "confirm", 5),
    )
    prefix_seed = 11
    for prefix_split, suffix_split, clusters in panels:
        for prefix_index in range(clusters):
            prefix8 = prefix_seed
            prefix_seed += 7
            for suffix_index in range(4):
                suffix12 = 0x101 + 13 * suffix_index
                low20 = (prefix8 << 12) | suffix12
                result.append(
                    {
                        "label": (
                            f"a220_{prefix_split}_p{prefix_index:02d}_"
                            f"{suffix_split}_s{suffix_index:02d}"
                        ),
                        "prefix_split": prefix_split,
                        "prefix_index": prefix_index,
                        "prefix8": prefix8,
                        "prefix8_binary": f"{prefix8:08b}",
                        "suffix_split": suffix_split,
                        "suffix_index": suffix_index,
                        "suffix12": suffix12,
                        "low20": low20,
                        "low20_hex": f"{low20:05x}",
                    }
                )
    assert len(result) == 92
    return result


def _selected_reader(bundle: str) -> dict[str, Any]:
    identity = CandidateIdentity(bundle, "P1_dense_local", "ridge_logistic", 0.01)
    constituents = (
        (bundle,)
        if not bundle.endswith("__dual_schedule")
        else (
            "numeric__staged_retained_resolve",
            "numeric__one_shot",
        )
    )
    readouts = {
        constituent: {
            "kind": identity.readout_kind,
            "feature_family": identity.feature_family,
            "feature_names": [f"f{index}" for index in range(12)],
            "means": [0.0] * 12,
            "scales": [1.0] * 12,
            "intercept": 0.0,
            "coefficients": [1.0, *([0.0] * 11)],
            "ridge_lambda": identity.ridge_lambda,
            "diagnostics": {"fixture": True},
        }
        for constituent in constituents
    }
    return {
        "selected_identity": identity.as_dict(),
        "selected_metrics": {"mean_log2_rank": 1.0},
        "selected_score_sha256": "11" * 32,
        "selected_constituent_readouts": readouts,
        "candidate_grid_sha256": "22" * 32,
    }


def _reader(bundle: str) -> dict[str, Any]:
    return {
        "schema": MODULE.READER_SCHEMA,
        "attempt_id": MODULE.ATTEMPT_ID,
        "evidence_stage": "FULLROUND_R20_FACTORIAL_READER_FROZEN_BEFORE_HOLDOUT",
        "protocol_sha256": MODULE.PROTOCOL_SHA256,
        "selected_reader": _selected_reader(bundle),
        "information_boundary": {
            "fit_select_measurements_loaded": True,
            "holdout_measurements_loaded": False,
            "future_prospective_target_loaded": False,
            "suffix_specific_target_floor_or_key_suffix_feature_used": False,
            "reader_frozen_before_any_holdout_trajectory_process": True,
        },
        "completion_gates": {
            "all_52_fit_select_shards_verified": True,
            "all_624_fresh_solver_processes_in_verified_index": True,
            "exactly_300_atomic_models_fit": True,
            "exactly_450_bundle_rows_evaluated": True,
            "all_64_matched_cluster_nulls_complete": True,
            "one_reader_selected_and_serialized": True,
            "holdout_trajectory_not_opened": True,
            "future_prospective_target_not_opened": True,
        },
    }


def _fake_view(run: dict[str, Any], reverse: dict[str, Any]) -> dict[str, PairFeatureView]:
    del reverse
    scores = np.asarray(run["fixture_scores"], dtype=np.float64)
    matrix = np.zeros((256, 12), dtype=np.float64)
    matrix[:, 0] = scores
    return {"P1_dense_local": PairFeatureView(tuple(f"f{i}" for i in range(12)), matrix)}


def _payloads(rows: list[dict[str, Any]], bundle: str, *, retained: bool) -> list[dict[str, Any]]:
    run_ids = holdout.selected_bundle_run_ids(bundle)
    result = []
    for row in rows:
        target = int(row["prefix8"])
        runs = {run_id: {"run_id": run_id} for run_id in run_ids}
        for run_id in run_ids:
            if "_forward__" not in run_id:
                continue
            if retained:
                scores = np.arange(256, dtype=np.float64) * 1e-9
                scores[target] = 100.0
            else:
                scores = np.linspace(0.0, 1.0, 256)
            runs[run_id]["fixture_scores"] = scores.tolist()
        result.append(
            {
                "key_factorial_identity": dict(row),
                "scientific_runs": runs,
            }
        )
    return result


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _fixture(
    tmp_path: Path,
    *,
    bundle: str = "numeric__one_shot",
    retained: bool = True,
) -> dict[str, Any]:
    rows = _rows()
    payloads = _payloads(rows, bundle, retained=retained)
    selected = _selected_reader(bundle)
    reader = _reader(bundle)
    run_ids = holdout.selected_bundle_run_ids(bundle)

    root = tmp_path / "root"
    reader_path = root / json.loads(PROTOCOL.read_bytes())["required_artifacts"]["reader_freeze"]
    _write_json(reader_path, reader)
    collector_path = tmp_path / "holdout_collect.py"
    collector_test_path = tmp_path / "test_holdout_collect.py"
    collector_path.write_text("# solver-free mocked collector source\n")
    collector_test_path.write_text("# mocked collector tests\n")

    index_path = (
        root / "research/results/v1/chacha20_round20_factorial_trajectory_holdout_v1/index.json"
    )
    shard_directory = index_path.parent / "shards"
    entries = []
    for row in rows:
        raw = f"verified-shard:{row['label']}\n".encode()
        shard = shard_directory / f"{row['label']}.measurement.json.zst"
        shard.parent.mkdir(parents=True, exist_ok=True)
        shard.write_bytes(raw)
        entries.append(
            {
                "key_label": row["label"],
                "prefix_split": row["prefix_split"],
                "prefix_index": row["prefix_index"],
                "suffix_split": row["suffix_split"],
                "suffix_index": row["suffix_index"],
                "panel": f"{row['prefix_split']}_by_{row['suffix_split']}",
                "relative_path": f"shards/{shard.name}",
                "measurement_sha256": _canonical_sha256(row),
                "measurement_bytes": 1000,
                "compressed_sha256": _sha256(raw),
                "compressed_bytes": len(raw),
            }
        )

    identity = selected["selected_identity"]
    identity_sha = _canonical_sha256(identity)
    readout_sha = MODULE._selected_readout_sha256(reader)
    launch = {
        "schema": MODULE.LAUNCH_SCHEMA,
        "attempt_id": MODULE.ATTEMPT_ID,
        "evidence_stage": "HOLDOUT_READER_AND_PLAN_FROZEN_BEFORE_ANY_SUBPROCESS",
        "protocol_path": "research/configs/chacha20_round20_factorial_trajectory_transfer_v1.json",
        "protocol_sha256": MODULE.PROTOCOL_SHA256,
        "reader_path": "research/results/v1/chacha20_round20_factorial_trajectory_reader_freeze_v1.json",
        "reader_artifact_sha256": _sha256(reader_path.read_bytes()),
        "selected_identity_sha256": identity_sha,
        "selected_readout_sha256": readout_sha,
        "selected_reader_identity": identity,
        "collector_source_sha256": _sha256(collector_path.read_bytes()),
        "collector_test_sha256": _sha256(collector_test_path.read_bytes()),
        "low_level_source_sha256": "33" * 32,
        "holdout_core_path": "src/arx_carry_leak/factorial_holdout.py",
        "holdout_core_sha256": MODULE.HOLDOUT_CORE_SHA256,
        "holdout_core_test_path": "tests/test_factorial_holdout.py",
        "holdout_core_test_sha256": MODULE.HOLDOUT_CORE_TEST_SHA256,
        "holdout_evaluator_source_sha256": _sha256(RUNNER.read_bytes()),
        "holdout_evaluator_test_sha256": _sha256(Path(__file__).read_bytes()),
        "factorial_design_path": "research/experiments/chacha20_round20_factorial_key_design.py",
        "factorial_design_sha256": "44" * 32,
        "factorial_ledger_sha256": "55" * 32,
        "holdout_rows": 92,
        "holdout_rows_sha256": _canonical_sha256(rows),
        "holdout_label_order_sha256": _canonical_sha256([row["label"] for row in rows]),
        "holdout_labels": [row["label"] for row in rows],
        "selected_run_plan": [
            {
                "run_id": run_id,
                "mode": f"A220_HOLDOUT_{rows[0]['label']}_{run_id}",
                "operator": run_id.split("__", 1)[0],
                "schedule": run_id.split("__", 1)[1],
                "conflict_horizons": [64],
                "order_uint8_sha256": "66" * 32,
            }
            for run_id in run_ids
        ],
        "selected_run_plan_template_sha256": "77" * 32,
        "full_holdout_process_plan_sha256": "88" * 32,
        "full_holdout_fresh_solver_processes": 92 * len(run_ids),
        "source_anchor_hashes": {},
        "resource_settings": {
            "maximum_concurrent_solver_processes": 2,
            "one_key_instantiated_CNF_active_at_a_time": True,
            "watchdog_seconds_per_stage": 5.0,
            "cell_count_per_run": 256,
            "complete_prefix_cover_per_run": True,
            "early_stop": False,
            "schedules": {
                "staged_retained_resolve": [8, 16, 32, 64],
                "one_shot": [64],
            },
            "zstandard_version": "0.25.0",
            "zstandard_level": 19,
            "zstandard_threads": 0,
        },
        "information_boundary": {
            "stage": "HOLDOUT",
            "reader_frozen_before_holdout": True,
            "fit_select_shards_or_index_opened": False,
            "prospective_target_opened": False,
            "low20_used_only_for_challenge_and_separate_label": True,
            "low20_passed_to_order_budget_or_features": False,
            "refit_reselection_or_threshold_adaptation": False,
        },
    }
    launch_path = index_path.parent / "launch_manifest.json"
    _write_json(launch_path, launch)
    index = {
        "schema": MODULE.COLLECTOR_SCHEMA,
        "attempt_id": MODULE.ATTEMPT_ID,
        "evidence_stage": "FULLROUND_R20_FACTORIAL_HOLDOUT_TRAJECTORY_COLLECTION",
        "protocol_sha256": MODULE.PROTOCOL_SHA256,
        "launch_manifest_relative_path": "launch_manifest.json",
        "launch_manifest_sha256": _sha256(launch_path.read_bytes()),
        "reader_artifact_sha256": _sha256(reader_path.read_bytes()),
        "selected_reader_identity_sha256": identity_sha,
        "selected_reader_readout_sha256": readout_sha,
        "collector_source_sha256": _sha256(collector_path.read_bytes()),
        "collector_test_sha256": _sha256(collector_test_path.read_bytes()),
        "source_anchor_hashes": {},
        "factorial_holdout_label_order_sha256": _canonical_sha256([row["label"] for row in rows]),
        "selected_run_plan_template_sha256": launch["selected_run_plan_template_sha256"],
        "verified_shards": entries,
        "completion_gates": {
            "verified_key_shards": 92,
            "expected_key_shards": 92,
            "selected_runs_per_key": len(run_ids),
            "verified_fresh_solver_processes": 92 * len(run_ids),
            "expected_fresh_solver_processes": 92 * len(run_ids),
            "all_92_key_shards_complete": True,
            "all_selected_fresh_solver_processes_complete": True,
            "all_shards_decompressed_and_hash_verified": True,
            "global_index_rebuilt_from_verified_shards": True,
            "collector_source_unchanged": True,
            "reader_launch_and_source_hashes_unchanged": True,
            "no_failure_tombstones": True,
        },
    }
    _write_json(index_path, index)
    return {
        "root": root,
        "rows": rows,
        "payloads": payloads,
        "index": index,
        "reader": reader,
        "launch": launch,
        "index_path": index_path,
        "shard_directory": shard_directory,
        "reader_path": reader_path,
        "launch_path": launch_path,
        "collector_path": collector_path,
        "collector_test_path": collector_test_path,
        "output": tmp_path / "out/result.json",
        "causal": tmp_path / "out/result.causal",
        "report": tmp_path / "out/report.md",
        "lock": tmp_path / "sealed/evaluator.lock",
    }


def _run_fixture(
    fixture: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    *,
    public_only: bool = True,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    calls: list[dict[str, Any]] = []

    def loader(**kwargs: Any):
        calls.append(kwargs)
        return (
            fixture["rows"],
            fixture["payloads"],
            fixture["index"],
            fixture["reader"],
            fixture["launch"],
        )

    monkeypatch.setattr(
        MODULE,
        "_import_path",
        lambda path, name: SimpleNamespace(load_verified_holdout_corpus=loader),
    )
    monkeypatch.setattr(holdout, "extract_pair_feature_views", _fake_view)
    result = MODULE.run(
        index_path=fixture["index_path"],
        shard_directory=fixture["shard_directory"],
        reader_path=fixture["reader_path"],
        launch_manifest_path=fixture["launch_path"],
        checkpoint_directory=None if public_only else fixture["root"] / "sealed/checkpoints",
        history_path=None if public_only else fixture["root"] / "sealed/attempts.jsonl",
        output_path=fixture["output"],
        causal_output_path=fixture["causal"],
        report_output_path=fixture["report"],
        lock_path=fixture["lock"],
        protocol_path=PROTOCOL,
        collector_path=fixture["collector_path"],
        collector_test_path=fixture["collector_test_path"],
        evaluator_test_path=Path(__file__),
        root=fixture["root"],
    )
    return result, calls


def test_protocol_requires_the_authoritative_reader_freeze(tmp_path: Path) -> None:
    protocol = MODULE._load_protocol(PROTOCOL)
    path = MODULE._required_reader_path(protocol, root=tmp_path)
    assert path.name == "chacha20_round20_factorial_trajectory_reader_freeze_v1.json"
    assert path != (
        tmp_path / "research/results/v1/chacha20_round20_factorial_trajectory_reader_v1.json"
    )


@pytest.mark.parametrize(
    ("bundle", "retained", "public_only"),
    [
        ("numeric__one_shot", True, True),
        ("numeric__dual_schedule", True, False),
        ("numeric__one_shot", False, True),
    ],
)
def test_atomic_dual_and_boundary_flows_use_one_verified_loader_and_exact_core(
    bundle: str,
    retained: bool,
    public_only: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path, bundle=bundle, retained=retained)
    result, calls = _run_fixture(fixture, monkeypatch, public_only=public_only)
    assert len(calls) == 1
    assert calls[0]["reader_path"] == fixture["reader_path"]
    assert (calls[0]["checkpoint_directory"] is None) is public_only
    assert result["completion_gates"]["public_reconstructive_verification_supported"] is True
    assert (
        result["completion_gates"]["sealed_execution_provenance_embedded_in_verified_shards"]
        is True
    )
    assert result["selected_reader"]["selected_identity"]["bundle_id"] == bundle
    assert len(result["selected_reader"]["selected_run_ids"]) == (4 if "dual" in bundle else 2)
    primary = result["evaluation"]["primary_exact_cluster_null"]
    assert len(primary["permutation_records"]) == 120
    assert primary["retained"] is retained
    assert len(result["holdout_input_manifest"]) == 92
    assert json.loads(fixture["output"].read_bytes()) == result

    causal_reader = CryptoCausalReader(fixture["causal"])
    assert causal_reader.verify_provenance()
    assert len(causal_reader.triplets(include_inferred=False)) == 3
    assert len(causal_reader.triplets(include_inferred=True)) == 5
    report = fixture["report"].read_text()
    assert result["evidence_stage"] in report
    assert "all 5! = 120 whole-cluster permutations" in report
    if retained:
        assert "prospectively reusable prefix-ordering operator" in report
        assert "not itself a recovery result" in report
    else:
        assert "probe-specific representation boundary" in report
        assert "not a general ChaCha20 immunity statement" in report


def test_incomplete_or_tombstoned_corpus_is_refused_before_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path)
    fixture["index"]["completion_gates"]["no_failure_tombstones"] = False
    _write_json(fixture["index_path"], fixture["index"])
    monkeypatch.setattr(
        MODULE,
        "_import_path",
        lambda path, name: SimpleNamespace(
            load_verified_holdout_corpus=lambda **kwargs: (
                fixture["rows"],
                fixture["payloads"],
                fixture["index"],
                fixture["reader"],
                fixture["launch"],
            )
        ),
    )
    monkeypatch.setattr(
        MODULE,
        "evaluate_verified_holdout",
        lambda *args, **kwargs: pytest.fail("evaluation must not run"),
    )
    with pytest.raises(RuntimeError, match="incomplete or contains a tombstone"):
        MODULE.run(
            index_path=fixture["index_path"],
            shard_directory=fixture["shard_directory"],
            reader_path=fixture["reader_path"],
            launch_manifest_path=fixture["launch_path"],
            checkpoint_directory=None,
            history_path=None,
            output_path=fixture["output"],
            causal_output_path=fixture["causal"],
            report_output_path=fixture["report"],
            lock_path=fixture["lock"],
            protocol_path=PROTOCOL,
            collector_path=fixture["collector_path"],
            collector_test_path=fixture["collector_test_path"],
            evaluator_test_path=Path(__file__),
            root=fixture["root"],
        )
    assert not fixture["output"].exists()


def test_missing_verified_loader_has_no_raw_shard_fallback(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="lacks load_verified_holdout_corpus"):
        MODULE._load_verified_corpus(
            collector=SimpleNamespace(),
            index_path=tmp_path / "index.json",
            shard_directory=tmp_path / "shards",
            reader_path=tmp_path / "reader.json",
            launch_manifest_path=tmp_path / "launch.json",
            checkpoint_directory=None,
            history_path=None,
        )


@pytest.mark.parametrize("drift", ["reader", "launch", "collector"])
def test_reader_launch_and_source_drift_after_scoring_is_refused(
    drift: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)

    def loader(**kwargs: Any):
        return (
            fixture["rows"],
            fixture["payloads"],
            fixture["index"],
            fixture["reader"],
            fixture["launch"],
        )

    monkeypatch.setattr(
        MODULE,
        "_import_path",
        lambda path, name: SimpleNamespace(load_verified_holdout_corpus=loader),
    )
    monkeypatch.setattr(holdout, "extract_pair_feature_views", _fake_view)
    original = MODULE.evaluate_verified_holdout

    def evaluate(*args: Any, **kwargs: Any):
        value = original(*args, **kwargs)
        path = {
            "reader": fixture["reader_path"],
            "launch": fixture["launch_path"],
            "collector": fixture["collector_path"],
        }[drift]
        path.write_bytes(path.read_bytes() + b" ")
        return value

    monkeypatch.setattr(MODULE, "evaluate_verified_holdout", evaluate)
    with pytest.raises(RuntimeError, match="drifted during inference"):
        MODULE.run(
            index_path=fixture["index_path"],
            shard_directory=fixture["shard_directory"],
            reader_path=fixture["reader_path"],
            launch_manifest_path=fixture["launch_path"],
            checkpoint_directory=None,
            history_path=None,
            output_path=fixture["output"],
            causal_output_path=fixture["causal"],
            report_output_path=fixture["report"],
            lock_path=fixture["lock"],
            protocol_path=PROTOCOL,
            collector_path=fixture["collector_path"],
            collector_test_path=fixture["collector_test_path"],
            evaluator_test_path=Path(__file__),
            root=fixture["root"],
        )
    assert not fixture["output"].exists()


def test_conflicting_existing_output_is_never_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path)
    fixture["output"].parent.mkdir(parents=True, exist_ok=True)
    fixture["output"].write_bytes(b"user-owned-conflict\n")
    with pytest.raises(RuntimeError, match="refuses conflicting existing output"):
        _run_fixture(fixture, monkeypatch)
    assert fixture["output"].read_bytes() == b"user-owned-conflict\n"
    assert not fixture["causal"].exists()
    assert not fixture["report"].exists()


def test_strict_and_public_only_verification_write_identical_artifact_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path)
    public_result, _ = _run_fixture(fixture, monkeypatch, public_only=True)
    public_bytes = tuple(fixture[name].read_bytes() for name in ("output", "causal", "report"))
    strict_result, _ = _run_fixture(fixture, monkeypatch, public_only=False)
    strict_bytes = tuple(fixture[name].read_bytes() for name in ("output", "causal", "report"))
    assert strict_result == public_result
    assert strict_bytes == public_bytes
    assert tuple(_sha256(raw) for raw in strict_bytes) == tuple(
        _sha256(raw) for raw in public_bytes
    )


def test_runner_has_no_solver_or_model_fitting_interface() -> None:
    source = RUNNER.read_text()
    assert "subprocess" not in source
    assert "fit_factorial_readout" not in source
    assert "select_candidate" not in source
    assert source.count("evaluate_verified_holdout(") == 1


def test_public_only_cli_passes_both_sealed_crossbinding_paths_as_none(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    captured: dict[str, Any] = {}

    def fake_run(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {
            "causal_artifact": {"file_sha256": "11" * 32},
            "evidence_stage": "TEST",
            "evaluation": {
                "primary_exact_cluster_null": {
                    "exact_lower_tail_p": 1 / 120,
                    "retained": True,
                }
            },
        }

    monkeypatch.setattr(MODULE, "run", fake_run)
    monkeypatch.setattr(MODULE, "_file_sha256", lambda path: "22" * 32)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(RUNNER),
            "--public-only-verification",
            "--output",
            "/tmp/a220-test-result.json",
        ],
    )
    MODULE.main()
    assert captured["checkpoint_directory"] is None
    assert captured["history_path"] is None
    assert json.loads(capsys.readouterr().out)["verification_mode"] == (
        "public_only_reconstructive"
    )
