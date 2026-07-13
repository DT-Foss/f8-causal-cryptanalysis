from __future__ import annotations

import ast
import copy
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest
import zstandard

ROOT = Path(__file__).parents[1]
SOURCE = (
    ROOT / "research/experiments/chacha20_round20_factorial_trajectory_holdout_collect.py"
)
FIT_TEST_SOURCE = ROOT / "tests/test_chacha20_round20_factorial_trajectory_collect.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load(SOURCE, "a220_holdout_collector_test")
FIT_TEST = _load(FIT_TEST_SOURCE, "a220_holdout_fit_collector_fixture")


@pytest.fixture(scope="module")
def protocol() -> dict[str, Any]:
    return MODULE._load_protocol()


@pytest.fixture(scope="module")
def design(protocol: dict[str, Any]):
    return _load(
        ROOT / protocol["anchors"]["factorial_design_path"],
        "a220_holdout_design_test",
    )


@pytest.fixture(scope="module")
def rows(protocol: dict[str, Any], design) -> list[dict[str, Any]]:
    return MODULE._holdout_rows(protocol, design)


@pytest.fixture(scope="module")
def orders(protocol: dict[str, Any], design) -> dict[str, list[str]]:
    return MODULE._operator_orders(protocol, design)


def _identity(bundle: str) -> dict[str, Any]:
    return {
        "bundle_id": bundle,
        "feature_family": "P3_dense_cube",
        "readout_kind": "ridge_logistic",
        "ridge_lambda": 1.0,
        "run_count": 4 if bundle.endswith("__dual_schedule") else 2,
    }


def _reader(bundle: str = "numeric__staged_retained_resolve") -> dict[str, Any]:
    protocol = MODULE._load_protocol()
    identity = _identity(bundle)
    feature_count = 36

    def readout(label: str) -> dict[str, Any]:
        return {
            "kind": identity["readout_kind"],
            "feature_family": identity["feature_family"],
            "feature_names": [f"f{index}" for index in range(feature_count)],
            "means": [0.0] * feature_count,
            "scales": [1.0] * feature_count,
            "intercept": 0.0,
            "coefficients": [0.0] * feature_count,
            "ridge_lambda": identity["ridge_lambda"],
            "diagnostics": {"fixture": label},
        }

    if bundle.endswith("__dual_schedule"):
        geometry = bundle.removesuffix("__dual_schedule")
        constituents = {
            f"{geometry}__staged_retained_resolve": readout("staged"),
            f"{geometry}__one_shot": readout("one-shot"),
        }
    else:
        constituents = {bundle: readout("atomic")}
    input_manifest = [{"key_label": f"fixture_{index:02d}"} for index in range(52)]
    observed_grid = [{"candidate": index} for index in range(450)]
    return {
        "schema": MODULE.READER_SCHEMA,
        "attempt_id": MODULE.ATTEMPT_ID,
        "evidence_stage": "FULLROUND_R20_FACTORIAL_READER_FROZEN_BEFORE_HOLDOUT",
        "protocol_sha256": MODULE.PROTOCOL_SHA256,
        "reader_runner_sha256": protocol["anchors"][
            "factorial_trajectory_reader_runner_sha256"
        ],
        "reader_checkpoint_sha256": "10" * 32,
        "software_versions": {"python": "fixture", "numpy": "fixture", "scipy": "fixture"},
        "factorial_trajectory_reader_sha256": protocol["anchors"][
            "factorial_trajectory_reader_sha256"
        ],
        "ridge_backend_sha256": protocol["anchors"]["ridge_backend_sha256"],
        "collector_source_sha256": "11" * 32,
        "fit_select_index_sha256": "12" * 32,
        "fit_select_input_manifest": input_manifest,
        "fit_select_input_manifest_sha256": MODULE._canonical_sha256(input_manifest),
        "feature_matrix_sha256": {"fixture": "13" * 32},
        "fit_panel": {"keys": 32, "cell_rows": 8192},
        "selection_panel": {"keys": 20, "cell_rows": 5120},
        "grid_definition": {"atomic_models": 300, "bundle_rows": 450},
        "observed_candidate_grid": observed_grid,
        "selected_reader": {
            "selected_identity": identity,
            "selected_metrics": {"fixture": True},
            "selected_constituent_readouts": constituents,
            "selected_score_sha256": "ab" * 32,
            "candidate_grid_sha256": MODULE._canonical_sha256(observed_grid),
        },
        "selection_matched_null": {
            "seed_label": protocol["selection_matched_null"]["seed_label"],
            "permutation_pairs_sha256": protocol["selection_matched_null"][
                "permutation_pairs_sha256"
            ],
            "replicates": [{"replicate": index} for index in range(64)],
        },
        "information_boundary": {
            "fit_select_measurements_loaded": True,
            "holdout_measurements_loaded": False,
            "future_prospective_target_loaded": False,
            "target_labels_used_for_fit": "32_fit_prefix_labels_only",
            "target_labels_used_for_selection": "20_selection_prefix_labels_only",
            "suffix_specific_target_floor_or_key_suffix_feature_used": False,
            "reader_frozen_before_any_holdout_trajectory_process": True,
        },
        "completion_gates": {
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
        },
    }


def _write_reader(path: Path, bundle: str = "numeric__staged_retained_resolve") -> None:
    MODULE._atomic_json(path, _reader(bundle))


def _reader_hashes(path: Path, reader: dict[str, Any]) -> dict[str, str]:
    identity = reader["selected_reader"]["selected_identity"]
    readout = {
        "selected_identity": identity,
        "selected_constituent_readouts": reader["selected_reader"][
            "selected_constituent_readouts"
        ],
        "selected_score_sha256": reader["selected_reader"]["selected_score_sha256"],
    }
    return {
        "reader_artifact_sha256": MODULE._file_sha256(path),
        "selected_identity_sha256": MODULE._canonical_sha256(identity),
        "selected_readout_sha256": MODULE._canonical_sha256(readout),
    }


def test_exact_92_row_partition_original_order_and_panel_hashes(
    protocol: dict[str, Any], design, rows: list[dict[str, Any]]
) -> None:
    ledger = design.factorial_ledger()
    expected = [
        dict(row)
        for row in ledger
        if not (row["prefix_split"] in {"fit", "select"} and row["suffix_split"] == "fit")
    ]
    assert rows == expected
    assert len(rows) == 92
    assert MODULE._canonical_sha256(rows) == MODULE.HOLDOUT_ROWS_SHA256
    assert (
        MODULE._canonical_sha256([row["label"] for row in rows])
        == MODULE.HOLDOUT_LABEL_ORDER_SHA256
    )
    assert {
        "fit_by_confirm": sum(
            row["prefix_split"] == "fit" and row["suffix_split"] == "confirm" for row in rows
        ),
        "select_by_confirm": sum(
            row["prefix_split"] == "select" and row["suffix_split"] == "confirm"
            for row in rows
        ),
        "confirm_by_fit": sum(
            row["prefix_split"] == "confirm" and row["suffix_split"] == "fit" for row in rows
        ),
        "confirm_by_confirm": sum(
            row["prefix_split"] == "confirm" and row["suffix_split"] == "confirm"
            for row in rows
        ),
    } == protocol["factorial_design"]["holdout_panels"]


def test_atomic_and_dual_reader_map_to_exact_two_and_four_run_plans(
    orders: dict[str, list[str]], rows: list[dict[str, Any]]
) -> None:
    atomic = MODULE._selected_plan_template(
        _identity("reflected_gray8__one_shot"), orders
    )
    assert [(row["operator"], row["schedule"]) for row in atomic] == [
        ("reflected_gray8_forward", "one_shot"),
        ("reflected_gray8_reverse_same_anchor", "one_shot"),
    ]
    assert all(row["conflict_horizons"] == [64] for row in atomic)
    dual = MODULE._selected_plan_template(_identity("formula_gray8__dual_schedule"), orders)
    assert [(row["operator"], row["schedule"]) for row in dual] == [
        ("formula_gray8_forward", "staged_retained_resolve"),
        ("formula_gray8_reverse_same_anchor", "staged_retained_resolve"),
        ("formula_gray8_forward", "one_shot"),
        ("formula_gray8_reverse_same_anchor", "one_shot"),
    ]
    assert [row["conflict_horizons"] for row in dual] == [
        [8, 16, 32, 64],
        [8, 16, 32, 64],
        [64],
        [64],
    ]
    plan = MODULE._run_plan(rows[0], dual)
    assert all(row["mode"].startswith(f"A220_HOLDOUT_{rows[0]['label']}_") for row in plan)
    assert all(len(row["order"]) == 256 for row in plan)


def test_reader_authority_schema_mutation_and_old_path_refused(
    protocol: dict[str, Any], tmp_path: Path
) -> None:
    authoritative = tmp_path / "reader_freeze.json"
    _write_reader(authoritative)
    reader, hashes = MODULE._load_reader(
        protocol, reader_path=authoritative, required_path=authoritative
    )
    assert reader["selected_reader"]["selected_identity"]["run_count"] == 2
    assert hashes["reader_artifact_sha256"] == MODULE._file_sha256(authoritative)
    wrong = tmp_path / "reader_v1.json"
    _write_reader(wrong)
    with pytest.raises(RuntimeError, match="non-authoritative"):
        MODULE._load_reader(protocol, reader_path=wrong, required_path=authoritative)
    mutated = _reader()
    mutated["information_boundary"]["holdout_measurements_loaded"] = True
    MODULE._atomic_json(authoritative, mutated)
    with pytest.raises(RuntimeError, match="schema/completion/information"):
        MODULE._load_reader(protocol, reader_path=authoritative, required_path=authoritative)


def test_launch_manifest_freezes_atomically_before_prepare_and_refuses_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manifest = tmp_path / "launch_manifest.json"
    monkeypatch.setattr(MODULE, "LEGACY_SEALED_LAUNCH_MANIFEST", tmp_path / "legacy.json")
    value, digest = MODULE._freeze_launch_manifest(manifest, {"schema": "test", "fixed": True})
    assert value == {"schema": "test", "fixed": True}
    assert digest == MODULE._file_sha256(manifest)
    with pytest.raises(RuntimeError, match="differs"):
        MODULE._freeze_launch_manifest(manifest, {"schema": "test", "fixed": False})
    (tmp_path / "legacy.json").write_text('{"schema":"different"}')
    with pytest.raises(RuntimeError, match="legacy"):
        MODULE._freeze_launch_manifest(manifest, {"schema": "test", "fixed": True})


def test_source_contains_no_fit_select_output_or_prospective_target_loader() -> None:
    source = SOURCE.read_text()
    assert "chacha20_round20_factorial_trajectory_fit_select_v1/index.json" not in source
    assert "chacha20_round20_factorial_trajectory_fit_select_v1/shards" not in source
    tree = ast.parse(source)
    path_literals = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and "/" in node.value
    ]
    assert not any(
        "research/" in value and "prospective" in value.lower() for value in path_literals
    )
    assert "analyze_loader" not in source
    assert 'path.endswith(".causal")' in source


def test_zstd19_deterministic_roundtrip_and_tamper_detection(tmp_path: Path) -> None:
    raw = MODULE._canonical_bytes({"evidence_stage": "HOLDOUT", "values": list(range(512))})
    first = MODULE._compress_measurement(raw)
    second = MODULE._compress_measurement(raw)
    assert first == second
    assert MODULE._decompress_measurement(first) == raw
    path = tmp_path / "measurement.json.zst"
    MODULE._atomic_bytes(path, first)
    damaged = bytearray(path.read_bytes())
    damaged[len(damaged) // 2] ^= 1
    with pytest.raises(zstandard.ZstdError):
        MODULE._decompress_measurement(bytes(damaged))


def _fake_paths(tmp_path: Path) -> dict[str, Path]:
    return {
        "shard_directory": tmp_path / "results/shards",
        "checkpoint_directory": tmp_path / "sealed/checkpoints",
        "volatile_directory": tmp_path / "sealed/volatile",
        "history_path": tmp_path / "sealed/attempts.jsonl",
    }


def _collect_fake_atomic(
    *,
    protocol: dict[str, Any],
    design,
    row: dict[str, Any],
    orders: dict[str, list[str]],
    tmp_path: Path,
) -> dict[str, Any]:
    prepared = FIT_TEST._fake_prepared(protocol, tmp_path)
    runner = FIT_TEST._FakeRunner(FIT_TEST.MODULE, protocol, prepared)
    reader = _reader("numeric__staged_retained_resolve")
    reader_path = tmp_path / "reader_freeze.json"
    MODULE._atomic_json(reader_path, reader)
    reader_hashes = _reader_hashes(reader_path, reader)
    launch_manifest = {
        "reader_artifact_sha256": reader_hashes["reader_artifact_sha256"],
        "reader_frozen_before_holdout": True,
    }
    launch_path = tmp_path / "results/launch_manifest.json"
    MODULE._atomic_json(launch_path, launch_manifest)
    launch_sha = MODULE._file_sha256(launch_path)
    plan_template = MODULE._selected_plan_template(
        reader["selected_reader"]["selected_identity"], orders
    )
    selected_manifests = MODULE._selected_order_manifests(design, plan_template)
    paths = _fake_paths(tmp_path)
    metadata = MODULE._collect_key(
        protocol=protocol,
        row=row,
        prepared=prepared,
        plan_template=plan_template,
        selected_order_manifests=selected_manifests,
        collector_sha256=MODULE._file_sha256(MODULE.ORCHESTRATOR),
        collector_test_sha256=MODULE._file_sha256(MODULE.TEST_SOURCE),
        launch_manifest_sha256=launch_sha,
        launch_manifest_path=launch_path,
        reader_path=reader_path,
        reader=reader,
        reader_hashes=reader_hashes,
        run_callable=runner,
        **paths,
    )
    return {
        "prepared": prepared,
        "runner": runner,
        "reader": reader,
        "reader_path": reader_path,
        "reader_hashes": reader_hashes,
        "launch_manifest": launch_manifest,
        "launch_path": launch_path,
        "launch_sha": launch_sha,
        "plan_template": plan_template,
        "selected_manifests": selected_manifests,
        "paths": paths,
        "metadata": metadata,
    }


def _verify_fake(
    fixture: dict[str, Any],
    *,
    protocol: dict[str, Any],
    row: dict[str, Any],
    path: Path,
    bind_execution_state: bool = True,
) -> dict[str, Any]:
    return MODULE._verify_shard(
        path,
        expected_row=row,
        protocol=protocol,
        reader=fixture["reader"],
        reader_hashes=fixture["reader_hashes"],
        launch_manifest=fixture["launch_manifest"],
        launch_manifest_sha256=fixture["launch_sha"],
        plan_template=fixture["plan_template"],
        selected_order_manifests=fixture["selected_manifests"],
        expected_collector_sha256=MODULE._file_sha256(MODULE.ORCHESTRATOR),
        expected_collector_test_sha256=MODULE._file_sha256(MODULE.TEST_SOURCE),
        expected_source_anchor_hashes=fixture["prepared"]["source_anchor_hashes_started"],
        checkpoint_path=(
            fixture["paths"]["checkpoint_directory"] / f"{row['label']}.checkpoint.json"
            if bind_execution_state
            else None
        ),
        history_path=fixture["paths"]["history_path"] if bind_execution_state else None,
    )


def test_solver_free_atomic_collection_max2_no_rerun_and_public_or_sealed_verify(
    protocol: dict[str, Any],
    design,
    rows: list[dict[str, Any]],
    orders: dict[str, list[str]],
    tmp_path: Path,
) -> None:
    fixture = _collect_fake_atomic(
        protocol=protocol,
        design=design,
        row=rows[0],
        orders=orders,
        tmp_path=tmp_path,
    )
    runner = fixture["runner"]
    assert len(runner.calls) == 2
    assert len(set(runner.calls)) == 2
    assert 1 <= runner.maximum_active <= 2
    assert not (fixture["prepared"]["directory"] / "a220_current_key_block0.cnf").exists()
    shard = fixture["paths"]["shard_directory"] / f"{rows[0]['label']}.measurement.json.zst"
    sealed = _verify_fake(fixture, protocol=protocol, row=rows[0], path=shard)
    public = _verify_fake(
        fixture,
        protocol=protocol,
        row=rows[0],
        path=shard,
        bind_execution_state=False,
    )
    assert sealed["measurement_sha256"] == public["measurement_sha256"]
    assert sealed["measurement_sha256"] == fixture["metadata"]["measurement_sha256"]
    assert len(sealed["payload"]["scientific_runs"]) == 2
    assert sum(len(run["cells"]) for run in sealed["payload"]["scientific_runs"].values()) == 512
    calls_before = len(runner.calls)
    # A second execution sees both durable checkpoint records and launches no process.
    key_prepared = MODULE._prepare_key(
        protocol=protocol, prepared=fixture["prepared"], row=rows[0]
    )
    try:
        records = MODULE._execute_key_runs(
            protocol=protocol,
            row=rows[0],
            prepared=fixture["prepared"],
            key_prepared=key_prepared,
            plan=MODULE._run_plan(rows[0], fixture["plan_template"]),
            selected_order_manifests=fixture["selected_manifests"],
            checkpoint_path=fixture["paths"]["checkpoint_directory"]
            / f"{rows[0]['label']}.checkpoint.json",
            history_path=fixture["paths"]["history_path"],
            collector_sha256=MODULE._file_sha256(MODULE.ORCHESTRATOR),
            collector_test_sha256=MODULE._file_sha256(MODULE.TEST_SOURCE),
            launch_manifest_sha256=fixture["launch_sha"],
            reader_hashes=fixture["reader_hashes"],
            reader_path=fixture["reader_path"],
            launch_manifest_path=fixture["launch_path"],
            run_callable=runner,
        )
        assert len(records) == 2
    finally:
        Path(key_prepared["cnf_path"]).unlink(missing_ok=True)
    assert len(runner.calls) == calls_before


def test_reconstructive_shard_rejects_assumption_model_summary_history_and_checkpoint_tamper(
    protocol: dict[str, Any],
    design,
    rows: list[dict[str, Any]],
    orders: dict[str, list[str]],
    tmp_path: Path,
) -> None:
    fixture = _collect_fake_atomic(
        protocol=protocol,
        design=design,
        row=rows[0],
        orders=orders,
        tmp_path=tmp_path,
    )
    shard = fixture["paths"]["shard_directory"] / f"{rows[0]['label']}.measurement.json.zst"
    original = shard.read_bytes()
    payload = json.loads(MODULE._decompress_measurement(original))

    def rejected(mutator, match: str, *, sealed: bool = False) -> None:
        changed = copy.deepcopy(payload)
        mutator(changed)
        shard.write_bytes(MODULE._compress_measurement(MODULE._canonical_bytes(changed)))
        with pytest.raises(RuntimeError, match=match):
            _verify_fake(
                fixture,
                protocol=protocol,
                row=rows[0],
                path=shard,
                bind_execution_state=sealed,
            )
        shard.write_bytes(original)

    rejected(
        lambda value: value["scientific_runs"][next(iter(value["scientific_runs"]))][
            "stages"
        ][0]["assumptions"].__setitem__(0, 999999),
        "reconstructed stage identity failed",
    )
    rejected(
        lambda value: value["scientific_runs"][next(iter(value["scientific_runs"]))][
            "stages"
        ][0].__setitem__("model_bits_bit0_through_bit19", [0] * 20),
        "reconstructed stage identity failed",
    )
    rejected(
        lambda value: value["scientific_runs"][next(iter(value["scientific_runs"]))][
            "summary"
        ].__setitem__("sat_cells", 999),
        "reconstructed summary failed",
    )
    rejected(
        lambda value: value["append_only_attempt_history_without_wallclock"][0][
            "retry_claim"
        ].__setitem__("is_retry", True),
        "stable attempt history failed",
    )

    checkpoint = fixture["paths"]["checkpoint_directory"] / f"{rows[0]['label']}.checkpoint.json"
    original_checkpoint = checkpoint.read_bytes()
    changed_checkpoint = json.loads(original_checkpoint)
    changed_checkpoint["reader_artifact_sha256"] = "00" * 32
    checkpoint.write_bytes(json.dumps(changed_checkpoint).encode())
    with pytest.raises(RuntimeError, match="checkpoint identity"):
        _verify_fake(fixture, protocol=protocol, row=rows[0], path=shard)
    checkpoint.write_bytes(original_checkpoint)


@pytest.mark.parametrize("commit_case", ["prewrite_absent", "postreplace_visible", "unreadable"])
def test_checkpoint_commit_ambiguity_is_fail_closed_and_resumable(
    commit_case: str,
    monkeypatch: pytest.MonkeyPatch,
    protocol: dict[str, Any],
    design,
    rows: list[dict[str, Any]],
    orders: dict[str, list[str]],
    tmp_path: Path,
) -> None:
    case_root = tmp_path / commit_case
    prepared = FIT_TEST._fake_prepared(protocol, case_root)
    runner = FIT_TEST._FakeRunner(FIT_TEST.MODULE, protocol, prepared)
    row = rows[0]
    reader = _reader()
    reader_path = case_root / "reader.json"
    MODULE._atomic_json(reader_path, reader)
    reader_hashes = _reader_hashes(reader_path, reader)
    launch_path = case_root / "launch.json"
    MODULE._atomic_json(launch_path, {"frozen": True})
    launch_sha = MODULE._file_sha256(launch_path)
    template = MODULE._selected_plan_template(reader["selected_reader"]["selected_identity"], orders)
    plan = MODULE._run_plan(row, template[:1])
    manifests = MODULE._selected_order_manifests(design, template[:1])
    key_prepared = MODULE._prepare_key(protocol=protocol, prepared=prepared, row=row)
    checkpoint = case_root / "checkpoint.json"
    history = case_root / "attempts.jsonl"
    original_atomic_json = MODULE._atomic_json
    tripped = False

    def failing_atomic(path: Path, value: Any, *, private: bool = False) -> None:
        nonlocal tripped
        if path != checkpoint or tripped:
            original_atomic_json(path, value, private=private)
            return
        tripped = True
        if commit_case == "postreplace_visible":
            original_atomic_json(path, value, private=private)
        elif commit_case == "unreadable":
            MODULE._atomic_bytes(path, b"{", private=True)
        raise OSError(f"injected {commit_case}")

    monkeypatch.setattr(MODULE, "_atomic_json", failing_atomic)

    def execute() -> dict[str, dict[str, Any]]:
        return MODULE._execute_key_runs(
            protocol=protocol,
            row=row,
            prepared=prepared,
            key_prepared=key_prepared,
            plan=plan,
            selected_order_manifests=manifests,
            checkpoint_path=checkpoint,
            history_path=history,
            collector_sha256=MODULE._file_sha256(MODULE.ORCHESTRATOR),
            collector_test_sha256=MODULE._file_sha256(MODULE.TEST_SOURCE),
            launch_manifest_sha256=launch_sha,
            reader_hashes=reader_hashes,
            reader_path=reader_path,
            launch_manifest_path=launch_path,
            run_callable=runner,
        )

    try:
        with pytest.raises((OSError, RuntimeError)):
            execute()
        assert len(runner.calls) == 1
        monkeypatch.setattr(MODULE, "_atomic_json", original_atomic_json)
        if commit_case == "unreadable":
            with pytest.raises((json.JSONDecodeError, RuntimeError)):
                execute()
            assert len(runner.calls) == 1
            checkpoint.unlink()
        completed = execute()
        assert set(completed) == {plan[0]["run_id"]}
        expected_calls = 1 if commit_case == "postreplace_visible" else 2
        assert len(runner.calls) == expected_calls
        run_events = MODULE._events_for_run(
            MODULE._read_attempt_history(history),
            key_label=row["label"],
            run_id=plan[0]["run_id"],
        )
        assert sum(event["event_type"] == "run_attempt_completed" for event in run_events) == 1
        expected_tombstones = 0 if commit_case == "postreplace_visible" else 1
        assert sum(event["event_type"] == "run_attempt_tombstone" for event in run_events) == (
            expected_tombstones
        )
    finally:
        Path(key_prepared["cnf_path"]).unlink(missing_ok=True)


def test_torn_attempt_history_tail_is_preserved_and_recovered(tmp_path: Path) -> None:
    path = tmp_path / "attempts.jsonl"
    MODULE._append_attempt_event(
        path,
        {
            "event_type": "synthetic_test_anchor",
            "protocol_sha256": MODULE.PROTOCOL_SHA256,
        },
    )
    original = path.read_bytes()
    fragment = b'{"unterminated":'
    path.write_bytes(original + fragment)
    events = MODULE._read_attempt_history(path)
    assert events[-1]["event_type"] == "attempt_history_torn_tail_recovery"
    assert events[-1]["recovered_fragment_sha256"] == MODULE._sha256(fragment)
    assert fragment in path.read_bytes()


def test_loader_supports_strict_local_and_public_only_modes_and_binds_index(
    monkeypatch: pytest.MonkeyPatch,
    protocol: dict[str, Any],
    design,
    rows: list[dict[str, Any]],
    orders: dict[str, list[str]],
    tmp_path: Path,
) -> None:
    reader_path = tmp_path / "reader_freeze.json"
    _write_reader(reader_path)
    reader, reader_hashes = MODULE._load_reader(
        protocol, reader_path=reader_path, required_path=reader_path
    )
    template = MODULE._selected_plan_template(reader["selected_reader"]["selected_identity"], orders)
    manifest = {"schema": "solver-free-loader-manifest"}
    results = tmp_path / "results"
    shards = results / "shards"
    shards.mkdir(parents=True)
    manifest_path = results / "launch_manifest.json"
    MODULE._atomic_json(manifest_path, manifest)
    fixed_metadata = {
        "measurement_sha256": "11" * 32,
        "measurement_bytes": 123,
        "compressed_sha256": "22" * 32,
        "compressed_bytes": 99,
    }
    entries = []
    for row in rows:
        shard = shards / f"{row['label']}.measurement.json.zst"
        shard.touch()
        entries.append(
            {
                "key_label": row["label"],
                "prefix_split": row["prefix_split"],
                "prefix_index": row["prefix_index"],
                "suffix_split": row["suffix_split"],
                "suffix_index": row["suffix_index"],
                "panel": f"{row['prefix_split']}_by_{row['suffix_split']}",
                "relative_path": f"shards/{shard.name}",
                **fixed_metadata,
            }
        )
    source_hashes = MODULE._verify_source_anchors(protocol)
    index = {
        "schema": MODULE.INDEX_SCHEMA,
        "attempt_id": MODULE.ATTEMPT_ID,
        "evidence_stage": MODULE.EVIDENCE_STAGE,
        "protocol_sha256": MODULE.PROTOCOL_SHA256,
        "launch_manifest_relative_path": "launch_manifest.json",
        "launch_manifest_sha256": MODULE._file_sha256(manifest_path),
        "reader_artifact_sha256": reader_hashes["reader_artifact_sha256"],
        "selected_reader_identity_sha256": reader_hashes["selected_identity_sha256"],
        "selected_reader_readout_sha256": reader_hashes["selected_readout_sha256"],
        "collector_source_sha256": MODULE._file_sha256(MODULE.ORCHESTRATOR),
        "collector_test_sha256": MODULE._file_sha256(MODULE.TEST_SOURCE),
        "source_anchor_hashes": source_hashes,
        "factorial_holdout_label_order_sha256": MODULE.HOLDOUT_LABEL_ORDER_SHA256,
        "selected_run_plan_template_sha256": MODULE._canonical_sha256(template),
        "verified_shards": entries,
        "completion_gates": {
            "verified_key_shards": 92,
            "expected_key_shards": 92,
            "selected_runs_per_key": 2,
            "verified_fresh_solver_processes": 184,
            "expected_fresh_solver_processes": 184,
            "no_failure_tombstones": True,
            "all_92_key_shards_complete": True,
            "all_selected_fresh_solver_processes_complete": True,
            "all_shards_decompressed_and_hash_verified": True,
            "global_index_rebuilt_from_verified_shards": True,
            "collector_source_unchanged": True,
            "reader_launch_and_source_hashes_unchanged": True,
        },
    }
    index_path = results / "index.json"
    MODULE._atomic_json(index_path, index)
    observed_execution_bindings: list[tuple[Path | None, Path | None]] = []

    def fake_verify(_path: Path, **kwargs: Any) -> dict[str, Any]:
        observed_execution_bindings.append(
            (kwargs["checkpoint_path"], kwargs["history_path"])
        )
        return {
            "payload": {"key_label": kwargs["expected_row"]["label"]},
            **fixed_metadata,
        }

    monkeypatch.setattr(MODULE, "_required_reader_path", lambda _protocol: reader_path)
    monkeypatch.setattr(MODULE, "_launch_manifest_candidate", lambda **_kwargs: manifest)
    monkeypatch.setattr(MODULE, "_verify_launch_binding", lambda **_kwargs: None)
    monkeypatch.setattr(MODULE, "_verify_shard", fake_verify)
    strict_checkpoint = tmp_path / "sealed/checkpoints"
    strict_history = tmp_path / "sealed/attempts.jsonl"
    loaded = MODULE.load_verified_holdout_corpus(
        index_path=index_path,
        shard_directory=shards,
        reader_path=reader_path,
        launch_manifest_path=manifest_path,
        checkpoint_directory=strict_checkpoint,
        history_path=strict_history,
    )
    assert len(loaded[0]) == len(loaded[1]) == 92
    assert all(checkpoint is not None and history == strict_history for checkpoint, history in observed_execution_bindings)
    observed_execution_bindings.clear()
    public = MODULE.load_verified_holdout_corpus(
        index_path=index_path,
        shard_directory=shards,
        reader_path=reader_path,
        launch_manifest_path=manifest_path,
        checkpoint_directory=None,
        history_path=None,
    )
    assert len(public[0]) == len(public[1]) == 92
    assert observed_execution_bindings == [(None, None)] * 92
    changed = copy.deepcopy(index)
    changed["launch_manifest_sha256"] = "00" * 32
    MODULE._atomic_json(index_path, changed)
    with pytest.raises(RuntimeError, match="completed index gate failed"):
        MODULE.load_verified_holdout_corpus(
            index_path=index_path,
            shard_directory=shards,
            reader_path=reader_path,
            launch_manifest_path=manifest_path,
            checkpoint_directory=None,
            history_path=None,
        )
