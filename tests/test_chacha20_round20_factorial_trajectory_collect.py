from __future__ import annotations

import ast
import importlib.util
import json
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import zstandard

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "research/experiments/chacha20_round20_factorial_trajectory_collect.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load(SOURCE, "a220_factorial_collector_test")


@pytest.fixture(scope="module")
def protocol() -> dict[str, Any]:
    return MODULE._load_protocol()


@pytest.fixture(scope="module")
def design(protocol: dict[str, Any]):
    return _load(ROOT / protocol["anchors"]["factorial_design_path"], "a220_collector_design_test")


@pytest.fixture(scope="module")
def rows(protocol: dict[str, Any], design) -> list[dict[str, Any]]:
    return MODULE._factorial_rows(protocol, design)


@pytest.fixture(scope="module")
def orders(protocol: dict[str, Any], design) -> dict[str, list[str]]:
    return MODULE._operator_orders(protocol, design)


def _fake_prepared(protocol: dict[str, Any], tmp_path: Path) -> dict[str, Any]:
    public = _load(
        ROOT / protocol["anchors"]["public_core_adapter_path"],
        f"a220_collector_public_test_{tmp_path.name}",
    )
    template = _load(
        ROOT / protocol["anchors"]["symbolic_template_path"],
        f"a220_collector_template_test_{tmp_path.name}",
    )
    directory = tmp_path / "work"
    directory.mkdir(parents=True, exist_ok=True)
    helper = directory / "fake_content_addressed_helper"
    helper.write_bytes(b"solver-free fake helper")
    base_raw = b"p cnf 4096 0\n"
    template_config = json.loads(
        (ROOT / protocol["anchors"]["symbolic_template_protocol_path"]).read_bytes()
    )["symbolic_R20_template"]
    helper_sha256 = protocol["anchors"]["retained_native_binary_sha256"]
    stable_build = {
        "returncode": 0,
        "environment": {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
        "stdout_sha256": MODULE._sha256(b""),
        "stderr_sha256": MODULE._sha256(b""),
        "source_sha256_started": protocol["anchors"]["retained_native_source_sha256"],
        "source_sha256_finished": protocol["anchors"]["retained_native_source_sha256"],
        "compiler_sha256": "11" * 32,
        "cadical_header_sha256": "22" * 32,
        "cadical_library_sha256": "33" * 32,
        "temporary_binary_sha256": helper_sha256,
        "binary_sha256": helper_sha256,
        "content_addressed_binary": True,
    }
    return {
        "public_module": public,
        "template_module": template,
        "public_template": public.validate_public_template(protocol["public_only_R20_material"]),
        "base_raw": base_raw,
        "key_mapping": list(template_config["key_one_literals_bit0_through_bit19"]),
        "output_mapping": [list(range(100 + lane * 32, 132 + lane * 32)) for lane in range(16)],
        "template_manifest": {
            "formula_sha256": template_config["formula_sha256"],
            "base_cnf_sha256": template_config["base_sha256"],
            "base_body_sha256": template_config["base_body_sha256"],
            "mapping_probe_count": template_config["mapping_export_count"],
            "key_mapping_sha256": MODULE._sha256(
                b"".join(
                    int(value).to_bytes(4, "little", signed=True)
                    for value in template_config["key_one_literals_bit0_through_bit19"]
                )
            ),
            "output_mapping_sha256": template_config["output_one_literal_matrix_sha256"],
            "all_mapping_probes_exact_unit_deltas": True,
        },
        "helper_path": helper,
        "helper_sha256": helper_sha256,
        "native_helper_build": {**stable_build, "elapsed_seconds": 0.125},
        "native_helper_stable_provenance": stable_build,
        "directory": directory,
        "source_anchor_hashes_started": MODULE._verify_source_anchors(protocol),
        "public_core_provenance": public.provenance(),
    }


class _FakeRunner:
    def __init__(
        self,
        module,
        protocol: dict[str, Any],
        prepared: dict[str, Any],
        *,
        fail_mode_once: str | None = None,
    ):
        self.module = module
        self.protocol = protocol
        self.prepared = prepared
        self.fail_mode_once = fail_mode_once
        self.failed = False
        self.calls: list[str] = []
        self.active = 0
        self.maximum_active = 0
        self.lock = threading.Lock()

    def __call__(
        self,
        *,
        helper: Path,
        cnf: Path,
        mode: str,
        order: list[str],
        key_one_literals_bit0_through_bit19: list[int],
        conflict_horizons: list[int],
        watchdog_seconds: float,
        external_timeout_seconds: float,
    ) -> dict[str, Any]:
        assert helper == self.prepared["helper_path"]
        assert cnf.name == "a220_current_key_block0.cnf"
        assert key_one_literals_bit0_through_bit19 == self.prepared["key_mapping"]
        assert watchdog_seconds == 5.0
        assert external_timeout_seconds == 120.0 + 256.0 * len(conflict_horizons) * 5.0
        with self.lock:
            self.calls.append(mode)
            self.active += 1
            self.maximum_active = max(self.maximum_active, self.active)
            should_fail = mode == self.fail_mode_once and not self.failed
            if should_fail:
                self.failed = True
        try:
            if should_fail:
                time.sleep(0.001)
                raise RuntimeError("intentional solver-free fake failure")
            if (
                self.fail_mode_once is not None
                and mode != self.fail_mode_once
                and len(self.calls) <= 2
            ):
                time.sleep(0.02)
            else:
                time.sleep(0.001)
            stages = []
            cells = []
            metrics = [0, 0, 0]
            states = {
                "active_variables": 1000,
                "irredundant_clauses": 2000,
                "redundant_clauses": 3000,
            }
            for cell_index, prefix in enumerate(order):
                cell_metrics_before = list(metrics)
                cell_states_before = dict(states)
                assumptions = [
                    variable if bit == "1" else -variable
                    for bit, variable in zip(
                        prefix,
                        [self.prepared["key_mapping"][bit] for bit in range(19, 11, -1)],
                        strict=True,
                    )
                ]
                for stage_index, horizon in enumerate(conflict_horizons):
                    increment = horizon - (conflict_horizons[stage_index - 1] if stage_index else 0)
                    stage_metrics_before = list(metrics)
                    metrics = [
                        metrics[0] + increment,
                        metrics[1] + increment + (cell_index % 3),
                        metrics[2] + 10 * increment + (cell_index % 5),
                    ]
                    state_before = dict(states)
                    states = {
                        "active_variables": states["active_variables"],
                        "irredundant_clauses": states["irredundant_clauses"],
                        "redundant_clauses": states["redundant_clauses"] + 1,
                    }
                    stage = {
                        "mode": mode,
                        "prefix8": prefix,
                        "cell_index": cell_index,
                        "stage_index": stage_index,
                        "horizon": horizon,
                        "conflict_increment": increment,
                        "status": "unknown",
                        "returncode": 0,
                        "terminal": False,
                        "conflict_budget_exhausted": True,
                        "watchdog_fired": False,
                        "watchdog_seconds": watchdog_seconds,
                        "elapsed_seconds": 0.0001 * (stage_index + 1),
                        "assumptions": assumptions,
                        "failed_assumptions": [],
                        "model_bits_bit0_through_bit19": [],
                        "metric_names": list(MODULE.METRIC_NAMES),
                        "metrics_stage_before": stage_metrics_before,
                        "metrics_stage_after": list(metrics),
                        "metrics_stage_delta": MODULE._difference(metrics, stage_metrics_before),
                        "metrics_cell_before": cell_metrics_before,
                        "metrics_cell_cumulative_delta": MODULE._difference(
                            metrics, cell_metrics_before
                        ),
                    }
                    for stem in MODULE.STATE_STEMS:
                        stage[f"{stem}_stage_before"] = state_before[stem]
                        stage[f"{stem}_stage_after"] = states[stem]
                        stage[f"{stem}_stage_delta"] = states[stem] - state_before[stem]
                        stage[f"{stem}_cell_before"] = cell_states_before[stem]
                        stage[f"{stem}_cell_cumulative_delta"] = (
                            states[stem] - cell_states_before[stem]
                        )
                    stages.append(stage)
                cell = {
                    "mode": mode,
                    "prefix8": prefix,
                    "cell_index": cell_index,
                    "assumptions": assumptions,
                    "stages_run": len(conflict_horizons),
                    "final_status": "unknown",
                    "terminal_stage_index": None,
                    "watchdog_fires": 0,
                    "metric_names": list(MODULE.METRIC_NAMES),
                    "metrics_before": cell_metrics_before,
                    "metrics_after": list(metrics),
                    "metrics_delta": MODULE._difference(metrics, cell_metrics_before),
                }
                for stem in MODULE.STATE_STEMS:
                    cell[f"{stem}_before"] = cell_states_before[stem]
                    cell[f"{stem}_after"] = states[stem]
                    cell[f"{stem}_delta"] = states[stem] - cell_states_before[stem]
                cells.append(cell)
            expected_hashes = {
                "wrapper_sha256": self.protocol["anchors"]["retained_wrapper_sha256"],
                "source_sha256": self.protocol["anchors"]["retained_native_source_sha256"],
                "helper_sha256": self.prepared["helper_sha256"],
                "cnf_sha256": self.module._file_sha256(cnf),
            }
            return {
                "mode": mode,
                "order": order,
                "conflict_horizons": conflict_horizons,
                "watchdog_seconds_per_stage": watchdog_seconds,
                "stages": stages,
                "cells": cells,
                "summary": {
                    "signature": "cadical-3.0.0",
                    "version": "3.0.0",
                    "mode": mode,
                    "variables": 4096,
                    "cells": 256,
                    "conflict_horizons": conflict_horizons,
                    "configured_stages_per_nonterminal_cell": len(conflict_horizons),
                    "stages_emitted": len(stages),
                    "sat_cells": 0,
                    "unsat_cells": 0,
                    "unknown_cells": 256,
                    "watchdog_seconds": watchdog_seconds,
                    "watchdog_fires": 0,
                    "metric_names": list(MODULE.METRIC_NAMES),
                },
                "retained_state_continuity_verified": True,
                "all_watchdogs_clear": True,
                "environment": {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
                "launch_artifact_hashes_started": expected_hashes,
                "launch_artifact_hashes_finished": expected_hashes,
                "launch_identity_verified": True,
                "process_elapsed_seconds": 0.01,
                "stdout_sha256": self.module._sha256(mode.encode()),
                "stderr_sha256": self.module._sha256(b""),
                "helper_returncode": 0,
            }
        finally:
            with self.lock:
                self.active -= 1


def _paths(tmp_path: Path) -> dict[str, Path]:
    return {
        "shard_directory": tmp_path / "results/shards",
        "checkpoint_directory": tmp_path / "sealed/checkpoints",
        "volatile_directory": tmp_path / "sealed/volatile",
        "history_path": tmp_path / "sealed/attempts.jsonl",
    }


def _collect_one(
    *,
    protocol: dict[str, Any],
    design,
    row: dict[str, Any],
    orders: dict[str, list[str]],
    prepared: dict[str, Any],
    runner: _FakeRunner,
    paths: dict[str, Path],
) -> dict[str, Any]:
    return MODULE._collect_key(
        protocol=protocol,
        row=row,
        prepared=prepared,
        orders=orders,
        order_manifests=MODULE._order_manifests(design, orders),
        collector_sha256=MODULE._file_sha256(MODULE.ORCHESTRATOR),
        run_callable=runner,
        **paths,
    )


def test_protocol_public_only_boundary_and_exact_624_run_plan(
    protocol: dict[str, Any], design, rows: list[dict[str, Any]], orders: dict[str, list[str]]
) -> None:
    assert len(rows) == 52
    plan = MODULE._corpus_plan_identity(protocol, rows, orders)
    assert len(plan) == 624
    assert len({(item["key_label"], item["run_id"]) for item in plan}) == 624
    assert Counter(item["schedule"] for item in plan) == {
        "staged_retained_resolve": 312,
        "one_shot": 312,
    }
    assert MODULE._canonical_sha256(rows) == (
        "482b6f2c4f362b644bd1dc60ca7605203e15bf1e828244794f151f3b37110f7f"
    )
    anchors = MODULE._declared_source_anchor_hashes(protocol)
    assert all(not path.startswith("research/results/") for path in anchors)
    assert all(not path.endswith(".causal") for path in anchors)

    tree = ast.parse(SOURCE.read_text())
    analyze_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "analyze"
    ]
    assert analyze_calls == []
    attribute_calls = [
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    ]
    assert attribute_calls.count("compile_template") == 1
    assert attribute_calls.count("compile_helper") == 1
    assert 'anchors["A220P_result_path"]' not in SOURCE.read_text()

    public = _load(
        ROOT / protocol["anchors"]["public_core_adapter_path"], "a220_boundary_public_test"
    )
    challenge = public.build_known_challenge(
        protocol["public_only_R20_material"], low20=rows[0]["low20"]
    )
    assert not (public.SECRET_FIELDS & set(challenge))
    assert len(challenge["target_block_sha256"]) == 8
    assert public.provenance()["historical_result_or_causal_loader_present"] is False


def test_global_nonblocking_lock_rejects_second_holder(tmp_path: Path) -> None:
    lock = tmp_path / "a220.lock"
    with MODULE._exclusive_orchestrator_lock(lock):
        with pytest.raises(RuntimeError, match="global launch lock"):
            with MODULE._exclusive_orchestrator_lock(lock):
                pytest.fail("second A220 collector acquired the lock")


def test_zstd19_is_deterministic_and_tamper_detected(tmp_path: Path) -> None:
    payload = {"schema": "solver-free-compression-test", "values": list(range(4096))}
    raw = MODULE._canonical_bytes(payload)
    left = MODULE._compress_measurement(raw)
    right = MODULE._compress_measurement(raw)
    assert left == right
    assert MODULE._decompress_measurement(left) == raw
    frame = zstandard.get_frame_parameters(left)
    assert frame.has_checksum is True
    assert frame.content_size == len(raw)
    assert frame.dict_id == 0
    path = tmp_path / "payload.measurement.json.zst"
    MODULE._atomic_bytes(path, left)
    damaged = bytearray(path.read_bytes())
    damaged[len(damaged) // 2] ^= 1
    path.write_bytes(damaged)
    with pytest.raises(zstandard.ZstdError):
        MODULE._decompress_measurement(path.read_bytes())


def test_solver_free_key_collection_writes_full_stable_shard_and_verified_index(
    protocol: dict[str, Any],
    design,
    rows: list[dict[str, Any]],
    orders: dict[str, list[str]],
    tmp_path: Path,
) -> None:
    prepared = _fake_prepared(protocol, tmp_path)
    runner = _FakeRunner(MODULE, protocol, prepared)
    paths = _paths(tmp_path)
    metadata = _collect_one(
        protocol=protocol,
        design=design,
        row=rows[0],
        orders=orders,
        prepared=prepared,
        runner=runner,
        paths=paths,
    )
    assert len(runner.calls) == 12
    assert len(set(runner.calls)) == 12
    assert 1 <= runner.maximum_active <= 2
    assert not (prepared["directory"] / "a220_current_key_block0.cnf").exists()
    shard = paths["shard_directory"] / f"{rows[0]['label']}.measurement.json.zst"
    verified = MODULE._verify_shard(shard, expected_row=rows[0])
    assert verified["measurement_sha256"] == metadata["measurement_sha256"]
    payload = verified["payload"]
    assert len(payload["scientific_runs"]) == 12
    assert sum(len(run["cells"]) for run in payload["scientific_runs"].values()) == 3072
    assert sum(len(run["stages"]) for run in payload["scientific_runs"].values()) == (
        6 * 256 * 4 + 6 * 256
    )
    assert "elapsed_seconds" not in json.dumps(payload)
    assert "stdout_sha256" not in json.dumps(payload["scientific_runs"])
    volatile = json.loads(
        (paths["volatile_directory"] / f"{rows[0]['label']}.volatile.json").read_bytes()
    )
    assert len(volatile["runs"]) == 12
    assert all("stdout_sha256" in value for value in volatile["runs"].values())

    index = MODULE._rebuild_index(
        rows=rows,
        shard_directory=paths["shard_directory"],
        index_path=tmp_path / "results/index.json",
        collector_sha256=MODULE._file_sha256(MODULE.ORCHESTRATOR),
        source_anchor_hashes=prepared["source_anchor_hashes_started"],
        checkpoint_directory=paths["checkpoint_directory"],
        history_path=paths["history_path"],
    )
    assert index["completion_gates"]["verified_key_shards"] == 1
    assert index["completion_gates"]["verified_fresh_solver_processes"] == 12
    assert index["completion_gates"]["all_52_key_shards_complete"] is False

    original_compressed = shard.read_bytes()
    original_raw = MODULE._decompress_measurement(original_compressed)
    checkpoint_path = paths["checkpoint_directory"] / f"{rows[0]['label']}.checkpoint.json"
    original_checkpoint = checkpoint_path.read_bytes()
    semantically_changed = json.loads(original_raw)
    first_run_id, first_run = next(iter(semantically_changed["scientific_runs"].items()))

    def offset_metric_origin(measurement: dict[str, Any]) -> None:
        for stage in measurement["stages"]:
            for field in (
                "metrics_stage_before",
                "metrics_stage_after",
                "metrics_cell_before",
            ):
                stage[field][0] += 1
        for cell in measurement["cells"]:
            cell["metrics_before"][0] += 1
            cell["metrics_after"][0] += 1

    offset_metric_origin(first_run)
    coordinated_checkpoint = json.loads(original_checkpoint)
    coordinated_record = coordinated_checkpoint["completed_runs"][first_run_id]
    offset_metric_origin(coordinated_record["scientific_measurement"])
    coordinated_record["checkpoint_record_sha256"] = MODULE._canonical_sha256(
        {
            key: value
            for key, value in coordinated_record.items()
            if key != "checkpoint_record_sha256"
        }
    )
    checkpoint_path.write_bytes(
        json.dumps(coordinated_checkpoint, indent=2, sort_keys=True).encode() + b"\n"
    )
    shard.write_bytes(MODULE._compress_measurement(MODULE._canonical_bytes(semantically_changed)))
    with pytest.raises(RuntimeError, match="shard/checkpoint run binding differs"):
        MODULE._verify_shard(
            shard,
            expected_row=rows[0],
            protocol=protocol,
            orders=orders,
            order_manifests=MODULE._order_manifests(design, orders),
            expected_collector_sha256=MODULE._file_sha256(MODULE.ORCHESTRATOR),
            expected_source_anchor_hashes=prepared["source_anchor_hashes_started"],
            checkpoint_path=checkpoint_path,
            history_path=paths["history_path"],
        )
    checkpoint_path.write_bytes(original_checkpoint)

    assumptions_changed = json.loads(original_raw)
    first_measurement = next(iter(assumptions_changed["scientific_runs"].values()))
    first_measurement["stages"][0]["assumptions"][0] *= -1
    shard.write_bytes(MODULE._compress_measurement(MODULE._canonical_bytes(assumptions_changed)))
    with pytest.raises(RuntimeError, match="reconstructed stage identity failed"):
        MODULE._verify_shard(shard, expected_row=rows[0])

    model_changed = json.loads(original_raw)
    next(iter(model_changed["scientific_runs"].values()))["stages"][0][
        "model_bits_bit0_through_bit19"
    ] = [0] * 20
    shard.write_bytes(MODULE._compress_measurement(MODULE._canonical_bytes(model_changed)))
    with pytest.raises(RuntimeError, match="reconstructed stage identity failed"):
        MODULE._verify_shard(shard, expected_row=rows[0])

    summary_changed = json.loads(original_raw)
    next(iter(summary_changed["scientific_runs"].values()))["summary"]["unbound_extra"] = 1
    shard.write_bytes(MODULE._compress_measurement(MODULE._canonical_bytes(summary_changed)))
    with pytest.raises(RuntimeError, match="reconstructed summary failed"):
        MODULE._verify_shard(shard, expected_row=rows[0])

    relabeled = json.loads(original_raw)
    relabeled["evidence_stage"] = "UNSEALED_LABEL"
    shard.write_bytes(MODULE._compress_measurement(MODULE._canonical_bytes(relabeled)))
    with pytest.raises(RuntimeError, match="measurement shard completion gate failed"):
        MODULE._verify_shard(shard, expected_row=rows[0])
    wrong_frame = zstandard.ZstdCompressor(
        level=1,
        write_checksum=False,
        write_content_size=True,
        write_dict_id=False,
    ).compress(original_raw)
    shard.write_bytes(wrong_frame)
    with pytest.raises(RuntimeError, match="canonical/zstd-19 frame gate failed"):
        MODULE._verify_shard(shard, expected_row=rows[0])
    shard.write_bytes(original_compressed)

    # If durable history says a run completed but its checkpoint and shard are
    # removed, fail closed instead of silently rerunning the completed process.
    shard.unlink()
    (paths["checkpoint_directory"] / f"{rows[0]['label']}.checkpoint.json").unlink()
    calls_before = len(runner.calls)
    with pytest.raises(RuntimeError, match="checkpoint is missing; reexecution refused"):
        _collect_one(
            protocol=protocol,
            design=design,
            row=rows[0],
            orders=orders,
            prepared=prepared,
            runner=runner,
            paths=paths,
        )
    assert len(runner.calls) == calls_before


def test_failure_tombstone_and_outcome_independent_resume_never_rerun_completed(
    protocol: dict[str, Any],
    design,
    rows: list[dict[str, Any]],
    orders: dict[str, list[str]],
    tmp_path: Path,
) -> None:
    prepared = _fake_prepared(protocol, tmp_path)
    row = rows[1]
    first_mode = MODULE._run_plan(protocol, row, orders)[0]["mode"]
    runner = _FakeRunner(MODULE, protocol, prepared, fail_mode_once=first_mode)
    paths = _paths(tmp_path)
    with pytest.raises(RuntimeError, match="intentional solver-free fake failure"):
        _collect_one(
            protocol=protocol,
            design=design,
            row=row,
            orders=orders,
            prepared=prepared,
            runner=runner,
            paths=paths,
        )
    events_after_failure = MODULE._read_attempt_history(paths["history_path"])
    tombstones = [
        event for event in events_after_failure if event["event_type"] == "run_attempt_tombstone"
    ]
    assert len(tombstones) == 1
    assert tombstones[0]["exception_message_sha256"] == MODULE._sha256(
        b"intentional solver-free fake failure"
    )
    assert tombstones[0]["returncode"] is None
    assert tombstones[0]["returncode_available"] is False
    assert set(tombstones[0]["artifact_hashes_finished"]) == {
        "collector_sha256",
        "protocol_sha256",
        "wrapper_sha256",
        "source_sha256",
        "helper_sha256",
        "cnf_sha256",
    }
    checkpoint = json.loads(
        (paths["checkpoint_directory"] / f"{row['label']}.checkpoint.json").read_bytes()
    )
    completed_first_invocation = set(checkpoint["completed_runs"])
    assert len(completed_first_invocation) == 1

    _collect_one(
        protocol=protocol,
        design=design,
        row=row,
        orders=orders,
        prepared=prepared,
        runner=runner,
        paths=paths,
    )
    counts = Counter(runner.calls)
    assert counts[first_mode] == 2
    for run_id in completed_first_invocation:
        mode = next(
            spec["mode"]
            for spec in MODULE._run_plan(protocol, row, orders)
            if spec["run_id"] == run_id
        )
        assert counts[mode] == 1
    assert sum(counts.values()) == 13
    events = MODULE._read_attempt_history(paths["history_path"])
    starts = [
        event
        for event in events
        if event["event_type"] == "run_attempt_started"
        and event["run_id"] == MODULE._run_plan(protocol, row, orders)[0]["run_id"]
    ]
    assert [event["attempt_number"] for event in starts] == [1, 2]
    assert starts[0]["retry_claim"]["is_retry"] is False
    assert starts[1]["retry_claim"]["is_retry"] is True
    assert starts[1]["retry_claim"]["derived_from_prior_started_attempts"] == 1
    assert (
        MODULE._verify_shard(
            paths["shard_directory"] / f"{row['label']}.measurement.json.zst",
            expected_row=row,
        )["payload"]["completion_gates"]["all_12_runs_complete"]
        is True
    )


def test_attempt_history_and_shard_tampering_fail_closed(
    protocol: dict[str, Any], tmp_path: Path
) -> None:
    history = tmp_path / "attempts.jsonl"
    MODULE._append_attempt_event(
        history,
        {
            "event_type": "run_attempt_started",
            "protocol_sha256": MODULE.PROTOCOL_SHA256,
            "key_label": "fake",
            "run_id": "fake",
            "attempt_number": 1,
            "attempt_id": "00" * 32,
        },
    )
    raw = bytearray(history.read_bytes())
    raw[raw.index(b"fake")] = ord("g")
    history.write_bytes(raw)
    with pytest.raises(RuntimeError, match="history chain differs"):
        MODULE._read_attempt_history(history)

    assert MODULE._load_protocol()["anchors"] == protocol["anchors"]


def test_checkpoint_commit_failure_cannot_leak_tombstoned_record_into_later_commit(
    protocol: dict[str, Any],
    design,
    rows: list[dict[str, Any]],
    orders: dict[str, list[str]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _fake_prepared(protocol, tmp_path)
    row = rows[2]
    runner = _FakeRunner(MODULE, protocol, prepared)
    paths = _paths(tmp_path)
    original_atomic_json = MODULE._atomic_json
    injected = {"done": False}

    def fail_first_checkpoint(path: Path, value: Any, *, private: bool = False) -> None:
        if (
            not injected["done"]
            and path.name.endswith(".checkpoint.json")
            and len(value.get("completed_runs", {})) == 1
        ):
            injected["done"] = True
            raise OSError("injected pre-durable checkpoint failure")
        original_atomic_json(path, value, private=private)

    monkeypatch.setattr(MODULE, "_atomic_json", fail_first_checkpoint)
    with pytest.raises(OSError, match="pre-durable checkpoint failure"):
        _collect_one(
            protocol=protocol,
            design=design,
            row=row,
            orders=orders,
            prepared=prepared,
            runner=runner,
            paths=paths,
        )
    events = MODULE._read_attempt_history(paths["history_path"])
    checkpoint = json.loads(
        (paths["checkpoint_directory"] / f"{row['label']}.checkpoint.json").read_bytes()
    )
    tombstone = next(event for event in events if event["event_type"] == "run_attempt_tombstone")
    assert tombstone["reason"] == "completed_record_checkpoint_commit_failed_before_durability"
    assert tombstone["returncode"] == 0
    assert tombstone["run_id"] not in checkpoint["completed_runs"]
    durable_before_resume = set(checkpoint["completed_runs"])
    assert len(durable_before_resume) == 1

    monkeypatch.setattr(MODULE, "_atomic_json", original_atomic_json)
    _collect_one(
        protocol=protocol,
        design=design,
        row=row,
        orders=orders,
        prepared=prepared,
        runner=runner,
        paths=paths,
    )
    counts = Counter(runner.calls)
    assert sum(counts.values()) == 13
    plan = MODULE._run_plan(protocol, row, orders)
    for run_id in durable_before_resume:
        mode = next(spec["mode"] for spec in plan if spec["run_id"] == run_id)
        assert counts[mode] == 1


def test_completion_append_failure_recovers_from_checkpoint_without_tombstone_or_rerun(
    protocol: dict[str, Any],
    design,
    rows: list[dict[str, Any]],
    orders: dict[str, list[str]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _fake_prepared(protocol, tmp_path)
    row = rows[3]
    runner = _FakeRunner(MODULE, protocol, prepared)
    paths = _paths(tmp_path)
    original_append_completion = MODULE._append_completion
    injected = {"done": False, "attempt_id": None}

    def fail_first_completion(*args, **kwargs):
        if not injected["done"]:
            injected["done"] = True
            injected["attempt_id"] = kwargs["attempt"]["attempt_id"]
            raise OSError("injected post-checkpoint completion append failure")
        return original_append_completion(*args, **kwargs)

    monkeypatch.setattr(MODULE, "_append_completion", fail_first_completion)
    with pytest.raises(OSError, match="post-checkpoint completion append failure"):
        _collect_one(
            protocol=protocol,
            design=design,
            row=row,
            orders=orders,
            prepared=prepared,
            runner=runner,
            paths=paths,
        )
    checkpoint = json.loads(
        (paths["checkpoint_directory"] / f"{row['label']}.checkpoint.json").read_bytes()
    )
    assert len(checkpoint["completed_runs"]) == 2
    events = MODULE._read_attempt_history(paths["history_path"])
    assert not any(
        event["event_type"] == "run_attempt_tombstone"
        and event.get("attempt_id") == injected["attempt_id"]
        for event in events
    )

    monkeypatch.setattr(MODULE, "_append_completion", original_append_completion)
    _collect_one(
        protocol=protocol,
        design=design,
        row=row,
        orders=orders,
        prepared=prepared,
        runner=runner,
        paths=paths,
    )
    assert len(runner.calls) == 12
    events = MODULE._read_attempt_history(paths["history_path"])
    recovered = [
        event
        for event in events
        if event["event_type"] == "run_attempt_completed"
        and event.get("attempt_id") == injected["attempt_id"]
    ]
    assert len(recovered) == 1
    assert recovered[0]["completion_recovered_from_checkpoint"] is True


@pytest.mark.parametrize(
    "failure_mode",
    ("reconfirm_failure", "exception_readback_failure", "success_readback_failure"),
)
def test_ambiguous_checkpoint_commit_leaves_open_attempt_for_resume(
    protocol: dict[str, Any],
    design,
    rows: list[dict[str, Any]],
    orders: dict[str, list[str]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
) -> None:
    prepared = _fake_prepared(protocol, tmp_path)
    row = rows[4]
    runner = _FakeRunner(MODULE, protocol, prepared)
    paths = _paths(tmp_path)
    original_atomic_json = MODULE._atomic_json
    original_reconfirm = MODULE._fsync_existing_file_and_parent
    original_read_bytes = Path.read_bytes
    injected: dict[str, Any] = {
        "write": False,
        "reconfirm": False,
        "readback": False,
        "run_id": None,
    }

    def replace_then_raise(path: Path, value: Any, *, private: bool = False) -> None:
        if (
            not injected["write"]
            and path.name.endswith(".checkpoint.json")
            and len(value.get("completed_runs", {})) == 1
        ):
            injected["write"] = True
            injected["run_id"] = next(iter(value["completed_runs"]))
            original_atomic_json(path, value, private=private)
            if failure_mode != "success_readback_failure":
                raise OSError("injected visible post-replace checkpoint failure")
            return
        original_atomic_json(path, value, private=private)

    def fail_reconfirmation(path: Path) -> None:
        if failure_mode == "reconfirm_failure" and not injected["reconfirm"]:
            injected["reconfirm"] = True
            raise OSError("injected parent fsync reconfirmation failure")
        original_reconfirm(path)

    def fail_checkpoint_readback(path: Path) -> bytes:
        if (
            failure_mode in {"exception_readback_failure", "success_readback_failure"}
            and not injected["readback"]
            and path.name.endswith(".checkpoint.json")
        ):
            injected["readback"] = True
            raise OSError("injected transient checkpoint readback failure")
        return original_read_bytes(path)

    monkeypatch.setattr(MODULE, "_atomic_json", replace_then_raise)
    monkeypatch.setattr(MODULE, "_fsync_existing_file_and_parent", fail_reconfirmation)
    monkeypatch.setattr(Path, "read_bytes", fail_checkpoint_readback)
    with pytest.raises(
        RuntimeError,
        match="durability reconfirmation failed|checkpoint state unreadable",
    ):
        _collect_one(
            protocol=protocol,
            design=design,
            row=row,
            orders=orders,
            prepared=prepared,
            runner=runner,
            paths=paths,
        )
    run_id = injected["run_id"]
    assert isinstance(run_id, str)
    events = MODULE._read_attempt_history(paths["history_path"])
    run_events = [event for event in events if event.get("run_id") == run_id]
    assert [event["event_type"] for event in run_events] == ["run_attempt_started"]
    checkpoint = json.loads(
        (paths["checkpoint_directory"] / f"{row['label']}.checkpoint.json").read_bytes()
    )
    assert run_id in checkpoint["completed_runs"]

    monkeypatch.setattr(MODULE, "_atomic_json", original_atomic_json)
    monkeypatch.setattr(MODULE, "_fsync_existing_file_and_parent", original_reconfirm)
    monkeypatch.setattr(Path, "read_bytes", original_read_bytes)
    _collect_one(
        protocol=protocol,
        design=design,
        row=row,
        orders=orders,
        prepared=prepared,
        runner=runner,
        paths=paths,
    )
    plan = MODULE._run_plan(protocol, row, orders)
    recovered_mode = next(spec["mode"] for spec in plan if spec["run_id"] == run_id)
    assert Counter(runner.calls)[recovered_mode] == 1
    assert len(runner.calls) == 13
    recovered = [
        event
        for event in MODULE._read_attempt_history(paths["history_path"])
        if event.get("run_id") == run_id and event["event_type"] == "run_attempt_completed"
    ]
    assert len(recovered) == 1
    assert recovered[0]["completion_recovered_from_checkpoint"] is True


def test_unterminated_attempt_history_tail_is_preserved_and_recovered_append_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    history = tmp_path / "attempts.jsonl"
    MODULE._append_attempt_event(
        history,
        {
            "event_type": "test_anchor",
            "protocol_sha256": MODULE.PROTOCOL_SHA256,
        },
    )
    fragment = b'{"schema":"torn-final-record"'
    with history.open("ab") as handle:
        handle.write(fragment)
        handle.flush()
    torn_bytes = history.read_bytes()
    original_atomic_bytes = MODULE._atomic_bytes

    def fail_before_recovery(*args, **kwargs):
        raise OSError("injected pre-atomic tail recovery failure")

    monkeypatch.setattr(MODULE, "_atomic_bytes", fail_before_recovery)
    with pytest.raises(OSError, match="pre-atomic tail recovery failure"):
        MODULE._read_attempt_history(history)
    assert history.read_bytes() == torn_bytes
    monkeypatch.setattr(MODULE, "_atomic_bytes", original_atomic_bytes)
    events = MODULE._read_attempt_history(history)
    assert len(events) == 2
    recovery = events[-1]
    assert recovery["event_type"] == "attempt_history_torn_tail_recovery"
    assert recovery["recovered_fragment_sha256"] == MODULE._sha256(fragment)
    assert fragment in history.read_bytes()
    MODULE._append_attempt_event(
        history,
        {
            "event_type": "test_after_recovery",
            "protocol_sha256": MODULE.PROTOCOL_SHA256,
        },
    )
    assert [event["event_index"] for event in MODULE._read_attempt_history(history)] == [0, 1, 2]


def test_open_started_attempt_gets_interruption_tombstone_before_fixed_retry(
    protocol: dict[str, Any],
    rows: list[dict[str, Any]],
    orders: dict[str, list[str]],
    tmp_path: Path,
) -> None:
    row = rows[4]
    spec = MODULE._run_plan(protocol, row, orders)[0]
    history = tmp_path / "attempts.jsonl"
    first = MODULE._begin_attempt(
        history_path=history,
        row=row,
        spec=spec,
        artifact_hashes={"test_sha256": "11" * 32},
    )
    MODULE._reconcile_attempt_history(
        history_path=history,
        row=row,
        plan=[spec],
        checkpoint={"completed_runs": {}},
        artifact_hashes={"test_sha256": "11" * 32},
    )
    second = MODULE._begin_attempt(
        history_path=history,
        row=row,
        spec=spec,
        artifact_hashes={"test_sha256": "11" * 32},
    )
    events = MODULE._read_attempt_history(history)
    tombstone = next(event for event in events if event["event_type"] == "run_attempt_tombstone")
    assert tombstone["attempt_id"] == first["attempt_id"]
    assert tombstone["reason"] == (
        "orchestrator_interruption_detected_before_outcome_independent_resume"
    )
    assert second["attempt_number"] == 2
    assert second["retry_claim"] == {
        "is_retry": True,
        "derived_from_prior_started_attempts": 1,
        "derived_from_prior_terminal_attempts": 1,
    }
