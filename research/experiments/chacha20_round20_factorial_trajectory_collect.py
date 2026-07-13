#!/usr/bin/env python3
"""Collect the frozen A220 fit/select trajectory corpus.

The collector is intentionally limited to explicit known calibration keys.  It
imports the public-only ChaCha20 adapter, never opens historical result/Causal
artifacts, and keeps the known low20 label out of solver order and budgets.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import zstandard

ROOT = Path(__file__).parents[2]
ORCHESTRATOR = Path(__file__).resolve()
PROTOCOL = ROOT / "research/configs/chacha20_round20_factorial_trajectory_transfer_v1.json"
PROTOCOL_SHA256 = "70df07cb4f4f22115e3aa63765de0fca0dd610607cc87356946a188f53fe5645"
OUTPUT_ROOT = ROOT / "research/results/v1/chacha20_round20_factorial_trajectory_fit_select_v1"
DEFAULT_SHARD_DIRECTORY = OUTPUT_ROOT / "shards"
DEFAULT_INDEX = OUTPUT_ROOT / "index.json"
SEALED_ROOT = ROOT / ".research_sealed/chacha20_round20_factorial_trajectory_fit_select_v1"
DEFAULT_ATTEMPT_HISTORY = SEALED_ROOT / "attempts.jsonl"
DEFAULT_CHECKPOINT_DIRECTORY = SEALED_ROOT / "checkpoints"
DEFAULT_VOLATILE_DIRECTORY = SEALED_ROOT / "volatile"
DEFAULT_LOCK = SEALED_ROOT / "orchestrator.lock"

ATTEMPT_ID = "A220"
SHARD_SCHEMA = "chacha20-round20-factorial-trajectory-fit-select-measurement-v1"
INDEX_SCHEMA = "chacha20-round20-factorial-trajectory-fit-select-index-v1"
CHECKPOINT_SCHEMA = "chacha20-round20-factorial-trajectory-fit-select-checkpoint-v1"
ATTEMPT_EVENT_SCHEMA = "chacha20-round20-factorial-trajectory-attempt-event-v1"
SCHEDULE_NAMES = ("staged_retained_resolve", "one_shot")
STABLE_STAGE_EXCLUSIONS = {"elapsed_seconds"}
ZSTD_VERSION = "0.25.0"
ZSTD_LEVEL = 19
METRIC_NAMES = ("conflicts", "decisions", "search_propagations")
STATE_STEMS = ("active_variables", "irredundant_clauses", "redundant_clauses")
STABLE_STAGE_FIELDS = {
    "mode",
    "prefix8",
    "cell_index",
    "stage_index",
    "horizon",
    "conflict_increment",
    "status",
    "returncode",
    "terminal",
    "conflict_budget_exhausted",
    "watchdog_fired",
    "watchdog_seconds",
    "assumptions",
    "failed_assumptions",
    "model_bits_bit0_through_bit19",
    "metric_names",
    "metrics_stage_before",
    "metrics_stage_after",
    "metrics_stage_delta",
    "metrics_cell_before",
    "metrics_cell_cumulative_delta",
    *{
        f"{stem}_{suffix}"
        for stem in STATE_STEMS
        for suffix in (
            "stage_before",
            "stage_after",
            "stage_delta",
            "cell_before",
            "cell_cumulative_delta",
        )
    },
}
STABLE_CELL_FIELDS = {
    "mode",
    "prefix8",
    "cell_index",
    "assumptions",
    "stages_run",
    "final_status",
    "terminal_stage_index",
    "watchdog_fires",
    "metric_names",
    "metrics_before",
    "metrics_after",
    "metrics_delta",
    *{f"{stem}_{suffix}" for stem in STATE_STEMS for suffix in ("before", "after", "delta")},
}
STABLE_SUMMARY_FIELDS = {
    "signature",
    "version",
    "mode",
    "variables",
    "cells",
    "conflict_horizons",
    "configured_stages_per_nonterminal_cell",
    "stages_emitted",
    "sat_cells",
    "unsat_cells",
    "unknown_cells",
    "watchdog_seconds",
    "watchdog_fires",
    "metric_names",
}

# Every runtime-read anchor is source or frozen configuration.  The A220P result
# anchor is intentionally absent: its interpretation is already byte-frozen in
# the A220 protocol and its historical payload must not enter this collector.
SOURCE_ANCHOR_PAIRS = (
    ("A220P_protocol_path", "A220P_protocol_sha256"),
    ("public_core_adapter_path", "public_core_adapter_sha256"),
    ("public_core_implementation_path", "public_core_implementation_sha256"),
    ("symbolic_template_path", "symbolic_template_sha256"),
    ("symbolic_template_protocol_path", "symbolic_template_protocol_sha256"),
    ("factorial_design_path", "factorial_design_sha256"),
    ("retained_wrapper_path", "retained_wrapper_sha256"),
    ("retained_native_source_path", "retained_native_source_sha256"),
    ("trajectory_readout_path", "trajectory_readout_sha256"),
    ("factorial_trajectory_reader_path", "factorial_trajectory_reader_sha256"),
    ("factorial_trajectory_reader_test_path", "factorial_trajectory_reader_test_sha256"),
    (
        "factorial_trajectory_reader_runner_path",
        "factorial_trajectory_reader_runner_sha256",
    ),
    (
        "factorial_trajectory_reader_runner_test_path",
        "factorial_trajectory_reader_runner_test_sha256",
    ),
    ("ridge_backend_path", "ridge_backend_sha256"),
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


def _atomic_json(path: Path, value: Any, *, private: bool = False) -> None:
    raw = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()
        + b"\n"
    )
    _atomic_bytes(path, raw, private=private)


def _atomic_bytes(path: Path, raw: bytes, *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    if private:
        temporary.chmod(0o600)
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _fsync_existing_file_and_parent(path: Path) -> None:
    """Establish durability after an atomic-replace call raised post-replace."""

    with path.open("rb") as handle:
        os.fsync(handle.fileno())
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A220 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_protocol() -> dict[str, Any]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A220 frozen protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    design = protocol.get("factorial_design", {})
    collection = protocol.get("fit_select_collection", {})
    shard = protocol.get("shard_protocol", {})
    compression = shard.get("compression", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != "chacha20-round20-factorial-trajectory-transfer-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A220P_and_before_any_A220_fit_select_solver_process_trajectory_measurement_model_fit_or_holdout_execution"
        or design.get("fit_select_rows") != 52
        or design.get("fit_rows") != 32
        or design.get("selection_rows") != 20
        or collection.get("runs_per_key") != 12
        or collection.get("total_fresh_solver_processes") != 624
        or collection.get("maximum_concurrent_solver_processes") != 2
        or collection.get("one_key_instantiated_CNF_active_at_a_time") is not True
        or collection.get("exclusive_orchestrator_lock") is not True
        or collection.get("schedules", {}).get("staged_retained_resolve") != [8, 16, 32, 64]
        or collection.get("schedules", {}).get("one_shot") != [64]
        or collection.get("watchdog_seconds_per_stage") != 5.0
        or collection.get("complete_prefix_cover_per_run") is not True
        or collection.get("early_stop") is not False
        or collection.get("failure_and_resume", {}).get(
            "fixed_outcome_independent_reexecution_of_an_incomplete_run_permitted"
        )
        is not True
        or collection.get("failure_and_resume", {}).get("completed_run_reexecution_permitted")
        is not False
        or shard.get("one_measurement_shard_per_key") is not True
        or compression
        != {
            "format": "zstd",
            "python_package_version": ZSTD_VERSION,
            "level": ZSTD_LEVEL,
            "threads": 0,
            "write_checksum": True,
            "write_content_size": True,
            "write_dict_id": False,
        }
        or boundary.get("historical_r20_analyze_loader_permitted") is not False
        or boundary.get("historical_result_causal_assignment_model_or_rank_file_loaded")
        is not False
        or boundary.get("holdout_measurements_available_during_fit_selection_or_null") is not False
        or boundary.get("future_prospective_target_generated_or_opened_in_A220") is not False
    ):
        raise RuntimeError("A220 frozen fit/select protocol semantic gate failed")
    return protocol


@contextmanager
def _exclusive_orchestrator_lock(path: Path = DEFAULT_LOCK):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        path.chmod(0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("another A220 collector holds the global launch lock") from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _declared_source_anchor_hashes(protocol: Mapping[str, Any]) -> dict[str, str]:
    anchors = protocol["anchors"]
    declared = {
        str(anchors[path_key]): str(anchors[hash_key]) for path_key, hash_key in SOURCE_ANCHOR_PAIRS
    }
    if any(path.startswith("research/results/") or path.endswith(".causal") for path in declared):
        raise RuntimeError("A220 source anchor set contains a forbidden historical artifact")
    return declared


def _verify_source_anchors(protocol: Mapping[str, Any]) -> dict[str, str]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A220 protocol changed during collection")
    declared = _declared_source_anchor_hashes(protocol)
    observed = {relative: _file_sha256(ROOT / relative) for relative in declared}
    if observed != declared:
        drift = {
            relative: observed.get(relative)
            for relative, expected in declared.items()
            if observed.get(relative) != expected
        }
        raise RuntimeError(f"A220 source anchor drift: {drift}")
    return observed


def _verify_self(expected_sha256: str) -> None:
    if _file_sha256(ORCHESTRATOR) != expected_sha256:
        raise RuntimeError("A220 collector source changed during execution")


def _factorial_rows(protocol: Mapping[str, Any], design: Any) -> list[dict[str, Any]]:
    ledger = design.factorial_ledger()
    forbidden = protocol["factorial_design"]["prior_key_exclusion"]["sorted_low20"]
    design.validate_factorial_ledger(ledger, forbidden_low20=forbidden)
    rows = [
        dict(row)
        for row in ledger
        if row["prefix_split"] in {"fit", "select"} and row["suffix_split"] == "fit"
    ]
    config = protocol["factorial_design"]
    if (
        design.ledger_sha256(ledger) != config["full_ledger_sha256"]
        or len(rows) != config["fit_select_rows"]
        or _canonical_sha256(rows) != config["fit_select_rows_sha256"]
        or _canonical_sha256([row["label"] for row in rows])
        != config["fit_select_label_order_sha256"]
        or sum(row["prefix_split"] == "fit" for row in rows) != config["fit_rows"]
        or sum(row["prefix_split"] == "select" for row in rows) != config["selection_rows"]
    ):
        raise RuntimeError("A220 fit/select factorial row gate failed")
    return rows


def _operator_orders(protocol: Mapping[str, Any], design: Any) -> dict[str, list[str]]:
    integer_orders = design.operator_orders()
    manifests = design.order_manifest()
    declared_names = protocol["fit_select_collection"]["orders"]
    if (
        list(integer_orders) != declared_names
        or _canonical_sha256(manifests)
        != protocol["factorial_design"]["operator_order_manifest_sha256"]
    ):
        raise RuntimeError("A220 factorial operator manifest differs")
    return {name: [f"{value:08b}" for value in integer_orders[name]] for name in declared_names}


def _order_manifests(design: Any, orders: Mapping[str, Sequence[str]]) -> dict[str, Any]:
    declared = design.order_manifest()
    result = {}
    for name, order in orders.items():
        values = [int(prefix, 2) for prefix in order]
        if (
            len(values) != 256
            or set(values) != set(range(256))
            or _sha256(bytes(values)) != declared[name]["sha256_uint8"]
        ):
            raise RuntimeError(f"A220 order is not the frozen factorial order: {name}")
        result[name] = dict(declared[name])
    return result


def _run_plan(
    protocol: Mapping[str, Any], row: Mapping[str, Any], orders: Mapping[str, Sequence[str]]
) -> list[dict[str, Any]]:
    schedules = protocol["fit_select_collection"]["schedules"]
    plan = []
    for operator, order in orders.items():
        for schedule in SCHEDULE_NAMES:
            plan.append(
                {
                    "run_id": f"{operator}__{schedule}",
                    "mode": f"A220_{row['label']}_{operator}_{schedule}",
                    "operator": operator,
                    "schedule": schedule,
                    "conflict_horizons": list(schedules[schedule]),
                    "order": list(order),
                    "order_uint8_sha256": _sha256(bytes(int(value, 2) for value in order)),
                }
            )
    if len(plan) != 12 or len({item["run_id"] for item in plan}) != 12:
        raise RuntimeError("A220 per-key plan is not twelve unique fresh processes")
    return plan


def _corpus_plan_identity(
    protocol: Mapping[str, Any], rows: Sequence[Mapping[str, Any]], orders: Mapping[str, Any]
) -> list[dict[str, Any]]:
    result = []
    for row in rows:
        for run in _run_plan(protocol, row, orders):
            result.append(
                {
                    "key_label": row["label"],
                    "run_id": run["run_id"],
                    "mode": run["mode"],
                    "operator": run["operator"],
                    "schedule": run["schedule"],
                    "conflict_horizons": run["conflict_horizons"],
                    "order_uint8_sha256": run["order_uint8_sha256"],
                }
            )
    expected = protocol["fit_select_collection"]["total_fresh_solver_processes"]
    if (
        len(result) != expected
        or len({(row["key_label"], row["run_id"]) for row in result}) != expected
    ):
        raise RuntimeError("A220 full fit/select plan is not exactly 624 unique runs")
    return result


def _stable_build_provenance(build: Mapping[str, Any]) -> dict[str, Any]:
    fields = (
        "returncode",
        "environment",
        "stdout_sha256",
        "stderr_sha256",
        "source_sha256_started",
        "source_sha256_finished",
        "compiler_sha256",
        "cadical_header_sha256",
        "cadical_library_sha256",
        "temporary_binary_sha256",
        "binary_sha256",
        "content_addressed_binary",
    )
    return {field: build[field] for field in fields}


def _prepare_real(
    protocol: Mapping[str, Any], rows: Sequence[Mapping[str, Any]], directory: Path
) -> dict[str, Any]:
    anchors = protocol["anchors"]
    source_hashes = _verify_source_anchors(protocol)
    public = _import_path(ROOT / anchors["public_core_adapter_path"], "a220_collect_public")
    template = _import_path(ROOT / anchors["symbolic_template_path"], "a220_collect_template")
    design = _import_path(ROOT / anchors["factorial_design_path"], "a220_collect_design")
    retained = _import_path(ROOT / anchors["retained_wrapper_path"], "a220_collect_retained")

    public_template = public.validate_public_template(protocol["public_only_R20_material"])
    if _canonical_sha256(public_template) != protocol["public_only_R20_material_sha256"]:
        raise RuntimeError("A220 public-only material hash differs")
    template_protocol = json.loads((ROOT / anchors["symbolic_template_protocol_path"]).read_bytes())
    reference = public.build_known_challenge(public_template, low20=int(rows[0]["low20"]))
    base_raw, key_mapping, output_mapping, template_manifest = template.compile_template(
        r20=public,
        public_challenge=reference,
        protocol=template_protocol,
        directory=directory,
    )
    build = retained.compile_helper()
    helper = Path(build["binary_path"])
    if (
        build["source_sha256_started"] != anchors["retained_native_source_sha256"]
        or build["source_sha256_finished"] != anchors["retained_native_source_sha256"]
        or build["binary_sha256"] != anchors["retained_native_binary_sha256"]
        or _file_sha256(helper) != anchors["retained_native_binary_sha256"]
    ):
        raise RuntimeError("A220 retained helper build gate failed")
    return {
        "public_module": public,
        "template_module": template,
        "design_module": design,
        "retained_module": retained,
        "public_template": public_template,
        "base_raw": base_raw,
        "key_mapping": key_mapping,
        "output_mapping": output_mapping,
        "template_manifest": template_manifest,
        "helper_path": helper,
        "helper_sha256": build["binary_sha256"],
        "native_helper_build": dict(build),
        "native_helper_stable_provenance": _stable_build_provenance(build),
        "run_callable": retained.run_multihorizon,
        "directory": directory,
        "source_anchor_hashes_started": source_hashes,
        "public_core_provenance": public.provenance(),
    }


def _prepare_key(
    *, protocol: Mapping[str, Any], prepared: Mapping[str, Any], row: Mapping[str, Any]
) -> dict[str, Any]:
    public = prepared["public_module"]
    template = prepared["template_module"]
    challenge = public.build_known_challenge(prepared["public_template"], low20=int(row["low20"]))
    raw, _, instantiation = template.instantiate_output(
        prepared["base_raw"], prepared["output_mapping"], challenge["target_words"][0]
    )
    cnf = Path(prepared["directory"]) / "a220_current_key_block0.cnf"
    if cnf.exists():
        raise RuntimeError("A220 one-key-at-a-time CNF gate found a prior active CNF")
    _atomic_bytes(cnf, raw, private=True)
    if _file_sha256(cnf) != instantiation["sha256"]:
        raise RuntimeError("A220 instantiated key CNF write/readback differs")

    public_material = prepared["public_template"]
    key_words = [
        int(public_material["known_key_word0_upper12"]) | int(row["low20"]),
        *[int(value) for value in public_material["known_key_words_1_through_7"]],
    ]
    confirmation = {
        "generated_block_count": 8,
        "generated_output_bits": 4096,
        "block_sha256": list(challenge["target_block_sha256"]),
        "all_block_hashes_unique": len(set(challenge["target_block_sha256"])) == 8,
        "full_key_words_little_endian_sha256": _sha256(
            b"".join(word.to_bytes(4, "little") for word in key_words)
        ),
        "formula_constrained_block_index": 0,
        "formula_constrained_output_bits": 512,
        "blocks_1_through_7_used_only_for_confirmation_metadata": True,
    }
    return {
        "cnf_path": cnf,
        "cnf_sha256": instantiation["sha256"],
        "instantiation_manifest": instantiation,
        "known_key_confirmation_metadata": confirmation,
    }


def _external_timeout(protocol: Mapping[str, Any], stage_count: int) -> float:
    watchdog = float(protocol["fit_select_collection"]["watchdog_seconds_per_stage"])
    return 120.0 + 256.0 * stage_count * watchdog


def _artifact_hashes(
    *, protocol: Mapping[str, Any], prepared: Mapping[str, Any], key_prepared: Mapping[str, Any]
) -> dict[str, str]:
    anchors = protocol["anchors"]
    paths = {
        "collector_sha256": ORCHESTRATOR,
        "protocol_sha256": PROTOCOL,
        "wrapper_sha256": ROOT / anchors["retained_wrapper_path"],
        "source_sha256": ROOT / anchors["retained_native_source_path"],
        "helper_sha256": Path(prepared["helper_path"]),
        "cnf_sha256": Path(key_prepared["cnf_path"]),
    }
    result = {}
    for name, path in paths.items():
        try:
            result[name] = _file_sha256(path)
        except OSError:
            result[name] = "MISSING"
    return result


def _expected_launch_hashes(
    protocol: Mapping[str, Any], prepared: Mapping[str, Any], key_prepared: Mapping[str, Any]
) -> dict[str, str]:
    return {
        "wrapper_sha256": protocol["anchors"]["retained_wrapper_sha256"],
        "source_sha256": protocol["anchors"]["retained_native_source_sha256"],
        "helper_sha256": prepared["helper_sha256"],
        "cnf_sha256": key_prepared["cnf_sha256"],
    }


def _scientific_run(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "mode": raw["mode"],
        "order": raw["order"],
        "conflict_horizons": raw["conflict_horizons"],
        "watchdog_seconds_per_stage": raw["watchdog_seconds_per_stage"],
        "stages": [
            {key: value for key, value in stage.items() if key not in STABLE_STAGE_EXCLUSIONS}
            for stage in raw["stages"]
        ],
        "cells": raw["cells"],
        "summary": raw["summary"],
        "retained_state_continuity_verified": raw["retained_state_continuity_verified"],
        "all_watchdogs_clear": raw["all_watchdogs_clear"],
        "helper_returncode": raw["helper_returncode"],
    }


def _stable_run_provenance(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "launch_artifact_hashes_started": raw["launch_artifact_hashes_started"],
        "launch_artifact_hashes_finished": raw["launch_artifact_hashes_finished"],
        "launch_identity_verified": raw["launch_identity_verified"],
        "environment": raw["environment"],
        "stderr_sha256": raw["stderr_sha256"],
        "helper_returncode": raw["helper_returncode"],
    }


def _volatile_run(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "process_elapsed_seconds": raw["process_elapsed_seconds"],
        "stage_elapsed_seconds": [stage["elapsed_seconds"] for stage in raw["stages"]],
        "stdout_sha256": raw["stdout_sha256"],
    }


def _record_run(
    *,
    raw: Mapping[str, Any],
    spec: Mapping[str, Any],
    protocol: Mapping[str, Any],
    prepared: Mapping[str, Any],
    key_prepared: Mapping[str, Any],
    attempt: Mapping[str, Any],
) -> dict[str, Any]:
    cells = raw.get("cells", [])
    expected_hashes = _expected_launch_hashes(protocol, prepared, key_prepared)
    if (
        raw.get("mode") != spec["mode"]
        or raw.get("order") != spec["order"]
        or raw.get("conflict_horizons") != spec["conflict_horizons"]
        or raw.get("watchdog_seconds_per_stage")
        != protocol["fit_select_collection"]["watchdog_seconds_per_stage"]
        or len(cells) != 256
        or [cell.get("prefix8") for cell in cells] != spec["order"]
        or raw.get("retained_state_continuity_verified") is not True
        or raw.get("all_watchdogs_clear") is not True
        or raw.get("helper_returncode") != 0
        or raw.get("launch_identity_verified") is not True
        or raw.get("launch_artifact_hashes_started") != expected_hashes
        or raw.get("launch_artifact_hashes_finished") != expected_hashes
    ):
        raise RuntimeError(f"A220 completed run gate failed: {spec['run_id']}")
    record = {
        "run_id": spec["run_id"],
        "operator": spec["operator"],
        "schedule": spec["schedule"],
        "fresh_solver_process": True,
        "attempt_id": attempt["attempt_id"],
        "attempt_number": attempt["attempt_number"],
        "scientific_measurement": _scientific_run(raw),
        "deterministic_artifact_provenance": _stable_run_provenance(raw),
        "volatile_observation": _volatile_run(raw),
    }
    record["checkpoint_record_sha256"] = _canonical_sha256(record)
    return record


def _checkpoint_identity(
    *,
    row: Mapping[str, Any],
    prepared: Mapping[str, Any],
    key_prepared: Mapping[str, Any],
    plan: Sequence[Mapping[str, Any]],
    order_manifests: Mapping[str, Any],
    collector_sha256: str,
) -> dict[str, Any]:
    plan_identity = [
        {
            key: run[key]
            for key in (
                "run_id",
                "mode",
                "operator",
                "schedule",
                "conflict_horizons",
                "order_uint8_sha256",
            )
        }
        for run in plan
    ]
    return {
        "schema": CHECKPOINT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "collector_source_sha256": collector_sha256,
        "key_factorial_identity_sha256": _canonical_sha256(row),
        "source_anchor_hashes": prepared["source_anchor_hashes_started"],
        "helper_sha256": prepared["helper_sha256"],
        "native_helper_stable_provenance_sha256": _canonical_sha256(
            prepared["native_helper_stable_provenance"]
        ),
        "base_cnf_sha256": prepared["template_manifest"]["base_cnf_sha256"],
        "symbolic_template_manifest_sha256": _canonical_sha256(prepared["template_manifest"]),
        "instantiated_cnf_sha256": key_prepared["cnf_sha256"],
        "instantiation_manifest_sha256": _canonical_sha256(key_prepared["instantiation_manifest"]),
        "known_key_confirmation_metadata_sha256": _canonical_sha256(
            key_prepared["known_key_confirmation_metadata"]
        ),
        "key_mapping_sha256": _canonical_sha256(prepared["key_mapping"]),
        "order_manifests_sha256": _canonical_sha256(order_manifests),
        "run_plan_sha256": _canonical_sha256(plan_identity),
    }


def _load_checkpoint(
    path: Path, *, identity: Mapping[str, Any], valid_run_ids: set[str]
) -> dict[str, Any]:
    if not path.exists():
        return {**identity, "completed_runs": {}}
    checkpoint = json.loads(path.read_bytes())
    if (
        set(checkpoint) != {*identity, "completed_runs"}
        or any(checkpoint.get(key) != value for key, value in identity.items())
        or not isinstance(checkpoint.get("completed_runs"), dict)
        or not set(checkpoint["completed_runs"]).issubset(valid_run_ids)
    ):
        raise RuntimeError("A220 per-key checkpoint identity differs")
    for run_id, record in checkpoint["completed_runs"].items():
        stored = record.get("checkpoint_record_sha256")
        unhashed = {
            key: value for key, value in record.items() if key != "checkpoint_record_sha256"
        }
        if record.get("run_id") != run_id or stored != _canonical_sha256(unhashed):
            raise RuntimeError(f"A220 checkpoint completed-run hash differs: {run_id}")
    return checkpoint


def _checkpoint_readback_state(
    path: Path, candidate: Mapping[str, Any]
) -> tuple[str, BaseException | None]:
    try:
        raw = path.read_bytes()
    except FileNotFoundError as error:
        return "absent", error
    except OSError as error:
        return "unreadable", error
    try:
        observed = json.loads(raw)
    except json.JSONDecodeError as error:
        return "unreadable", error
    return ("candidate" if observed == candidate else "different"), None


def _parse_attempt_history(raw: bytes) -> list[dict[str, Any]]:
    events = []
    previous = None
    lines = raw.splitlines()
    cursor = 0
    while cursor < len(lines):
        line = lines[cursor]
        if not line:
            raise RuntimeError("A220 attempt history contains an empty record")
        recovery = None
        if cursor + 1 < len(lines):
            try:
                candidate = json.loads(lines[cursor + 1])
            except json.JSONDecodeError:
                candidate = None
            if (
                isinstance(candidate, dict)
                and candidate.get("event_type") == "attempt_history_torn_tail_recovery"
                and candidate.get("recovered_fragment_sha256") == _sha256(line)
                and candidate.get("recovered_fragment_bytes") == len(line)
            ):
                recovery = candidate
        if recovery is not None:
            event = recovery
            cursor += 1
        else:
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                if cursor + 1 >= len(lines):
                    raise RuntimeError(
                        "A220 attempt history has an unrecovered torn tail"
                    ) from error
                raise RuntimeError(
                    "A220 attempt history has non-final semantic corruption"
                ) from error
        stored = event.get("event_sha256")
        unhashed = {key: value for key, value in event.items() if key != "event_sha256"}
        if (
            event.get("schema") != ATTEMPT_EVENT_SCHEMA
            or event.get("event_index") != len(events)
            or event.get("previous_event_sha256") != previous
            or stored != _canonical_sha256(unhashed)
        ):
            raise RuntimeError(f"A220 attempt history chain differs at event {len(events)}")
        events.append(event)
        previous = stored
        cursor += 1
    return events


def _recover_torn_attempt_history_tail(path: Path) -> None:
    if not path.exists():
        return
    raw = path.read_bytes()
    if not raw or raw.endswith(b"\n"):
        return
    prefix, separator, fragment = raw.rpartition(b"\n")
    prefix_raw = prefix + separator if separator else b""
    events = _parse_attempt_history(prefix_raw)
    if not fragment:
        return
    recovery = {
        "schema": ATTEMPT_EVENT_SCHEMA,
        "event_index": len(events),
        "previous_event_sha256": events[-1]["event_sha256"] if events else None,
        "event_type": "attempt_history_torn_tail_recovery",
        "protocol_sha256": PROTOCOL_SHA256,
        "recovered_fragment_sha256": _sha256(fragment),
        "recovered_fragment_bytes": len(fragment),
        "recovery_semantics": "append_only_preservation_of_unterminated_final_fragment",
    }
    recovery["event_sha256"] = _canonical_sha256(recovery)
    # Preserve every prior byte, including the torn fragment, but publish the
    # separator and recovery event as one atomic replacement.  A second crash
    # therefore leaves either the original torn tail or the complete recovery,
    # never an unrecoverable half-recovery.
    _atomic_bytes(
        path,
        raw + b"\n" + _canonical_bytes(recovery) + b"\n",
        private=True,
    )


def _read_attempt_history(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    _recover_torn_attempt_history_tail(path)
    return _parse_attempt_history(path.read_bytes())


def _append_attempt_event(path: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    events = _read_attempt_history(path)
    event = {
        "schema": ATTEMPT_EVENT_SCHEMA,
        "event_index": len(events),
        "previous_event_sha256": events[-1]["event_sha256"] if events else None,
        **dict(payload),
    }
    event["event_sha256"] = _canonical_sha256(event)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as handle:
        path.chmod(0o600)
        handle.write(_canonical_bytes(event) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    if _read_attempt_history(path)[-1] != event:
        raise RuntimeError("A220 attempt history append verification failed")
    return event


def _events_for_run(
    events: Sequence[Mapping[str, Any]], *, key_label: str, run_id: str
) -> list[Mapping[str, Any]]:
    return [
        event
        for event in events
        if event.get("key_label") == key_label and event.get("run_id") == run_id
    ]


def _begin_attempt(
    *,
    history_path: Path,
    row: Mapping[str, Any],
    spec: Mapping[str, Any],
    artifact_hashes: Mapping[str, str],
) -> dict[str, Any]:
    prior = _events_for_run(
        _read_attempt_history(history_path), key_label=str(row["label"]), run_id=str(spec["run_id"])
    )
    prior_started = [event for event in prior if event["event_type"] == "run_attempt_started"]
    prior_terminal = [
        event
        for event in prior
        if event["event_type"] in {"run_attempt_completed", "run_attempt_tombstone"}
    ]
    attempt_number = len(prior_started) + 1
    attempt_identity = {
        "protocol_sha256": PROTOCOL_SHA256,
        "key_label": row["label"],
        "run_id": spec["run_id"],
        "attempt_number": attempt_number,
        "prior_started_attempts": len(prior_started),
        "prior_terminal_attempts": len(prior_terminal),
    }
    event = _append_attempt_event(
        history_path,
        {
            "event_type": "run_attempt_started",
            **attempt_identity,
            "attempt_id": _canonical_sha256(attempt_identity),
            "run_spec_sha256": _canonical_sha256(
                {
                    key: spec[key]
                    for key in (
                        "run_id",
                        "mode",
                        "operator",
                        "schedule",
                        "conflict_horizons",
                        "order_uint8_sha256",
                    )
                }
            ),
            "retry_claim": {
                "is_retry": bool(prior_started),
                "derived_from_prior_started_attempts": len(prior_started),
                "derived_from_prior_terminal_attempts": len(prior_terminal),
            },
            "artifact_hashes_started": dict(artifact_hashes),
        },
    )
    return event


def _append_completion(
    history_path: Path,
    *,
    row: Mapping[str, Any],
    spec: Mapping[str, Any],
    attempt: Mapping[str, Any],
    record: Mapping[str, Any],
    recovered: bool = False,
) -> dict[str, Any]:
    return _append_attempt_event(
        history_path,
        {
            "event_type": "run_attempt_completed",
            "protocol_sha256": PROTOCOL_SHA256,
            "key_label": row["label"],
            "run_id": spec["run_id"],
            "attempt_number": attempt["attempt_number"],
            "attempt_id": attempt["attempt_id"],
            "completion_recovered_from_checkpoint": recovered,
            "returncode": record["scientific_measurement"]["helper_returncode"],
            "artifact_hashes_finished": record["deterministic_artifact_provenance"][
                "launch_artifact_hashes_finished"
            ],
            "checkpoint_record_sha256": record["checkpoint_record_sha256"],
        },
    )


def _append_tombstone(
    history_path: Path,
    *,
    row: Mapping[str, Any],
    spec: Mapping[str, Any],
    attempt: Mapping[str, Any],
    error: BaseException,
    artifact_hashes: Mapping[str, str],
    reason: str,
    returncode_override: int | None = None,
) -> dict[str, Any]:
    returncode = (
        returncode_override
        if returncode_override is not None
        else getattr(error, "returncode", None)
    )
    if not isinstance(returncode, int) or isinstance(returncode, bool):
        returncode = None
    return _append_attempt_event(
        history_path,
        {
            "event_type": "run_attempt_tombstone",
            "protocol_sha256": PROTOCOL_SHA256,
            "key_label": row["label"],
            "run_id": spec["run_id"],
            "attempt_number": attempt["attempt_number"],
            "attempt_id": attempt["attempt_id"],
            "reason": reason,
            "exception_class": f"{type(error).__module__}.{type(error).__qualname__}",
            "exception_message_sha256": _sha256(str(error).encode()),
            "returncode": returncode,
            "returncode_available": returncode is not None,
            "artifact_hashes_finished": dict(artifact_hashes),
        },
    )


def _reconcile_attempt_history(
    *,
    history_path: Path,
    row: Mapping[str, Any],
    plan: Sequence[Mapping[str, Any]],
    checkpoint: Mapping[str, Any],
    artifact_hashes: Mapping[str, str],
) -> None:
    specs = {str(spec["run_id"]): spec for spec in plan}
    events = _read_attempt_history(history_path)
    for run_id, spec in specs.items():
        run_events = _events_for_run(events, key_label=str(row["label"]), run_id=run_id)
        starts = {
            event["attempt_id"]: event
            for event in run_events
            if event["event_type"] == "run_attempt_started"
        }
        terminals = {
            event["attempt_id"]
            for event in run_events
            if event["event_type"] in {"run_attempt_completed", "run_attempt_tombstone"}
        }
        record = checkpoint["completed_runs"].get(run_id)
        if record is not None and record["attempt_id"] not in starts:
            raise RuntimeError(f"A220 completed checkpoint lacks its start event: {run_id}")
        completed_events = [
            event for event in run_events if event["event_type"] == "run_attempt_completed"
        ]
        completed_attempts = {event["attempt_id"] for event in completed_events}
        tombstoned_attempts = {
            event["attempt_id"]
            for event in run_events
            if event["event_type"] == "run_attempt_tombstone"
        }
        if len(completed_events) > 1:
            raise RuntimeError(f"A220 history contains a reexecuted completed run: {run_id}")
        if record is None and completed_events:
            raise RuntimeError(
                f"A220 completed run checkpoint is missing; reexecution refused: {run_id}"
            )
        if record is not None and record["attempt_id"] in tombstoned_attempts:
            raise RuntimeError(
                f"A220 checkpoint-complete attempt is tombstoned; recovery refused: {run_id}"
            )
        if record is not None and record["attempt_id"] not in completed_attempts:
            _append_completion(
                history_path,
                row=row,
                spec=spec,
                attempt=starts[record["attempt_id"]],
                record=record,
                recovered=True,
            )
            events = _read_attempt_history(history_path)
            run_events = _events_for_run(events, key_label=str(row["label"]), run_id=run_id)
            terminals = {
                event["attempt_id"]
                for event in run_events
                if event["event_type"] in {"run_attempt_completed", "run_attempt_tombstone"}
            }
        for attempt_id, start in starts.items():
            if attempt_id in terminals:
                continue
            if record is not None and record["attempt_id"] == attempt_id:
                _append_completion(
                    history_path,
                    row=row,
                    spec=spec,
                    attempt=start,
                    record=record,
                    recovered=True,
                )
            else:
                interruption = RuntimeError("prior orchestrator ended before a terminal event")
                _append_tombstone(
                    history_path,
                    row=row,
                    spec=spec,
                    attempt=start,
                    error=interruption,
                    artifact_hashes=artifact_hashes,
                    reason="orchestrator_interruption_detected_before_outcome_independent_resume",
                )
        events = _read_attempt_history(history_path)


def _invoke_run(
    *,
    run_callable: Callable[..., dict[str, Any]],
    prepared: Mapping[str, Any],
    key_prepared: Mapping[str, Any],
    protocol: Mapping[str, Any],
    spec: Mapping[str, Any],
) -> dict[str, Any]:
    return run_callable(
        helper=prepared["helper_path"],
        cnf=key_prepared["cnf_path"],
        mode=spec["mode"],
        order=spec["order"],
        key_one_literals_bit0_through_bit19=prepared["key_mapping"],
        conflict_horizons=spec["conflict_horizons"],
        watchdog_seconds=protocol["fit_select_collection"]["watchdog_seconds_per_stage"],
        external_timeout_seconds=_external_timeout(protocol, len(spec["conflict_horizons"])),
    )


def _execute_key_runs(
    *,
    protocol: Mapping[str, Any],
    row: Mapping[str, Any],
    prepared: Mapping[str, Any],
    key_prepared: Mapping[str, Any],
    plan: Sequence[Mapping[str, Any]],
    order_manifests: Mapping[str, Any],
    checkpoint_path: Path,
    history_path: Path,
    collector_sha256: str,
    run_callable: Callable[..., dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    identity = _checkpoint_identity(
        row=row,
        prepared=prepared,
        key_prepared=key_prepared,
        plan=plan,
        order_manifests=order_manifests,
        collector_sha256=collector_sha256,
    )
    checkpoint = _load_checkpoint(
        checkpoint_path,
        identity=identity,
        valid_run_ids={str(spec["run_id"]) for spec in plan},
    )
    artifacts = _artifact_hashes(protocol=protocol, prepared=prepared, key_prepared=key_prepared)
    _reconcile_attempt_history(
        history_path=history_path,
        row=row,
        plan=plan,
        checkpoint=checkpoint,
        artifact_hashes=artifacts,
    )
    completed: dict[str, dict[str, Any]] = checkpoint["completed_runs"]
    pending = [spec for spec in plan if spec["run_id"] not in completed]
    if not pending:
        return completed

    executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="a220-collect")
    active: dict[Future[dict[str, Any]], tuple[Mapping[str, Any], Mapping[str, Any]]] = {}
    iterator = iter(pending)
    failure: BaseException | None = None
    checkpoint_state_unreadable = False

    def submit_next() -> bool:
        try:
            spec = next(iterator)
        except StopIteration:
            return False
        attempt = _begin_attempt(
            history_path=history_path,
            row=row,
            spec=spec,
            artifact_hashes=_artifact_hashes(
                protocol=protocol, prepared=prepared, key_prepared=key_prepared
            ),
        )
        try:
            future = executor.submit(
                _invoke_run,
                run_callable=run_callable,
                prepared=prepared,
                key_prepared=key_prepared,
                protocol=protocol,
                spec=spec,
            )
        except BaseException as error:
            _append_tombstone(
                history_path,
                row=row,
                spec=spec,
                attempt=attempt,
                error=error,
                artifact_hashes=_artifact_hashes(
                    protocol=protocol, prepared=prepared, key_prepared=key_prepared
                ),
                reason="solver_process_submission_failed",
            )
            raise
        active[future] = (spec, attempt)
        return True

    try:
        try:
            submit_next()
            submit_next()
        except BaseException as error:
            failure = error
        while active:
            future = next(as_completed(tuple(active)))
            spec, attempt = active.pop(future)
            if checkpoint_state_unreadable:
                # Do not overwrite a checkpoint whose post-commit state could
                # not be read.  Already-launched attempts remain open and are
                # resolved prospectively by startup reconciliation.
                try:
                    future.result()
                except BaseException:
                    pass
                continue
            raw: Mapping[str, Any] | None = None
            try:
                raw = future.result()
                record = _record_run(
                    raw=raw,
                    spec=spec,
                    protocol=protocol,
                    prepared=prepared,
                    key_prepared=key_prepared,
                    attempt=attempt,
                )
            except BaseException as error:
                _append_tombstone(
                    history_path,
                    row=row,
                    spec=spec,
                    attempt=attempt,
                    error=error,
                    artifact_hashes=_artifact_hashes(
                        protocol=protocol, prepared=prepared, key_prepared=key_prepared
                    ),
                    reason="solver_process_or_completed_run_gate_failed",
                    returncode_override=(
                        raw.get("helper_returncode")
                        if raw is not None
                        and isinstance(raw.get("helper_returncode"), int)
                        and not isinstance(raw.get("helper_returncode"), bool)
                        else None
                    ),
                )
                if failure is None:
                    failure = error
            else:
                candidate_completed = {**completed, str(spec["run_id"]): record}
                candidate_checkpoint = {
                    **checkpoint,
                    "completed_runs": candidate_completed,
                }
                checkpoint_durable = False
                checkpoint_error: BaseException | None = None
                checkpoint_commit_ambiguous = False
                try:
                    _atomic_json(checkpoint_path, candidate_checkpoint, private=True)
                except BaseException as error:
                    checkpoint_error = error
                    readback_state, readback_error = _checkpoint_readback_state(
                        checkpoint_path, candidate_checkpoint
                    )
                    if readback_state == "candidate":
                        try:
                            _fsync_existing_file_and_parent(checkpoint_path)
                            confirmed_state, confirmed_error = _checkpoint_readback_state(
                                checkpoint_path, candidate_checkpoint
                            )
                            if confirmed_state != "candidate":
                                raise RuntimeError(
                                    "A220 checkpoint changed during durability reconfirmation: "
                                    f"{confirmed_state}:"
                                    f"{type(confirmed_error).__name__ if confirmed_error else 'none'}"
                                )
                            checkpoint_durable = True
                        except BaseException as durability_error:
                            checkpoint_commit_ambiguous = True
                            checkpoint_state_unreadable = True
                            checkpoint_error = RuntimeError(
                                "A220 visible checkpoint durability reconfirmation failed: "
                                f"{type(durability_error).__name__}"
                            )
                            # Preserve the visible record in every later
                            # in-process checkpoint candidate.  It remains an
                            # open attempt until a future startup observes a
                            # surviving checkpoint and seals completion, or
                            # observes its absence and tombstones the attempt.
                            completed[str(spec["run_id"])] = record
                    elif readback_state == "unreadable":
                        checkpoint_commit_ambiguous = True
                        checkpoint_state_unreadable = True
                        checkpoint_error = RuntimeError(
                            "A220 checkpoint state unreadable after write exception: "
                            f"{type(readback_error).__name__}"
                        )
                else:
                    readback_state, readback_error = _checkpoint_readback_state(
                        checkpoint_path, candidate_checkpoint
                    )
                    if readback_state == "candidate":
                        checkpoint_durable = True
                    elif readback_state == "unreadable":
                        checkpoint_commit_ambiguous = True
                        checkpoint_state_unreadable = True
                        checkpoint_error = RuntimeError(
                            "A220 checkpoint state unreadable after durable write: "
                            f"{type(readback_error).__name__}"
                        )
                        completed[str(spec["run_id"])] = record
                    else:
                        checkpoint_error = RuntimeError(
                            f"A220 checkpoint post-write verification differs: {readback_state}"
                        )
                if not checkpoint_durable:
                    assert checkpoint_error is not None
                    if not checkpoint_commit_ambiguous:
                        _append_tombstone(
                            history_path,
                            row=row,
                            spec=spec,
                            attempt=attempt,
                            error=checkpoint_error,
                            artifact_hashes=_artifact_hashes(
                                protocol=protocol,
                                prepared=prepared,
                                key_prepared=key_prepared,
                            ),
                            reason="completed_record_checkpoint_commit_failed_before_durability",
                            returncode_override=record["scientific_measurement"][
                                "helper_returncode"
                            ],
                        )
                    if failure is None:
                        failure = checkpoint_error
                else:
                    completed[str(spec["run_id"])] = record
                    try:
                        _append_completion(
                            history_path,
                            row=row,
                            spec=spec,
                            attempt=attempt,
                            record=record,
                        )
                    except BaseException as error:
                        # The record is already durable.  Do not misclassify a
                        # provenance-append failure as a solver failure and do
                        # not emit a false tombstone.  Resume reconstructs the
                        # completion from this exact checkpoint record.
                        if failure is None:
                            failure = error
                    else:
                        print(f"A220 complete {row['label']} {spec['run_id']}", flush=True)
                    if checkpoint_error is not None and failure is None:
                        # Covers a post-replace failure (for example chmod): the
                        # candidate was read back exactly, so it remains a
                        # completed run and must never be reexecuted.
                        failure = checkpoint_error
            if failure is None:
                try:
                    submit_next()
                except BaseException as error:
                    failure = error
    finally:
        executor.shutdown(wait=True, cancel_futures=False)
    if failure is not None:
        raise failure
    if set(completed) != {str(spec["run_id"]) for spec in plan}:
        raise RuntimeError(f"A220 complete-run set differs for {row['label']}")
    return completed


def _stable_attempt_history(
    history_path: Path, *, row: Mapping[str, Any], plan: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    events = _read_attempt_history(history_path)
    order = {str(spec["run_id"]): index for index, spec in enumerate(plan)}
    selected = [event for event in events if event.get("key_label") == row["label"]]
    fields = (
        "event_type",
        "protocol_sha256",
        "key_label",
        "run_id",
        "attempt_number",
        "attempt_id",
        "run_spec_sha256",
        "retry_claim",
        "artifact_hashes_started",
        "completion_recovered_from_checkpoint",
        "returncode",
        "artifact_hashes_finished",
        "checkpoint_record_sha256",
        "reason",
        "exception_class",
        "exception_message_sha256",
        "returncode_available",
    )
    phase = {"run_attempt_started": 0, "run_attempt_completed": 1, "run_attempt_tombstone": 1}
    normalized = [{field: event[field] for field in fields if field in event} for event in selected]
    normalized.sort(
        key=lambda event: (
            order[str(event["run_id"])],
            int(event["attempt_number"]),
            phase[str(event["event_type"])],
            str(event["event_type"]),
        )
    )
    return normalized


def _assemble_shard(
    *,
    protocol: Mapping[str, Any],
    row: Mapping[str, Any],
    prepared: Mapping[str, Any],
    key_prepared: Mapping[str, Any],
    records: Mapping[str, Mapping[str, Any]],
    plan: Sequence[Mapping[str, Any]],
    order_manifests: Mapping[str, Any],
    history_path: Path,
    collector_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    ordered = {str(spec["run_id"]): records[str(spec["run_id"])] for spec in plan}
    stable_history = _stable_attempt_history(history_path, row=row, plan=plan)
    terminal_completed = {
        (event["run_id"], event["attempt_id"])
        for event in stable_history
        if event["event_type"] == "run_attempt_completed"
    }
    if any(
        (run_id, record["attempt_id"]) not in terminal_completed
        for run_id, record in ordered.items()
    ):
        raise RuntimeError("A220 completed run lacks append-only completion history")
    completed_event_counts = {
        run_id: sum(
            event["event_type"] == "run_attempt_completed" and event["run_id"] == run_id
            for event in stable_history
        )
        for run_id in ordered
    }
    if set(completed_event_counts.values()) != {1}:
        raise RuntimeError("A220 completed-run history is not exactly once per run")
    completion = {
        "all_12_runs_complete": len(ordered) == 12,
        "all_12_runs_are_fresh_solver_processes": all(
            record["fresh_solver_process"] is True for record in ordered.values()
        ),
        "all_3072_cells_complete": sum(
            len(record["scientific_measurement"]["cells"]) for record in ordered.values()
        )
        == 12 * 256,
        "all_retained_state_continuity_verified": all(
            record["scientific_measurement"]["retained_state_continuity_verified"] is True
            for record in ordered.values()
        ),
        "all_watchdogs_clear": all(
            record["scientific_measurement"]["all_watchdogs_clear"] is True
            for record in ordered.values()
        ),
        "all_launch_hashes_pre_post_identical": all(
            record["deterministic_artifact_provenance"]["launch_artifact_hashes_started"]
            == record["deterministic_artifact_provenance"]["launch_artifact_hashes_finished"]
            for record in ordered.values()
        ),
        "completed_runs_never_reexecuted": len(
            {record["attempt_id"] for record in ordered.values()}
        )
        == 12,
        "maximum_concurrent_solver_processes": 2,
        "one_key_instantiated_CNF_active": True,
        "collector_source_unchanged": _file_sha256(ORCHESTRATOR) == collector_sha256,
        "source_anchors_unchanged": _verify_source_anchors(protocol)
        == prepared["source_anchor_hashes_started"],
        "historical_result_or_causal_artifact_loaded": False,
    }
    required_true = (
        "all_12_runs_complete",
        "all_12_runs_are_fresh_solver_processes",
        "all_3072_cells_complete",
        "all_retained_state_continuity_verified",
        "all_watchdogs_clear",
        "all_launch_hashes_pre_post_identical",
        "completed_runs_never_reexecuted",
        "one_key_instantiated_CNF_active",
        "collector_source_unchanged",
        "source_anchors_unchanged",
    )
    if (
        not all(completion[key] is True for key in required_true)
        or completion["maximum_concurrent_solver_processes"] != 2
        or completion["historical_result_or_causal_artifact_loaded"] is not False
    ):
        raise RuntimeError(f"A220 per-key completion gate failed: {row['label']}")
    shard = {
        "schema": SHARD_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FULLROUND_R20_FACTORIAL_FIT_SELECT_TRAJECTORY_COLLECTION",
        "protocol_sha256": PROTOCOL_SHA256,
        "collector_source_sha256": collector_sha256,
        "key_factorial_identity": dict(row),
        "known_key_confirmation_metadata": key_prepared["known_key_confirmation_metadata"],
        "public_only_R20_material_sha256": protocol["public_only_R20_material_sha256"],
        "public_core_provenance": prepared["public_core_provenance"],
        "source_anchor_hashes": prepared["source_anchor_hashes_started"],
        "symbolic_template_manifest": prepared["template_manifest"],
        "instantiated_CNF_manifest": key_prepared["instantiation_manifest"],
        "key_mapping_canonical_sha256": _canonical_sha256(prepared["key_mapping"]),
        "native_helper_stable_provenance": prepared["native_helper_stable_provenance"],
        "operator_order_manifests": order_manifests,
        "run_plan": [
            {
                key: spec[key]
                for key in (
                    "run_id",
                    "mode",
                    "operator",
                    "schedule",
                    "conflict_horizons",
                    "order_uint8_sha256",
                )
            }
            for spec in plan
        ],
        "scientific_runs": {
            run_id: record["scientific_measurement"] for run_id, record in ordered.items()
        },
        "deterministic_run_artifact_provenance": {
            run_id: record["deterministic_artifact_provenance"]
            for run_id, record in ordered.items()
        },
        "append_only_attempt_history_without_wallclock": stable_history,
        "information_boundary": {
            **protocol["information_boundary"],
            "known_low20_used_for_eight_block_target_construction": True,
            "known_low20_passed_to_solver_order_or_budget": False,
            "historical_result_or_causal_artifact_loaded_during_collection": False,
            "holdout_trajectory_opened_during_fit_select_collection": False,
        },
        "completion_gates": completion,
    }
    volatile = {
        "schema": "chacha20-round20-factorial-trajectory-fit-select-volatile-v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "collector_source_sha256": collector_sha256,
        "key_label": row["label"],
        "native_build_elapsed_seconds": prepared["native_helper_build"].get("elapsed_seconds"),
        "runs": {run_id: record["volatile_observation"] for run_id, record in ordered.items()},
    }
    return shard, volatile


def _compress_measurement(raw: bytes) -> bytes:
    if zstandard.__version__ != ZSTD_VERSION:
        raise RuntimeError("A220 frozen zstandard package version differs")
    compressor = zstandard.ZstdCompressor(
        level=ZSTD_LEVEL,
        threads=0,
        write_checksum=True,
        write_content_size=True,
        write_dict_id=False,
    )
    return compressor.compress(raw)


def _decompress_measurement(raw: bytes) -> bytes:
    return zstandard.ZstdDecompressor().decompress(raw, max_output_size=1 << 30)


def _integer(value: Any, *, nonnegative: bool = False) -> bool:
    return (
        isinstance(value, int) and not isinstance(value, bool) and (not nonnegative or value >= 0)
    )


def _integer_vector(value: Any, *, length: int, nonnegative: bool = False) -> bool:
    return (
        isinstance(value, list)
        and len(value) == length
        and all(_integer(item, nonnegative=nonnegative) for item in value)
    )


def _difference(after: Sequence[int], before: Sequence[int]) -> list[int]:
    return [right - left for left, right in zip(before, after, strict=True)]


def _verify_scientific_run(
    *,
    measurement: Mapping[str, Any],
    provenance: Mapping[str, Any],
    spec: Mapping[str, Any],
    protocol: Mapping[str, Any],
    key_mapping: Sequence[int],
    expected_variables: int,
) -> None:
    if not isinstance(measurement, Mapping) or not isinstance(provenance, Mapping):
        raise RuntimeError(f"A220 reconstructed run is not an object: {spec['run_id']}")
    expected_measurement_fields = {
        "mode",
        "order",
        "conflict_horizons",
        "watchdog_seconds_per_stage",
        "stages",
        "cells",
        "summary",
        "retained_state_continuity_verified",
        "all_watchdogs_clear",
        "helper_returncode",
    }
    expected_provenance_fields = {
        "launch_artifact_hashes_started",
        "launch_artifact_hashes_finished",
        "launch_identity_verified",
        "environment",
        "stderr_sha256",
        "helper_returncode",
    }
    horizons = list(spec["conflict_horizons"])
    order = list(spec["order"])
    mapping = list(key_mapping)
    if (
        len(mapping) != 20
        or any(not _integer(value) or value == 0 for value in mapping)
        or len({abs(value) for value in mapping}) != 20
        or not _integer(expected_variables, nonnegative=True)
    ):
        raise RuntimeError(f"A220 reconstructed mapping identity failed: {spec['run_id']}")
    assumption_one = [mapping[bit] for bit in range(19, 11, -1)]
    cells = measurement.get("cells")
    stages = measurement.get("stages")
    expected_launch = {
        "wrapper_sha256": protocol["anchors"]["retained_wrapper_sha256"],
        "source_sha256": protocol["anchors"]["retained_native_source_sha256"],
        "helper_sha256": protocol["anchors"]["retained_native_binary_sha256"],
        "cnf_sha256": None,
    }
    started = provenance.get("launch_artifact_hashes_started")
    finished = provenance.get("launch_artifact_hashes_finished")
    if (
        set(measurement) != expected_measurement_fields
        or set(provenance) != expected_provenance_fields
        or measurement.get("mode") != spec["mode"]
        or measurement.get("order") != order
        or measurement.get("conflict_horizons") != horizons
        or measurement.get("watchdog_seconds_per_stage")
        != protocol["fit_select_collection"]["watchdog_seconds_per_stage"]
        or not isinstance(cells, list)
        or len(cells) != 256
        or not isinstance(stages, list)
        or not stages
        or measurement.get("retained_state_continuity_verified") is not True
        or measurement.get("all_watchdogs_clear") is not True
        or measurement.get("helper_returncode") != 0
        or provenance.get("launch_identity_verified") is not True
        or provenance.get("environment") != {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
        or provenance.get("stderr_sha256") != _sha256(b"")
        or provenance.get("helper_returncode") != 0
        or not isinstance(started, dict)
        or started != finished
        or set(started) != set(expected_launch)
        or any(started[key] != value for key, value in expected_launch.items() if value is not None)
        or not isinstance(started.get("cnf_sha256"), str)
        or len(started["cnf_sha256"]) != 64
    ):
        raise RuntimeError(f"A220 reconstructed run identity failed: {spec['run_id']}")

    cursor = 0
    previous_cell: Mapping[str, Any] | None = None
    status_counts = {"sat": 0, "unsat": 0, "unknown": 0}
    for cell_index, (prefix8, cell) in enumerate(zip(order, cells, strict=True)):
        expected_assumptions = [
            literal if bit == "1" else -literal
            for bit, literal in zip(prefix8, assumption_one, strict=True)
        ]
        if (
            not isinstance(cell, dict)
            or set(cell) != STABLE_CELL_FIELDS
            or cell.get("mode") != spec["mode"]
            or cell.get("prefix8") != prefix8
            or cell.get("cell_index") != cell_index
            or cell.get("assumptions") != expected_assumptions
            or cell.get("metric_names") != list(METRIC_NAMES)
            or cell.get("final_status") not in status_counts
            or cell.get("watchdog_fires") != 0
            or not _integer_vector(cell.get("metrics_before"), length=3, nonnegative=True)
            or not _integer_vector(cell.get("metrics_after"), length=3, nonnegative=True)
            or not _integer_vector(cell.get("metrics_delta"), length=3, nonnegative=True)
            or cell["metrics_delta"] != _difference(cell["metrics_after"], cell["metrics_before"])
        ):
            raise RuntimeError(
                f"A220 reconstructed cell identity failed: {spec['run_id']}:{cell_index}"
            )
        current_stages = []
        while (
            cursor < len(stages)
            and isinstance(stages[cursor], dict)
            and stages[cursor].get("cell_index") == cell_index
        ):
            current_stages.append(stages[cursor])
            cursor += 1
        if not 1 <= len(current_stages) <= len(horizons):
            raise RuntimeError(
                f"A220 reconstructed stage count failed: {spec['run_id']}:{cell_index}"
            )
        previous_stage: Mapping[str, Any] | None = None
        for stage_index, stage in enumerate(current_stages):
            status = stage.get("status")
            expected_increment = horizons[stage_index] - (
                horizons[stage_index - 1] if stage_index else 0
            )
            before = stage.get("metrics_stage_before")
            after = stage.get("metrics_stage_after")
            delta = stage.get("metrics_stage_delta")
            cell_before = stage.get("metrics_cell_before")
            cumulative = stage.get("metrics_cell_cumulative_delta")
            failed = stage.get("failed_assumptions")
            model = stage.get("model_bits_bit0_through_bit19")
            expected_model_prefix = [int(bit) for bit in reversed(prefix8)]
            if (
                not isinstance(stage, dict)
                or set(stage) != STABLE_STAGE_FIELDS
                or stage.get("mode") != spec["mode"]
                or stage.get("prefix8") != prefix8
                or stage.get("cell_index") != cell_index
                or stage.get("stage_index") != stage_index
                or stage.get("assumptions") != expected_assumptions
                or stage.get("horizon") != horizons[stage_index]
                or stage.get("conflict_increment") != expected_increment
                or status not in status_counts
                or stage.get("returncode") != {"sat": 10, "unsat": 20, "unknown": 0}[status]
                or stage.get("terminal") is not (status != "unknown")
                or stage.get("watchdog_fired") is not False
                or stage.get("conflict_budget_exhausted") is not (status == "unknown")
                or stage.get("watchdog_seconds")
                != protocol["fit_select_collection"]["watchdog_seconds_per_stage"]
                or stage.get("metric_names") != list(METRIC_NAMES)
                or not all(
                    _integer_vector(value, length=3, nonnegative=True)
                    for value in (before, after, delta, cell_before, cumulative)
                )
                or cell_before != cell["metrics_before"]
                or delta != _difference(after, before)
                or cumulative != _difference(after, cell_before)
                or not isinstance(failed, list)
                or any(not _integer(value) for value in failed)
                or len(set(failed)) != len(failed)
                or any(literal not in expected_assumptions for literal in failed)
                or (status != "unsat" and failed)
                or (
                    status == "sat"
                    and (
                        not isinstance(model, list)
                        or len(model) != 20
                        or any(not _integer(value) or value not in {0, 1} for value in model)
                        or model[12:] != expected_model_prefix
                    )
                )
                or (status != "sat" and model != [])
            ):
                raise RuntimeError(
                    f"A220 reconstructed stage identity failed: "
                    f"{spec['run_id']}:{cell_index}:{stage_index}"
                )
            for stem in STATE_STEMS:
                stage_before = stage.get(f"{stem}_stage_before")
                stage_after = stage.get(f"{stem}_stage_after")
                stage_delta = stage.get(f"{stem}_stage_delta")
                state_cell_before = stage.get(f"{stem}_cell_before")
                cell_delta = stage.get(f"{stem}_cell_cumulative_delta")
                if (
                    not all(
                        isinstance(value, int) and not isinstance(value, bool) and value >= 0
                        for value in (stage_before, stage_after, state_cell_before)
                    )
                    or not all(
                        isinstance(value, int) and not isinstance(value, bool)
                        for value in (stage_delta, cell_delta)
                    )
                    or stage_after - stage_before != stage_delta
                    or stage_after - state_cell_before != cell_delta
                    or state_cell_before != cell[f"{stem}_before"]
                ):
                    raise RuntimeError(
                        f"A220 reconstructed state delta failed: "
                        f"{spec['run_id']}:{cell_index}:{stage_index}:{stem}"
                    )
            if previous_stage is None:
                if before != cell["metrics_before"] or any(
                    stage[f"{stem}_stage_before"] != cell[f"{stem}_before"] for stem in STATE_STEMS
                ):
                    raise RuntimeError(
                        f"A220 reconstructed cell-start continuity failed: "
                        f"{spec['run_id']}:{cell_index}"
                    )
                if previous_cell is not None and (
                    before != previous_cell["metrics_after"]
                    or any(
                        stage[f"{stem}_stage_before"] != previous_cell[f"{stem}_after"]
                        for stem in STATE_STEMS
                    )
                ):
                    raise RuntimeError(
                        f"A220 reconstructed between-cell continuity failed: "
                        f"{spec['run_id']}:{cell_index}"
                    )
            elif before != previous_stage["metrics_stage_after"] or any(
                stage[f"{stem}_stage_before"] != previous_stage[f"{stem}_stage_after"]
                for stem in STATE_STEMS
            ):
                raise RuntimeError(
                    f"A220 reconstructed within-cell continuity failed: "
                    f"{spec['run_id']}:{cell_index}:{stage_index}"
                )
            if previous_stage is not None and previous_stage["status"] != "unknown":
                raise RuntimeError(
                    f"A220 reconstructed solve continued after terminal: "
                    f"{spec['run_id']}:{cell_index}:{stage_index}"
                )
            previous_stage = stage

        final_stage = current_stages[-1]
        final_status = final_stage["status"]
        expected_terminal = len(current_stages) - 1 if final_status != "unknown" else None
        if (
            (final_status == "unknown" and len(current_stages) != len(horizons))
            or cell["stages_run"] != len(current_stages)
            or cell["final_status"] != final_status
            or cell["terminal_stage_index"] != expected_terminal
            or cell["metrics_after"] != final_stage["metrics_stage_after"]
            or any(
                cell[f"{stem}_after"] != final_stage[f"{stem}_stage_after"]
                or cell[f"{stem}_after"] - cell[f"{stem}_before"] != cell[f"{stem}_delta"]
                for stem in STATE_STEMS
            )
        ):
            raise RuntimeError(
                f"A220 reconstructed cell aggregate failed: {spec['run_id']}:{cell_index}"
            )
        status_counts[final_status] += 1
        previous_cell = cell
    if cursor != len(stages):
        raise RuntimeError(f"A220 reconstructed stage alignment failed: {spec['run_id']}")
    summary = measurement.get("summary")
    if (
        not isinstance(summary, dict)
        or set(summary) != STABLE_SUMMARY_FIELDS
        or summary.get("signature") != "cadical-3.0.0"
        or summary.get("version") != "3.0.0"
        or summary.get("mode") != spec["mode"]
        or summary.get("variables") != expected_variables
        or summary.get("cells") != 256
        or summary.get("conflict_horizons") != horizons
        or summary.get("configured_stages_per_nonterminal_cell") != len(horizons)
        or summary.get("stages_emitted") != len(stages)
        or summary.get("sat_cells") != status_counts["sat"]
        or summary.get("unsat_cells") != status_counts["unsat"]
        or summary.get("unknown_cells") != status_counts["unknown"]
        or summary.get("watchdog_seconds")
        != protocol["fit_select_collection"]["watchdog_seconds_per_stage"]
        or summary.get("watchdog_fires") != 0
        or summary.get("metric_names") != list(METRIC_NAMES)
    ):
        raise RuntimeError(f"A220 reconstructed summary failed: {spec['run_id']}")


def _verify_stable_attempt_history(history: Any, *, expected_run_ids: set[str]) -> None:
    if not isinstance(history, list):
        raise RuntimeError("A220 stable attempt history is not a list")
    for run_id in expected_run_ids:
        events = [event for event in history if event.get("run_id") == run_id]
        starts = [event for event in events if event.get("event_type") == "run_attempt_started"]
        completed = [
            event for event in events if event.get("event_type") == "run_attempt_completed"
        ]
        tombstones = [
            event for event in events if event.get("event_type") == "run_attempt_tombstone"
        ]
        start_ids = {event.get("attempt_id") for event in starts}
        terminal_ids = {event.get("attempt_id") for event in [*completed, *tombstones]}
        if (
            not starts
            or [event.get("attempt_number") for event in starts] != list(range(1, len(starts) + 1))
            or len(start_ids) != len(starts)
            or len(completed) != 1
            or len(completed) + len(tombstones) != len(starts)
            or len(terminal_ids) != len(completed) + len(tombstones)
            or completed[0].get("attempt_id") != starts[-1].get("attempt_id")
            or start_ids != terminal_ids
            or any(
                event.get("retry_claim", {}).get("is_retry") is not (index > 0)
                or event.get("retry_claim", {}).get("derived_from_prior_started_attempts") != index
                or event.get("retry_claim", {}).get("derived_from_prior_terminal_attempts") != index
                for index, event in enumerate(starts)
            )
        ):
            raise RuntimeError(f"A220 stable attempt history failed: {run_id}")
    if any(event.get("run_id") not in expected_run_ids for event in history):
        raise RuntimeError("A220 stable attempt history contains an unknown run")


def _verify_checkpoint_binding(
    path: Path,
    *,
    payload: Mapping[str, Any],
    expected_row: Mapping[str, Any],
    plan: Sequence[Mapping[str, Any]],
) -> None:
    checkpoint = json.loads(path.read_bytes())
    if not isinstance(checkpoint, dict):
        raise RuntimeError("A220 per-key checkpoint is not an object")
    plan_identity = [
        {
            key: run[key]
            for key in (
                "run_id",
                "mode",
                "operator",
                "schedule",
                "conflict_horizons",
                "order_uint8_sha256",
            )
        }
        for run in plan
    ]
    expected_identity = {
        "schema": CHECKPOINT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "collector_source_sha256": payload["collector_source_sha256"],
        "key_factorial_identity_sha256": _canonical_sha256(expected_row),
        "source_anchor_hashes": payload["source_anchor_hashes"],
        "helper_sha256": payload["native_helper_stable_provenance"]["binary_sha256"],
        "native_helper_stable_provenance_sha256": _canonical_sha256(
            payload["native_helper_stable_provenance"]
        ),
        "base_cnf_sha256": payload["symbolic_template_manifest"]["base_cnf_sha256"],
        "symbolic_template_manifest_sha256": _canonical_sha256(
            payload["symbolic_template_manifest"]
        ),
        "instantiated_cnf_sha256": payload["instantiated_CNF_manifest"]["sha256"],
        "instantiation_manifest_sha256": _canonical_sha256(payload["instantiated_CNF_manifest"]),
        "known_key_confirmation_metadata_sha256": _canonical_sha256(
            payload["known_key_confirmation_metadata"]
        ),
        "key_mapping_sha256": payload["key_mapping_canonical_sha256"],
        "order_manifests_sha256": _canonical_sha256(payload["operator_order_manifests"]),
        "run_plan_sha256": _canonical_sha256(plan_identity),
    }
    records = checkpoint.get("completed_runs")
    expected_run_ids = {str(run["run_id"]) for run in plan}
    if (
        set(checkpoint) != {*expected_identity, "completed_runs"}
        or any(checkpoint.get(key) != value for key, value in expected_identity.items())
        or not isinstance(records, dict)
        or set(records) != expected_run_ids
    ):
        raise RuntimeError("A220 shard/checkpoint identity binding differs")
    history = payload["append_only_attempt_history_without_wallclock"]
    completed_events = {
        event["run_id"]: event
        for event in history
        if event["event_type"] == "run_attempt_completed"
    }
    for run in plan:
        run_id = str(run["run_id"])
        record = records[run_id]
        unhashed = {
            key: value for key, value in record.items() if key != "checkpoint_record_sha256"
        }
        event = completed_events[run_id]
        if (
            record.get("checkpoint_record_sha256") != _canonical_sha256(unhashed)
            or record.get("run_id") != run_id
            or record.get("operator") != run["operator"]
            or record.get("schedule") != run["schedule"]
            or record.get("fresh_solver_process") is not True
            or record.get("attempt_id") != event.get("attempt_id")
            or record.get("attempt_number") != event.get("attempt_number")
            or record.get("checkpoint_record_sha256") != event.get("checkpoint_record_sha256")
            or record.get("scientific_measurement") != payload["scientific_runs"][run_id]
            or record.get("deterministic_artifact_provenance")
            != payload["deterministic_run_artifact_provenance"][run_id]
        ):
            raise RuntimeError(f"A220 shard/checkpoint run binding differs: {run_id}")


def _write_shard(path: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    canonical = _canonical_bytes(payload)
    compressed = _compress_measurement(canonical)
    if _compress_measurement(canonical) != compressed:
        raise RuntimeError("A220 zstd-19 compression is not deterministic")
    if _decompress_measurement(compressed) != canonical:
        raise RuntimeError("A220 zstd pre-write decompression roundtrip failed")
    if path.exists():
        existing = path.read_bytes()
        if existing != compressed or _decompress_measurement(existing) != canonical:
            raise RuntimeError("A220 completed measurement shard reexecution/overwrite refused")
    else:
        _atomic_bytes(path, compressed)
    observed = path.read_bytes()
    roundtrip = _decompress_measurement(observed)
    if observed != compressed or roundtrip != canonical or _sha256(roundtrip) != _sha256(canonical):
        raise RuntimeError("A220 atomic shard roundtrip/hash verification failed")
    return {
        "measurement_sha256": _sha256(canonical),
        "measurement_bytes": len(canonical),
        "compressed_sha256": _sha256(compressed),
        "compressed_bytes": len(compressed),
    }


def _verify_shard(
    path: Path,
    *,
    expected_row: Mapping[str, Any],
    protocol: Mapping[str, Any] | None = None,
    orders: Mapping[str, Sequence[str]] | None = None,
    order_manifests: Mapping[str, Any] | None = None,
    expected_collector_sha256: str | None = None,
    expected_source_anchor_hashes: Mapping[str, str] | None = None,
    checkpoint_path: Path | None = None,
    history_path: Path | None = None,
) -> dict[str, Any]:
    compressed = path.read_bytes()
    try:
        raw = _decompress_measurement(compressed)
        payload = json.loads(raw)
        frame = zstandard.get_frame_parameters(compressed)
    except (zstandard.ZstdError, json.JSONDecodeError) as error:
        raise RuntimeError(f"A220 measurement shard decode failed: {path.name}") from error
    if not isinstance(payload, dict):
        raise RuntimeError(f"A220 measurement shard root is not an object: {path.name}")
    if (
        raw != _canonical_bytes(payload)
        or frame.has_checksum is not True
        or frame.content_size != len(raw)
        or frame.dict_id != 0
        or _compress_measurement(raw) != compressed
    ):
        raise RuntimeError(
            f"A220 measurement shard canonical/zstd-19 frame gate failed: {path.name}"
        )
    protocol = _load_protocol() if protocol is None else protocol
    if orders is None or order_manifests is None:
        design = _import_path(
            ROOT / protocol["anchors"]["factorial_design_path"],
            "a220_verify_shard_factorial_design",
        )
        orders = _operator_orders(protocol, design)
        order_manifests = _order_manifests(design, orders)
    plan = _run_plan(protocol, expected_row, orders)
    expected_plan = [
        {
            key: spec[key]
            for key in (
                "run_id",
                "mode",
                "operator",
                "schedule",
                "conflict_horizons",
                "order_uint8_sha256",
            )
        }
        for spec in plan
    ]
    expected_run_ids = {str(spec["run_id"]) for spec in plan}
    template_protocol = json.loads(
        (ROOT / protocol["anchors"]["symbolic_template_protocol_path"]).read_bytes()
    )["symbolic_R20_template"]
    instantiation_manifest = payload.get("instantiated_CNF_manifest")
    expected_instantiation_fields = {
        "header",
        "bytes",
        "sha256",
        "unit_count",
        "unit_int32le_sha256",
    }
    if (
        not isinstance(instantiation_manifest, dict)
        or set(instantiation_manifest) != expected_instantiation_fields
        or not isinstance(instantiation_manifest.get("header"), str)
        or not _integer(instantiation_manifest.get("bytes"), nonnegative=True)
        or instantiation_manifest["bytes"] <= 0
        or not isinstance(instantiation_manifest.get("sha256"), str)
        or len(instantiation_manifest["sha256"]) != 64
        or instantiation_manifest.get("unit_count") != 512
        or not isinstance(instantiation_manifest.get("unit_int32le_sha256"), str)
        or len(instantiation_manifest["unit_int32le_sha256"]) != 64
    ):
        raise RuntimeError(f"A220 instantiated CNF manifest failed: {path.name}")
    header_fields = instantiation_manifest["header"].split()
    try:
        expected_variables = int(header_fields[2])
        expected_clauses = int(header_fields[3])
    except (IndexError, ValueError) as error:
        raise RuntimeError(f"A220 instantiated CNF header failed: {path.name}") from error
    if (
        len(header_fields) != 4
        or header_fields[:2] != ["p", "cnf"]
        or expected_variables <= 0
        or expected_clauses < 512
    ):
        raise RuntimeError(f"A220 instantiated CNF header failed: {path.name}")
    public = _import_path(
        ROOT / protocol["anchors"]["public_core_adapter_path"],
        "a220_verify_shard_public_core",
    )
    challenge = public.build_known_challenge(
        protocol["public_only_R20_material"], low20=int(expected_row["low20"])
    )
    public_material = protocol["public_only_R20_material"]
    key_words = [
        int(public_material["known_key_word0_upper12"]) | int(expected_row["low20"]),
        *[int(value) for value in public_material["known_key_words_1_through_7"]],
    ]
    expected_confirmation = {
        "generated_block_count": 8,
        "generated_output_bits": 4096,
        "block_sha256": list(challenge["target_block_sha256"]),
        "all_block_hashes_unique": len(set(challenge["target_block_sha256"])) == 8,
        "full_key_words_little_endian_sha256": _sha256(
            b"".join(word.to_bytes(4, "little") for word in key_words)
        ),
        "formula_constrained_block_index": 0,
        "formula_constrained_output_bits": 512,
        "blocks_1_through_7_used_only_for_confirmation_metadata": True,
    }
    completion = payload.get("completion_gates", {})
    scientific_runs = payload.get("scientific_runs")
    provenance_runs = payload.get("deterministic_run_artifact_provenance")
    declared_source_hashes = _declared_source_anchor_hashes(protocol)
    collector_sha256 = payload.get("collector_source_sha256")
    expected_boundary = {
        **protocol["information_boundary"],
        "known_low20_used_for_eight_block_target_construction": True,
        "known_low20_passed_to_solver_order_or_budget": False,
        "historical_result_or_causal_artifact_loaded_during_collection": False,
        "holdout_trajectory_opened_during_fit_select_collection": False,
    }
    expected_top_level_fields = {
        "schema",
        "attempt_id",
        "evidence_stage",
        "protocol_sha256",
        "collector_source_sha256",
        "key_factorial_identity",
        "known_key_confirmation_metadata",
        "public_only_R20_material_sha256",
        "public_core_provenance",
        "source_anchor_hashes",
        "symbolic_template_manifest",
        "instantiated_CNF_manifest",
        "key_mapping_canonical_sha256",
        "native_helper_stable_provenance",
        "operator_order_manifests",
        "run_plan",
        "scientific_runs",
        "deterministic_run_artifact_provenance",
        "append_only_attempt_history_without_wallclock",
        "information_boundary",
        "completion_gates",
    }
    if (
        set(payload) != expected_top_level_fields
        or payload.get("schema") != SHARD_SCHEMA
        or payload.get("attempt_id") != ATTEMPT_ID
        or payload.get("evidence_stage")
        != "FULLROUND_R20_FACTORIAL_FIT_SELECT_TRAJECTORY_COLLECTION"
        or payload.get("protocol_sha256") != PROTOCOL_SHA256
        or not isinstance(collector_sha256, str)
        or len(collector_sha256) != 64
        or (expected_collector_sha256 is not None and collector_sha256 != expected_collector_sha256)
        or payload.get("key_factorial_identity") != dict(expected_row)
        or payload.get("known_key_confirmation_metadata") != expected_confirmation
        or payload.get("public_only_R20_material_sha256")
        != protocol["public_only_R20_material_sha256"]
        or payload.get("source_anchor_hashes") != declared_source_hashes
        or (
            expected_source_anchor_hashes is not None
            and payload.get("source_anchor_hashes") != dict(expected_source_anchor_hashes)
        )
        or payload.get("public_core_provenance") != public.provenance()
        or payload.get("symbolic_template_manifest", {}).get("formula_sha256")
        != template_protocol["formula_sha256"]
        or payload.get("symbolic_template_manifest", {}).get("base_cnf_sha256")
        != template_protocol["base_sha256"]
        or payload.get("symbolic_template_manifest", {}).get("base_body_sha256")
        != template_protocol["base_body_sha256"]
        or payload.get("symbolic_template_manifest", {}).get("mapping_probe_count")
        != template_protocol["mapping_export_count"]
        or payload.get("symbolic_template_manifest", {}).get("key_mapping_sha256")
        != _sha256(
            b"".join(
                int(value).to_bytes(4, "little", signed=True)
                for value in template_protocol["key_one_literals_bit0_through_bit19"]
            )
        )
        or payload.get("symbolic_template_manifest", {}).get("output_mapping_sha256")
        != template_protocol["output_one_literal_matrix_sha256"]
        or payload.get("symbolic_template_manifest", {}).get("all_mapping_probes_exact_unit_deltas")
        is not True
        or not isinstance(payload.get("instantiated_CNF_manifest", {}).get("sha256"), str)
        or len(payload["instantiated_CNF_manifest"]["sha256"]) != 64
        or payload.get("instantiated_CNF_manifest", {}).get("unit_count") != 512
        or not isinstance(payload.get("key_mapping_canonical_sha256"), str)
        or len(payload["key_mapping_canonical_sha256"]) != 64
        or payload["key_mapping_canonical_sha256"]
        != _canonical_sha256(template_protocol["key_one_literals_bit0_through_bit19"])
        or payload.get("native_helper_stable_provenance", {}).get("binary_sha256")
        != protocol["anchors"]["retained_native_binary_sha256"]
        or payload.get("native_helper_stable_provenance", {}).get("source_sha256_started")
        != protocol["anchors"]["retained_native_source_sha256"]
        or payload.get("native_helper_stable_provenance", {}).get("source_sha256_finished")
        != protocol["anchors"]["retained_native_source_sha256"]
        or payload.get("operator_order_manifests") != order_manifests
        or payload.get("run_plan") != expected_plan
        or not isinstance(scientific_runs, dict)
        or set(scientific_runs) != expected_run_ids
        or not isinstance(provenance_runs, dict)
        or set(provenance_runs) != expected_run_ids
        or payload.get("information_boundary") != expected_boundary
    ):
        raise RuntimeError(f"A220 measurement shard completion gate failed: {path.name}")
    for spec in plan:
        run_id = str(spec["run_id"])
        _verify_scientific_run(
            measurement=scientific_runs[run_id],
            provenance=provenance_runs[run_id],
            spec=spec,
            protocol=protocol,
            key_mapping=template_protocol["key_one_literals_bit0_through_bit19"],
            expected_variables=expected_variables,
        )
        if (
            provenance_runs[run_id]["launch_artifact_hashes_started"]["cnf_sha256"]
            != payload["instantiated_CNF_manifest"]["sha256"]
        ):
            raise RuntimeError(f"A220 run/CNF provenance differs: {run_id}")
    _verify_stable_attempt_history(
        payload.get("append_only_attempt_history_without_wallclock"),
        expected_run_ids=expected_run_ids,
    )
    if history_path is not None and payload[
        "append_only_attempt_history_without_wallclock"
    ] != _stable_attempt_history(history_path, row=expected_row, plan=plan):
        raise RuntimeError("A220 shard/sealed attempt-history binding differs")
    if checkpoint_path is not None:
        _verify_checkpoint_binding(
            checkpoint_path,
            payload=payload,
            expected_row=expected_row,
            plan=plan,
        )
    reconstructed_completion = {
        "all_12_runs_complete": len(scientific_runs) == 12,
        "all_12_runs_are_fresh_solver_processes": True,
        "all_3072_cells_complete": sum(len(run["cells"]) for run in scientific_runs.values())
        == 3072,
        "all_retained_state_continuity_verified": all(
            run["retained_state_continuity_verified"] is True for run in scientific_runs.values()
        ),
        "all_watchdogs_clear": all(
            run["all_watchdogs_clear"] is True for run in scientific_runs.values()
        ),
        "all_launch_hashes_pre_post_identical": all(
            run["launch_artifact_hashes_started"] == run["launch_artifact_hashes_finished"]
            for run in provenance_runs.values()
        ),
        "completed_runs_never_reexecuted": True,
        "maximum_concurrent_solver_processes": 2,
        "one_key_instantiated_CNF_active": True,
        "collector_source_unchanged": True,
        "source_anchors_unchanged": True,
        "historical_result_or_causal_artifact_loaded": False,
    }
    if completion != reconstructed_completion:
        raise RuntimeError(f"A220 stored completion gates are not reconstructed: {path.name}")
    return {
        "payload": payload,
        "measurement_sha256": _sha256(raw),
        "measurement_bytes": len(raw),
        "compressed_sha256": _sha256(compressed),
        "compressed_bytes": len(compressed),
    }


def _rebuild_index(
    *,
    rows: Sequence[Mapping[str, Any]],
    shard_directory: Path,
    index_path: Path,
    collector_sha256: str,
    source_anchor_hashes: Mapping[str, str],
    checkpoint_directory: Path | None = None,
    history_path: Path | None = None,
) -> dict[str, Any]:
    shard_directory.mkdir(parents=True, exist_ok=True)
    protocol = _load_protocol()
    design = _import_path(
        ROOT / protocol["anchors"]["factorial_design_path"],
        "a220_rebuild_index_factorial_design",
    )
    orders = _operator_orders(protocol, design)
    order_manifests = _order_manifests(design, orders)
    expected = {str(row["label"]): row for row in rows}
    observed_paths = {path.name: path for path in shard_directory.glob("*.measurement.json.zst")}
    expected_names = {f"{label}.measurement.json.zst" for label in expected}
    unexpected = set(observed_paths) - expected_names
    if unexpected:
        raise RuntimeError(f"A220 shard directory contains unexpected files: {sorted(unexpected)}")
    entries = []
    collector_hashes = set()
    for row in rows:
        name = f"{row['label']}.measurement.json.zst"
        path = observed_paths.get(name)
        if path is None:
            continue
        checkpoint_path = (
            checkpoint_directory / f"{row['label']}.checkpoint.json"
            if checkpoint_directory is not None
            else None
        )
        if checkpoint_path is not None and not checkpoint_path.exists():
            raise RuntimeError(f"A220 verified shard lacks its checkpoint: {row['label']}")
        verified = _verify_shard(
            path,
            expected_row=row,
            protocol=protocol,
            orders=orders,
            order_manifests=order_manifests,
            expected_collector_sha256=collector_sha256,
            expected_source_anchor_hashes=source_anchor_hashes,
            checkpoint_path=checkpoint_path,
            history_path=history_path,
        )
        payload = verified.pop("payload")
        collector_hashes.add(payload["collector_source_sha256"])
        entries.append(
            {
                "key_label": row["label"],
                "prefix_split": row["prefix_split"],
                "prefix_index": row["prefix_index"],
                "suffix_split": row["suffix_split"],
                "suffix_index": row["suffix_index"],
                "relative_path": os.path.relpath(path, index_path.parent),
                **verified,
            }
        )
    if collector_hashes and collector_hashes != {collector_sha256}:
        raise RuntimeError("A220 shards were produced by a different collector source")
    complete = len(entries) == len(rows)
    index = {
        "schema": INDEX_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "collector_source_sha256": collector_sha256,
        "source_anchor_hashes": dict(source_anchor_hashes),
        "factorial_fit_select_label_order_sha256": _canonical_sha256(
            [row["label"] for row in rows]
        ),
        "verified_shards": entries,
        "completion_gates": {
            "verified_key_shards": len(entries),
            "expected_key_shards": len(rows),
            "verified_fresh_solver_processes": len(entries) * 12,
            "expected_fresh_solver_processes": len(rows) * 12,
            "all_52_key_shards_complete": complete and len(rows) == 52,
            "all_624_fresh_solver_processes_complete": complete and len(rows) * 12 == 624,
            "all_shards_decompressed_and_hash_verified": True,
            "global_index_rebuilt_from_verified_shards": True,
            "collector_source_unchanged": _file_sha256(ORCHESTRATOR) == collector_sha256,
        },
    }
    _atomic_json(index_path, index)
    reread = json.loads(index_path.read_bytes())
    if reread != index or _canonical_sha256(reread) != _canonical_sha256(index):
        raise RuntimeError("A220 rebuilt global index verification failed")
    return index


def _collect_key(
    *,
    protocol: Mapping[str, Any],
    row: Mapping[str, Any],
    prepared: Mapping[str, Any],
    orders: Mapping[str, Sequence[str]],
    order_manifests: Mapping[str, Any],
    shard_directory: Path,
    checkpoint_directory: Path,
    volatile_directory: Path,
    history_path: Path,
    collector_sha256: str,
    run_callable: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    _verify_self(collector_sha256)
    if _verify_source_anchors(protocol) != prepared["source_anchor_hashes_started"]:
        raise RuntimeError("A220 source anchors differ before key launch")
    key_prepared = _prepare_key(protocol=protocol, prepared=prepared, row=row)
    plan = _run_plan(protocol, row, orders)
    checkpoint = checkpoint_directory / f"{row['label']}.checkpoint.json"
    shard = shard_directory / f"{row['label']}.measurement.json.zst"
    volatile = volatile_directory / f"{row['label']}.volatile.json"
    try:
        records = _execute_key_runs(
            protocol=protocol,
            row=row,
            prepared=prepared,
            key_prepared=key_prepared,
            plan=plan,
            order_manifests=order_manifests,
            checkpoint_path=checkpoint,
            history_path=history_path,
            collector_sha256=collector_sha256,
            run_callable=run_callable,
        )
        payload, volatile_payload = _assemble_shard(
            protocol=protocol,
            row=row,
            prepared=prepared,
            key_prepared=key_prepared,
            records=records,
            plan=plan,
            order_manifests=order_manifests,
            history_path=history_path,
            collector_sha256=collector_sha256,
        )
        metadata = _write_shard(shard, payload)
        _atomic_json(volatile, volatile_payload, private=True)
        verified = _verify_shard(
            shard,
            expected_row=row,
            protocol=protocol,
            orders=orders,
            order_manifests=order_manifests,
            expected_collector_sha256=collector_sha256,
            expected_source_anchor_hashes=prepared["source_anchor_hashes_started"],
            checkpoint_path=checkpoint,
            history_path=history_path,
        )
        if any(verified[key] != metadata[key] for key in metadata):
            raise RuntimeError("A220 post-write shard metadata differs")
        return metadata
    finally:
        Path(key_prepared["cnf_path"]).unlink(missing_ok=True)


def run(
    *,
    shard_directory: Path = DEFAULT_SHARD_DIRECTORY,
    index_path: Path = DEFAULT_INDEX,
    checkpoint_directory: Path = DEFAULT_CHECKPOINT_DIRECTORY,
    volatile_directory: Path = DEFAULT_VOLATILE_DIRECTORY,
    history_path: Path = DEFAULT_ATTEMPT_HISTORY,
    lock_path: Path = DEFAULT_LOCK,
) -> dict[str, Any]:
    """Collect all 52 fit/select keys, resuming only incomplete fixed runs."""
    protocol = _load_protocol()
    collector_sha256 = _file_sha256(ORCHESTRATOR)
    source_hashes = _verify_source_anchors(protocol)
    anchors = protocol["anchors"]
    design = _import_path(ROOT / anchors["factorial_design_path"], "a220_collect_design_plan")
    rows = _factorial_rows(protocol, design)
    orders = _operator_orders(protocol, design)
    _corpus_plan_identity(protocol, rows, orders)
    manifests = _order_manifests(design, orders)
    with _exclusive_orchestrator_lock(lock_path):
        existing = _rebuild_index(
            rows=rows,
            shard_directory=shard_directory,
            index_path=index_path,
            collector_sha256=collector_sha256,
            source_anchor_hashes=source_hashes,
            checkpoint_directory=checkpoint_directory,
            history_path=history_path,
        )
        if existing["completion_gates"]["all_52_key_shards_complete"]:
            return existing
        with tempfile.TemporaryDirectory(prefix="a220-factorial-collect-") as raw_directory:
            prepared = _prepare_real(protocol, rows, Path(raw_directory))
            for row in rows:
                shard = shard_directory / f"{row['label']}.measurement.json.zst"
                if shard.exists():
                    continue
                _collect_key(
                    protocol=protocol,
                    row=row,
                    prepared=prepared,
                    orders=orders,
                    order_manifests=manifests,
                    shard_directory=shard_directory,
                    checkpoint_directory=checkpoint_directory,
                    volatile_directory=volatile_directory,
                    history_path=history_path,
                    collector_sha256=collector_sha256,
                    run_callable=prepared["run_callable"],
                )
        _verify_self(collector_sha256)
        if _verify_source_anchors(protocol) != source_hashes:
            raise RuntimeError("A220 source anchors differ at corpus completion")
        final = _rebuild_index(
            rows=rows,
            shard_directory=shard_directory,
            index_path=index_path,
            collector_sha256=collector_sha256,
            source_anchor_hashes=source_hashes,
            checkpoint_directory=checkpoint_directory,
            history_path=history_path,
        )
        if not final["completion_gates"]["all_624_fresh_solver_processes_complete"]:
            raise RuntimeError("A220 corpus completion gate failed")
        return final


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shard-directory", type=Path, default=DEFAULT_SHARD_DIRECTORY)
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    parser.add_argument("--checkpoint-directory", type=Path, default=DEFAULT_CHECKPOINT_DIRECTORY)
    parser.add_argument("--volatile-directory", type=Path, default=DEFAULT_VOLATILE_DIRECTORY)
    parser.add_argument("--attempt-history", type=Path, default=DEFAULT_ATTEMPT_HISTORY)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    arguments = parser.parse_args()
    index = run(
        shard_directory=arguments.shard_directory,
        index_path=arguments.index,
        checkpoint_directory=arguments.checkpoint_directory,
        volatile_directory=arguments.volatile_directory,
        history_path=arguments.attempt_history,
        lock_path=arguments.lock,
    )
    print(
        json.dumps(
            {
                "index": str(arguments.index),
                "index_sha256": _file_sha256(arguments.index),
                "verified_key_shards": index["completion_gates"]["verified_key_shards"],
                "all_624_fresh_solver_processes_complete": index["completion_gates"][
                    "all_624_fresh_solver_processes_complete"
                ],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
