#!/usr/bin/env python3
"""Collect the frozen-reader A220 holdout trajectory corpus.

The holdout collector is a measurement-only stage.  It freezes the Reader and
the complete execution plan before any subprocess, then executes only the two
or four runs selected by that Reader.  It never opens the fit/select corpus or
the future prospective target.
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
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
ORCHESTRATOR = Path(__file__).resolve()
TEST_SOURCE = ROOT / "tests/test_chacha20_round20_factorial_trajectory_holdout_collect.py"
PROTOCOL = ROOT / "research/configs/chacha20_round20_factorial_trajectory_transfer_v1.json"
PROTOCOL_SHA256 = "70df07cb4f4f22115e3aa63765de0fca0dd610607cc87356946a188f53fe5645"
LOW_LEVEL_SOURCE = (
    ROOT / "research/experiments/chacha20_round20_factorial_trajectory_collect.py"
)
HOLDOUT_CORE_SOURCE = ROOT / "src/arx_carry_leak/factorial_holdout.py"
HOLDOUT_CORE_TEST = ROOT / "tests/test_factorial_holdout.py"
HOLDOUT_EVALUATOR_SOURCE = (
    ROOT / "research/experiments/chacha20_round20_factorial_trajectory_holdout_evaluate.py"
)
HOLDOUT_EVALUATOR_TEST = (
    ROOT / "tests/test_chacha20_round20_factorial_trajectory_holdout_evaluate.py"
)
HOLDOUT_EVALUATOR_SHA256 = (
    "d3db06f9db83af2103b9761b0c6e7fdcfbd6752ac846e17829d49b5b2607eb5f"
)
HOLDOUT_EVALUATOR_TEST_SHA256 = (
    "24778441af01918737505013fc986b0f199381739d1b34bbcf283b27ebe2b9e6"
)
HOLDOUT_CORE_SHA256 = "d2ab7a8f35a1160f7022f72cdd4ce3e18bb05b8ecd5a06136f8d2f9ea697c411"
HOLDOUT_CORE_TEST_SHA256 = (
    "73b1283c50e5eb9e843b8c9c1e473898738e331e050c6e7995884dfab1974e2d"
)
OUTPUT_ROOT = ROOT / "research/results/v1/chacha20_round20_factorial_trajectory_holdout_v1"
DEFAULT_SHARD_DIRECTORY = OUTPUT_ROOT / "shards"
DEFAULT_INDEX = OUTPUT_ROOT / "index.json"
DEFAULT_LAUNCH_MANIFEST = OUTPUT_ROOT / "launch_manifest.json"
SEALED_ROOT = ROOT / ".research_sealed/chacha20_round20_factorial_trajectory_holdout_v1"
DEFAULT_ATTEMPT_HISTORY = SEALED_ROOT / "attempts.jsonl"
DEFAULT_CHECKPOINT_DIRECTORY = SEALED_ROOT / "checkpoints"
DEFAULT_VOLATILE_DIRECTORY = SEALED_ROOT / "volatile"
LEGACY_SEALED_LAUNCH_MANIFEST = SEALED_ROOT / "launch_manifest.json"
DEFAULT_LOCK = SEALED_ROOT / "orchestrator.lock"

ATTEMPT_ID = "A220"
READER_SCHEMA = "chacha20-round20-factorial-trajectory-reader-v1"
LAUNCH_SCHEMA = "chacha20-round20-factorial-trajectory-holdout-launch-v1"
SHARD_SCHEMA = "chacha20-round20-factorial-trajectory-holdout-measurement-v1"
INDEX_SCHEMA = "chacha20-round20-factorial-trajectory-holdout-index-v1"
CHECKPOINT_SCHEMA = "chacha20-round20-factorial-trajectory-holdout-checkpoint-v1"
ATTEMPT_EVENT_SCHEMA = "chacha20-round20-factorial-trajectory-holdout-attempt-event-v1"
VOLATILE_SCHEMA = "chacha20-round20-factorial-trajectory-holdout-volatile-v1"
EVIDENCE_STAGE = "FULLROUND_R20_FACTORIAL_HOLDOUT_TRAJECTORY_COLLECTION"
HOLDOUT_ROWS_SHA256 = "2fb51de526b8e2c89dfe8f533e3b19c721d749de6ac5488d608d88c1b48524f7"
HOLDOUT_LABEL_ORDER_SHA256 = (
    "317801bcb5b72840dd340b170d7699e929c1399a641a1ec186b83adac6ed89dc"
)
ZSTD_VERSION = "0.25.0"
ZSTD_LEVEL = 19
MAX_WORKERS = 2
WATCHDOG_SECONDS = 5.0
SCHEDULES = {
    "staged_retained_resolve": [8, 16, 32, 64],
    "one_shot": [64],
}
GEOMETRY_OPERATORS = {
    "numeric": ("numeric_forward", "numeric_reverse_same_anchor"),
    "reflected_gray8": (
        "reflected_gray8_forward",
        "reflected_gray8_reverse_same_anchor",
    ),
    "formula_gray8": ("formula_gray8_forward", "formula_gray8_reverse_same_anchor"),
}
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


def _atomic_json(path: Path, value: Any, *, private: bool = False) -> None:
    raw = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()
        + b"\n"
    )
    _atomic_bytes(path, raw, private=private)


def _fsync_existing_file_and_parent(path: Path) -> None:
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
        raise RuntimeError(f"cannot import A220 holdout dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_LOW_LEVEL: Any | None = None


def _low_level() -> Any:
    global _LOW_LEVEL
    if _LOW_LEVEL is None:
        _LOW_LEVEL = _import_path(LOW_LEVEL_SOURCE, "a220_holdout_low_level")
    return _LOW_LEVEL


def _load_protocol() -> dict[str, Any]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A220 frozen protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    holdout = protocol.get("holdout_protocol", {})
    design = protocol.get("factorial_design", {})
    collection = protocol.get("fit_select_collection", {})
    boundary = protocol.get("information_boundary", {})
    compression = protocol.get("shard_protocol", {}).get("compression", {})
    required = protocol.get("required_artifacts", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-factorial-trajectory-transfer-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or holdout.get("execution_starts_only_after_reader_artifact_atomic_write_and_hash_freeze")
        is not True
        or holdout.get("keys") != 92
        or holdout.get("selected_atomic_bundle_runs_per_key") != 2
        or holdout.get("selected_dual_schedule_bundle_runs_per_key") != 4
        or holdout.get("only_frozen_bundle_orders_and_schedules_executed") is not True
        or holdout.get("refit_reselection_or_threshold_change_permitted") is not False
        or holdout.get("panels")
        != ["fit_by_confirm", "select_by_confirm", "confirm_by_fit", "confirm_by_confirm"]
        or design.get("full_ledger_rows") != 144
        or design.get("fit_select_rows") != 52
        or design.get("holdout_rows") != 92
        or design.get("holdout_panels")
        != {
            "fit_by_confirm": 32,
            "select_by_confirm": 20,
            "confirm_by_fit": 20,
            "confirm_by_confirm": 20,
        }
        or collection.get("maximum_concurrent_solver_processes") != MAX_WORKERS
        or collection.get("one_key_instantiated_CNF_active_at_a_time") is not True
        or collection.get("watchdog_seconds_per_stage") != WATCHDOG_SECONDS
        or collection.get("complete_prefix_cover_per_run") is not True
        or collection.get("early_stop") is not False
        or collection.get("schedules") != SCHEDULES
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
        or boundary.get("known_low20_label_passed_to_formula_solver_order_or_budget") is not False
        or boundary.get("known_low20_used_only_for_eight_block_target_construction_and_separate_reader_label")
        is not True
        or boundary.get("future_prospective_target_generated_or_opened_in_A220") is not False
        or required.get("reader_freeze")
        != "research/results/v1/chacha20_round20_factorial_trajectory_reader_freeze_v1.json"
        or required.get("holdout_index")
        != "research/results/v1/chacha20_round20_factorial_trajectory_holdout_v1/index.json"
    ):
        raise RuntimeError("A220 frozen holdout protocol semantic gate failed")
    return protocol


def _declared_source_anchor_hashes(protocol: Mapping[str, Any]) -> dict[str, str]:
    anchors = protocol["anchors"]
    declared = {
        str(anchors[path_key]): str(anchors[hash_key])
        for path_key, hash_key in SOURCE_ANCHOR_PAIRS
    }
    if any(path.startswith("research/results/") or path.endswith(".causal") for path in declared):
        raise RuntimeError("A220 holdout source anchors contain a forbidden artifact")
    return declared


def _verify_source_anchors(protocol: Mapping[str, Any]) -> dict[str, str]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A220 protocol changed during holdout collection")
    declared = _declared_source_anchor_hashes(protocol)
    observed = {relative: _file_sha256(ROOT / relative) for relative in declared}
    if observed != declared:
        raise RuntimeError("A220 holdout source anchor drift")
    if (
        _file_sha256(HOLDOUT_CORE_SOURCE) != HOLDOUT_CORE_SHA256
        or _file_sha256(HOLDOUT_CORE_TEST) != HOLDOUT_CORE_TEST_SHA256
        or _file_sha256(HOLDOUT_EVALUATOR_SOURCE) != HOLDOUT_EVALUATOR_SHA256
        or _file_sha256(HOLDOUT_EVALUATOR_TEST) != HOLDOUT_EVALUATOR_TEST_SHA256
    ):
        raise RuntimeError("A220 holdout core/evaluator anchor drift")
    return observed


def _required_reader_path(protocol: Mapping[str, Any]) -> Path:
    path = ROOT / str(protocol["required_artifacts"]["reader_freeze"])
    old_default = ROOT / "research/results/v1/chacha20_round20_factorial_trajectory_reader_v1.json"
    if path == old_default or path.name != "chacha20_round20_factorial_trajectory_reader_freeze_v1.json":
        raise RuntimeError("A220 holdout protocol names the mismatched old Reader path")
    return path


def _validate_selected_identity(reader: Mapping[str, Any]) -> dict[str, Any]:
    selected = reader.get("selected_reader", {})
    identity = selected.get("selected_identity") if isinstance(selected, Mapping) else None
    if not isinstance(identity, dict) or set(identity) != {
        "bundle_id",
        "feature_family",
        "readout_kind",
        "ridge_lambda",
        "run_count",
    }:
        raise RuntimeError("A220 frozen Reader selected identity schema differs")
    bundle = identity.get("bundle_id")
    geometry: str
    schedule: str | None
    if isinstance(bundle, str) and bundle.endswith("__dual_schedule"):
        geometry = bundle.removesuffix("__dual_schedule")
        schedule = None
        expected_runs = 4
        expected_constituents = {
            f"{geometry}__staged_retained_resolve",
            f"{geometry}__one_shot",
        }
    elif isinstance(bundle, str) and "__" in bundle:
        geometry, schedule = bundle.split("__", 1)
        expected_runs = 2
        expected_constituents = {bundle}
    else:
        raise RuntimeError("A220 frozen Reader bundle identity differs")
    if (
        geometry not in GEOMETRY_OPERATORS
        or schedule not in {None, *SCHEDULES}
        or identity.get("run_count") != expected_runs
        or identity.get("feature_family")
        not in {"P1_dense_local", "P2_dense_cross", "P3_dense_cube", "P4_dense_path", "P5_dense_all"}
        or identity.get("readout_kind") not in {"ridge_logistic", "gram_wiener_fisher"}
        or identity.get("ridge_lambda") not in {0.01, 0.1, 1.0, 10.0, 100.0}
    ):
        raise RuntimeError("A220 frozen Reader selected identity is outside the frozen grid")
    readouts = selected.get("selected_constituent_readouts")
    if not isinstance(readouts, dict) or set(readouts) != expected_constituents:
        raise RuntimeError("A220 frozen Reader constituent readout set differs")
    reader_core = _import_path(
        ROOT / "src/arx_carry_leak/factorial_trajectory.py",
        "a220_holdout_reader_schema_core",
    )
    try:
        restored = [reader_core.readout_from_dict(value) for value in readouts.values()]
    except (TypeError, ValueError) as error:
        raise RuntimeError("A220 frozen Reader constituent readout is malformed") from error
    if any(
        value.kind != identity["readout_kind"]
        or value.feature_family != identity["feature_family"]
        or value.ridge_lambda != identity["ridge_lambda"]
        for value in restored
    ):
        raise RuntimeError("A220 frozen Reader constituent readout identity differs")
    return dict(identity)


def _load_reader(
    protocol: Mapping[str, Any],
    *,
    reader_path: Path | None = None,
    required_path: Path | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    authoritative = _required_reader_path(protocol) if required_path is None else required_path
    path = authoritative if reader_path is None else reader_path
    if path.resolve() != authoritative.resolve():
        raise RuntimeError("A220 holdout refuses a non-authoritative Reader path")
    raw = path.read_bytes()
    reader = json.loads(raw)
    boundary = reader.get("information_boundary", {}) if isinstance(reader, dict) else {}
    completion = reader.get("completion_gates", {}) if isinstance(reader, dict) else {}
    expected_top_fields = {
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
    expected_boundary = {
        "fit_select_measurements_loaded": True,
        "holdout_measurements_loaded": False,
        "future_prospective_target_loaded": False,
        "target_labels_used_for_fit": "32_fit_prefix_labels_only",
        "target_labels_used_for_selection": "20_selection_prefix_labels_only",
        "suffix_specific_target_floor_or_key_suffix_feature_used": False,
        "reader_frozen_before_any_holdout_trajectory_process": True,
    }
    expected_completion_fields = {
        "all_52_fit_select_shards_verified",
        "all_624_fresh_solver_processes_in_verified_index",
        "exactly_300_atomic_models_fit",
        "exactly_450_bundle_rows_evaluated",
        "all_64_matched_cluster_nulls_complete",
        "reader_resume_checkpoint_verified",
        "one_reader_selected_and_serialized",
        "reader_source_unchanged",
        "holdout_trajectory_not_opened",
        "future_prospective_target_not_opened",
    }
    selected = reader.get("selected_reader", {}) if isinstance(reader, dict) else {}
    input_manifest = reader.get("fit_select_input_manifest") if isinstance(reader, dict) else None
    observed_grid = reader.get("observed_candidate_grid") if isinstance(reader, dict) else None
    matched_null = reader.get("selection_matched_null", {}) if isinstance(reader, dict) else {}
    if (
        not isinstance(reader, dict)
        or set(reader) != expected_top_fields
        or reader.get("schema") != READER_SCHEMA
        or reader.get("attempt_id") != ATTEMPT_ID
        or reader.get("evidence_stage")
        != "FULLROUND_R20_FACTORIAL_READER_FROZEN_BEFORE_HOLDOUT"
        or reader.get("protocol_sha256") != PROTOCOL_SHA256
        or reader.get("reader_runner_sha256")
        != protocol["anchors"]["factorial_trajectory_reader_runner_sha256"]
        or reader.get("factorial_trajectory_reader_sha256")
        != protocol["anchors"]["factorial_trajectory_reader_sha256"]
        or reader.get("ridge_backend_sha256") != protocol["anchors"]["ridge_backend_sha256"]
        or any(
            not isinstance(reader.get(field), str) or len(reader[field]) != 64
            for field in (
                "reader_checkpoint_sha256",
                "collector_source_sha256",
                "fit_select_index_sha256",
            )
        )
        or not isinstance(input_manifest, list)
        or len(input_manifest) != 52
        or reader.get("fit_select_input_manifest_sha256")
        != _canonical_sha256(input_manifest)
        or not isinstance(reader.get("feature_matrix_sha256"), dict)
        or reader.get("fit_panel", {}).get("keys") != 32
        or reader.get("fit_panel", {}).get("cell_rows") != 8192
        or reader.get("selection_panel", {}).get("keys") != 20
        or reader.get("selection_panel", {}).get("cell_rows") != 5120
        or reader.get("grid_definition", {}).get("atomic_models") != 300
        or reader.get("grid_definition", {}).get("bundle_rows") != 450
        or not isinstance(observed_grid, list)
        or len(observed_grid) != 450
        or not isinstance(selected, dict)
        or set(selected)
        != {
            "selected_identity",
            "selected_metrics",
            "selected_score_sha256",
            "selected_constituent_readouts",
            "candidate_grid_sha256",
        }
        or selected.get("candidate_grid_sha256") != _canonical_sha256(observed_grid)
        or not isinstance(selected.get("selected_metrics"), dict)
        or not isinstance(selected.get("selected_score_sha256"), str)
        or len(selected["selected_score_sha256"]) != 64
        or matched_null.get("seed_label")
        != protocol["selection_matched_null"]["seed_label"]
        or matched_null.get("permutation_pairs_sha256")
        != protocol["selection_matched_null"]["permutation_pairs_sha256"]
        or not isinstance(matched_null.get("replicates"), list)
        or len(matched_null["replicates"]) != 64
        or boundary != expected_boundary
        or set(completion) != expected_completion_fields
        or not all(value is True for value in completion.values())
    ):
        raise RuntimeError("A220 frozen Reader schema/completion/information gate failed")
    identity = _validate_selected_identity(reader)
    readout_material = {
        "selected_identity": identity,
        "selected_constituent_readouts": reader["selected_reader"][
            "selected_constituent_readouts"
        ],
        "selected_score_sha256": reader["selected_reader"].get("selected_score_sha256"),
    }
    return reader, {
        "reader_artifact_sha256": _sha256(raw),
        "selected_identity_sha256": _canonical_sha256(identity),
        "selected_readout_sha256": _canonical_sha256(readout_material),
    }


def _holdout_rows(protocol: Mapping[str, Any], design: Any) -> list[dict[str, Any]]:
    ledger = design.factorial_ledger()
    forbidden = protocol["factorial_design"]["prior_key_exclusion"]["sorted_low20"]
    design.validate_factorial_ledger(ledger, forbidden_low20=forbidden)
    fit_select = [
        dict(row)
        for row in ledger
        if row["prefix_split"] in {"fit", "select"} and row["suffix_split"] == "fit"
    ]
    rows = [dict(row) for row in ledger if row not in fit_select]
    panels = {
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
    }
    if (
        len(ledger) != 144
        or len(fit_select) != 52
        or len(rows) != 92
        or {row["label"] for row in fit_select} & {row["label"] for row in rows}
        or [*fit_select, *rows] == ledger
        or {row["label"] for row in fit_select} | {row["label"] for row in rows}
        != {row["label"] for row in ledger}
        or panels != protocol["factorial_design"]["holdout_panels"]
        or _canonical_sha256(rows) != HOLDOUT_ROWS_SHA256
        or _canonical_sha256([row["label"] for row in rows]) != HOLDOUT_LABEL_ORDER_SHA256
        or design.ledger_sha256(ledger) != protocol["factorial_design"]["full_ledger_sha256"]
    ):
        raise RuntimeError("A220 exact 92-row holdout partition/order gate failed")
    return rows


def _operator_orders(protocol: Mapping[str, Any], design: Any) -> dict[str, list[str]]:
    integer_orders = design.operator_orders()
    manifests = design.order_manifest()
    if (
        list(integer_orders) != protocol["fit_select_collection"]["orders"]
        or _canonical_sha256(manifests)
        != protocol["factorial_design"]["operator_order_manifest_sha256"]
    ):
        raise RuntimeError("A220 frozen operator order manifest differs")
    return {name: [f"{value:08b}" for value in order] for name, order in integer_orders.items()}


def _selected_plan_template(
    identity: Mapping[str, Any], orders: Mapping[str, Sequence[str]]
) -> list[dict[str, Any]]:
    bundle = str(identity["bundle_id"])
    if bundle.endswith("__dual_schedule"):
        geometry = bundle.removesuffix("__dual_schedule")
        schedule_names = ("staged_retained_resolve", "one_shot")
    else:
        geometry, selected_schedule = bundle.split("__", 1)
        schedule_names = (selected_schedule,)
    if geometry not in GEOMETRY_OPERATORS or any(name not in SCHEDULES for name in schedule_names):
        raise RuntimeError("A220 Reader selected a non-frozen holdout plan")
    result = []
    for schedule in schedule_names:
        for operator in GEOMETRY_OPERATORS[geometry]:
            order = list(orders[operator])
            result.append(
                {
                    "run_id": f"{operator}__{schedule}",
                    "operator": operator,
                    "schedule": schedule,
                    "conflict_horizons": list(SCHEDULES[schedule]),
                    "order": order,
                    "order_uint8_sha256": _sha256(bytes(int(value, 2) for value in order)),
                }
            )
    if len(result) != int(identity["run_count"]) or len({row["run_id"] for row in result}) != len(result):
        raise RuntimeError("A220 selected holdout plan run count differs")
    return result


def _run_plan(
    row: Mapping[str, Any], template: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    return [
        {
            **dict(spec),
            "mode": f"A220_HOLDOUT_{row['label']}_{spec['operator']}_{spec['schedule']}",
        }
        for spec in template
    ]


def _plan_identity(plan: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
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


def _launch_manifest_candidate(
    *,
    protocol: Mapping[str, Any],
    reader_path: Path,
    reader: Mapping[str, Any],
    reader_hashes: Mapping[str, str],
    rows: Sequence[Mapping[str, Any]],
    design: Any,
    plan_template: Sequence[Mapping[str, Any]],
    source_hashes: Mapping[str, str],
) -> dict[str, Any]:
    full_plan = [
        {"key_label": row["label"], **item}
        for row in rows
        for item in _plan_identity(_run_plan(row, plan_template))
    ]
    collector_sha = _file_sha256(ORCHESTRATOR)
    test_sha = _file_sha256(TEST_SOURCE)
    low_level_sha = _file_sha256(LOW_LEVEL_SOURCE)
    selected = reader["selected_reader"]["selected_identity"]
    return {
        "schema": LAUNCH_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "HOLDOUT_READER_AND_PLAN_FROZEN_BEFORE_ANY_SUBPROCESS",
        "protocol_path": os.path.relpath(PROTOCOL, ROOT),
        "protocol_sha256": PROTOCOL_SHA256,
        "reader_path": os.path.relpath(reader_path, ROOT),
        **dict(reader_hashes),
        "selected_reader_identity": selected,
        "collector_source_sha256": collector_sha,
        "collector_test_sha256": test_sha,
        "low_level_source_sha256": low_level_sha,
        "holdout_core_path": os.path.relpath(HOLDOUT_CORE_SOURCE, ROOT),
        "holdout_core_sha256": HOLDOUT_CORE_SHA256,
        "holdout_core_test_path": os.path.relpath(HOLDOUT_CORE_TEST, ROOT),
        "holdout_core_test_sha256": HOLDOUT_CORE_TEST_SHA256,
        "holdout_evaluator_source_sha256": HOLDOUT_EVALUATOR_SHA256,
        "holdout_evaluator_test_sha256": HOLDOUT_EVALUATOR_TEST_SHA256,
        "factorial_design_path": protocol["anchors"]["factorial_design_path"],
        "factorial_design_sha256": protocol["anchors"]["factorial_design_sha256"],
        "factorial_ledger_sha256": design.ledger_sha256(),
        "holdout_rows": len(rows),
        "holdout_rows_sha256": _canonical_sha256(rows),
        "holdout_label_order_sha256": _canonical_sha256([row["label"] for row in rows]),
        "holdout_labels": [row["label"] for row in rows],
        "selected_run_plan": _plan_identity(_run_plan(rows[0], plan_template)),
        "selected_run_plan_template_sha256": _canonical_sha256(list(plan_template)),
        "full_holdout_process_plan_sha256": _canonical_sha256(full_plan),
        "full_holdout_fresh_solver_processes": len(full_plan),
        "source_anchor_hashes": dict(source_hashes),
        "resource_settings": {
            "maximum_concurrent_solver_processes": MAX_WORKERS,
            "one_key_instantiated_CNF_active_at_a_time": True,
            "watchdog_seconds_per_stage": WATCHDOG_SECONDS,
            "cell_count_per_run": 256,
            "complete_prefix_cover_per_run": True,
            "early_stop": False,
            "schedules": SCHEDULES,
            "zstandard_version": ZSTD_VERSION,
            "zstandard_level": ZSTD_LEVEL,
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


def _freeze_launch_manifest(path: Path, candidate: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    value = dict(candidate)
    if path.exists():
        observed = json.loads(path.read_bytes())
        if observed != value:
            raise RuntimeError("A220 holdout launch manifest differs from the frozen launch")
    else:
        _atomic_json(path, value, private=True)
    raw = path.read_bytes()
    reread = json.loads(raw)
    if reread != value or _canonical_sha256(reread) != _canonical_sha256(value):
        raise RuntimeError("A220 holdout launch manifest atomic readback differs")
    if LEGACY_SEALED_LAUNCH_MANIFEST.exists():
        legacy = json.loads(LEGACY_SEALED_LAUNCH_MANIFEST.read_bytes())
        if legacy != value:
            raise RuntimeError("A220 holdout conflicting legacy sealed launch manifest exists")
    return reread, _sha256(raw)


def _verify_launch_binding(
    *,
    protocol: Mapping[str, Any],
    manifest_path: Path,
    expected_manifest: Mapping[str, Any],
    expected_manifest_sha256: str,
    reader_path: Path,
) -> None:
    if (
        _file_sha256(ORCHESTRATOR) != expected_manifest["collector_source_sha256"]
        or _file_sha256(TEST_SOURCE) != expected_manifest["collector_test_sha256"]
        or _file_sha256(LOW_LEVEL_SOURCE) != expected_manifest["low_level_source_sha256"]
        or _file_sha256(HOLDOUT_CORE_SOURCE) != expected_manifest["holdout_core_sha256"]
        or _file_sha256(HOLDOUT_CORE_TEST) != expected_manifest["holdout_core_test_sha256"]
        or _file_sha256(HOLDOUT_EVALUATOR_SOURCE)
        != expected_manifest["holdout_evaluator_source_sha256"]
        or _file_sha256(HOLDOUT_EVALUATOR_TEST)
        != expected_manifest["holdout_evaluator_test_sha256"]
        or _file_sha256(reader_path) != expected_manifest["reader_artifact_sha256"]
        or _file_sha256(manifest_path) != expected_manifest_sha256
        or json.loads(manifest_path.read_bytes()) != dict(expected_manifest)
        or (
            LEGACY_SEALED_LAUNCH_MANIFEST.exists()
            and json.loads(LEGACY_SEALED_LAUNCH_MANIFEST.read_bytes())
            != dict(expected_manifest)
        )
        or _verify_source_anchors(protocol) != expected_manifest["source_anchor_hashes"]
    ):
        raise RuntimeError("A220 holdout launch/source/Reader binding drifted")


@contextmanager
def _exclusive_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        path.chmod(0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("another A220 holdout collector holds the launch lock") from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _prepare_real(
    protocol: Mapping[str, Any], rows: Sequence[Mapping[str, Any]], directory: Path
) -> dict[str, Any]:
    """Use only the frozen collector's low-level template/helper preparation."""

    prepared = _low_level()._prepare_real(protocol, rows, directory)
    if prepared.get("source_anchor_hashes_started") != _verify_source_anchors(protocol):
        raise RuntimeError("A220 holdout low-level preparation source view differs")
    return prepared


def _prepare_key(
    *, protocol: Mapping[str, Any], prepared: Mapping[str, Any], row: Mapping[str, Any]
) -> dict[str, Any]:
    return _low_level()._prepare_key(protocol=protocol, prepared=prepared, row=row)


def _external_timeout(stage_count: int) -> float:
    return 120.0 + 256.0 * stage_count * WATCHDOG_SECONDS


def _artifact_hashes(
    *,
    protocol: Mapping[str, Any],
    prepared: Mapping[str, Any],
    key_prepared: Mapping[str, Any],
    reader_path: Path,
    launch_manifest_path: Path,
) -> dict[str, str]:
    paths = {
        "collector_sha256": ORCHESTRATOR,
        "collector_test_sha256": TEST_SOURCE,
        "protocol_sha256": PROTOCOL,
        "reader_sha256": reader_path,
        "launch_manifest_sha256": launch_manifest_path,
        "low_level_source_sha256": LOW_LEVEL_SOURCE,
        "wrapper_sha256": ROOT / protocol["anchors"]["retained_wrapper_path"],
        "source_sha256": ROOT / protocol["anchors"]["retained_native_source_path"],
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


def _invoke_run(
    *,
    run_callable: Callable[..., dict[str, Any]],
    prepared: Mapping[str, Any],
    key_prepared: Mapping[str, Any],
    spec: Mapping[str, Any],
) -> dict[str, Any]:
    return run_callable(
        helper=prepared["helper_path"],
        cnf=key_prepared["cnf_path"],
        mode=spec["mode"],
        order=spec["order"],
        key_one_literals_bit0_through_bit19=prepared["key_mapping"],
        conflict_horizons=spec["conflict_horizons"],
        watchdog_seconds=WATCHDOG_SECONDS,
        external_timeout_seconds=_external_timeout(len(spec["conflict_horizons"])),
    )


def _record_run(
    *,
    raw: Mapping[str, Any],
    spec: Mapping[str, Any],
    protocol: Mapping[str, Any],
    prepared: Mapping[str, Any],
    key_prepared: Mapping[str, Any],
    attempt: Mapping[str, Any],
) -> dict[str, Any]:
    return _low_level()._record_run(
        raw=raw,
        spec=spec,
        protocol=protocol,
        prepared=prepared,
        key_prepared=key_prepared,
        attempt=attempt,
    )


def _checkpoint_identity(
    *,
    row: Mapping[str, Any],
    prepared: Mapping[str, Any],
    key_prepared: Mapping[str, Any],
    plan: Sequence[Mapping[str, Any]],
    selected_order_manifests: Mapping[str, Any],
    collector_sha256: str,
    collector_test_sha256: str,
    launch_manifest_sha256: str,
    reader_hashes: Mapping[str, str],
) -> dict[str, Any]:
    return {
        "schema": CHECKPOINT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "HOLDOUT",
        "protocol_sha256": PROTOCOL_SHA256,
        "collector_source_sha256": collector_sha256,
        "collector_test_sha256": collector_test_sha256,
        "launch_manifest_sha256": launch_manifest_sha256,
        **dict(reader_hashes),
        "key_factorial_identity_sha256": _canonical_sha256(row),
        "source_anchor_hashes": prepared["source_anchor_hashes_started"],
        "helper_sha256": prepared["helper_sha256"],
        "native_helper_stable_provenance_sha256": _canonical_sha256(
            prepared["native_helper_stable_provenance"]
        ),
        "base_cnf_sha256": prepared["template_manifest"]["base_cnf_sha256"],
        "symbolic_template_manifest_sha256": _canonical_sha256(prepared["template_manifest"]),
        "instantiated_cnf_sha256": key_prepared["cnf_sha256"],
        "instantiation_manifest_sha256": _canonical_sha256(
            key_prepared["instantiation_manifest"]
        ),
        "known_key_confirmation_metadata_sha256": _canonical_sha256(
            key_prepared["known_key_confirmation_metadata"]
        ),
        "key_mapping_sha256": _canonical_sha256(prepared["key_mapping"]),
        "selected_order_manifests_sha256": _canonical_sha256(selected_order_manifests),
        "run_plan_sha256": _canonical_sha256(_plan_identity(plan)),
    }


def _load_checkpoint(
    path: Path, *, identity: Mapping[str, Any], valid_run_ids: set[str]
) -> dict[str, Any]:
    if not path.exists():
        return {**dict(identity), "completed_runs": {}}
    checkpoint = json.loads(path.read_bytes())
    if (
        not isinstance(checkpoint, dict)
        or set(checkpoint) != {*identity, "completed_runs"}
        or any(checkpoint.get(key) != value for key, value in identity.items())
        or not isinstance(checkpoint.get("completed_runs"), dict)
        or not set(checkpoint["completed_runs"]).issubset(valid_run_ids)
    ):
        raise RuntimeError("A220 holdout per-key checkpoint identity differs")
    for run_id, record in checkpoint["completed_runs"].items():
        if not isinstance(record, dict):
            raise RuntimeError("A220 holdout checkpoint completed record is malformed")
        stored = record.get("checkpoint_record_sha256")
        unhashed = {key: value for key, value in record.items() if key != "checkpoint_record_sha256"}
        if record.get("run_id") != run_id or stored != _canonical_sha256(unhashed):
            raise RuntimeError(f"A220 holdout checkpoint record hash differs: {run_id}")
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
    events: list[dict[str, Any]] = []
    previous = None
    lines = raw.splitlines()
    cursor = 0
    while cursor < len(lines):
        line = lines[cursor]
        if not line:
            raise RuntimeError("A220 holdout attempt history contains an empty record")
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
                        "A220 holdout attempt history has an unrecovered torn tail"
                    ) from error
                raise RuntimeError(
                    "A220 holdout attempt history has non-final semantic corruption"
                ) from error
        stored = event.get("event_sha256")
        unhashed = {key: value for key, value in event.items() if key != "event_sha256"}
        if (
            event.get("schema") != ATTEMPT_EVENT_SCHEMA
            or event.get("event_index") != len(events)
            or event.get("previous_event_sha256") != previous
            or stored != _canonical_sha256(unhashed)
        ):
            raise RuntimeError(
                f"A220 holdout attempt history chain differs at event {len(events)}"
            )
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
    events = _parse_attempt_history(prefix + separator if separator else b"")
    if not fragment:
        return
    recovery = {
        "schema": ATTEMPT_EVENT_SCHEMA,
        "event_index": len(events),
        "previous_event_sha256": events[-1]["event_sha256"] if events else None,
        "event_type": "attempt_history_torn_tail_recovery",
        "protocol_sha256": PROTOCOL_SHA256,
        "evidence_stage": "HOLDOUT",
        "recovered_fragment_sha256": _sha256(fragment),
        "recovered_fragment_bytes": len(fragment),
        "recovery_semantics": "append_only_preservation_of_unterminated_final_fragment",
    }
    recovery["event_sha256"] = _canonical_sha256(recovery)
    _atomic_bytes(path, raw + b"\n" + _canonical_bytes(recovery) + b"\n", private=True)


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
        raise RuntimeError("A220 holdout attempt history append readback failed")
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
    launch_manifest_sha256: str,
) -> dict[str, Any]:
    prior = _events_for_run(
        _read_attempt_history(history_path),
        key_label=str(row["label"]),
        run_id=str(spec["run_id"]),
    )
    starts = [event for event in prior if event["event_type"] == "run_attempt_started"]
    terminals = [
        event
        for event in prior
        if event["event_type"] in {"run_attempt_completed", "run_attempt_tombstone"}
    ]
    attempt_number = len(starts) + 1
    identity = {
        "protocol_sha256": PROTOCOL_SHA256,
        "launch_manifest_sha256": launch_manifest_sha256,
        "evidence_stage": "HOLDOUT",
        "reader_frozen_before_holdout": True,
        "key_label": row["label"],
        "run_id": spec["run_id"],
        "attempt_number": attempt_number,
        "prior_started_attempts": len(starts),
        "prior_terminal_attempts": len(terminals),
    }
    return _append_attempt_event(
        history_path,
        {
            "event_type": "run_attempt_started",
            **identity,
            "attempt_id": _canonical_sha256(identity),
            "run_spec_sha256": _canonical_sha256(_plan_identity([spec])[0]),
            "retry_claim": {
                "is_retry": bool(starts),
                "derived_from_prior_started_attempts": len(starts),
                "derived_from_prior_terminal_attempts": len(terminals),
            },
            "artifact_hashes_started": dict(artifact_hashes),
        },
    )


def _append_completion(
    history_path: Path,
    *,
    row: Mapping[str, Any],
    spec: Mapping[str, Any],
    attempt: Mapping[str, Any],
    record: Mapping[str, Any],
    launch_manifest_sha256: str,
    recovered: bool = False,
) -> dict[str, Any]:
    return _append_attempt_event(
        history_path,
        {
            "event_type": "run_attempt_completed",
            "protocol_sha256": PROTOCOL_SHA256,
            "launch_manifest_sha256": launch_manifest_sha256,
            "evidence_stage": "HOLDOUT",
            "reader_frozen_before_holdout": True,
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
    launch_manifest_sha256: str,
    reason: str,
    returncode_override: int | None = None,
) -> dict[str, Any]:
    returncode = returncode_override
    if returncode is None:
        returncode = getattr(error, "returncode", None)
    if not isinstance(returncode, int) or isinstance(returncode, bool):
        returncode = None
    return _append_attempt_event(
        history_path,
        {
            "event_type": "run_attempt_tombstone",
            "protocol_sha256": PROTOCOL_SHA256,
            "launch_manifest_sha256": launch_manifest_sha256,
            "evidence_stage": "HOLDOUT",
            "reader_frozen_before_holdout": True,
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
    launch_manifest_sha256: str,
) -> None:
    events = _read_attempt_history(history_path)
    for spec in plan:
        run_id = str(spec["run_id"])
        run_events = _events_for_run(events, key_label=str(row["label"]), run_id=run_id)
        starts = {
            str(event["attempt_id"]): event
            for event in run_events
            if event["event_type"] == "run_attempt_started"
        }
        completed_events = [
            event for event in run_events if event["event_type"] == "run_attempt_completed"
        ]
        completed_ids = {str(event["attempt_id"]) for event in completed_events}
        tombstoned_ids = {
            str(event["attempt_id"])
            for event in run_events
            if event["event_type"] == "run_attempt_tombstone"
        }
        record = checkpoint["completed_runs"].get(run_id)
        if len(completed_events) > 1:
            raise RuntimeError(f"A220 holdout completed run was reexecuted: {run_id}")
        if record is None and completed_events:
            raise RuntimeError(f"A220 holdout completed checkpoint is missing: {run_id}")
        if record is not None and record["attempt_id"] not in starts:
            raise RuntimeError(f"A220 holdout completed checkpoint lacks start: {run_id}")
        if record is not None and record["attempt_id"] in tombstoned_ids:
            raise RuntimeError(f"A220 holdout completed attempt is tombstoned: {run_id}")
        if record is not None and record["attempt_id"] not in completed_ids:
            _append_completion(
                history_path,
                row=row,
                spec=spec,
                attempt=starts[record["attempt_id"]],
                record=record,
                launch_manifest_sha256=launch_manifest_sha256,
                recovered=True,
            )
        events = _read_attempt_history(history_path)
        run_events = _events_for_run(events, key_label=str(row["label"]), run_id=run_id)
        terminal_ids = {
            str(event["attempt_id"])
            for event in run_events
            if event["event_type"] in {"run_attempt_completed", "run_attempt_tombstone"}
        }
        for attempt_id, start in starts.items():
            if attempt_id in terminal_ids:
                continue
            if record is not None and record["attempt_id"] == attempt_id:
                _append_completion(
                    history_path,
                    row=row,
                    spec=spec,
                    attempt=start,
                    record=record,
                    launch_manifest_sha256=launch_manifest_sha256,
                    recovered=True,
                )
            else:
                _append_tombstone(
                    history_path,
                    row=row,
                    spec=spec,
                    attempt=start,
                    error=RuntimeError("prior holdout orchestrator ended before terminal event"),
                    artifact_hashes=artifact_hashes,
                    launch_manifest_sha256=launch_manifest_sha256,
                    reason="orchestrator_interruption_detected_before_fixed_resume",
                )
        events = _read_attempt_history(history_path)


def _execute_key_runs(
    *,
    protocol: Mapping[str, Any],
    row: Mapping[str, Any],
    prepared: Mapping[str, Any],
    key_prepared: Mapping[str, Any],
    plan: Sequence[Mapping[str, Any]],
    selected_order_manifests: Mapping[str, Any],
    checkpoint_path: Path,
    history_path: Path,
    collector_sha256: str,
    collector_test_sha256: str,
    launch_manifest_sha256: str,
    reader_hashes: Mapping[str, str],
    reader_path: Path,
    launch_manifest_path: Path,
    run_callable: Callable[..., dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    identity = _checkpoint_identity(
        row=row,
        prepared=prepared,
        key_prepared=key_prepared,
        plan=plan,
        selected_order_manifests=selected_order_manifests,
        collector_sha256=collector_sha256,
        collector_test_sha256=collector_test_sha256,
        launch_manifest_sha256=launch_manifest_sha256,
        reader_hashes=reader_hashes,
    )
    checkpoint = _load_checkpoint(
        checkpoint_path,
        identity=identity,
        valid_run_ids={str(spec["run_id"]) for spec in plan},
    )

    def artifacts() -> dict[str, str]:
        return _artifact_hashes(
            protocol=protocol,
            prepared=prepared,
            key_prepared=key_prepared,
            reader_path=reader_path,
            launch_manifest_path=launch_manifest_path,
        )

    _reconcile_attempt_history(
        history_path=history_path,
        row=row,
        plan=plan,
        checkpoint=checkpoint,
        artifact_hashes=artifacts(),
        launch_manifest_sha256=launch_manifest_sha256,
    )
    completed: dict[str, dict[str, Any]] = checkpoint["completed_runs"]
    pending = [spec for spec in plan if spec["run_id"] not in completed]
    if not pending:
        return completed

    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="a220-holdout")
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
            artifact_hashes=artifacts(),
            launch_manifest_sha256=launch_manifest_sha256,
        )
        try:
            future = executor.submit(
                _invoke_run,
                run_callable=run_callable,
                prepared=prepared,
                key_prepared=key_prepared,
                spec=spec,
            )
        except BaseException as error:
            _append_tombstone(
                history_path,
                row=row,
                spec=spec,
                attempt=attempt,
                error=error,
                artifact_hashes=artifacts(),
                launch_manifest_sha256=launch_manifest_sha256,
                reason="solver_process_submission_failed",
            )
            raise
        active[future] = (spec, attempt)
        return True

    try:
        try:
            for _ in range(MAX_WORKERS):
                submit_next()
        except BaseException as error:
            failure = error
        while active:
            future = next(as_completed(tuple(active)))
            spec, attempt = active.pop(future)
            if checkpoint_state_unreadable:
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
                    artifact_hashes=artifacts(),
                    launch_manifest_sha256=launch_manifest_sha256,
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
                candidate_checkpoint = {**checkpoint, "completed_runs": candidate_completed}
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
                            confirmed, confirmed_error = _checkpoint_readback_state(
                                checkpoint_path, candidate_checkpoint
                            )
                            if confirmed != "candidate":
                                raise RuntimeError(
                                    "A220 holdout checkpoint changed during durability "
                                    f"reconfirmation: {confirmed}:"
                                    f"{type(confirmed_error).__name__ if confirmed_error else 'none'}"
                                )
                            checkpoint_durable = True
                        except BaseException as durability_error:
                            checkpoint_commit_ambiguous = True
                            checkpoint_state_unreadable = True
                            checkpoint_error = RuntimeError(
                                "A220 holdout visible checkpoint durability reconfirmation "
                                f"failed: {type(durability_error).__name__}"
                            )
                            completed[str(spec["run_id"])] = record
                    elif readback_state == "unreadable":
                        checkpoint_commit_ambiguous = True
                        checkpoint_state_unreadable = True
                        checkpoint_error = RuntimeError(
                            "A220 holdout checkpoint unreadable after write exception: "
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
                            "A220 holdout checkpoint unreadable after durable write: "
                            f"{type(readback_error).__name__}"
                        )
                        completed[str(spec["run_id"])] = record
                    else:
                        checkpoint_error = RuntimeError(
                            f"A220 holdout checkpoint post-write differs: {readback_state}"
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
                            artifact_hashes=artifacts(),
                            launch_manifest_sha256=launch_manifest_sha256,
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
                            launch_manifest_sha256=launch_manifest_sha256,
                        )
                    except BaseException as error:
                        if failure is None:
                            failure = error
                    else:
                        print(
                            f"A220 HOLDOUT complete {row['label']} {spec['run_id']}",
                            flush=True,
                        )
                    if checkpoint_error is not None and failure is None:
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
    expected = {str(spec["run_id"]) for spec in plan}
    if set(completed) != expected:
        raise RuntimeError(f"A220 holdout complete-run set differs for {row['label']}")
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
        "launch_manifest_sha256",
        "evidence_stage",
        "reader_frozen_before_holdout",
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


def _verify_stable_attempt_history(
    history: Any,
    *,
    expected_run_ids: set[str],
    launch_manifest_sha256: str,
) -> None:
    if not isinstance(history, list):
        raise RuntimeError("A220 holdout stable attempt history is not a list")
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
            or [event.get("attempt_number") for event in starts]
            != list(range(1, len(starts) + 1))
            or len(start_ids) != len(starts)
            or len(completed) != 1
            or len(completed) + len(tombstones) != len(starts)
            or len(terminal_ids) != len(completed) + len(tombstones)
            or completed[0].get("attempt_id") != starts[-1].get("attempt_id")
            or start_ids != terminal_ids
            or any(
                event.get("protocol_sha256") != PROTOCOL_SHA256
                or event.get("launch_manifest_sha256") != launch_manifest_sha256
                or event.get("evidence_stage") != "HOLDOUT"
                or event.get("reader_frozen_before_holdout") is not True
                for event in events
            )
            or any(
                event.get("retry_claim", {}).get("is_retry") is not (index > 0)
                or event.get("retry_claim", {}).get("derived_from_prior_started_attempts")
                != index
                or event.get("retry_claim", {}).get("derived_from_prior_terminal_attempts")
                != index
                for index, event in enumerate(starts)
            )
        ):
            raise RuntimeError(f"A220 holdout stable attempt history failed: {run_id}")
    if any(event.get("run_id") not in expected_run_ids for event in history):
        raise RuntimeError("A220 holdout stable history contains an unknown run")


def _compress_measurement(raw: bytes) -> bytes:
    if zstandard.__version__ != ZSTD_VERSION:
        raise RuntimeError("A220 holdout frozen zstandard package version differs")
    return zstandard.ZstdCompressor(
        level=ZSTD_LEVEL,
        threads=0,
        write_checksum=True,
        write_content_size=True,
        write_dict_id=False,
    ).compress(raw)


def _decompress_measurement(raw: bytes) -> bytes:
    return zstandard.ZstdDecompressor().decompress(raw, max_output_size=1 << 30)


def _write_shard(path: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    canonical = _canonical_bytes(payload)
    compressed = _compress_measurement(canonical)
    if _compress_measurement(canonical) != compressed:
        raise RuntimeError("A220 holdout zstd-19 compression is not deterministic")
    if _decompress_measurement(compressed) != canonical:
        raise RuntimeError("A220 holdout zstd pre-write roundtrip failed")
    if path.exists():
        existing = path.read_bytes()
        if existing != compressed or _decompress_measurement(existing) != canonical:
            raise RuntimeError("A220 holdout completed shard overwrite refused")
    else:
        _atomic_bytes(path, compressed)
    observed = path.read_bytes()
    roundtrip = _decompress_measurement(observed)
    if observed != compressed or roundtrip != canonical:
        raise RuntimeError("A220 holdout atomic shard readback differs")
    return {
        "measurement_sha256": _sha256(canonical),
        "measurement_bytes": len(canonical),
        "compressed_sha256": _sha256(compressed),
        "compressed_bytes": len(compressed),
    }


def _selected_order_manifests(
    design: Any, plan_template: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    all_manifests = design.order_manifest()
    operators = [str(spec["operator"]) for spec in plan_template]
    result = {operator: all_manifests[operator] for operator in dict.fromkeys(operators)}
    for spec in plan_template:
        if result[str(spec["operator"])]["sha256_uint8"] != spec["order_uint8_sha256"]:
            raise RuntimeError("A220 selected order plan/manifest differs")
    return result


def _information_boundary(protocol: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **dict(protocol["information_boundary"]),
        "stage": "HOLDOUT",
        "reader_frozen_before_holdout": True,
        "holdout_trajectory_collected": True,
        "fit_select_shards_index_checkpoint_or_history_opened": False,
        "future_prospective_target_opened": False,
        "known_low20_used_for_eight_block_target_construction_and_separate_label": True,
        "known_low20_passed_to_solver_order_budget_or_features": False,
        "reader_coefficients_used_to_adapt_collection": False,
        "refit_reselection_or_threshold_adaptation": False,
    }


def _assemble_shard(
    *,
    protocol: Mapping[str, Any],
    row: Mapping[str, Any],
    prepared: Mapping[str, Any],
    key_prepared: Mapping[str, Any],
    records: Mapping[str, Mapping[str, Any]],
    plan: Sequence[Mapping[str, Any]],
    selected_order_manifests: Mapping[str, Any],
    history_path: Path,
    collector_sha256: str,
    collector_test_sha256: str,
    launch_manifest_sha256: str,
    reader: Mapping[str, Any],
    reader_hashes: Mapping[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    ordered = {str(spec["run_id"]): records[str(spec["run_id"])] for spec in plan}
    stable_history = _stable_attempt_history(history_path, row=row, plan=plan)
    expected_run_ids = set(ordered)
    _verify_stable_attempt_history(
        stable_history,
        expected_run_ids=expected_run_ids,
        launch_manifest_sha256=launch_manifest_sha256,
    )
    completed_events = {
        str(event["run_id"]): event
        for event in stable_history
        if event["event_type"] == "run_attempt_completed"
    }
    if any(
        record["attempt_id"] != completed_events[run_id]["attempt_id"]
        or record["checkpoint_record_sha256"]
        != completed_events[run_id]["checkpoint_record_sha256"]
        for run_id, record in ordered.items()
    ):
        raise RuntimeError("A220 holdout completed records/history differ")
    run_count = len(plan)
    completion = {
        "expected_selected_runs": run_count,
        "completed_selected_runs": len(ordered),
        "all_selected_runs_complete": len(ordered) == run_count,
        "all_selected_runs_are_fresh_solver_processes": all(
            record["fresh_solver_process"] is True for record in ordered.values()
        ),
        "expected_cells": run_count * 256,
        "completed_cells": sum(
            len(record["scientific_measurement"]["cells"]) for record in ordered.values()
        ),
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
        == run_count,
        "maximum_concurrent_solver_processes": MAX_WORKERS,
        "one_key_instantiated_CNF_active": True,
        "reader_frozen_before_holdout": True,
        "collector_source_unchanged": _file_sha256(ORCHESTRATOR) == collector_sha256,
        "collector_test_unchanged": _file_sha256(TEST_SOURCE) == collector_test_sha256,
        "source_anchors_unchanged": _verify_source_anchors(protocol)
        == prepared["source_anchor_hashes_started"],
        "fit_select_or_prospective_artifact_loaded": False,
    }
    if (
        not all(
            completion[key] is True
            for key in (
                "all_selected_runs_complete",
                "all_selected_runs_are_fresh_solver_processes",
                "all_retained_state_continuity_verified",
                "all_watchdogs_clear",
                "all_launch_hashes_pre_post_identical",
                "completed_runs_never_reexecuted",
                "one_key_instantiated_CNF_active",
                "reader_frozen_before_holdout",
                "collector_source_unchanged",
                "collector_test_unchanged",
                "source_anchors_unchanged",
            )
        )
        or completion["completed_cells"] != completion["expected_cells"]
        or completion["fit_select_or_prospective_artifact_loaded"] is not False
    ):
        raise RuntimeError(f"A220 holdout per-key completion gate failed: {row['label']}")
    selected_identity = reader["selected_reader"]["selected_identity"]
    shard = {
        "schema": SHARD_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": EVIDENCE_STAGE,
        "protocol_sha256": PROTOCOL_SHA256,
        "launch_manifest_sha256": launch_manifest_sha256,
        "reader_artifact_sha256": reader_hashes["reader_artifact_sha256"],
        "selected_reader_identity": selected_identity,
        "selected_reader_identity_sha256": reader_hashes["selected_identity_sha256"],
        "selected_reader_readout_sha256": reader_hashes["selected_readout_sha256"],
        "collector_source_sha256": collector_sha256,
        "collector_test_sha256": collector_test_sha256,
        "key_factorial_identity": dict(row),
        "known_key_confirmation_metadata": key_prepared["known_key_confirmation_metadata"],
        "public_only_R20_material_sha256": protocol["public_only_R20_material_sha256"],
        "public_core_provenance": prepared["public_core_provenance"],
        "source_anchor_hashes": prepared["source_anchor_hashes_started"],
        "symbolic_template_manifest": prepared["template_manifest"],
        "instantiated_CNF_manifest": key_prepared["instantiation_manifest"],
        "key_mapping_canonical_sha256": _canonical_sha256(prepared["key_mapping"]),
        "native_helper_stable_provenance": prepared["native_helper_stable_provenance"],
        "selected_operator_order_manifests": dict(selected_order_manifests),
        "run_plan": _plan_identity(plan),
        "scientific_runs": {
            run_id: record["scientific_measurement"] for run_id, record in ordered.items()
        },
        "deterministic_run_artifact_provenance": {
            run_id: record["deterministic_artifact_provenance"]
            for run_id, record in ordered.items()
        },
        "append_only_attempt_history_without_wallclock": stable_history,
        "information_boundary": _information_boundary(protocol),
        "completion_gates": completion,
    }
    volatile = {
        "schema": VOLATILE_SCHEMA,
        "protocol_sha256": PROTOCOL_SHA256,
        "launch_manifest_sha256": launch_manifest_sha256,
        "collector_source_sha256": collector_sha256,
        "collector_test_sha256": collector_test_sha256,
        "evidence_stage": "HOLDOUT",
        "reader_frozen_before_holdout": True,
        "key_label": row["label"],
        "native_build_elapsed_seconds": prepared["native_helper_build"].get("elapsed_seconds"),
        "runs": {run_id: record["volatile_observation"] for run_id, record in ordered.items()},
    }
    return shard, volatile


def _verify_checkpoint_binding(
    path: Path,
    *,
    payload: Mapping[str, Any],
    expected_row: Mapping[str, Any],
    plan: Sequence[Mapping[str, Any]],
) -> None:
    checkpoint = json.loads(path.read_bytes())
    expected_identity = {
        "schema": CHECKPOINT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "HOLDOUT",
        "protocol_sha256": PROTOCOL_SHA256,
        "collector_source_sha256": payload["collector_source_sha256"],
        "collector_test_sha256": payload["collector_test_sha256"],
        "launch_manifest_sha256": payload["launch_manifest_sha256"],
        "reader_artifact_sha256": payload["reader_artifact_sha256"],
        "selected_identity_sha256": payload["selected_reader_identity_sha256"],
        "selected_readout_sha256": payload["selected_reader_readout_sha256"],
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
        "instantiation_manifest_sha256": _canonical_sha256(
            payload["instantiated_CNF_manifest"]
        ),
        "known_key_confirmation_metadata_sha256": _canonical_sha256(
            payload["known_key_confirmation_metadata"]
        ),
        "key_mapping_sha256": payload["key_mapping_canonical_sha256"],
        "selected_order_manifests_sha256": _canonical_sha256(
            payload["selected_operator_order_manifests"]
        ),
        "run_plan_sha256": _canonical_sha256(_plan_identity(plan)),
    }
    records = checkpoint.get("completed_runs") if isinstance(checkpoint, dict) else None
    expected_ids = {str(spec["run_id"]) for spec in plan}
    if (
        not isinstance(checkpoint, dict)
        or set(checkpoint) != {*expected_identity, "completed_runs"}
        or any(checkpoint.get(key) != value for key, value in expected_identity.items())
        or not isinstance(records, dict)
        or set(records) != expected_ids
    ):
        raise RuntimeError("A220 holdout shard/checkpoint identity differs")
    completed_events = {
        event["run_id"]: event
        for event in payload["append_only_attempt_history_without_wallclock"]
        if event["event_type"] == "run_attempt_completed"
    }
    expected_record_fields = {
        "run_id",
        "operator",
        "schedule",
        "fresh_solver_process",
        "attempt_id",
        "attempt_number",
        "scientific_measurement",
        "deterministic_artifact_provenance",
        "volatile_observation",
        "checkpoint_record_sha256",
    }
    for spec in plan:
        run_id = str(spec["run_id"])
        record = records[run_id]
        unhashed = {key: value for key, value in record.items() if key != "checkpoint_record_sha256"}
        event = completed_events[run_id]
        if (
            set(record) != expected_record_fields
            or record.get("checkpoint_record_sha256") != _canonical_sha256(unhashed)
            or record.get("run_id") != run_id
            or record.get("operator") != spec["operator"]
            or record.get("schedule") != spec["schedule"]
            or record.get("fresh_solver_process") is not True
            or record.get("attempt_id") != event.get("attempt_id")
            or record.get("attempt_number") != event.get("attempt_number")
            or record.get("checkpoint_record_sha256") != event.get("checkpoint_record_sha256")
            or record.get("scientific_measurement") != payload["scientific_runs"][run_id]
            or record.get("deterministic_artifact_provenance")
            != payload["deterministic_run_artifact_provenance"][run_id]
        ):
            raise RuntimeError(f"A220 holdout checkpoint run binding differs: {run_id}")


def _verify_shard(
    path: Path,
    *,
    expected_row: Mapping[str, Any],
    protocol: Mapping[str, Any],
    reader: Mapping[str, Any],
    reader_hashes: Mapping[str, str],
    launch_manifest: Mapping[str, Any],
    launch_manifest_sha256: str,
    plan_template: Sequence[Mapping[str, Any]],
    selected_order_manifests: Mapping[str, Any],
    expected_collector_sha256: str,
    expected_collector_test_sha256: str,
    expected_source_anchor_hashes: Mapping[str, str],
    checkpoint_path: Path | None = None,
    history_path: Path | None = None,
) -> dict[str, Any]:
    compressed = path.read_bytes()
    try:
        raw = _decompress_measurement(compressed)
        payload = json.loads(raw)
        frame = zstandard.get_frame_parameters(compressed)
    except (zstandard.ZstdError, json.JSONDecodeError) as error:
        raise RuntimeError(f"A220 holdout shard decode failed: {path.name}") from error
    if (
        not isinstance(payload, dict)
        or raw != _canonical_bytes(payload)
        or frame.has_checksum is not True
        or frame.content_size != len(raw)
        or frame.dict_id != 0
        or _compress_measurement(raw) != compressed
    ):
        raise RuntimeError(f"A220 holdout shard canonical/zstd gate failed: {path.name}")

    plan = _run_plan(expected_row, plan_template)
    expected_plan = _plan_identity(plan)
    expected_run_ids = {str(spec["run_id"]) for spec in plan}
    template_protocol = json.loads(
        (ROOT / protocol["anchors"]["symbolic_template_protocol_path"]).read_bytes()
    )["symbolic_R20_template"]
    instantiation = payload.get("instantiated_CNF_manifest")
    if (
        not isinstance(instantiation, dict)
        or set(instantiation)
        != {"header", "bytes", "sha256", "unit_count", "unit_int32le_sha256"}
        or not isinstance(instantiation.get("header"), str)
        or not isinstance(instantiation.get("bytes"), int)
        or isinstance(instantiation.get("bytes"), bool)
        or instantiation["bytes"] <= 0
        or not isinstance(instantiation.get("sha256"), str)
        or len(instantiation["sha256"]) != 64
        or instantiation.get("unit_count") != 512
        or not isinstance(instantiation.get("unit_int32le_sha256"), str)
        or len(instantiation["unit_int32le_sha256"]) != 64
    ):
        raise RuntimeError(f"A220 holdout instantiated CNF manifest failed: {path.name}")
    header = instantiation["header"].split()
    try:
        expected_variables = int(header[2])
        expected_clauses = int(header[3])
    except (IndexError, ValueError) as error:
        raise RuntimeError(f"A220 holdout CNF header failed: {path.name}") from error
    if (
        len(header) != 4
        or header[:2] != ["p", "cnf"]
        or expected_variables <= 0
        or expected_clauses < 512
    ):
        raise RuntimeError(f"A220 holdout CNF header failed: {path.name}")

    public = _import_path(
        ROOT / protocol["anchors"]["public_core_adapter_path"],
        f"a220_holdout_verify_public_{expected_row['label']}",
    )
    challenge = public.build_known_challenge(
        protocol["public_only_R20_material"], low20=int(expected_row["low20"])
    )
    material = protocol["public_only_R20_material"]
    key_words = [
        int(material["known_key_word0_upper12"]) | int(expected_row["low20"]),
        *[int(value) for value in material["known_key_words_1_through_7"]],
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
    selected_identity = reader["selected_reader"]["selected_identity"]
    scientific_runs = payload.get("scientific_runs")
    provenance_runs = payload.get("deterministic_run_artifact_provenance")
    expected_top_fields = {
        "schema",
        "attempt_id",
        "evidence_stage",
        "protocol_sha256",
        "launch_manifest_sha256",
        "reader_artifact_sha256",
        "selected_reader_identity",
        "selected_reader_identity_sha256",
        "selected_reader_readout_sha256",
        "collector_source_sha256",
        "collector_test_sha256",
        "key_factorial_identity",
        "known_key_confirmation_metadata",
        "public_only_R20_material_sha256",
        "public_core_provenance",
        "source_anchor_hashes",
        "symbolic_template_manifest",
        "instantiated_CNF_manifest",
        "key_mapping_canonical_sha256",
        "native_helper_stable_provenance",
        "selected_operator_order_manifests",
        "run_plan",
        "scientific_runs",
        "deterministic_run_artifact_provenance",
        "append_only_attempt_history_without_wallclock",
        "information_boundary",
        "completion_gates",
    }
    if (
        set(payload) != expected_top_fields
        or payload.get("schema") != SHARD_SCHEMA
        or payload.get("attempt_id") != ATTEMPT_ID
        or payload.get("evidence_stage") != EVIDENCE_STAGE
        or payload.get("protocol_sha256") != PROTOCOL_SHA256
        or payload.get("launch_manifest_sha256") != launch_manifest_sha256
        or payload.get("reader_artifact_sha256") != reader_hashes["reader_artifact_sha256"]
        or payload.get("selected_reader_identity") != selected_identity
        or payload.get("selected_reader_identity_sha256")
        != reader_hashes["selected_identity_sha256"]
        or payload.get("selected_reader_readout_sha256")
        != reader_hashes["selected_readout_sha256"]
        or payload.get("collector_source_sha256") != expected_collector_sha256
        or payload.get("collector_test_sha256") != expected_collector_test_sha256
        or payload.get("key_factorial_identity") != dict(expected_row)
        or payload.get("known_key_confirmation_metadata") != expected_confirmation
        or payload.get("public_only_R20_material_sha256")
        != protocol["public_only_R20_material_sha256"]
        or payload.get("public_core_provenance") != public.provenance()
        or payload.get("source_anchor_hashes") != dict(expected_source_anchor_hashes)
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
        or payload.get("symbolic_template_manifest", {}).get(
            "all_mapping_probes_exact_unit_deltas"
        )
        is not True
        or payload.get("key_mapping_canonical_sha256")
        != _canonical_sha256(template_protocol["key_one_literals_bit0_through_bit19"])
        or payload.get("native_helper_stable_provenance", {}).get("binary_sha256")
        != protocol["anchors"]["retained_native_binary_sha256"]
        or payload.get("native_helper_stable_provenance", {}).get("source_sha256_started")
        != protocol["anchors"]["retained_native_source_sha256"]
        or payload.get("native_helper_stable_provenance", {}).get("source_sha256_finished")
        != protocol["anchors"]["retained_native_source_sha256"]
        or payload.get("selected_operator_order_manifests")
        != dict(selected_order_manifests)
        or payload.get("run_plan") != expected_plan
        or payload.get("information_boundary") != _information_boundary(protocol)
        or not isinstance(scientific_runs, dict)
        or set(scientific_runs) != expected_run_ids
        or not isinstance(provenance_runs, dict)
        or set(provenance_runs) != expected_run_ids
        or launch_manifest.get("reader_artifact_sha256") != payload["reader_artifact_sha256"]
    ):
        raise RuntimeError(f"A220 holdout shard identity gate failed: {path.name}")

    low = _low_level()
    for spec in plan:
        run_id = str(spec["run_id"])
        low._verify_scientific_run(
            measurement=scientific_runs[run_id],
            provenance=provenance_runs[run_id],
            spec=spec,
            protocol=protocol,
            key_mapping=template_protocol["key_one_literals_bit0_through_bit19"],
            expected_variables=expected_variables,
        )
        if (
            provenance_runs[run_id]["launch_artifact_hashes_started"]["cnf_sha256"]
            != instantiation["sha256"]
        ):
            raise RuntimeError(f"A220 holdout run/CNF binding differs: {run_id}")
    stable_history = payload.get("append_only_attempt_history_without_wallclock")
    _verify_stable_attempt_history(
        stable_history,
        expected_run_ids=expected_run_ids,
        launch_manifest_sha256=launch_manifest_sha256,
    )
    if history_path is not None and stable_history != _stable_attempt_history(
        history_path, row=expected_row, plan=plan
    ):
        raise RuntimeError("A220 holdout shard/sealed history binding differs")
    if checkpoint_path is not None:
        _verify_checkpoint_binding(
            checkpoint_path, payload=payload, expected_row=expected_row, plan=plan
        )
    run_count = len(plan)
    completion = payload.get("completion_gates")
    reconstructed = {
        "expected_selected_runs": run_count,
        "completed_selected_runs": len(scientific_runs),
        "all_selected_runs_complete": len(scientific_runs) == run_count,
        "all_selected_runs_are_fresh_solver_processes": True,
        "expected_cells": run_count * 256,
        "completed_cells": sum(len(run["cells"]) for run in scientific_runs.values()),
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
        "maximum_concurrent_solver_processes": MAX_WORKERS,
        "one_key_instantiated_CNF_active": True,
        "reader_frozen_before_holdout": True,
        "collector_source_unchanged": True,
        "collector_test_unchanged": True,
        "source_anchors_unchanged": True,
        "fit_select_or_prospective_artifact_loaded": False,
    }
    if completion != reconstructed:
        raise RuntimeError(f"A220 holdout stored completion gates differ: {path.name}")
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
    checkpoint_directory: Path,
    history_path: Path,
    protocol: Mapping[str, Any],
    reader: Mapping[str, Any],
    reader_hashes: Mapping[str, str],
    launch_manifest: Mapping[str, Any],
    launch_manifest_path: Path,
    launch_manifest_sha256: str,
    plan_template: Sequence[Mapping[str, Any]],
    selected_order_manifests: Mapping[str, Any],
    collector_sha256: str,
    collector_test_sha256: str,
    source_anchor_hashes: Mapping[str, str],
) -> dict[str, Any]:
    _verify_launch_binding(
        protocol=protocol,
        manifest_path=launch_manifest_path,
        expected_manifest=launch_manifest,
        expected_manifest_sha256=launch_manifest_sha256,
        reader_path=_required_reader_path(protocol),
    )
    shard_directory.mkdir(parents=True, exist_ok=True)
    expected = {str(row["label"]): row for row in rows}
    observed_paths = {path.name: path for path in shard_directory.glob("*.measurement.json.zst")}
    expected_names = {f"{label}.measurement.json.zst" for label in expected}
    unexpected = set(observed_paths) - expected_names
    if unexpected:
        raise RuntimeError(f"A220 holdout shard directory contains unexpected files: {sorted(unexpected)}")
    entries = []
    payloads = []
    for row in rows:
        path = observed_paths.get(f"{row['label']}.measurement.json.zst")
        if path is None:
            continue
        checkpoint = checkpoint_directory / f"{row['label']}.checkpoint.json"
        if not checkpoint.exists():
            raise RuntimeError(f"A220 holdout verified shard lacks checkpoint: {row['label']}")
        verified = _verify_shard(
            path,
            expected_row=row,
            protocol=protocol,
            reader=reader,
            reader_hashes=reader_hashes,
            launch_manifest=launch_manifest,
            launch_manifest_sha256=launch_manifest_sha256,
            plan_template=plan_template,
            selected_order_manifests=selected_order_manifests,
            expected_collector_sha256=collector_sha256,
            expected_collector_test_sha256=collector_test_sha256,
            expected_source_anchor_hashes=source_anchor_hashes,
            checkpoint_path=checkpoint,
            history_path=history_path,
        )
        payload = verified.pop("payload")
        payloads.append(payload)
        entries.append(
            {
                "key_label": row["label"],
                "prefix_split": row["prefix_split"],
                "prefix_index": row["prefix_index"],
                "suffix_split": row["suffix_split"],
                "suffix_index": row["suffix_index"],
                "panel": f"{row['prefix_split']}_by_{row['suffix_split']}",
                "relative_path": os.path.relpath(path, index_path.parent),
                **verified,
            }
        )
    run_count = len(plan_template)
    complete = len(entries) == len(rows) == 92
    expected_processes = len(rows) * run_count
    verified_processes = len(entries) * run_count
    no_tombstones = all(
        event["event_type"] != "run_attempt_tombstone"
        for payload in payloads
        for event in payload["append_only_attempt_history_without_wallclock"]
    )
    completion = {
        "verified_key_shards": len(entries),
        "expected_key_shards": len(rows),
        "selected_runs_per_key": run_count,
        "verified_fresh_solver_processes": verified_processes,
        "expected_fresh_solver_processes": expected_processes,
        "no_failure_tombstones": no_tombstones,
        "all_92_key_shards_complete": complete,
        "all_selected_fresh_solver_processes_complete": complete
        and verified_processes == expected_processes,
        "all_shards_decompressed_and_hash_verified": True,
        "global_index_rebuilt_from_verified_shards": True,
        "collector_source_unchanged": _file_sha256(ORCHESTRATOR) == collector_sha256,
        "reader_launch_and_source_hashes_unchanged": True,
    }
    index = {
        "schema": INDEX_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": EVIDENCE_STAGE,
        "protocol_sha256": PROTOCOL_SHA256,
        "launch_manifest_relative_path": os.path.relpath(
            launch_manifest_path, index_path.parent
        ),
        "launch_manifest_sha256": launch_manifest_sha256,
        "reader_artifact_sha256": reader_hashes["reader_artifact_sha256"],
        "selected_reader_identity_sha256": reader_hashes["selected_identity_sha256"],
        "selected_reader_readout_sha256": reader_hashes["selected_readout_sha256"],
        "collector_source_sha256": collector_sha256,
        "collector_test_sha256": collector_test_sha256,
        "source_anchor_hashes": dict(source_anchor_hashes),
        "factorial_holdout_label_order_sha256": _canonical_sha256(
            [row["label"] for row in rows]
        ),
        "selected_run_plan_template_sha256": _canonical_sha256(list(plan_template)),
        "verified_shards": entries,
        "completion_gates": completion,
    }
    _atomic_json(index_path, index)
    reread = json.loads(index_path.read_bytes())
    if reread != index or _canonical_sha256(reread) != _canonical_sha256(index):
        raise RuntimeError("A220 holdout rebuilt index readback differs")
    return index


def _collect_key(
    *,
    protocol: Mapping[str, Any],
    row: Mapping[str, Any],
    prepared: Mapping[str, Any],
    plan_template: Sequence[Mapping[str, Any]],
    selected_order_manifests: Mapping[str, Any],
    shard_directory: Path,
    checkpoint_directory: Path,
    volatile_directory: Path,
    history_path: Path,
    collector_sha256: str,
    collector_test_sha256: str,
    launch_manifest_sha256: str,
    launch_manifest_path: Path,
    reader_path: Path,
    reader: Mapping[str, Any],
    reader_hashes: Mapping[str, str],
    run_callable: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    key_prepared = _prepare_key(protocol=protocol, prepared=prepared, row=row)
    plan = _run_plan(row, plan_template)
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
            selected_order_manifests=selected_order_manifests,
            checkpoint_path=checkpoint,
            history_path=history_path,
            collector_sha256=collector_sha256,
            collector_test_sha256=collector_test_sha256,
            launch_manifest_sha256=launch_manifest_sha256,
            reader_hashes=reader_hashes,
            reader_path=reader_path,
            launch_manifest_path=launch_manifest_path,
            run_callable=run_callable,
        )
        payload, volatile_payload = _assemble_shard(
            protocol=protocol,
            row=row,
            prepared=prepared,
            key_prepared=key_prepared,
            records=records,
            plan=plan,
            selected_order_manifests=selected_order_manifests,
            history_path=history_path,
            collector_sha256=collector_sha256,
            collector_test_sha256=collector_test_sha256,
            launch_manifest_sha256=launch_manifest_sha256,
            reader=reader,
            reader_hashes=reader_hashes,
        )
        metadata = _write_shard(shard, payload)
        _atomic_json(volatile, volatile_payload, private=True)
        verified = _verify_shard(
            shard,
            expected_row=row,
            protocol=protocol,
            reader=reader,
            reader_hashes=reader_hashes,
            launch_manifest=json.loads(launch_manifest_path.read_bytes()),
            launch_manifest_sha256=launch_manifest_sha256,
            plan_template=plan_template,
            selected_order_manifests=selected_order_manifests,
            expected_collector_sha256=collector_sha256,
            expected_collector_test_sha256=collector_test_sha256,
            expected_source_anchor_hashes=prepared["source_anchor_hashes_started"],
            checkpoint_path=checkpoint,
            history_path=history_path,
        )
        if any(verified[key] != metadata[key] for key in metadata):
            raise RuntimeError("A220 holdout post-write shard metadata differs")
        return metadata
    finally:
        Path(key_prepared["cnf_path"]).unlink(missing_ok=True)


def load_verified_holdout_corpus(
    index_path: Path = DEFAULT_INDEX,
    shard_directory: Path = DEFAULT_SHARD_DIRECTORY,
    reader_path: Path | None = None,
    launch_manifest_path: Path = DEFAULT_LAUNCH_MANIFEST,
    *,
    checkpoint_directory: Path | None = DEFAULT_CHECKPOINT_DIRECTORY,
    history_path: Path | None = DEFAULT_ATTEMPT_HISTORY,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    """Load and reconstructively verify the complete 92-key holdout corpus.

    This function starts no subprocess and is the authoritative evaluator entry
    point.  It returns ``(rows, payloads, index, reader, launch_manifest)`` in
    the original factorial-ledger order.  Defaults additionally bind sealed
    checkpoints/history; passing ``checkpoint_directory=None, history_path=None``
    performs the complete public-only clean-clone verification.
    """

    protocol = _load_protocol()
    authoritative_reader = _required_reader_path(protocol)
    selected_reader_path = authoritative_reader if reader_path is None else reader_path
    reader, reader_hashes = _load_reader(protocol, reader_path=selected_reader_path)
    design = _import_path(
        ROOT / protocol["anchors"]["factorial_design_path"],
        "a220_holdout_loader_design",
    )
    rows = _holdout_rows(protocol, design)
    orders = _operator_orders(protocol, design)
    plan_template = _selected_plan_template(
        reader["selected_reader"]["selected_identity"], orders
    )
    selected_manifests = _selected_order_manifests(design, plan_template)
    source_hashes = _verify_source_anchors(protocol)
    launch_manifest = json.loads(launch_manifest_path.read_bytes())
    launch_manifest_sha256 = _file_sha256(launch_manifest_path)
    candidate = _launch_manifest_candidate(
        protocol=protocol,
        reader_path=selected_reader_path,
        reader=reader,
        reader_hashes=reader_hashes,
        rows=rows,
        design=design,
        plan_template=plan_template,
        source_hashes=source_hashes,
    )
    if launch_manifest != candidate:
        raise RuntimeError("A220 holdout public launch manifest differs from reconstruction")
    _verify_launch_binding(
        protocol=protocol,
        manifest_path=launch_manifest_path,
        expected_manifest=launch_manifest,
        expected_manifest_sha256=launch_manifest_sha256,
        reader_path=selected_reader_path,
    )
    index = json.loads(index_path.read_bytes())
    expected_index_fields = {
        "schema",
        "attempt_id",
        "evidence_stage",
        "protocol_sha256",
        "launch_manifest_relative_path",
        "launch_manifest_sha256",
        "reader_artifact_sha256",
        "selected_reader_identity_sha256",
        "selected_reader_readout_sha256",
        "collector_source_sha256",
        "collector_test_sha256",
        "source_anchor_hashes",
        "factorial_holdout_label_order_sha256",
        "selected_run_plan_template_sha256",
        "verified_shards",
        "completion_gates",
    }
    gates = index.get("completion_gates", {}) if isinstance(index, dict) else {}
    if (
        not isinstance(index, dict)
        or set(index) != expected_index_fields
        or index.get("schema") != INDEX_SCHEMA
        or index.get("attempt_id") != ATTEMPT_ID
        or index.get("evidence_stage") != EVIDENCE_STAGE
        or index.get("protocol_sha256") != PROTOCOL_SHA256
        or index.get("launch_manifest_relative_path") != "launch_manifest.json"
        or (index_path.parent / index["launch_manifest_relative_path"]).resolve()
        != launch_manifest_path.resolve()
        or index.get("launch_manifest_sha256") != launch_manifest_sha256
        or index.get("reader_artifact_sha256") != reader_hashes["reader_artifact_sha256"]
        or index.get("selected_reader_identity_sha256")
        != reader_hashes["selected_identity_sha256"]
        or index.get("selected_reader_readout_sha256")
        != reader_hashes["selected_readout_sha256"]
        or index.get("collector_source_sha256") != _file_sha256(ORCHESTRATOR)
        or index.get("collector_test_sha256") != _file_sha256(TEST_SOURCE)
        or index.get("source_anchor_hashes") != source_hashes
        or index.get("factorial_holdout_label_order_sha256") != HOLDOUT_LABEL_ORDER_SHA256
        or index.get("selected_run_plan_template_sha256")
        != _canonical_sha256(plan_template)
        or not isinstance(index.get("verified_shards"), list)
        or len(index["verified_shards"]) != 92
        or [entry.get("key_label") for entry in index["verified_shards"]]
        != [row["label"] for row in rows]
        or gates.get("verified_key_shards") != 92
        or gates.get("expected_key_shards") != 92
        or gates.get("selected_runs_per_key") != len(plan_template)
        or gates.get("verified_fresh_solver_processes") != 92 * len(plan_template)
        or gates.get("expected_fresh_solver_processes") != 92 * len(plan_template)
        or gates.get("no_failure_tombstones") is not True
        or gates.get("all_92_key_shards_complete") is not True
        or gates.get("all_selected_fresh_solver_processes_complete") is not True
        or gates.get("all_shards_decompressed_and_hash_verified") is not True
        or gates.get("global_index_rebuilt_from_verified_shards") is not True
        or gates.get("collector_source_unchanged") is not True
        or gates.get("reader_launch_and_source_hashes_unchanged") is not True
    ):
        raise RuntimeError("A220 holdout completed index gate failed")
    payloads = []
    shard_root = shard_directory.resolve()
    for row, entry in zip(rows, index["verified_shards"], strict=True):
        path = (index_path.parent / str(entry["relative_path"])).resolve()
        if path.parent != shard_root or path.name != f"{row['label']}.measurement.json.zst":
            raise RuntimeError("A220 holdout index shard path escapes frozen directory")
        checkpoint = (
            checkpoint_directory / f"{row['label']}.checkpoint.json"
            if checkpoint_directory is not None
            else None
        )
        verified = _verify_shard(
            path,
            expected_row=row,
            protocol=protocol,
            reader=reader,
            reader_hashes=reader_hashes,
            launch_manifest=launch_manifest,
            launch_manifest_sha256=launch_manifest_sha256,
            plan_template=plan_template,
            selected_order_manifests=selected_manifests,
            expected_collector_sha256=index["collector_source_sha256"],
            expected_collector_test_sha256=index["collector_test_sha256"],
            expected_source_anchor_hashes=source_hashes,
            checkpoint_path=checkpoint,
            history_path=history_path,
        )
        payload = verified.pop("payload")
        expected_entry = {
            "key_label": row["label"],
            "prefix_split": row["prefix_split"],
            "prefix_index": row["prefix_index"],
            "suffix_split": row["suffix_split"],
            "suffix_index": row["suffix_index"],
            "panel": f"{row['prefix_split']}_by_{row['suffix_split']}",
            "relative_path": entry["relative_path"],
            **verified,
        }
        if entry != expected_entry:
            raise RuntimeError(f"A220 holdout index/shard metadata differs: {row['label']}")
        payloads.append(payload)
    return rows, payloads, index, reader, launch_manifest


def run(
    *,
    shard_directory: Path = DEFAULT_SHARD_DIRECTORY,
    index_path: Path = DEFAULT_INDEX,
    checkpoint_directory: Path = DEFAULT_CHECKPOINT_DIRECTORY,
    volatile_directory: Path = DEFAULT_VOLATILE_DIRECTORY,
    history_path: Path = DEFAULT_ATTEMPT_HISTORY,
    launch_manifest_path: Path = DEFAULT_LAUNCH_MANIFEST,
    lock_path: Path = DEFAULT_LOCK,
) -> dict[str, Any]:
    """Collect all 92 Reader-selected holdout keys without adaptation."""

    protocol = _load_protocol()
    reader_path = _required_reader_path(protocol)
    reader, reader_hashes = _load_reader(protocol, reader_path=reader_path)
    source_hashes = _verify_source_anchors(protocol)
    collector_sha256 = _file_sha256(ORCHESTRATOR)
    collector_test_sha256 = _file_sha256(TEST_SOURCE)
    design = _import_path(
        ROOT / protocol["anchors"]["factorial_design_path"],
        "a220_holdout_collect_design",
    )
    rows = _holdout_rows(protocol, design)
    orders = _operator_orders(protocol, design)
    plan_template = _selected_plan_template(
        reader["selected_reader"]["selected_identity"], orders
    )
    selected_manifests = _selected_order_manifests(design, plan_template)
    candidate = _launch_manifest_candidate(
        protocol=protocol,
        reader_path=reader_path,
        reader=reader,
        reader_hashes=reader_hashes,
        rows=rows,
        design=design,
        plan_template=plan_template,
        source_hashes=source_hashes,
    )
    if launch_manifest_path.resolve() != DEFAULT_LAUNCH_MANIFEST.resolve():
        raise RuntimeError("A220 holdout launch manifest must use the authoritative public path")
    with _exclusive_lock(lock_path):
        launch_manifest, launch_manifest_sha256 = _freeze_launch_manifest(
            launch_manifest_path, candidate
        )
        _verify_launch_binding(
            protocol=protocol,
            manifest_path=launch_manifest_path,
            expected_manifest=launch_manifest,
            expected_manifest_sha256=launch_manifest_sha256,
            reader_path=reader_path,
        )
        existing = _rebuild_index(
            rows=rows,
            shard_directory=shard_directory,
            index_path=index_path,
            checkpoint_directory=checkpoint_directory,
            history_path=history_path,
            protocol=protocol,
            reader=reader,
            reader_hashes=reader_hashes,
            launch_manifest=launch_manifest,
            launch_manifest_path=launch_manifest_path,
            launch_manifest_sha256=launch_manifest_sha256,
            plan_template=plan_template,
            selected_order_manifests=selected_manifests,
            collector_sha256=collector_sha256,
            collector_test_sha256=collector_test_sha256,
            source_anchor_hashes=source_hashes,
        )
        if existing["completion_gates"]["all_92_key_shards_complete"]:
            if existing["completion_gates"]["no_failure_tombstones"] is not True:
                raise RuntimeError("A220 holdout complete corpus contains failure tombstones")
            return existing
        # This is the first operation in the holdout path that may spawn a
        # subprocess (native helper compilation).  The Reader/plan manifest is
        # already durably frozen and read back above.
        with tempfile.TemporaryDirectory(prefix="a220-factorial-holdout-") as raw_directory:
            prepared = _prepare_real(protocol, rows, Path(raw_directory))
            for row in rows:
                shard = shard_directory / f"{row['label']}.measurement.json.zst"
                if shard.exists():
                    continue
                _verify_launch_binding(
                    protocol=protocol,
                    manifest_path=launch_manifest_path,
                    expected_manifest=launch_manifest,
                    expected_manifest_sha256=launch_manifest_sha256,
                    reader_path=reader_path,
                )
                _collect_key(
                    protocol=protocol,
                    row=row,
                    prepared=prepared,
                    plan_template=plan_template,
                    selected_order_manifests=selected_manifests,
                    shard_directory=shard_directory,
                    checkpoint_directory=checkpoint_directory,
                    volatile_directory=volatile_directory,
                    history_path=history_path,
                    collector_sha256=collector_sha256,
                    collector_test_sha256=collector_test_sha256,
                    launch_manifest_sha256=launch_manifest_sha256,
                    launch_manifest_path=launch_manifest_path,
                    reader_path=reader_path,
                    reader=reader,
                    reader_hashes=reader_hashes,
                    run_callable=prepared["run_callable"],
                )
        _verify_launch_binding(
            protocol=protocol,
            manifest_path=launch_manifest_path,
            expected_manifest=launch_manifest,
            expected_manifest_sha256=launch_manifest_sha256,
            reader_path=reader_path,
        )
        final = _rebuild_index(
            rows=rows,
            shard_directory=shard_directory,
            index_path=index_path,
            checkpoint_directory=checkpoint_directory,
            history_path=history_path,
            protocol=protocol,
            reader=reader,
            reader_hashes=reader_hashes,
            launch_manifest=launch_manifest,
            launch_manifest_path=launch_manifest_path,
            launch_manifest_sha256=launch_manifest_sha256,
            plan_template=plan_template,
            selected_order_manifests=selected_manifests,
            collector_sha256=collector_sha256,
            collector_test_sha256=collector_test_sha256,
            source_anchor_hashes=source_hashes,
        )
        gates = final["completion_gates"]
        if (
            gates["all_selected_fresh_solver_processes_complete"] is not True
            or gates["no_failure_tombstones"] is not True
        ):
            raise RuntimeError("A220 holdout corpus completion gate failed")
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
                "evidence_stage": EVIDENCE_STAGE,
                "verified_key_shards": index["completion_gates"]["verified_key_shards"],
                "all_selected_fresh_solver_processes_complete": index["completion_gates"][
                    "all_selected_fresh_solver_processes_complete"
                ],
                "reader_frozen_before_holdout": True,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
