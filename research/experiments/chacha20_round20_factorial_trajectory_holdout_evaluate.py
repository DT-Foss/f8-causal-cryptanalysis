#!/usr/bin/env python3
"""Finalize the frozen A220 factorial-trajectory holdout evaluation.

This stage has no solver interface.  Its only scientific input path is the
holdout collector's reconstructively verified corpus loader; its only
statistical operation is ``evaluate_verified_holdout`` from the frozen pure
core.  It writes the result, exact causal graph, and report as one deterministic
artifact set after all source and provenance gates pass.
"""

from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import importlib.util
import itertools
import json
import math
import os
import sys
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from arx_carry_leak.crypto_causal import (
    CryptoCausalBuilder,
    CryptoCausalReader,
    ExactRule,
)
from arx_carry_leak.factorial_holdout import (
    HOLDOUT_PANEL_COUNTS,
    HOLDOUT_PANEL_ORDER,
    PRIMARY_EXACT_PERMUTATIONS,
    PRIMARY_P_THRESHOLD,
    PRIMARY_PANEL,
    UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2,
    evaluate_verified_holdout,
    holdout_panel_name,
    selected_bundle_run_ids,
)

ROOT = Path(__file__).parents[2]
ORCHESTRATOR = Path(__file__).resolve()
TEST_SOURCE = ROOT / "tests/test_chacha20_round20_factorial_trajectory_holdout_evaluate.py"
PROTOCOL = ROOT / "research/configs/chacha20_round20_factorial_trajectory_transfer_v1.json"
PROTOCOL_SHA256 = "70df07cb4f4f22115e3aa63765de0fca0dd610607cc87356946a188f53fe5645"
COLLECTOR = ROOT / "research/experiments/chacha20_round20_factorial_trajectory_holdout_collect.py"
COLLECTOR_TEST = ROOT / "tests/test_chacha20_round20_factorial_trajectory_holdout_collect.py"
HOLDOUT_CORE = ROOT / "src/arx_carry_leak/factorial_holdout.py"
HOLDOUT_CORE_TEST = ROOT / "tests/test_factorial_holdout.py"
HOLDOUT_CORE_SHA256 = "d2ab7a8f35a1160f7022f72cdd4ce3e18bb05b8ecd5a06136f8d2f9ea697c411"
HOLDOUT_CORE_TEST_SHA256 = "73b1283c50e5eb9e843b8c9c1e473898738e331e050c6e7995884dfab1974e2d"

DEFAULT_INDEX = (
    ROOT / "research/results/v1/chacha20_round20_factorial_trajectory_holdout_v1/index.json"
)
DEFAULT_SHARD_DIRECTORY = DEFAULT_INDEX.parent / "shards"
DEFAULT_LAUNCH_MANIFEST = DEFAULT_INDEX.parent / "launch_manifest.json"
DEFAULT_CHECKPOINT_DIRECTORY = (
    ROOT / ".research_sealed/chacha20_round20_factorial_trajectory_holdout_v1/checkpoints"
)
DEFAULT_ATTEMPT_HISTORY = (
    ROOT / ".research_sealed/chacha20_round20_factorial_trajectory_holdout_v1/attempts.jsonl"
)
DEFAULT_OUTPUT = ROOT / "research/results/v1/chacha20_round20_factorial_trajectory_transfer_v1.json"
DEFAULT_CAUSAL_OUTPUT = DEFAULT_OUTPUT.with_suffix(".causal")
DEFAULT_REPORT_OUTPUT = (
    ROOT / "research/reports/CAUSAL_CHACHA20_ROUND20_FACTORIAL_TRAJECTORY_TRANSFER_V1.md"
)
DEFAULT_LOCK = ROOT / ".research_sealed/chacha20_round20_factorial_trajectory_transfer_v1.lock"

SCHEMA = "chacha20-round20-factorial-trajectory-transfer-v1"
ATTEMPT_ID = "A220"
COLLECTOR_SCHEMA = "chacha20-round20-factorial-trajectory-holdout-index-v1"
READER_SCHEMA = "chacha20-round20-factorial-trajectory-reader-v1"
LAUNCH_SCHEMA = "chacha20-round20-factorial-trajectory-holdout-launch-v1"
EXPECTED_HOLDOUT_KEYS = 92


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


def _display_path(path: Path, *, root: Path) -> str:
    try:
        return os.path.relpath(path.resolve(), root.resolve())
    except ValueError:
        return str(path.resolve())


def _atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


@contextmanager
def _exclusive_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        path.chmod(0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("another A220 holdout finalizer holds the lock") from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A220 verified holdout collector {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_protocol(path: Path = PROTOCOL) -> dict[str, Any]:
    if _file_sha256(path) != PROTOCOL_SHA256:
        raise RuntimeError("A220 frozen protocol hash differs")
    protocol = json.loads(path.read_bytes())
    holdout = protocol.get("holdout_protocol", {})
    boundary = protocol.get("information_boundary", {})
    required = protocol.get("required_artifacts", {})
    if (
        protocol.get("schema") != "chacha20-round20-factorial-trajectory-transfer-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or holdout.get("keys") != EXPECTED_HOLDOUT_KEYS
        or holdout.get("selected_atomic_bundle_runs_per_key") != 2
        or holdout.get("selected_dual_schedule_bundle_runs_per_key") != 4
        or holdout.get("refit_reselection_or_threshold_change_permitted") is not False
        or holdout.get("panels") != list(HOLDOUT_PANEL_ORDER)
        or holdout.get("primary_panel") != PRIMARY_PANEL
        or holdout.get("primary_exact_permutations") != PRIMARY_EXACT_PERMUTATIONS
        or holdout.get("uniform_random_rank_expected_mean_log2")
        != UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2
        or holdout.get("primary_retention_rule")
        != "exact_lower_tail_p_at_most_0.05_and_observed_mean_log2_rank_below_6.578110496969589"
        or boundary.get("future_prospective_target_generated_or_opened_in_A220") is not False
        or boundary.get(
            "prospective_target_test_requires_a_new_separately_frozen_attempt_after_A220_holdout"
        )
        is not True
        or required.get("reader_freeze")
        != "research/results/v1/chacha20_round20_factorial_trajectory_reader_freeze_v1.json"
        or required.get("holdout_index")
        != "research/results/v1/chacha20_round20_factorial_trajectory_holdout_v1/index.json"
        or required.get("final_result")
        != "research/results/v1/chacha20_round20_factorial_trajectory_transfer_v1.json"
        or required.get("causal")
        != "research/results/v1/chacha20_round20_factorial_trajectory_transfer_v1.causal"
        or required.get("report")
        != "research/reports/CAUSAL_CHACHA20_ROUND20_FACTORIAL_TRAJECTORY_TRANSFER_V1.md"
    ):
        raise RuntimeError("A220 frozen holdout-evaluation protocol gate failed")
    return protocol


def _required_reader_path(protocol: Mapping[str, Any], *, root: Path = ROOT) -> Path:
    relative = protocol["required_artifacts"]["reader_freeze"]
    path = (root / str(relative)).resolve()
    old = (
        root / "research/results/v1/chacha20_round20_factorial_trajectory_reader_v1.json"
    ).resolve()
    if path == old or path.name != "chacha20_round20_factorial_trajectory_reader_freeze_v1.json":
        raise RuntimeError("A220 protocol does not name the authoritative Reader freeze")
    return path


def _load_verified_corpus(
    *,
    collector: Any,
    index_path: Path,
    shard_directory: Path,
    reader_path: Path,
    launch_manifest_path: Path,
    checkpoint_directory: Path | None,
    history_path: Path | None,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    loader = getattr(collector, "load_verified_holdout_corpus", None)
    if not callable(loader):
        raise RuntimeError("A220 collector lacks load_verified_holdout_corpus")
    loaded = loader(
        index_path=index_path,
        shard_directory=shard_directory,
        reader_path=reader_path,
        launch_manifest_path=launch_manifest_path,
        checkpoint_directory=checkpoint_directory,
        history_path=history_path,
    )
    if not isinstance(loaded, tuple) or len(loaded) != 5:
        raise RuntimeError("A220 verified-corpus loader interface differs")
    rows, payloads, index, reader, launch = loaded
    if (
        type(rows) is not list
        or type(payloads) is not list
        or type(index) is not dict
        or type(reader) is not dict
        or type(launch) is not dict
    ):
        raise RuntimeError("A220 verified-corpus loader return schema differs")
    return rows, payloads, index, reader, launch


def _selected_readout_sha256(reader: Mapping[str, Any]) -> str:
    selected = reader.get("selected_reader")
    if not isinstance(selected, Mapping):
        raise RuntimeError("A220 Reader lacks the selected Reader")
    material = {
        "selected_identity": selected.get("selected_identity"),
        "selected_constituent_readouts": selected.get("selected_constituent_readouts"),
        "selected_score_sha256": selected.get("selected_score_sha256"),
    }
    return _canonical_sha256(material)


def _require_digest(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RuntimeError(f"A220 {label} is not a SHA-256 digest")
    return value


def _validate_verified_corpus(
    *,
    protocol: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    payloads: Sequence[Mapping[str, Any]],
    index: Mapping[str, Any],
    reader: Mapping[str, Any],
    launch: Mapping[str, Any],
    index_path: Path,
    reader_path: Path,
    launch_manifest_path: Path,
    collector_path: Path,
    collector_test_path: Path,
    evaluator_test_path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if (
        json.loads(index_path.read_bytes()) != index
        or json.loads(reader_path.read_bytes()) != reader
        or json.loads(launch_manifest_path.read_bytes()) != launch
    ):
        raise RuntimeError("A220 verified loader return objects differ from their artifacts")
    if len(rows) != EXPECTED_HOLDOUT_KEYS or len(payloads) != EXPECTED_HOLDOUT_KEYS:
        raise RuntimeError("A220 verified holdout corpus does not contain exactly 92 keys")
    if any(type(row) is not dict for row in rows) or any(type(row) is not dict for row in payloads):
        raise RuntimeError("A220 verified holdout rows or payloads differ")
    labels = [row.get("label") for row in rows]
    if any(not isinstance(label, str) or not label for label in labels) or len(set(labels)) != 92:
        raise RuntimeError("A220 verified holdout labels differ")
    panels = [holdout_panel_name(row) for row in rows]
    if Counter(panels) != HOLDOUT_PANEL_COUNTS:
        raise RuntimeError("A220 verified holdout panel counts differ")

    index_fields = {
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
    if set(index) != index_fields:
        raise RuntimeError("A220 verified holdout index schema differs")
    if (
        index.get("schema") != COLLECTOR_SCHEMA
        or index.get("attempt_id") != ATTEMPT_ID
        or index.get("evidence_stage") != "FULLROUND_R20_FACTORIAL_HOLDOUT_TRAJECTORY_COLLECTION"
        or index.get("protocol_sha256") != PROTOCOL_SHA256
        or index.get("launch_manifest_relative_path") != "launch_manifest.json"
        or launch_manifest_path.resolve() != (index_path.parent / "launch_manifest.json").resolve()
        or index.get("launch_manifest_sha256") != _file_sha256(launch_manifest_path)
        or index.get("reader_artifact_sha256") != _file_sha256(reader_path)
        or index.get("collector_source_sha256") != _file_sha256(collector_path)
        or index.get("collector_test_sha256") != _file_sha256(collector_test_path)
    ):
        raise RuntimeError("A220 verified holdout index provenance differs")

    if (
        reader.get("schema") != READER_SCHEMA
        or reader.get("attempt_id") != ATTEMPT_ID
        or reader.get("evidence_stage") != "FULLROUND_R20_FACTORIAL_READER_FROZEN_BEFORE_HOLDOUT"
        or reader.get("protocol_sha256") != PROTOCOL_SHA256
    ):
        raise RuntimeError("A220 authoritative Reader identity differs")
    reader_boundary = reader.get("information_boundary", {})
    reader_completion = reader.get("completion_gates", {})
    if (
        reader_boundary.get("holdout_measurements_loaded") is not False
        or reader_boundary.get("future_prospective_target_loaded") is not False
        or reader_boundary.get("reader_frozen_before_any_holdout_trajectory_process") is not True
        or reader_completion.get("all_52_fit_select_shards_verified") is not True
        or reader_completion.get("all_624_fresh_solver_processes_in_verified_index") is not True
        or reader_completion.get("exactly_300_atomic_models_fit") is not True
        or reader_completion.get("exactly_450_bundle_rows_evaluated") is not True
        or reader_completion.get("all_64_matched_cluster_nulls_complete") is not True
        or reader_completion.get("one_reader_selected_and_serialized") is not True
        or reader_completion.get("holdout_trajectory_not_opened") is not True
        or reader_completion.get("future_prospective_target_not_opened") is not True
    ):
        raise RuntimeError("A220 authoritative Reader freeze/completion gate differs")
    selected_reader = reader.get("selected_reader")
    if not isinstance(selected_reader, dict):
        raise RuntimeError("A220 authoritative Reader payload differs")
    selected_identity = selected_reader.get("selected_identity")
    if not isinstance(selected_identity, dict):
        raise RuntimeError("A220 selected Reader identity differs")
    selected_run_ids = selected_bundle_run_ids(str(selected_identity.get("bundle_id")))
    if selected_identity.get("run_count") != len(selected_run_ids) or len(selected_run_ids) not in {
        2,
        4,
    }:
        raise RuntimeError("A220 selected Reader run count differs")
    identity_sha256 = _canonical_sha256(selected_identity)
    readout_sha256 = _selected_readout_sha256(reader)
    if (
        index.get("selected_reader_identity_sha256") != identity_sha256
        or index.get("selected_reader_readout_sha256") != readout_sha256
    ):
        raise RuntimeError("A220 index/Reader selected readout binding differs")

    launch_fields = {
        "schema",
        "attempt_id",
        "evidence_stage",
        "protocol_path",
        "protocol_sha256",
        "reader_path",
        "reader_artifact_sha256",
        "selected_identity_sha256",
        "selected_readout_sha256",
        "selected_reader_identity",
        "collector_source_sha256",
        "collector_test_sha256",
        "low_level_source_sha256",
        "holdout_core_path",
        "holdout_core_sha256",
        "holdout_core_test_path",
        "holdout_core_test_sha256",
        "holdout_evaluator_source_sha256",
        "holdout_evaluator_test_sha256",
        "factorial_design_path",
        "factorial_design_sha256",
        "factorial_ledger_sha256",
        "holdout_rows",
        "holdout_rows_sha256",
        "holdout_label_order_sha256",
        "holdout_labels",
        "selected_run_plan",
        "selected_run_plan_template_sha256",
        "full_holdout_process_plan_sha256",
        "full_holdout_fresh_solver_processes",
        "source_anchor_hashes",
        "resource_settings",
        "information_boundary",
    }
    if set(launch) != launch_fields:
        raise RuntimeError("A220 holdout launch-manifest schema differs")
    authoritative_reader_relative = protocol["required_artifacts"]["reader_freeze"]
    run_plan = launch.get("selected_run_plan")
    if (
        launch.get("schema") != LAUNCH_SCHEMA
        or launch.get("attempt_id") != ATTEMPT_ID
        or launch.get("evidence_stage") != "HOLDOUT_READER_AND_PLAN_FROZEN_BEFORE_ANY_SUBPROCESS"
        or launch.get("protocol_sha256") != PROTOCOL_SHA256
        or launch.get("protocol_path")
        != "research/configs/chacha20_round20_factorial_trajectory_transfer_v1.json"
        or launch.get("reader_path") != authoritative_reader_relative
        or launch.get("reader_artifact_sha256") != _file_sha256(reader_path)
        or launch.get("selected_identity_sha256") != identity_sha256
        or launch.get("selected_readout_sha256") != readout_sha256
        or launch.get("selected_reader_identity") != selected_identity
        or launch.get("collector_source_sha256") != index["collector_source_sha256"]
        or launch.get("collector_test_sha256") != index["collector_test_sha256"]
        or launch.get("holdout_core_sha256") != HOLDOUT_CORE_SHA256
        or launch.get("holdout_core_path") != "src/arx_carry_leak/factorial_holdout.py"
        or launch.get("holdout_core_test_sha256") != HOLDOUT_CORE_TEST_SHA256
        or launch.get("holdout_core_test_path") != "tests/test_factorial_holdout.py"
        or launch.get("holdout_evaluator_source_sha256") != _file_sha256(ORCHESTRATOR)
        or launch.get("holdout_evaluator_test_sha256") != _file_sha256(evaluator_test_path)
        or launch.get("holdout_rows") != 92
        or launch.get("holdout_rows_sha256") != _canonical_sha256(rows)
        or launch.get("holdout_labels") != labels
        or launch.get("holdout_label_order_sha256") != _canonical_sha256(labels)
        or index.get("factorial_holdout_label_order_sha256")
        != launch.get("holdout_label_order_sha256")
        or launch.get("selected_run_plan_template_sha256")
        != index["selected_run_plan_template_sha256"]
        or not isinstance(run_plan, list)
        or [entry.get("run_id") for entry in run_plan] != list(selected_run_ids)
        or launch.get("full_holdout_fresh_solver_processes")
        != EXPECTED_HOLDOUT_KEYS * len(selected_run_ids)
        or launch.get("source_anchor_hashes") != index["source_anchor_hashes"]
    ):
        raise RuntimeError("A220 holdout launch/Reader/index binding differs")
    resource = launch.get("resource_settings", {})
    launch_boundary = launch.get("information_boundary", {})
    if (
        resource.get("maximum_concurrent_solver_processes") != 2
        or resource.get("cell_count_per_run") != 256
        or resource.get("complete_prefix_cover_per_run") is not True
        or resource.get("early_stop") is not False
        or launch_boundary.get("reader_frozen_before_holdout") is not True
        or launch_boundary.get("fit_select_shards_or_index_opened") is not False
        or launch_boundary.get("prospective_target_opened") is not False
        or launch_boundary.get("refit_reselection_or_threshold_adaptation") is not False
    ):
        raise RuntimeError("A220 holdout launch resource/information gate differs")

    entries = index.get("verified_shards")
    if not isinstance(entries, list) or len(entries) != 92:
        raise RuntimeError("A220 index lacks exactly 92 verified shards")
    if [entry.get("key_label") for entry in entries if isinstance(entry, Mapping)] != labels:
        raise RuntimeError("A220 index does not preserve the exact holdout label order")
    entry_fields = {
        "key_label",
        "prefix_split",
        "prefix_index",
        "suffix_split",
        "suffix_index",
        "panel",
        "relative_path",
        "measurement_sha256",
        "measurement_bytes",
        "compressed_sha256",
        "compressed_bytes",
    }
    if any(
        not isinstance(entry, dict)
        or set(entry) != entry_fields
        or entry.get("panel") != holdout_panel_name(row)
        for row, entry in zip(rows, entries, strict=True)
    ):
        raise RuntimeError("A220 verified holdout input-manifest schema differs")
    input_manifest = copy.deepcopy(entries)
    input_manifest_sha256 = _canonical_sha256(input_manifest)
    for row, payload in zip(rows, payloads, strict=True):
        runs = payload.get("scientific_runs")
        if (
            payload.get("key_factorial_identity") != row
            or not isinstance(runs, dict)
            or set(runs) != set(selected_run_ids)
        ):
            raise RuntimeError("A220 verified payload selected-run cover/order differs")

    completion = index.get("completion_gates")
    if not isinstance(completion, dict):
        raise RuntimeError("A220 index completion gates differ")
    required_true = (
        "all_92_key_shards_complete",
        "all_selected_fresh_solver_processes_complete",
        "all_shards_decompressed_and_hash_verified",
        "global_index_rebuilt_from_verified_shards",
        "collector_source_unchanged",
        "reader_launch_and_source_hashes_unchanged",
        "no_failure_tombstones",
    )
    completion_fields = {
        "verified_key_shards",
        "expected_key_shards",
        "selected_runs_per_key",
        "verified_fresh_solver_processes",
        "expected_fresh_solver_processes",
        "no_failure_tombstones",
        "all_92_key_shards_complete",
        "all_selected_fresh_solver_processes_complete",
        "all_shards_decompressed_and_hash_verified",
        "global_index_rebuilt_from_verified_shards",
        "collector_source_unchanged",
        "reader_launch_and_source_hashes_unchanged",
    }
    if (
        set(completion) != completion_fields
        or completion.get("verified_key_shards") != 92
        or completion.get("expected_key_shards") != 92
        or completion.get("selected_runs_per_key") != len(selected_run_ids)
        or completion.get("verified_fresh_solver_processes") != 92 * len(selected_run_ids)
        or completion.get("expected_fresh_solver_processes") != 92 * len(selected_run_ids)
        or any(completion.get(key) is not True for key in required_true)
    ):
        raise RuntimeError("A220 holdout corpus is incomplete or contains a tombstone")

    return input_manifest, {
        "selected_identity": copy.deepcopy(selected_identity),
        "selected_identity_sha256": identity_sha256,
        "selected_readout_sha256": readout_sha256,
        "selected_run_ids": list(selected_run_ids),
        "input_manifest_sha256": input_manifest_sha256,
    }


def _source_snapshot(
    *,
    protocol_path: Path,
    collector_path: Path,
    collector_test_path: Path,
    reader_path: Path,
    launch_manifest_path: Path,
    index_path: Path,
    evaluator_test_path: Path,
) -> dict[str, str]:
    paths = {
        "protocol_sha256": protocol_path,
        "collector_source_sha256": collector_path,
        "collector_test_sha256": collector_test_path,
        "evaluator_source_sha256": ORCHESTRATOR,
        "evaluator_test_sha256": evaluator_test_path,
        "factorial_holdout_core_sha256": HOLDOUT_CORE,
        "factorial_holdout_core_test_sha256": HOLDOUT_CORE_TEST,
        "reader_artifact_sha256": reader_path,
        "launch_manifest_sha256": launch_manifest_path,
        "holdout_index_sha256": index_path,
    }
    result = {key: _file_sha256(path) for key, path in paths.items()}
    if (
        result["protocol_sha256"] != PROTOCOL_SHA256
        or result["factorial_holdout_core_sha256"] != HOLDOUT_CORE_SHA256
        or result["factorial_holdout_core_test_sha256"] != HOLDOUT_CORE_TEST_SHA256
    ):
        raise RuntimeError("A220 evaluator/core/protocol source anchor differs")
    return result


def _verify_input_files_unchanged(
    *, index_path: Path, shard_directory: Path, input_manifest: Sequence[Mapping[str, Any]]
) -> None:
    root = shard_directory.resolve()
    for entry in input_manifest:
        relative = entry.get("relative_path")
        if not isinstance(relative, str):
            raise RuntimeError("A220 input-manifest shard path differs")
        path = (index_path.parent / relative).resolve()
        if path.parent != root or path.name != f"{entry.get('key_label')}.measurement.json.zst":
            raise RuntimeError("A220 input-manifest shard path escapes the frozen directory")
        raw = path.read_bytes()
        if len(raw) != entry.get("compressed_bytes") or _sha256(raw) != entry.get(
            "compressed_sha256"
        ):
            raise RuntimeError("A220 verified holdout shard drifted after corpus loading")


def _validate_evaluation(evaluation: Mapping[str, Any], reader_meta: Mapping[str, Any]) -> None:
    if (
        not isinstance(evaluation, dict)
        or evaluation.get("selected_identity") != reader_meta["selected_identity"]
        or evaluation.get("selected_run_ids") != reader_meta["selected_run_ids"]
        or set(evaluation.get("panel_metrics", {})) != set(HOLDOUT_PANEL_ORDER)
        or evaluation.get("evidence_stage")
        not in {
            "FULLROUND_R20_FACTORIAL_TRAJECTORY_HOLDOUT_TRANSFER",
            "FULLROUND_R20_FACTORIAL_TRAJECTORY_PROBE_SPECIFIC_BOUNDARY",
        }
    ):
        raise RuntimeError("A220 pure-core holdout evaluation schema differs")
    primary = evaluation.get("primary_exact_cluster_null")
    if not isinstance(primary, dict):
        raise RuntimeError("A220 pure-core primary null differs")
    records = primary.get("permutation_records")
    expected_permutations = set(itertools.permutations(range(5)))
    observed_permutations = (
        {
            tuple(record.get("cluster_permutation", ()))
            for record in records
            if isinstance(record, Mapping)
        }
        if isinstance(records, list)
        else set()
    )
    p_value = primary.get("exact_lower_tail_p")
    observed_mean = primary.get("observed_metrics", {}).get("mean_log2_rank")
    retained = primary.get("retained")
    expected_retained = (
        isinstance(p_value, (int, float))
        and not isinstance(p_value, bool)
        and isinstance(observed_mean, (int, float))
        and not isinstance(observed_mean, bool)
        and math.isfinite(float(p_value))
        and math.isfinite(float(observed_mean))
        and float(p_value) <= PRIMARY_P_THRESHOLD
        and float(observed_mean) < UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2
    )
    panel_metrics = evaluation["panel_metrics"]
    for panel in HOLDOUT_PANEL_ORDER:
        metrics = panel_metrics[panel]
        ranks = metrics.get("ranks") if isinstance(metrics, Mapping) else None
        if not isinstance(ranks, list) or len(ranks) != HOLDOUT_PANEL_COUNTS[panel]:
            raise RuntimeError("A220 pure-core panel rank count differs")
    statistics = (
        [record.get("mean_log2_rank") for record in records if isinstance(record, Mapping)]
        if isinstance(records, list)
        else []
    )
    expected_p = (
        sum(float(value) <= float(observed_mean) for value in statistics)
        / PRIMARY_EXACT_PERMUTATIONS
        if len(statistics) == PRIMARY_EXACT_PERMUTATIONS
        and all(isinstance(value, (int, float)) for value in statistics)
        and isinstance(observed_mean, (int, float))
        else None
    )
    expected_bit_gain = (
        UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2 - float(observed_mean)
        if isinstance(observed_mean, (int, float))
        else None
    )
    if (
        len(records) != PRIMARY_EXACT_PERMUTATIONS
        or observed_permutations != expected_permutations
        or primary.get("panel") != PRIMARY_PANEL
        or primary.get("uniform_random_rank_expected_mean_log2")
        != UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2
        or primary.get("retention_threshold") != PRIMARY_P_THRESHOLD
        or p_value != expected_p
        or primary.get("observed_bit_gain_over_uniform_mean_log2") != expected_bit_gain
        or primary.get("geometric_rank_concentration_factor")
        != (float(2.0**expected_bit_gain) if expected_bit_gain is not None else None)
        or retained is not expected_retained
        or evaluation.get("evidence_stage").endswith("HOLDOUT_TRANSFER") is not expected_retained
    ):
        raise RuntimeError("A220 pure-core exact 5-factorial null/retention rule differs")
    unhashed = {key: value for key, value in evaluation.items() if key != "evaluation_sha256"}
    if evaluation.get("evaluation_sha256") != _canonical_sha256(unhashed):
        raise RuntimeError("A220 pure-core evaluation digest differs")


def _representation_condition(
    selected_identity: Mapping[str, Any], selected_run_ids: Sequence[str]
) -> str:
    return (
        "standard ChaCha20 with 20 rounds and feed-forward; 236 known and 20 unknown "
        "key bits; eight known-key blocks; the frozen A220 "
        f"{selected_identity['bundle_id']} / {selected_identity['feature_family']} / "
        f"{selected_identity['readout_kind']} / ridge lambda "
        f"{selected_identity['ridge_lambda']} Reader; exactly {len(selected_run_ids)} "
        "fresh selected trajectory runs per key; decisions, search-propagations and "
        "redundant-clause-delta features; 92 factorial holdout keys; and the complete "
        "confirm-by-confirm 5! whole-prefix-cluster label null under fixed budgets"
    )


def _next_scientific_action(retained: bool) -> str:
    if retained:
        return (
            "Freeze a new, separate prospective prefix-ordering attempt that reuses this "
            "Reader byte-for-byte and fixes its execution budget before any new challenge is opened."
        )
    return (
        "Use the already computed four panels to localize prefix novelty, suffix novelty, "
        "or their interaction, then freeze the highest-information new representation probe "
        "before collecting any additional trajectories."
    )


def _build_causal_bytes(
    *,
    measurement_sha256: str,
    evaluation: Mapping[str, Any],
    reader_meta: Mapping[str, Any],
    representation_condition: str,
    next_action: str,
    causal_output: Path,
) -> tuple[bytes, dict[str, Any]]:
    primary = evaluation["primary_exact_cluster_null"]
    retained = bool(primary["retained"])
    branch_outcome = (
        "A220:prospectively_reusable_prefix_ordering_operator_retained"
        if retained
        else "A220:probe_specific_representation_boundary_identified"
    )
    builder = CryptoCausalBuilder(
        experiment="chacha20_round20_factorial_trajectory_holdout_transfer",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "protocol_sha256": PROTOCOL_SHA256,
            "measurement_sha256": measurement_sha256,
            "selected_identity_sha256": reader_meta["selected_identity_sha256"],
            "selected_readout_sha256": reader_meta["selected_readout_sha256"],
            "holdout_keys": EXPECTED_HOLDOUT_KEYS,
            "exact_primary_permutations": PRIMARY_EXACT_PERMUTATIONS,
            "retained": retained,
            "fuzzy_matching": False,
        },
    )
    builder.add_rule(
        ExactRule(
            name="frozen_reader_to_fixed_holdout_scoring",
            first="reader_frozen_with_exact_selected_run_plan",
            second="fresh_fullround_trajectories_scored_by_fixed_reader",
            conclusion="prospective_fixed_reader_holdout_scoring",
        )
    )
    builder.add_rule(
        ExactRule(
            name="fixed_scoring_to_exact_factorial_inference",
            first="prospective_fixed_reader_holdout_scoring",
            second="complete_5_factorial_whole_prefix_cluster_null",
            conclusion="exact_factorial_holdout_inference",
        )
    )
    edge_ids = (
        "a220-holdout-1-reader-freeze",
        "a220-holdout-2-fixed-scoring",
        "a220-holdout-3-exact-cluster-null",
    )
    builder.add_triplet(
        edge_id=edge_ids[0],
        trigger="A220:fit_select_reader_selection_complete",
        mechanism="reader_frozen_with_exact_selected_run_plan",
        outcome="A220:frozen_reader_and_selected_holdout_plan",
        confidence=1.0,
        evidence_kind="atomic_reader_and_preexecution_launch_freeze",
        source=f"reader:sha256:{reader_meta['reader_artifact_sha256']}",
        attrs={
            "selected_identity": reader_meta["selected_identity"],
            "selected_identity_sha256": reader_meta["selected_identity_sha256"],
            "selected_readout_sha256": reader_meta["selected_readout_sha256"],
            "selected_run_ids": reader_meta["selected_run_ids"],
            "fresh_runs_per_key": len(reader_meta["selected_run_ids"]),
            "reader_frozen_before_any_holdout_trajectory_process": True,
        },
    )
    builder.add_triplet(
        edge_id=edge_ids[1],
        trigger="A220:frozen_reader_and_selected_holdout_plan",
        mechanism="fresh_fullround_trajectories_scored_by_fixed_reader",
        outcome="A220:fixed_reader_holdout_prefix_ranks",
        confidence=1.0,
        evidence_kind="verified_92_key_fullround_R20_holdout_measurement",
        source=f"measurement:sha256:{measurement_sha256}",
        provenance=[edge_ids[0]],
        attrs={
            "holdout_keys": 92,
            "panels": evaluation["panel_metrics"],
            "score_matrix_float64_le_sha256": evaluation["score_matrix_float64_le_sha256"],
            "evaluation_sha256": evaluation["evaluation_sha256"],
            "refit_reselection_or_threshold_adaptation": False,
        },
    )
    builder.add_triplet(
        edge_id=edge_ids[2],
        trigger="A220:fixed_reader_holdout_prefix_ranks",
        mechanism="complete_5_factorial_whole_prefix_cluster_null",
        outcome=branch_outcome,
        confidence=1.0,
        evidence_kind=(
            "exact_factorial_transfer_retention"
            if retained
            else "exact_probe_specific_representation_boundary"
        ),
        source=f"measurement:sha256:{measurement_sha256}",
        provenance=[edge_ids[1]],
        attrs={
            "observed_metrics": primary["observed_metrics"],
            "exact_lower_tail_p": primary["exact_lower_tail_p"],
            "retention_threshold": primary["retention_threshold"],
            "uniform_mean_log2_boundary": primary["uniform_random_rank_expected_mean_log2"],
            "observed_bit_gain_over_uniform_mean_log2": primary[
                "observed_bit_gain_over_uniform_mean_log2"
            ],
            "geometric_rank_concentration_factor": primary["geometric_rank_concentration_factor"],
            "retained": retained,
            "representation_condition": representation_condition,
            "interpretation": (
                "prospectively_reusable_prefix_ordering_operator_not_a_recovery_result"
                if retained
                else "boundary_only_for_the_exact_tested_representation_not_cipher_immunity"
            ),
            "next_scientific_action": next_action,
        },
    )
    inferred = builder.infer_exact_closure(max_hops=3)
    if len(inferred) != 2:
        raise RuntimeError("A220 exact Causal rule closure differs")

    causal_output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".a220-holdout-causal-", dir=causal_output.parent
    ) as temporary:
        temporary_path = Path(temporary) / causal_output.name
        stats = builder.save(temporary_path)
        raw = temporary_path.read_bytes()
        reader = CryptoCausalReader(temporary_path)
        explicit = reader.triplets(include_inferred=False)
        all_rows = reader.triplets(include_inferred=True)
        by_id = {row["edge_id"]: row for row in explicit}
        if (
            [row["edge_id"] for row in explicit] != list(edge_ids)
            or len(all_rows) != 5
            or sum(bool(row.get("is_inferred")) for row in all_rows) != 2
            or not reader.verify_provenance()
            or reader.graph_sha256 != stats["graph_sha256"]
            or by_id[edge_ids[0]]["outcome"] != by_id[edge_ids[1]]["trigger"]
            or by_id[edge_ids[1]]["outcome"] != by_id[edge_ids[2]]["trigger"]
            or by_id[edge_ids[2]]["outcome"] != branch_outcome
            or [row["provenance"] for row in explicit] != [[], [edge_ids[0]], [edge_ids[1]]]
        ):
            raise RuntimeError("A220 Causal exact chain/readback gate failed")
    return raw, {
        "path": str(causal_output),
        "bytes": len(raw),
        "triplets": 5,
        "explicit_triplets": 3,
        "inferred_triplets": 2,
        "file_sha256": _sha256(raw),
        "graph_sha256": stats["graph_sha256"],
        "reader_verified": True,
        "provenance_chain_verified": True,
    }


def _metric(value: Any) -> str:
    return f"{float(value):.12g}"


def _report_bytes(payload: Mapping[str, Any]) -> bytes:
    evaluation = payload["evaluation"]
    primary = evaluation["primary_exact_cluster_null"]
    identity = payload["selected_reader"]["selected_identity"]
    retained = bool(primary["retained"])
    if retained:
        headline = "Retained result: frozen full-round R20 trajectory Reader transfers"
        conclusion = (
            "The pre-frozen Reader satisfies the complete prospective holdout retention rule. "
            "It therefore supplies a prospectively reusable prefix-ordering operator; this A220 "
            "holdout result is not itself a recovery result."
        )
    else:
        headline = (
            "New boundary: frozen full-round R20 trajectory Reader under the exact A220 probe"
        )
        conclusion = (
            "The pre-frozen Reader does not satisfy the registered retention conjunction under "
            "this exact representation. This is a probe-specific representation boundary, not a "
            "general ChaCha20 immunity statement."
        )
    lines = [
        "# A220 — ChaCha20 R20 Factorial-Trajectory Holdout",
        "",
        f"## {headline}",
        "",
        f"**Evidence stage:** `{payload['evidence_stage']}`",
        "",
        conclusion,
        "",
        "## Frozen Reader",
        "",
        f"- Bundle: `{identity['bundle_id']}` ({identity['run_count']} fresh runs per key)",
        f"- Feature family: `{identity['feature_family']}`",
        f"- Readout: `{identity['readout_kind']}`; ridge lambda `{identity['ridge_lambda']}`",
        f"- Selected identity SHA-256: `{payload['selected_reader']['selected_identity_sha256']}`",
        f"- Selected readout SHA-256: `{payload['selected_reader']['selected_readout_sha256']}`",
        "- Refit, reselection, feature changes, threshold changes, and adaptive execution: `false`",
        "",
        "## Four frozen holdout panels",
        "",
        "| Panel | Keys | Mean log2 rank | Median rank | Mean rank | Hit@1 | Hit@8 | Hit@16 | Hit@32 | Hit@64 | MRR |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for panel in HOLDOUT_PANEL_ORDER:
        metrics = evaluation["panel_metrics"][panel]
        lines.append(
            "| "
            + " | ".join(
                [
                    panel,
                    str(HOLDOUT_PANEL_COUNTS[panel]),
                    _metric(metrics["mean_log2_rank"]),
                    _metric(metrics["median_rank"]),
                    _metric(metrics["mean_rank"]),
                    _metric(metrics["hit_at_1"]),
                    _metric(metrics["hit_at_8"]),
                    _metric(metrics["hit_at_16"]),
                    _metric(metrics["hit_at_32"]),
                    _metric(metrics["hit_at_64"]),
                    _metric(metrics["mean_reciprocal_rank"]),
                ]
            )
            + " |"
        )
    observed = primary["observed_metrics"]
    lines.extend(
        [
            "",
            "## Primary confirm-by-confirm exact inference",
            "",
            f"- Observed mean log2 rank: `{_metric(observed['mean_log2_rank'])}`",
            f"- Observed median rank: `{_metric(observed['median_rank'])}`",
            f"- Observed mean rank: `{_metric(observed['mean_rank'])}`",
            f"- Exact lower-tail p-value over all 5! = 120 whole-cluster permutations: `{_metric(primary['exact_lower_tail_p'])}`",
            f"- Registered p threshold: `{PRIMARY_P_THRESHOLD}`",
            f"- Uniform mean-log2 boundary: `{UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2}`",
            f"- Bit gain over uniform mean log2: `{_metric(primary['observed_bit_gain_over_uniform_mean_log2'])}`",
            f"- Geometric rank concentration factor: `{_metric(primary['geometric_rank_concentration_factor'])}`",
            f"- Retained: `{str(retained).lower()}`",
            "",
            "## Completion and provenance",
            "",
            "- Verified holdout keys: `92/92`",
            f"- Fresh selected solver trajectories represented in the verified corpus: `{92 * identity['run_count']}`",
            f"- Exact cluster-null permutations: `{len(primary['permutation_records'])}/120`",
            f"- Holdout input manifest SHA-256: `{payload['holdout_input_manifest_sha256']}`",
            f"- Reader artifact SHA-256: `{payload['reader_artifact_sha256']}`",
            f"- Public launch manifest SHA-256: `{payload['holdout_launch_manifest_sha256']}`",
            f"- Holdout index SHA-256: `{payload['holdout_index_sha256']}`",
            f"- Pure-core evaluation SHA-256: `{evaluation['evaluation_sha256']}`",
            f"- Measurement SHA-256: `{payload['measurement_sha256']}`",
            f"- Causal graph SHA-256: `{payload['causal_artifact']['graph_sha256']}`",
            f"- Causal Reader provenance verified: `{str(payload['causal_artifact']['reader_verified']).lower()}`",
            "- Public reconstructive verification supported: `true`",
            "- Sealed execution provenance embedded in verified shards: `true`",
            "",
            "## Scope",
            "",
            payload["tested_representation_condition"] + ".",
            "",
            "## Next scientific action",
            "",
            payload["next_scientific_action"],
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def _commit_artifact_set(artifacts: Mapping[Path, bytes]) -> None:
    if len(artifacts) != 3 or len({path.resolve() for path in artifacts}) != 3:
        raise ValueError("A220 result, Causal, and report paths must be distinct")
    conflicts = [
        path for path, raw in artifacts.items() if path.exists() and path.read_bytes() != raw
    ]
    if conflicts:
        raise RuntimeError(
            "A220 finalizer refuses conflicting existing output: "
            + ", ".join(str(path) for path in conflicts)
        )
    for path, raw in artifacts.items():
        if not path.exists():
            _atomic_bytes(path, raw)
    if any(path.read_bytes() != raw for path, raw in artifacts.items()):
        raise RuntimeError("A220 final artifact atomic readback differs")


def run(
    *,
    index_path: Path = DEFAULT_INDEX,
    shard_directory: Path = DEFAULT_SHARD_DIRECTORY,
    reader_path: Path | None = None,
    launch_manifest_path: Path = DEFAULT_LAUNCH_MANIFEST,
    checkpoint_directory: Path | None = DEFAULT_CHECKPOINT_DIRECTORY,
    history_path: Path | None = DEFAULT_ATTEMPT_HISTORY,
    output_path: Path = DEFAULT_OUTPUT,
    causal_output_path: Path = DEFAULT_CAUSAL_OUTPUT,
    report_output_path: Path = DEFAULT_REPORT_OUTPUT,
    lock_path: Path = DEFAULT_LOCK,
    protocol_path: Path = PROTOCOL,
    collector_path: Path = COLLECTOR,
    collector_test_path: Path = COLLECTOR_TEST,
    evaluator_test_path: Path = TEST_SOURCE,
    root: Path = ROOT,
) -> dict[str, Any]:
    if (checkpoint_directory is None) is not (history_path is None):
        raise ValueError(
            "A220 verification requires both sealed crossbinding paths or public-only mode"
        )
    protocol = _load_protocol(protocol_path)
    authoritative_reader = _required_reader_path(protocol, root=root)
    if reader_path is not None and reader_path.resolve() != authoritative_reader:
        raise RuntimeError("A220 finalizer refuses a non-authoritative Reader path")
    reader_path = authoritative_reader
    collector = _import_path(collector_path, "a220_holdout_finalizer_verified_collector")

    with _exclusive_lock(lock_path):
        rows, payloads, index, reader, launch = _load_verified_corpus(
            collector=collector,
            index_path=index_path,
            shard_directory=shard_directory,
            reader_path=reader_path,
            launch_manifest_path=launch_manifest_path,
            checkpoint_directory=checkpoint_directory,
            history_path=history_path,
        )
        input_manifest, reader_meta = _validate_verified_corpus(
            protocol=protocol,
            rows=rows,
            payloads=payloads,
            index=index,
            reader=reader,
            launch=launch,
            index_path=index_path,
            reader_path=reader_path,
            launch_manifest_path=launch_manifest_path,
            collector_path=collector_path,
            collector_test_path=collector_test_path,
            evaluator_test_path=evaluator_test_path,
        )
        source_snapshot = _source_snapshot(
            protocol_path=protocol_path,
            collector_path=collector_path,
            collector_test_path=collector_test_path,
            reader_path=reader_path,
            launch_manifest_path=launch_manifest_path,
            index_path=index_path,
            evaluator_test_path=evaluator_test_path,
        )
        if (
            source_snapshot["reader_artifact_sha256"] != index["reader_artifact_sha256"]
            or source_snapshot["launch_manifest_sha256"] != index["launch_manifest_sha256"]
            or source_snapshot["collector_source_sha256"] != index["collector_source_sha256"]
            or source_snapshot["collector_test_sha256"] != index["collector_test_sha256"]
        ):
            raise RuntimeError("A220 finalizer source/index snapshot differs")
        _verify_input_files_unchanged(
            index_path=index_path,
            shard_directory=shard_directory,
            input_manifest=input_manifest,
        )

        # The sole statistical operation in this finalizer.  No fit, selection,
        # threshold, or feature-construction function is imported here.
        evaluation = evaluate_verified_holdout(reader["selected_reader"], rows, payloads)
        _validate_evaluation(evaluation, reader_meta)
        condition = _representation_condition(
            reader_meta["selected_identity"], reader_meta["selected_run_ids"]
        )
        next_action = _next_scientific_action(
            bool(evaluation["primary_exact_cluster_null"]["retained"])
        )
        completion_gates = {
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
        information_boundary = {
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
        measurement: dict[str, Any] = {
            "schema": SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "evidence_stage": evaluation["evidence_stage"],
            "protocol_path": _display_path(protocol_path, root=root),
            "protocol_sha256": source_snapshot["protocol_sha256"],
            "reader_path": _display_path(reader_path, root=root),
            "reader_artifact_sha256": source_snapshot["reader_artifact_sha256"],
            "holdout_launch_manifest_path": _display_path(launch_manifest_path, root=root),
            "holdout_launch_manifest_sha256": source_snapshot["launch_manifest_sha256"],
            "holdout_index_path": _display_path(index_path, root=root),
            "holdout_index_sha256": source_snapshot["holdout_index_sha256"],
            "holdout_collector_path": _display_path(collector_path, root=root),
            "holdout_collector_sha256": source_snapshot["collector_source_sha256"],
            "holdout_collector_test_path": _display_path(collector_test_path, root=root),
            "holdout_collector_test_sha256": source_snapshot["collector_test_sha256"],
            "holdout_evaluator_path": _display_path(ORCHESTRATOR, root=root),
            "holdout_evaluator_sha256": source_snapshot["evaluator_source_sha256"],
            "holdout_evaluator_test_path": _display_path(evaluator_test_path, root=root),
            "holdout_evaluator_test_sha256": source_snapshot["evaluator_test_sha256"],
            "factorial_holdout_core_path": _display_path(HOLDOUT_CORE, root=root),
            "factorial_holdout_core_sha256": source_snapshot["factorial_holdout_core_sha256"],
            "factorial_holdout_core_test_path": _display_path(HOLDOUT_CORE_TEST, root=root),
            "factorial_holdout_core_test_sha256": source_snapshot[
                "factorial_holdout_core_test_sha256"
            ],
            "source_anchor_hashes": copy.deepcopy(index["source_anchor_hashes"]),
            "selected_reader": {
                "selected_identity": reader_meta["selected_identity"],
                "selected_identity_sha256": reader_meta["selected_identity_sha256"],
                "selected_readout_sha256": reader_meta["selected_readout_sha256"],
                "selected_run_ids": reader_meta["selected_run_ids"],
            },
            "holdout_input_manifest": input_manifest,
            "holdout_input_manifest_sha256": reader_meta["input_manifest_sha256"],
            "evaluation": evaluation,
            "tested_representation_condition": condition,
            "next_scientific_action": next_action,
            "information_boundary": information_boundary,
            "completion_gates": completion_gates,
        }
        measurement_sha256 = _canonical_sha256(measurement)
        reader_meta = {
            **reader_meta,
            "reader_artifact_sha256": source_snapshot["reader_artifact_sha256"],
        }
        causal_raw, causal_artifact = _build_causal_bytes(
            measurement_sha256=measurement_sha256,
            evaluation=evaluation,
            reader_meta=reader_meta,
            representation_condition=condition,
            next_action=next_action,
            causal_output=causal_output_path,
        )
        causal_artifact["path"] = _display_path(causal_output_path, root=root)
        result = {
            **measurement,
            "measurement_sha256": measurement_sha256,
            "causal_artifact": causal_artifact,
        }
        result_raw = _json_bytes(result)
        report_raw = _report_bytes(result)

        _verify_input_files_unchanged(
            index_path=index_path,
            shard_directory=shard_directory,
            input_manifest=input_manifest,
        )
        if (
            _source_snapshot(
                protocol_path=protocol_path,
                collector_path=collector_path,
                collector_test_path=collector_test_path,
                reader_path=reader_path,
                launch_manifest_path=launch_manifest_path,
                index_path=index_path,
                evaluator_test_path=evaluator_test_path,
            )
            != source_snapshot
        ):
            raise RuntimeError("A220 evaluator source/Reader/launch/index drifted during inference")

        _commit_artifact_set(
            {
                output_path: result_raw,
                causal_output_path: causal_raw,
                report_output_path: report_raw,
            }
        )
        reread = json.loads(output_path.read_bytes())
        causal_reader = CryptoCausalReader(causal_output_path)
        if (
            reread != result
            or reread.get("measurement_sha256")
            != _canonical_sha256(
                {
                    key: value
                    for key, value in reread.items()
                    if key not in {"measurement_sha256", "causal_artifact"}
                }
            )
            or causal_reader.file_sha256 != causal_artifact["file_sha256"]
            or causal_reader.graph_sha256 != causal_artifact["graph_sha256"]
            or not causal_reader.verify_provenance()
            or report_output_path.read_bytes() != report_raw
        ):
            raise RuntimeError("A220 final JSON/Causal/report readback verification failed")
        if (
            _source_snapshot(
                protocol_path=protocol_path,
                collector_path=collector_path,
                collector_test_path=collector_test_path,
                reader_path=reader_path,
                launch_manifest_path=launch_manifest_path,
                index_path=index_path,
                evaluator_test_path=evaluator_test_path,
            )
            != source_snapshot
        ):
            raise RuntimeError("A220 sources drifted across final artifact commit")
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    parser.add_argument("--shard-directory", type=Path, default=DEFAULT_SHARD_DIRECTORY)
    parser.add_argument("--reader", type=Path, default=None)
    parser.add_argument("--launch-manifest", type=Path, default=DEFAULT_LAUNCH_MANIFEST)
    parser.add_argument("--checkpoint-directory", type=Path, default=DEFAULT_CHECKPOINT_DIRECTORY)
    parser.add_argument("--history", type=Path, default=DEFAULT_ATTEMPT_HISTORY)
    parser.add_argument(
        "--public-only-verification",
        action="store_true",
        help=(
            "verify public shards, embedded histories, Index, Launch, and Reader "
            "without sealed checkpoint/history crossbinding"
        ),
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--causal-output", type=Path, default=DEFAULT_CAUSAL_OUTPUT)
    parser.add_argument("--report-output", type=Path, default=DEFAULT_REPORT_OUTPUT)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    arguments = parser.parse_args()
    result = run(
        index_path=arguments.index.resolve(),
        shard_directory=arguments.shard_directory.resolve(),
        reader_path=arguments.reader.resolve() if arguments.reader is not None else None,
        launch_manifest_path=arguments.launch_manifest.resolve(),
        checkpoint_directory=(
            None if arguments.public_only_verification else arguments.checkpoint_directory.resolve()
        ),
        history_path=(None if arguments.public_only_verification else arguments.history.resolve()),
        output_path=arguments.output.resolve(),
        causal_output_path=arguments.causal_output.resolve(),
        report_output_path=arguments.report_output.resolve(),
        lock_path=arguments.lock.resolve(),
    )
    print(
        json.dumps(
            {
                "output": str(arguments.output),
                "output_sha256": _file_sha256(arguments.output),
                "causal_output": str(arguments.causal_output),
                "causal_sha256": result["causal_artifact"]["file_sha256"],
                "report_output": str(arguments.report_output),
                "evidence_stage": result["evidence_stage"],
                "primary_exact_lower_tail_p": result["evaluation"]["primary_exact_cluster_null"][
                    "exact_lower_tail_p"
                ],
                "retained": result["evaluation"]["primary_exact_cluster_null"]["retained"],
                "verification_mode": (
                    "public_only_reconstructive"
                    if arguments.public_only_verification
                    else "sealed_execution_crossbinding"
                ),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
