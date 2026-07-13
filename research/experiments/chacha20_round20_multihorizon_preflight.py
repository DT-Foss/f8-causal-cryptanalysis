#!/usr/bin/env python3
"""Run the frozen A220P known-key multi-horizon interpretation preflight."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import math
import sys
import tempfile
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
ORCHESTRATOR = Path(__file__).resolve()
RESEARCH = ROOT / "research"
PROTOCOL = RESEARCH / "configs/chacha20_round20_multihorizon_preflight_v1.json"
PROTOCOL_SHA256 = "a1f544800f0f2349d6a74ceca041e212a624e74b5a0ade3975e233571eb3e474"
DEFAULT_OUTPUT = RESEARCH / "results/v1/chacha20_round20_multihorizon_preflight_v1.json"
DEFAULT_CHECKPOINT = (
    ROOT / ".research_sealed/chacha20_round20_multihorizon_preflight_v1.checkpoint.json"
)
DEFAULT_LOCK = ROOT / ".research_sealed/chacha20_round20_multihorizon_preflight_v1.lock"
ATTEMPT_ID = "A220P"
SCHEMA = "chacha20-round20-multihorizon-preflight-v1"
CHECKPOINT_SCHEMA = "chacha20-round20-multihorizon-preflight-checkpoint-v1"
SCHEDULE_NAMES = ("staged_retained_resolve", "one_shot")
NONNEGATIVE_CHANNELS = ("conflicts", "decisions", "search_propagations")
SIGNED_CHANNELS = (
    "active_variables_delta",
    "irredundant_clauses_delta",
    "redundant_clauses_delta",
)
CHANNELS = (*NONNEGATIVE_CHANNELS, *SIGNED_CHANNELS)
VOLATILE_STAGE_FIELDS = {"elapsed_seconds"}


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
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    )
    if private:
        temporary.chmod(0o600)
    temporary.replace(path)
    if private:
        path.chmod(0o600)


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A220P dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_protocol() -> dict[str, Any]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A220P frozen protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    execution = protocol.get("execution", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != "chacha20-round20-multihorizon-preflight-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_before_any_A220P_solver_process_or_multihorizon_measurement"
        or execution.get("schedules", {}).get("staged_retained_resolve") != [8, 16, 32, 64]
        or execution.get("schedules", {}).get("one_shot") != [64]
        or execution.get("runs") != 12
        or execution.get("fresh_solver_process_per_run") is not True
        or execution.get("maximum_concurrent_solver_processes") != 2
        or execution.get("exclusive_orchestrator_lock") is not True
        or execution.get("watchdog_seconds_per_stage") != 5.0
        or execution.get("retry_after_failure") is not False
        or execution.get("fail_closed") is not True
        or boundary.get("prospective_target_secret_or_salt_loaded") is not False
        or boundary.get("prospective_target_result_or_rank_used") is not False
        or boundary.get("target_secret_dependency_paths") != []
        or boundary.get("model_selection_or_recovery_claim_permitted") is not False
    ):
        raise RuntimeError("A220P frozen protocol semantic gate failed")
    return protocol


@contextmanager
def _exclusive_orchestrator_lock(path: Path = DEFAULT_LOCK):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        path.chmod(0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError(
                "another A220P orchestrator already holds the launch lock"
            ) from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _declared_anchor_hashes(protocol: Mapping[str, Any]) -> dict[str, str]:
    anchors = protocol["anchors"]
    pairs = (
        ("R20_runner_path", "R20_runner_sha256"),
        ("A214_knownkey_helper_path", "A214_knownkey_helper_sha256"),
        ("A214_symbolic_template_path", "A214_symbolic_template_sha256"),
        ("A214_template_protocol_path", "A214_template_protocol_sha256"),
        ("A212_formula_protocol_path", "A212_formula_protocol_sha256"),
        ("A212_formula_result_path", "A212_formula_result_sha256"),
        ("multihorizon_wrapper_path", "multihorizon_wrapper_sha256"),
        ("multihorizon_native_source_path", "multihorizon_native_source_sha256"),
    )
    return {str(anchors[path_key]): str(anchors[hash_key]) for path_key, hash_key in pairs}


def _verify_anchor_files(protocol: Mapping[str, Any]) -> dict[str, str]:
    declared = _declared_anchor_hashes(protocol)
    drift = {
        relative: _file_sha256(ROOT / relative)
        for relative, expected in declared.items()
        if _file_sha256(ROOT / relative) != expected
    }
    if drift:
        raise RuntimeError(f"A220P anchor drift: {drift}")
    return declared


def _order_uint8_sha256(order: Sequence[str]) -> str:
    return _sha256(bytes(int(prefix, 2) for prefix in order))


def _formula_gray8_order() -> list[int]:
    bit_map = (5, 4, 3, 7, 6, 0, 1, 2)
    order: list[int] = []
    for value in range(256):
        gray = value ^ (value >> 1)
        mapped = 0
        for source, target in enumerate(bit_map):
            mapped |= ((gray >> source) & 1) << target
        order.append(mapped ^ 176)
    return order


def _operator_orders(
    protocol: Mapping[str, Any], *, a212_result: Mapping[str, Any] | None = None
) -> dict[str, list[str]]:
    numeric = list(range(256))
    gray = [value ^ (value >> 1) for value in numeric]
    formula = _formula_gray8_order()
    integer_orders = {
        "numeric_forward": numeric,
        "numeric_reverse_same_anchor": [numeric[0], *reversed(numeric[1:])],
        "reflected_gray8_forward": gray,
        "reflected_gray8_reverse_same_anchor": [gray[0], *reversed(gray[1:])],
        "formula_gray8_forward": formula,
        "formula_gray8_reverse_same_anchor": [formula[0], *reversed(formula[1:])],
    }
    declared = protocol["operator_orders"]
    if [row["name"] for row in declared] != list(integer_orders):
        raise RuntimeError("A220P operator order names or sequence differ")
    complete = set(range(256))
    for row in declared:
        values = integer_orders[row["name"]]
        if (
            len(values) != 256
            or set(values) != complete
            or f"{values[0]:08b}" != row["anchor_prefix8"]
            or _sha256(bytes(values)) != row["order_uint8_sha256"]
        ):
            raise RuntimeError(f"A220P operator order gate failed: {row['name']}")
    for forward, reverse in (
        ("numeric_forward", "numeric_reverse_same_anchor"),
        ("reflected_gray8_forward", "reflected_gray8_reverse_same_anchor"),
        ("formula_gray8_forward", "formula_gray8_reverse_same_anchor"),
    ):
        left, right = integer_orders[forward], integer_orders[reverse]
        if right != [left[0], *reversed(left[1:])]:
            raise RuntimeError(f"A220P same-anchor reverse gate failed: {reverse}")
    if a212_result is not None:
        schedule = a212_result.get("prospective_schedule", {})
        if (
            schedule.get("start_prefix8") != "10110000"
            or schedule.get("selected_bit_permutation_source_to_target") != [5, 4, 3, 7, 6, 0, 1, 2]
            or schedule.get("selected_direction") != "forward"
            or schedule.get("formula_gray8_order") != [f"{value:08b}" for value in formula]
            or schedule.get("formula_gray8_order_sha256")
            != "ba9cf4d93c1937665772c77b9091d45cb575054c70037d9cc540ee70a9609127"
            or schedule.get("future_solver_outcome_used") is not False
        ):
            raise RuntimeError("A220P A212 formula-order audit gate failed")
    return {name: [f"{value:08b}" for value in values] for name, values in integer_orders.items()}


def _order_manifests(
    protocol: Mapping[str, Any], orders: Mapping[str, Sequence[str]]
) -> dict[str, dict[str, Any]]:
    declared = {row["name"]: row for row in protocol["operator_orders"]}
    return {
        name: {
            "anchor_prefix8": order[0],
            "cell_count": len(order),
            "complete_prefix_permutation": len(order) == 256
            and set(order) == {f"{value:08b}" for value in range(256)},
            "order_uint8_sha256": _order_uint8_sha256(order),
            "construction": declared[name]["construction"],
            **(
                {"reversal_semantics": declared[name]["reversal_semantics"]}
                if "reversal_semantics" in declared[name]
                else {}
            ),
        }
        for name, order in orders.items()
    }


def _run_plan(
    protocol: Mapping[str, Any], orders: Mapping[str, Sequence[str]]
) -> list[dict[str, Any]]:
    schedules = protocol["execution"]["schedules"]
    plan = []
    for operator, order in orders.items():
        for schedule_name in SCHEDULE_NAMES:
            plan.append(
                {
                    "run_id": f"{operator}__{schedule_name}",
                    "mode": f"A220P_{operator}_{schedule_name}",
                    "operator": operator,
                    "schedule": schedule_name,
                    "conflict_horizons": list(schedules[schedule_name]),
                    "order": list(order),
                    "order_uint8_sha256": _order_uint8_sha256(order),
                }
            )
    if len(plan) != 12 or len({row["run_id"] for row in plan}) != 12:
        raise RuntimeError("A220P run plan is not exactly twelve unique runs")
    return plan


def _validate_known_key_ledger(protocol: Mapping[str, Any], knownkey: Any) -> dict[str, Any]:
    ledger = knownkey.atlas_ledger()
    anchor = protocol["known_key_anchor"]
    selected = [
        row
        for row in ledger
        if row["split"] == anchor["ledger_split"]
        and int(row["index"]) == int(anchor["ledger_index"])
    ]
    if (
        knownkey.atlas_ledger_sha256(ledger) != protocol["anchors"]["A214_knownkey_ledger_sha256"]
        or len(selected) != 1
        or int(selected[0]["low20"]) != int(anchor["low20"])
        or selected[0]["low20_hex"] != anchor["low20_hex"]
        or selected[0]["derivation_label"] != anchor["derivation_label"]
        or f"{int(selected[0]['low20']) >> 12:08b}" != anchor["target_prefix8"]
    ):
        raise RuntimeError("A220P A214 train_00 key identity gate failed")
    return {
        "role": "explicit_known_calibration_key",
        "ledger_split": selected[0]["split"],
        "ledger_index": int(selected[0]["index"]),
        "derivation_label": selected[0]["derivation_label"],
        "known_low20": int(selected[0]["low20"]),
        "known_low20_hex": selected[0]["low20_hex"],
        "known_prefix8": anchor["target_prefix8"],
    }


def _fixed_public_material(public: Mapping[str, Any]) -> dict[str, Any]:
    fields = (
        "known_key_word0_upper12",
        "known_key_words_1_through_7",
        "counter_start",
        "nonce_words",
        "block_count",
        "rounds",
        "public_seed_hex",
    )
    return {field: public[field] for field in fields}


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


def _prepare_real(protocol: Mapping[str, Any], directory: Path) -> dict[str, Any]:
    anchor_hashes = _verify_anchor_files(protocol)
    anchors = protocol["anchors"]
    r20 = _import_path(ROOT / anchors["R20_runner_path"], "a220p_r20")
    knownkey = _import_path(ROOT / anchors["A214_knownkey_helper_path"], "a220p_knownkey")
    template = _import_path(ROOT / anchors["A214_symbolic_template_path"], "a220p_template")
    retained = _import_path(ROOT / anchors["multihorizon_wrapper_path"], "a220p_multihorizon")
    a212_result = json.loads((ROOT / anchors["A212_formula_result_path"]).read_bytes())
    _operator_orders(protocol, a212_result=a212_result)
    known_key_identity = _validate_known_key_ledger(protocol, knownkey)
    template_protocol = json.loads((ROOT / anchors["A214_template_protocol_path"]).read_bytes())
    analysis = r20.analyze()
    public = analysis["public_challenge"]
    public_config = protocol["public_R20_material"]
    if _canonical_sha256(public) != public_config[
        "public_challenge_sha256"
    ] or _fixed_public_material(public) != {
        key: public_config[key] for key in _fixed_public_material(public)
    }:
        raise RuntimeError("A220P public R20 material differs from A214")

    low20 = int(known_key_identity["known_low20"])
    challenge = knownkey.training_challenge(public, low20=low20, chacha_block=r20.P1._chacha_block)
    key_words = [
        int(public["known_key_word0_upper12"]) | low20,
        *[int(value) for value in public["known_key_words_1_through_7"]],
    ]
    key_sha256 = _sha256(b"".join(value.to_bytes(4, "little") for value in key_words))
    if (
        f"{key_words[0]:08x}" != protocol["known_key_anchor"]["full_key_word0_hex"]
        or key_sha256 != protocol["known_key_anchor"]["full_key_words_little_endian_sha256"]
        or challenge["target_block_sha256"] != public_config["known_train_00_block_sha256"]
        or len(challenge["target_words"]) != 8
    ):
        raise RuntimeError("A220P known train_00 output confirmation gate failed")
    confirmation = {
        "generated_block_count": 8,
        "generated_output_bits": 4096,
        "block_sha256": list(challenge["target_block_sha256"]),
        "full_key_word0_hex": f"{key_words[0]:08x}",
        "full_key_words_little_endian_sha256": key_sha256,
        "formula_constrained_block_index": 0,
        "formula_constrained_output_bits": 512,
        "blocks_1_through_7_used_only_for_confirmation_metadata": True,
    }

    build = retained.compile_helper()
    helper = Path(build["binary_path"])
    if (
        build["source_sha256_started"] != anchors["multihorizon_native_source_sha256"]
        or build["source_sha256_finished"] != anchors["multihorizon_native_source_sha256"]
        or build["binary_sha256"] != anchors["multihorizon_content_addressed_binary_sha256"]
        or _file_sha256(helper) != anchors["multihorizon_content_addressed_binary_sha256"]
    ):
        raise RuntimeError("A220P content-addressed helper build gate failed")

    base_raw, key_mapping, output_mapping, template_manifest = template.compile_template(
        r20=r20,
        public_challenge=public,
        protocol=template_protocol,
        directory=directory,
    )
    raw, _, instantiation = template.instantiate_output(
        base_raw, output_mapping, challenge["target_words"][0]
    )
    template_config = protocol["symbolic_template"]
    expected_instantiation = {
        "header": template_config["train_00_instantiated_header"],
        "bytes": template_config["train_00_instantiated_bytes"],
        "sha256": template_config["train_00_instantiated_sha256"],
        "unit_count": template_config["train_00_unit_count"],
        "unit_int32le_sha256": template_config["train_00_unit_int32le_sha256"],
    }
    if (
        template_manifest["base_cnf_sha256"] != template_config["base_cnf_sha256"]
        or key_mapping != template_config["key_one_literals_bit0_through_bit19"]
        or instantiation != expected_instantiation
    ):
        raise RuntimeError("A220P symbolic train_00 instantiation gate failed")
    cnf = directory / "a220p_train_00_block0.cnf"
    cnf.write_bytes(raw)
    if _file_sha256(cnf) != expected_instantiation["sha256"]:
        raise RuntimeError("A220P instantiated CNF write/readback differs")
    return {
        "anchor_hashes": anchor_hashes,
        "known_key_identity": known_key_identity,
        "known_key_confirmation_metadata": confirmation,
        "template_manifest": template_manifest,
        "instantiation_manifest": instantiation,
        "key_mapping": key_mapping,
        "cnf_path": cnf,
        "cnf_sha256": instantiation["sha256"],
        "helper_path": helper,
        "helper_sha256": build["binary_sha256"],
        "native_helper_build": dict(build),
        "native_helper_stable_provenance": _stable_build_provenance(build),
        "run_callable": retained.run_multihorizon,
        "target_secret_or_salt_accessed": False,
        "prospective_target_artifact_accessed": False,
    }


def _external_timeout(protocol: Mapping[str, Any], stage_count: int) -> float:
    watchdog = float(protocol["execution"]["watchdog_seconds_per_stage"])
    return 120.0 + 256.0 * stage_count * watchdog


def _scientific_run(raw: Mapping[str, Any]) -> dict[str, Any]:
    stages = [
        {key: value for key, value in row.items() if key not in VOLATILE_STAGE_FIELDS}
        for row in raw["stages"]
    ]
    return {
        "mode": raw["mode"],
        "order": raw["order"],
        "conflict_horizons": raw["conflict_horizons"],
        "watchdog_seconds_per_stage": raw["watchdog_seconds_per_stage"],
        "stages": stages,
        "cells": raw["cells"],
        "summary": raw["summary"],
        "retained_state_continuity_verified": raw["retained_state_continuity_verified"],
        "all_watchdogs_clear": raw["all_watchdogs_clear"],
        "helper_returncode": raw["helper_returncode"],
    }


def _run_provenance(raw: Mapping[str, Any]) -> dict[str, Any]:
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
        "stage_elapsed_seconds": [row["elapsed_seconds"] for row in raw["stages"]],
        "stdout_sha256": raw["stdout_sha256"],
    }


def _record_run(
    *,
    raw: Mapping[str, Any],
    spec: Mapping[str, Any],
    prepared: Mapping[str, Any],
    protocol: Mapping[str, Any],
) -> dict[str, Any]:
    expected_hashes = {
        "wrapper_sha256": protocol["anchors"]["multihorizon_wrapper_sha256"],
        "source_sha256": protocol["anchors"]["multihorizon_native_source_sha256"],
        "helper_sha256": prepared["helper_sha256"],
        "cnf_sha256": prepared["cnf_sha256"],
    }
    cells = raw.get("cells", [])
    if (
        raw.get("mode") != spec["mode"]
        or raw.get("order") != spec["order"]
        or raw.get("conflict_horizons") != spec["conflict_horizons"]
        or raw.get("watchdog_seconds_per_stage")
        != protocol["execution"]["watchdog_seconds_per_stage"]
        or len(cells) != 256
        or [row.get("prefix8") for row in cells] != spec["order"]
        or raw.get("retained_state_continuity_verified") is not True
        or raw.get("all_watchdogs_clear") is not True
        or raw.get("helper_returncode") != 0
        or raw.get("launch_identity_verified") is not True
        or raw.get("launch_artifact_hashes_started") != expected_hashes
        or raw.get("launch_artifact_hashes_finished") != expected_hashes
    ):
        raise RuntimeError(f"A220P completed run gate failed: {spec['run_id']}")
    record = {
        "run_id": spec["run_id"],
        "operator": spec["operator"],
        "schedule": spec["schedule"],
        "fresh_solver_process": True,
        "scientific_measurement": _scientific_run(raw),
        "deterministic_artifact_provenance": _run_provenance(raw),
        "volatile_observation": _volatile_run(raw),
    }
    record["checkpoint_record_sha256"] = _canonical_sha256(record)
    return record


def _checkpoint_identity(
    *,
    prepared: Mapping[str, Any],
    order_manifests: Mapping[str, Any],
    plan: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    plan_identity = [
        {
            key: row[key]
            for key in (
                "run_id",
                "mode",
                "operator",
                "schedule",
                "conflict_horizons",
                "order_uint8_sha256",
            )
        }
        for row in plan
    ]
    return {
        "schema": CHECKPOINT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "orchestrator_source_sha256_started": prepared["orchestrator_source_sha256_started"],
        "anchor_hashes": prepared["anchor_hashes"],
        "helper_sha256": prepared["helper_sha256"],
        "cnf_sha256": prepared["cnf_sha256"],
        "order_manifests_sha256": _canonical_sha256(order_manifests),
        "run_plan_sha256": _canonical_sha256(plan_identity),
    }


def _load_checkpoint(
    path: Path,
    *,
    identity: Mapping[str, Any],
    valid_run_ids: set[str],
) -> dict[str, Any]:
    expected_keys = {*identity, "completed_runs"}
    if not path.exists():
        return {**identity, "completed_runs": {}}
    checkpoint = json.loads(path.read_bytes())
    if (
        set(checkpoint) != expected_keys
        or any(checkpoint.get(key) != value for key, value in identity.items())
        or not isinstance(checkpoint.get("completed_runs"), dict)
        or not set(checkpoint["completed_runs"]).issubset(valid_run_ids)
    ):
        raise RuntimeError("A220P checkpoint identity differs")
    for run_id, record in checkpoint["completed_runs"].items():
        stored_hash = record.get("checkpoint_record_sha256")
        unhashed = {
            key: value for key, value in record.items() if key != "checkpoint_record_sha256"
        }
        if record.get("run_id") != run_id or stored_hash != _canonical_sha256(unhashed):
            raise RuntimeError(f"A220P checkpoint completed-run hash differs: {run_id}")
    return checkpoint


def _invoke_run(
    *,
    run_callable: Callable[..., dict[str, Any]],
    prepared: Mapping[str, Any],
    protocol: Mapping[str, Any],
    spec: Mapping[str, Any],
) -> dict[str, Any]:
    return run_callable(
        helper=prepared["helper_path"],
        cnf=prepared["cnf_path"],
        mode=spec["mode"],
        order=spec["order"],
        key_one_literals_bit0_through_bit19=prepared["key_mapping"],
        conflict_horizons=spec["conflict_horizons"],
        watchdog_seconds=protocol["execution"]["watchdog_seconds_per_stage"],
        external_timeout_seconds=_external_timeout(protocol, len(spec["conflict_horizons"])),
    )


def _execute_runs(
    *,
    protocol: Mapping[str, Any],
    prepared: Mapping[str, Any],
    plan: Sequence[Mapping[str, Any]],
    order_manifests: Mapping[str, Any],
    checkpoint_path: Path,
    run_callable: Callable[..., dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    identity = _checkpoint_identity(prepared=prepared, order_manifests=order_manifests, plan=plan)
    checkpoint = _load_checkpoint(
        checkpoint_path,
        identity=identity,
        valid_run_ids={str(row["run_id"]) for row in plan},
    )
    completed: dict[str, dict[str, Any]] = checkpoint["completed_runs"]
    pending = [row for row in plan if row["run_id"] not in completed]
    if not pending:
        return completed

    executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="a220p")
    active: dict[Future[dict[str, Any]], Mapping[str, Any]] = {}
    iterator = iter(pending)

    def submit_next() -> bool:
        try:
            spec = next(iterator)
        except StopIteration:
            return False
        future = executor.submit(
            _invoke_run,
            run_callable=run_callable,
            prepared=prepared,
            protocol=protocol,
            spec=spec,
        )
        active[future] = spec
        return True

    submit_next()
    submit_next()
    try:
        while active:
            future = next(as_completed(tuple(active)))
            spec = active.pop(future)
            raw = future.result()
            record = _record_run(raw=raw, spec=spec, prepared=prepared, protocol=protocol)
            completed[str(spec["run_id"])] = record
            _atomic_json(checkpoint_path, checkpoint, private=True)
            print(f"A220P complete {spec['run_id']}", flush=True)
            submit_next()
    except BaseException:
        for future in active:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
        raise
    executor.shutdown(wait=True)
    if set(completed) != {str(row["run_id"]) for row in plan}:
        raise RuntimeError("A220P complete-run set differs from frozen plan")
    return completed


def _channel_value(cell: Mapping[str, Any], channel: str) -> int:
    if channel in NONNEGATIVE_CHANNELS:
        index = NONNEGATIVE_CHANNELS.index(channel)
        value = cell["metrics_delta"][index]
    else:
        value = cell[channel]
    if not isinstance(value, int) or isinstance(value, bool):
        raise RuntimeError(f"A220P channel is not integral: {channel}")
    if channel in NONNEGATIVE_CHANNELS and value < 0:
        raise RuntimeError(f"A220P nonnegative channel is negative: {channel}")
    return value


def _transform(values: Sequence[int], *, signed: bool) -> list[float]:
    if signed:
        return [math.copysign(math.log1p(abs(value)), value) if value else 0.0 for value in values]
    return [math.log1p(value) for value in values]


def _zscore(values: Sequence[float]) -> tuple[list[float], float, float]:
    mean = math.fsum(values) / len(values)
    variance = math.fsum((value - mean) ** 2 for value in values) / len(values)
    standard_deviation = math.sqrt(max(0.0, variance))
    if standard_deviation == 0.0:
        return [0.0] * len(values), mean, standard_deviation
    return [(value - mean) / standard_deviation for value in values], mean, standard_deviation


def _pearson(left: Sequence[float], right: Sequence[float]) -> float | None:
    left_z, _, left_sd = _zscore(left)
    right_z, _, right_sd = _zscore(right)
    if left_sd == 0.0 or right_sd == 0.0:
        return None
    value = math.fsum(a * b for a, b in zip(left_z, right_z, strict=True)) / len(left_z)
    return max(-1.0, min(1.0, value))


def _average_ranks(values: Sequence[float]) -> list[float]:
    indexed = sorted(enumerate(values), key=lambda item: (item[1], item[0]))
    ranks = [0.0] * len(values)
    cursor = 0
    while cursor < len(indexed):
        end = cursor + 1
        while end < len(indexed) and indexed[end][1] == indexed[cursor][1]:
            end += 1
        average = ((cursor + 1) + end) / 2.0
        for index, _ in indexed[cursor:end]:
            ranks[index] = average
        cursor = end
    return ranks


def _comparison_for_pair(staged: Mapping[str, Any], one_shot: Mapping[str, Any]) -> dict[str, Any]:
    staged_cells = {row["prefix8"]: row for row in staged["scientific_measurement"]["cells"]}
    one_shot_cells = {row["prefix8"]: row for row in one_shot["scientific_measurement"]["cells"]}
    prefixes = [f"{value:08b}" for value in range(256)]
    if set(staged_cells) != set(prefixes) or set(one_shot_cells) != set(prefixes):
        raise RuntimeError("A220P comparison prefix alignment is incomplete")
    channels: dict[str, Any] = {}
    for channel in CHANNELS:
        staged_raw = [_channel_value(staged_cells[prefix], channel) for prefix in prefixes]
        one_shot_raw = [_channel_value(one_shot_cells[prefix], channel) for prefix in prefixes]
        signed = channel in SIGNED_CHANNELS
        staged_values = _transform(staged_raw, signed=signed)
        one_shot_values = _transform(one_shot_raw, signed=signed)
        staged_z, staged_mean, staged_sd = _zscore(staged_values)
        one_shot_z, one_shot_mean, one_shot_sd = _zscore(one_shot_values)
        staged_ranks = _average_ranks(staged_values)
        one_shot_ranks = _average_ranks(one_shot_values)
        channels[channel] = {
            "transform": "signed_log1p_abs" if signed else "log1p",
            "same_prefix_cells": 256,
            "identical_raw_cells": sum(
                left == right for left, right in zip(staged_raw, one_shot_raw, strict=True)
            ),
            "mean_absolute_transformed_delta": math.fsum(
                abs(left - right)
                for left, right in zip(staged_values, one_shot_values, strict=True)
            )
            / 256.0,
            "staged_transformed_mean": staged_mean,
            "staged_transformed_population_sd": staged_sd,
            "one_shot_transformed_mean": one_shot_mean,
            "one_shot_transformed_population_sd": one_shot_sd,
            "zscore_pearson": _pearson(staged_values, one_shot_values),
            "staged_zscore_sha256": _canonical_sha256(staged_z),
            "one_shot_zscore_sha256": _canonical_sha256(one_shot_z),
            "average_rank_spearman": _pearson(staged_ranks, one_shot_ranks),
            "staged_average_rank_sha256": _canonical_sha256(staged_ranks),
            "one_shot_average_rank_sha256": _canonical_sha256(one_shot_ranks),
        }
    staged_status = Counter(
        row["final_status"] for row in staged["scientific_measurement"]["cells"]
    )
    one_shot_status = Counter(
        row["final_status"] for row in one_shot["scientific_measurement"]["cells"]
    )
    return {
        "alignment": "same_prefix_within_same_operator",
        "compared_measurement": (
            "final cumulative per-cell delta from staged retained re-solve versus "
            "per-cell delta from one-shot horizon 64"
        ),
        "staged_semantics": (
            "retained re-solve with the same assumptions at cumulative horizons 8,16,32,64; "
            "not one uninterrupted solve"
        ),
        "one_shot_semantics": "one solve call at conflict horizon 64 per cell",
        "staged_final_status_counts": {
            status: staged_status[status] for status in ("sat", "unsat", "unknown")
        },
        "one_shot_status_counts": {
            status: one_shot_status[status] for status in ("sat", "unsat", "unknown")
        },
        "same_final_status_cells": sum(
            staged_cells[prefix]["final_status"] == one_shot_cells[prefix]["final_status"]
            for prefix in prefixes
        ),
        "channels": channels,
    }


def _comparisons(
    records: Mapping[str, Mapping[str, Any]], orders: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        operator: _comparison_for_pair(
            records[f"{operator}__staged_retained_resolve"],
            records[f"{operator}__one_shot"],
        )
        for operator in orders
    }


def _measurement_projection(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": payload["schema"],
        "attempt_id": payload["attempt_id"],
        "protocol_sha256": payload["protocol_sha256"],
        "scientific_scope": payload["scientific_scope"],
        "anchor_hashes": payload["anchor_hashes"],
        "known_key_identity": payload["known_key_identity"],
        "known_key_confirmation_metadata": payload["known_key_confirmation_metadata"],
        "symbolic_template_manifest": payload["symbolic_template_manifest"],
        "instantiated_CNF_manifest": payload["instantiated_CNF_manifest"],
        "operator_order_manifests": payload["operator_order_manifests"],
        "schedule_semantics": payload["schedule_semantics"],
        "native_helper_stable_provenance": payload["native_helper_stable_provenance"],
        "orchestrator_source_provenance": payload["orchestrator_source_provenance"],
        "scientific_runs": {
            run_id: record["scientific_measurement"]
            for run_id, record in payload["run_records"].items()
        },
        "deterministic_run_artifact_provenance": {
            run_id: record["deterministic_artifact_provenance"]
            for run_id, record in payload["run_records"].items()
        },
        "staged_vs_one_shot_comparisons": payload["staged_vs_one_shot_comparisons"],
        "information_boundary": payload["information_boundary"],
        "completion_gates": payload["completion_gates"],
    }


def _verify_final(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_bytes())
    if (
        payload.get("schema") != SCHEMA
        or payload.get("attempt_id") != ATTEMPT_ID
        or payload.get("protocol_sha256") != PROTOCOL_SHA256
        or payload.get("measurement_sha256") != _canonical_sha256(_measurement_projection(payload))
        or payload.get("completion_gates", {}).get("all_12_runs_complete") is not True
        or payload.get("completion_gates", {}).get("orchestrator_source_unchanged") is not True
        or payload.get("completion_gates", {}).get("exclusive_orchestrator_lock_acquired")
        is not True
    ):
        raise RuntimeError("A220P final artifact verification failed")
    return payload


def _assemble_payload(
    *,
    protocol: Mapping[str, Any],
    prepared: Mapping[str, Any],
    records: Mapping[str, Mapping[str, Any]],
    orders: Mapping[str, Sequence[str]],
    order_manifests: Mapping[str, Any],
) -> dict[str, Any]:
    comparisons = _comparisons(records, orders)
    ordered_records = {
        f"{operator}__{schedule}": records[f"{operator}__{schedule}"]
        for operator in orders
        for schedule in SCHEDULE_NAMES
    }
    completion = {
        "all_12_runs_complete": len(ordered_records) == 12,
        "all_runs_fresh_processes": all(
            record["fresh_solver_process"] is True for record in ordered_records.values()
        ),
        "all_retained_state_continuity_verified": all(
            record["scientific_measurement"]["retained_state_continuity_verified"] is True
            for record in ordered_records.values()
        ),
        "all_watchdogs_clear": all(
            record["scientific_measurement"]["all_watchdogs_clear"] is True
            for record in ordered_records.values()
        ),
        "all_launch_pre_post_hashes_identical": all(
            record["deterministic_artifact_provenance"]["launch_artifact_hashes_started"]
            == record["deterministic_artifact_provenance"]["launch_artifact_hashes_finished"]
            for record in ordered_records.values()
        ),
        "maximum_concurrent_solver_processes": 2,
        "exclusive_orchestrator_lock_acquired": prepared["exclusive_orchestrator_lock_acquired"],
        "orchestrator_source_unchanged": (
            prepared["orchestrator_source_sha256_started"]
            == prepared["orchestrator_source_sha256_finished"]
        ),
        "retry_after_failure_used": False,
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FULLROUND_R20_MULTIHORIZON_KNOWNKEY_CALIBRATION_PREFLIGHT",
        "protocol_sha256": PROTOCOL_SHA256,
        "scientific_scope": protocol["scientific_scope"],
        "anchor_hashes": prepared["anchor_hashes"],
        "known_key_identity": prepared["known_key_identity"],
        "known_key_confirmation_metadata": prepared["known_key_confirmation_metadata"],
        "symbolic_template_manifest": prepared["template_manifest"],
        "instantiated_CNF_manifest": prepared["instantiation_manifest"],
        "operator_order_manifests": order_manifests,
        "schedule_semantics": {
            "schedules": protocol["execution"]["schedules"],
            "watchdog_seconds_per_stage": protocol["execution"]["watchdog_seconds_per_stage"],
            "fresh_solver_process_per_run": True,
            "staged_semantics": protocol["execution"]["staged_semantics"],
        },
        "native_helper_stable_provenance": prepared["native_helper_stable_provenance"],
        "orchestrator_source_provenance": {
            "path": str(ORCHESTRATOR.relative_to(ROOT)),
            "sha256_started": prepared["orchestrator_source_sha256_started"],
            "sha256_finished": prepared["orchestrator_source_sha256_finished"],
            "unchanged_during_execution": (
                prepared["orchestrator_source_sha256_started"]
                == prepared["orchestrator_source_sha256_finished"]
            ),
        },
        "native_helper_build_observation": prepared["native_helper_build"],
        "run_records": ordered_records,
        "staged_vs_one_shot_comparisons": comparisons,
        "information_boundary": {
            **protocol["information_boundary"],
            "target_secret_or_salt_accessed_during_execution": prepared[
                "target_secret_or_salt_accessed"
            ],
            "prospective_target_artifact_accessed_during_execution": prepared[
                "prospective_target_artifact_accessed"
            ],
            "known_low20_source": "A214_train_00_public_deterministic_ledger",
        },
        "completion_gates": completion,
        "measurement_hash_scope": protocol["measurement_hash_scope"],
        "volatile_observations": {
            "native_build_elapsed_seconds": prepared["native_helper_build"].get("elapsed_seconds"),
            "runs": {
                run_id: record["volatile_observation"] for run_id, record in ordered_records.items()
            },
        },
    }
    payload["measurement_sha256"] = _canonical_sha256(_measurement_projection(payload))
    return payload


def _run_prepared(
    *,
    protocol: Mapping[str, Any],
    prepared: Mapping[str, Any],
    output: Path,
    checkpoint_path: Path,
    run_callable: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    if _file_sha256(ORCHESTRATOR) != prepared["orchestrator_source_sha256_started"]:
        raise RuntimeError("A220P orchestrator source changed during execution")
    orders = _operator_orders(protocol)
    manifests = _order_manifests(protocol, orders)
    plan = _run_plan(protocol, orders)
    records = _execute_runs(
        protocol=protocol,
        prepared=prepared,
        plan=plan,
        order_manifests=manifests,
        checkpoint_path=checkpoint_path,
        run_callable=run_callable,
    )
    finished = _file_sha256(ORCHESTRATOR)
    if finished != prepared["orchestrator_source_sha256_started"]:
        raise RuntimeError("A220P orchestrator source changed during execution")
    prepared = {
        **prepared,
        "orchestrator_source_sha256_finished": finished,
    }
    payload = _assemble_payload(
        protocol=protocol,
        prepared=prepared,
        records=records,
        orders=orders,
        order_manifests=manifests,
    )
    _atomic_json(output, payload)
    verified = _verify_final(output)
    checkpoint_path.unlink(missing_ok=True)
    return verified


def run(
    output: Path = DEFAULT_OUTPUT,
    checkpoint_path: Path = DEFAULT_CHECKPOINT,
    *,
    _test_prepared: Mapping[str, Any] | None = None,
    _test_run_callable: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Execute A220P; underscored injections provide a solver-free test path only."""
    protocol = _load_protocol()
    if (_test_prepared is None) != (_test_run_callable is None):
        raise ValueError("A220P test preparation and test runner must be supplied together")
    if _test_prepared is not None and _test_run_callable is not None:
        return _run_prepared(
            protocol=protocol,
            prepared=_test_prepared,
            output=output,
            checkpoint_path=checkpoint_path,
            run_callable=_test_run_callable,
        )
    with _exclusive_orchestrator_lock():
        orchestrator_sha256_started = _file_sha256(ORCHESTRATOR)
        with tempfile.TemporaryDirectory(prefix="a220p-multihorizon-") as raw_directory:
            prepared = {
                **_prepare_real(protocol, Path(raw_directory)),
                "orchestrator_source_sha256_started": orchestrator_sha256_started,
                "exclusive_orchestrator_lock_acquired": True,
            }
            return _run_prepared(
                protocol=protocol,
                prepared=prepared,
                output=output,
                checkpoint_path=checkpoint_path,
                run_callable=prepared["run_callable"],
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    arguments = parser.parse_args()
    payload = run(arguments.output, arguments.checkpoint)
    print(
        json.dumps(
            {
                "output": str(arguments.output),
                "output_sha256": _file_sha256(arguments.output),
                "measurement_sha256": payload["measurement_sha256"],
                "all_12_runs_complete": payload["completion_gates"]["all_12_runs_complete"],
                "target_secret_or_salt_accessed": payload["information_boundary"][
                    "target_secret_or_salt_accessed_during_execution"
                ],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
