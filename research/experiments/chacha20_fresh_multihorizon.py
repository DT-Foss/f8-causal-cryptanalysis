"""Fresh-state multi-horizon CaDiCaL execution and strict readback.

Every candidate prefix receives a newly constructed solver containing the same
CNF.  Horizons remain cumulative inside one candidate, but no learned clause or
search state can cross a candidate boundary.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import subprocess
import time
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
SOURCE = ROOT / "research/native/cadical_fresh_multihorizon.cpp"
BINARY = ROOT / "research/native/build/cadical_fresh_multihorizon"
WRAPPER = Path(__file__).resolve()
COMPILER = Path("/usr/bin/clang++")
CADICAL_HEADER = Path("/opt/homebrew/include/cadical.hpp")
CADICAL_LIBRARY = Path("/opt/homebrew/lib/libcadical.a")
EXECUTION_ENVIRONMENT = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
STAGE_PREFIX = "FRESH_MH_STAGE "
CELL_PREFIX = "FRESH_MH_CELL "
SUMMARY_PREFIX = "FRESH_MH_SUMMARY "
METRIC_NAMES = ("conflicts", "decisions", "search_propagations")
STATE_STEMS = ("active_variables", "irredundant_clauses", "redundant_clauses")
MODE_PATTERN = re.compile(r"[A-Za-z0-9_.-]+")

STAGE_FIELDS = {
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
    "elapsed_seconds",
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
        for suffix in ("before", "after", "delta")
    },
}
CELL_FIELDS = {
    "mode",
    "prefix8",
    "cell_index",
    "fresh_solver_instance",
    "assumptions",
    "stages_run",
    "final_status",
    "terminal_stage_index",
    "metric_names",
    "metrics_before",
    "metrics_after",
    "metrics_delta",
    *{
        f"{stem}_{suffix}"
        for stem in STATE_STEMS
        for suffix in ("before", "after", "delta")
    },
}
SUMMARY_FIELDS = {
    "signature",
    "version",
    "mode",
    "variables",
    "clauses",
    "literal_stream_items",
    "cells",
    "fresh_solver_instances",
    "base_copy_source_solved",
    "base_copy_method",
    "base_snapshot_identical",
    "conflict_horizons",
    "configured_stages_per_nonterminal_cell",
    "stages_emitted",
    "sat_cells",
    "unsat_cells",
    "unknown_cells",
    "watchdog_seconds",
    "metric_names",
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def numeric_order() -> list[str]:
    return [f"{value:08b}" for value in range(256)]


def _validate_mapping(values: Sequence[int]) -> list[int]:
    mapping = list(values)
    if (
        len(mapping) != 20
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value == 0
            for value in mapping
        )
        or len({abs(value) for value in mapping}) != 20
    ):
        raise ValueError("fresh-state mapping must contain twenty distinct signed literals")
    return mapping


def _validate_inputs(
    *, mode: str, order: Sequence[str], conflict_horizons: Sequence[int], watchdog_seconds: float
) -> tuple[list[str], list[int]]:
    expected_order = list(order)
    horizons = list(conflict_horizons)
    if MODE_PATTERN.fullmatch(mode) is None:
        raise ValueError("fresh-state mode contains unsupported characters")
    if len(expected_order) != 256 or set(expected_order) != set(numeric_order()):
        raise ValueError("fresh-state order must cover every eight-bit prefix exactly once")
    if (
        not horizons
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in horizons
        )
        or any(right <= left for left, right in zip(horizons, horizons[1:], strict=False))
    ):
        raise ValueError("fresh-state horizons must be positive and strictly increasing")
    if (
        not isinstance(watchdog_seconds, (int, float))
        or isinstance(watchdog_seconds, bool)
        or not math.isfinite(float(watchdog_seconds))
        or float(watchdog_seconds) <= 0.0
    ):
        raise ValueError("fresh-state watchdog must be finite and positive")
    return expected_order, horizons


def _mapping_arguments(key_one_literals_bit0_through_bit19: Sequence[int]) -> list[str]:
    mapping = _validate_mapping(key_one_literals_bit0_through_bit19)
    return [
        "--assumption-one-literals",
        ",".join(str(mapping[bit]) for bit in range(19, 11, -1)),
        "--model-one-literals",
        ",".join(str(value) for value in mapping),
    ]


def compile_helper(*, output_base: Path = BINARY) -> dict[str, Any]:
    output_base.parent.mkdir(parents=True, exist_ok=True)
    lock_path = output_base.with_name(f".{output_base.name}.compile.lock")
    temporary = output_base.with_name(f".{output_base.name}.deterministic-link")
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            temporary.unlink(missing_ok=True)
            source_sha_started = file_sha256(SOURCE)
            command = [
                str(COMPILER),
                "-std=c++17",
                "-O3",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I/opt/homebrew/include",
                str(SOURCE),
                str(CADICAL_LIBRARY),
                "-lpthread",
                "-o",
                str(temporary),
            ]
            started = time.perf_counter()
            result = subprocess.run(
                command,
                text=True,
                capture_output=True,
                check=False,
                env=EXECUTION_ENVIRONMENT,
            )
            source_sha_finished = file_sha256(SOURCE)
            temporary_sha = file_sha256(temporary) if temporary.exists() else None
            observation = {
                "command": command,
                "environment": EXECUTION_ENVIRONMENT,
                "returncode": result.returncode,
                "elapsed_seconds": time.perf_counter() - started,
                "stdout_sha256": _sha256(result.stdout.encode()),
                "stderr_sha256": _sha256(result.stderr.encode()),
                "source_sha256_started": source_sha_started,
                "source_sha256_finished": source_sha_finished,
                "compiler_sha256": file_sha256(COMPILER),
                "cadical_header_sha256": file_sha256(CADICAL_HEADER),
                "cadical_library_sha256": file_sha256(CADICAL_LIBRARY),
                "temporary_binary_sha256": temporary_sha,
            }
            if (
                result.returncode != 0
                or result.stdout
                or result.stderr
                or temporary_sha is None
                or source_sha_started != source_sha_finished
            ):
                raise RuntimeError(f"fresh-state CaDiCaL helper build failed: {observation}")
            final = output_base.with_name(
                f"{output_base.name}-{source_sha_started}-{temporary_sha}"
            )
            try:
                os.link(temporary, final)
            except FileExistsError as error:
                if file_sha256(final) != temporary_sha:
                    raise RuntimeError("fresh-state content-addressed helper has wrong bytes") from error
            final.chmod(0o755)
            if file_sha256(final) != temporary_sha:
                raise RuntimeError("fresh-state helper final hash gate failed")
            observation.update(
                {
                    "binary_path": str(final),
                    "binary_sha256": temporary_sha,
                    "content_addressed_binary": True,
                }
            )
            return observation
        finally:
            temporary.unlink(missing_ok=True)
            fcntl.flock(lock, fcntl.LOCK_UN)


def _parse_events(stdout: str) -> list[tuple[str, dict[str, Any]]]:
    prefixes = (("stage", STAGE_PREFIX), ("cell", CELL_PREFIX), ("summary", SUMMARY_PREFIX))
    events: list[tuple[str, dict[str, Any]]] = []
    for line in stdout.splitlines():
        if not line:
            continue
        for kind, prefix in prefixes:
            if line.startswith(prefix):
                try:
                    record = json.loads(line.removeprefix(prefix))
                except json.JSONDecodeError as error:
                    raise RuntimeError(f"malformed fresh-state JSON: {error}") from error
                if not isinstance(record, dict):
                    raise RuntimeError("fresh-state record must be a JSON object")
                events.append((kind, record))
                break
        else:
            raise RuntimeError(f"unexpected fresh-state output line: {line[:160]}")
    return events


def _int(value: Any, *, nonnegative: bool = False) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and (not nonnegative or value >= 0)
    )


def _metric_vector(value: Any) -> bool:
    return isinstance(value, list) and len(value) == 3 and all(
        _int(item, nonnegative=True) for item in value
    )


def _difference(after: Sequence[int], before: Sequence[int]) -> list[int]:
    return [right - left for left, right in zip(before, after, strict=True)]


def _state_snapshot(row: dict[str, Any], suffix: str) -> tuple[int, ...]:
    metrics_key = "metrics_before" if suffix == "before" else "metrics_after"
    return (
        *row[metrics_key],
        *(row[f"{stem}_{suffix}"] for stem in STATE_STEMS),
    )


def parse_fresh_output(
    *,
    stdout: str,
    returncode: int,
    mode: str,
    order: Sequence[str],
    key_one_literals_bit0_through_bit19: Sequence[int],
    conflict_horizons: Sequence[int],
    watchdog_seconds: float,
) -> dict[str, Any]:
    expected_order, horizons = _validate_inputs(
        mode=mode,
        order=order,
        conflict_horizons=conflict_horizons,
        watchdog_seconds=watchdog_seconds,
    )
    mapping = _validate_mapping(key_one_literals_bit0_through_bit19)
    if returncode != 0:
        raise RuntimeError(f"fresh-state helper returned {returncode}")
    events = _parse_events(stdout)
    if not events or events[-1][0] != "summary":
        raise RuntimeError("fresh-state summary is missing or misplaced")
    if any(kind == "summary" for kind, _ in events[:-1]):
        raise RuntimeError("fresh-state summary must be final")

    assumption_one = [mapping[bit] for bit in range(19, 11, -1)]
    stage_rows: list[dict[str, Any]] = []
    cell_rows: list[dict[str, Any]] = []
    cursor = 0
    reference_base: tuple[int, ...] | None = None
    for cell_index, prefix8 in enumerate(expected_order):
        assumptions = [
            literal if bit == "1" else -literal
            for bit, literal in zip(prefix8, assumption_one, strict=True)
        ]
        current_stages: list[dict[str, Any]] = []
        while cursor < len(events) and events[cursor][0] == "stage":
            row = events[cursor][1]
            if row.get("cell_index") != cell_index:
                break
            current_stages.append(row)
            cursor += 1
        if not current_stages or cursor >= len(events) or events[cursor][0] != "cell":
            raise RuntimeError(f"fresh-state cell block incomplete at {cell_index}")
        cell = events[cursor][1]
        cursor += 1
        if len(current_stages) > len(horizons):
            raise RuntimeError(f"too many fresh-state stages at {cell_index}")

        previous_after: list[int] | None = None
        for stage_index, row in enumerate(current_stages):
            before = row.get("metrics_stage_before")
            after = row.get("metrics_stage_after")
            delta = row.get("metrics_stage_delta")
            cumulative = row.get("metrics_cell_cumulative_delta")
            expected_increment = horizons[stage_index] - (horizons[stage_index - 1] if stage_index else 0)
            if (
                set(row) != STAGE_FIELDS
                or row.get("mode") != mode
                or row.get("prefix8") != prefix8
                or row.get("cell_index") != cell_index
                or row.get("stage_index") != stage_index
                or row.get("horizon") != horizons[stage_index]
                or row.get("conflict_increment") != expected_increment
                or row.get("status") not in {"unknown", "sat", "unsat"}
                or row.get("returncode") not in {0, 10, 20}
                or row.get("terminal") != (row.get("status") != "unknown")
                or row.get("watchdog_fired") is not False
                or float(row.get("watchdog_seconds", -1)) != float(watchdog_seconds)
                or not isinstance(row.get("elapsed_seconds"), (int, float))
                or row.get("elapsed_seconds") < 0
                or row.get("assumptions") != assumptions
                or row.get("metric_names") != list(METRIC_NAMES)
                or not all(_metric_vector(value) for value in (before, after, delta, cumulative))
                or delta != _difference(after, before)
                or cumulative != _difference(after, row.get("metrics_cell_before"))
                or (previous_after is not None and before != previous_after)
            ):
                raise RuntimeError(f"fresh-state stage gate failed at {cell_index}:{stage_index}")
            if row["status"] == "sat":
                if (
                    len(row["model_bits_bit0_through_bit19"]) != 20
                    or row["failed_assumptions"]
                    or row["model_bits_bit0_through_bit19"][12:]
                    != [int(bit) for bit in reversed(prefix8)]
                ):
                    raise RuntimeError("fresh-state SAT payload gate failed")
            elif row["status"] == "unsat":
                if (
                    row["model_bits_bit0_through_bit19"]
                    or any(literal not in assumptions for literal in row["failed_assumptions"])
                ):
                    raise RuntimeError("fresh-state UNSAT payload gate failed")
            elif row["model_bits_bit0_through_bit19"] or row["failed_assumptions"]:
                raise RuntimeError("fresh-state UNKNOWN payload gate failed")
            for stem in STATE_STEMS:
                before_value = row[f"{stem}_before"]
                after_value = row[f"{stem}_after"]
                if (
                    not _int(before_value, nonnegative=True)
                    or not _int(after_value, nonnegative=True)
                    or row[f"{stem}_delta"] != after_value - before_value
                ):
                    raise RuntimeError(f"fresh-state {stem} stage gate failed")
            previous_after = after

        final = current_stages[-1]
        before = cell.get("metrics_before")
        after = cell.get("metrics_after")
        if (
            set(cell) != CELL_FIELDS
            or cell.get("mode") != mode
            or cell.get("prefix8") != prefix8
            or cell.get("cell_index") != cell_index
            or cell.get("fresh_solver_instance") is not True
            or cell.get("assumptions") != assumptions
            or cell.get("stages_run") != len(current_stages)
            or cell.get("final_status") != final["status"]
            or cell.get("terminal_stage_index")
            != (len(current_stages) - 1 if final["terminal"] else None)
            or (not final["terminal"] and len(current_stages) != len(horizons))
            or cell.get("metric_names") != list(METRIC_NAMES)
            or not _metric_vector(before)
            or not _metric_vector(after)
            or cell.get("metrics_delta") != _difference(after, before)
            or after != final["metrics_stage_after"]
            or before != current_stages[0]["metrics_cell_before"]
        ):
            raise RuntimeError(f"fresh-state cell gate failed at {cell_index}")
        for stem in STATE_STEMS:
            left = cell[f"{stem}_before"]
            right = cell[f"{stem}_after"]
            if (
                not _int(left, nonnegative=True)
                or not _int(right, nonnegative=True)
                or cell[f"{stem}_delta"] != right - left
                or right != final[f"{stem}_after"]
            ):
                raise RuntimeError(f"fresh-state {stem} cell gate failed")
        base = _state_snapshot(cell, "before")
        if reference_base is None:
            reference_base = base
        elif base != reference_base:
            raise RuntimeError("fresh-state base snapshot differs across candidates")
        stage_rows.extend(current_stages)
        cell_rows.append(cell)

    if cursor != len(events) - 1:
        raise RuntimeError("fresh-state output has misplaced or extra records")
    summary = events[-1][1]
    counts = Counter(cell["final_status"] for cell in cell_rows)
    if (
        set(summary) != SUMMARY_FIELDS
        or summary.get("signature") != "cadical-3.0.0"
        or summary.get("version") != "3.0.0"
        or summary.get("mode") != mode
        or not _int(summary.get("variables"), nonnegative=True)
        or not _int(summary.get("clauses"), nonnegative=True)
        or not _int(summary.get("literal_stream_items"), nonnegative=True)
        or summary.get("cells") != 256
        or summary.get("fresh_solver_instances") != 256
        or summary.get("base_copy_source_solved") is not False
        or summary.get("base_copy_method") != "cadical_copy_irredundant_units_options"
        or summary.get("base_snapshot_identical") is not True
        or summary.get("conflict_horizons") != horizons
        or summary.get("configured_stages_per_nonterminal_cell") != len(horizons)
        or summary.get("stages_emitted") != len(stage_rows)
        or summary.get("sat_cells") != counts["sat"]
        or summary.get("unsat_cells") != counts["unsat"]
        or summary.get("unknown_cells") != counts["unknown"]
        or float(summary.get("watchdog_seconds", -1)) != float(watchdog_seconds)
        or summary.get("metric_names") != list(METRIC_NAMES)
    ):
        raise RuntimeError("fresh-state summary gate failed")
    return {
        "mode": mode,
        "order": expected_order,
        "conflict_horizons": horizons,
        "watchdog_seconds_per_stage": float(watchdog_seconds),
        "stages": stage_rows,
        "cells": cell_rows,
        "summary": summary,
        "fresh_solver_per_candidate_verified": True,
        "base_snapshot_identical_verified": True,
        "all_watchdogs_clear": True,
    }


def run_fresh_multihorizon(
    *,
    helper: Path,
    cnf: Path,
    mode: str,
    order: Sequence[str],
    key_one_literals_bit0_through_bit19: Sequence[int],
    conflict_horizons: Sequence[int],
    watchdog_seconds: float,
    external_timeout_seconds: float = 600.0,
) -> dict[str, Any]:
    expected_order, horizons = _validate_inputs(
        mode=mode,
        order=order,
        conflict_horizons=conflict_horizons,
        watchdog_seconds=watchdog_seconds,
    )
    helper = helper.resolve()
    cnf = cnf.resolve()
    if not helper.is_file() or not cnf.is_file():
        raise ValueError("fresh-state helper and CNF must be regular files")
    hashes_started = {
        "wrapper_sha256": file_sha256(WRAPPER),
        "source_sha256": file_sha256(SOURCE),
        "helper_sha256": file_sha256(helper),
        "cnf_sha256": file_sha256(cnf),
    }
    expected_name = (
        f"{BINARY.name}-{hashes_started['source_sha256']}-{hashes_started['helper_sha256']}"
    )
    if helper.name != expected_name:
        raise RuntimeError("fresh-state helper is not the expected content-addressed artifact")
    command = [
        str(helper),
        "--cnf",
        str(cnf),
        "--mode",
        mode,
        *_mapping_arguments(key_one_literals_bit0_through_bit19),
        "--cell-order",
        ",".join(expected_order),
        "--conflict-horizons",
        ",".join(str(value) for value in horizons),
        "--watchdog-seconds",
        str(watchdog_seconds),
    ]
    started = time.perf_counter()
    result = subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=external_timeout_seconds,
        check=False,
        env=EXECUTION_ENVIRONMENT,
    )
    hashes_finished = {
        "wrapper_sha256": file_sha256(WRAPPER),
        "source_sha256": file_sha256(SOURCE),
        "helper_sha256": file_sha256(helper),
        "cnf_sha256": file_sha256(cnf),
    }
    if hashes_finished != hashes_started:
        raise RuntimeError("fresh-state launch artifact drift")
    if result.stderr:
        raise RuntimeError(f"fresh-state helper emitted stderr: {result.stderr[:240]}")
    parsed = parse_fresh_output(
        stdout=result.stdout,
        returncode=result.returncode,
        mode=mode,
        order=expected_order,
        key_one_literals_bit0_through_bit19=key_one_literals_bit0_through_bit19,
        conflict_horizons=horizons,
        watchdog_seconds=watchdog_seconds,
    )
    return {
        **parsed,
        "command": command,
        "environment": EXECUTION_ENVIRONMENT,
        "launch_artifact_hashes_started": hashes_started,
        "launch_artifact_hashes_finished": hashes_finished,
        "launch_identity_verified": True,
        "process_elapsed_seconds": time.perf_counter() - started,
        "stdout_sha256": _sha256(result.stdout.encode()),
        "stderr_sha256": _sha256(result.stderr.encode()),
        "helper_returncode": result.returncode,
    }
