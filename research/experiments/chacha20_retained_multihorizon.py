"""Strict retained-state multi-horizon CaDiCaL execution and parsing."""

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
SOURCE = ROOT / "research/native/cadical_global_incremental_multihorizon.cpp"
BINARY = ROOT / "research/native/build/cadical_global_incremental_multihorizon"
WRAPPER = Path(__file__).resolve()
COMPILER = Path("/usr/bin/clang++")
CADICAL_HEADER = Path("/opt/homebrew/include/cadical.hpp")
CADICAL_LIBRARY = Path("/opt/homebrew/lib/libcadical.a")
EXECUTION_ENVIRONMENT = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
STAGE_PREFIX = "RETAINED_MH_STAGE "
CELL_PREFIX = "RETAINED_MH_CELL "
SUMMARY_PREFIX = "RETAINED_MH_SUMMARY "
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
        for suffix in (
            "stage_before",
            "stage_after",
            "stage_delta",
            "cell_before",
            "cell_cumulative_delta",
        )
    },
}
CELL_FIELDS = {
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
SUMMARY_FIELDS = {
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


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def numeric_order() -> list[str]:
    return [f"{value:08b}" for value in range(256)]


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
                "deterministic_link_path": str(temporary),
            }
            if (
                result.returncode != 0
                or result.stdout
                or result.stderr
                or temporary_sha is None
                or source_sha_started != source_sha_finished
            ):
                raise RuntimeError(f"multi-horizon CaDiCaL helper build failed: {observation}")
            final = output_base.with_name(
                f"{output_base.name}-{source_sha_started}-{temporary_sha}"
            )
            try:
                os.link(temporary, final)
            except FileExistsError as error:
                if file_sha256(final) != temporary_sha:
                    raise RuntimeError(
                        "content-addressed multi-horizon helper path has wrong bytes"
                    ) from error
            final.chmod(0o755)
            if file_sha256(final) != temporary_sha:
                raise RuntimeError("content-addressed multi-horizon helper failed final hash gate")
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


def _mapping_arguments(
    key_one_literals_bit0_through_bit19: Sequence[int],
) -> list[str]:
    mapping = _validate_mapping(key_one_literals_bit0_through_bit19)
    return [
        "--assumption-one-literals",
        ",".join(str(mapping[bit]) for bit in range(19, 11, -1)),
        "--model-one-literals",
        ",".join(str(value) for value in mapping),
    ]


def _validate_mapping(values: Sequence[int]) -> list[int]:
    mapping = list(values)
    if (
        len(mapping) != 20
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value == 0 for value in mapping
        )
        or len({abs(value) for value in mapping}) != 20
    ):
        raise ValueError("multi-horizon mapping must contain twenty distinct signed literals")
    return mapping


def _validate_inputs(
    *, mode: str, order: Sequence[str], conflict_horizons: Sequence[int], watchdog_seconds: float
) -> tuple[list[str], list[int]]:
    expected_order = list(order)
    horizons = list(conflict_horizons)
    if MODE_PATTERN.fullmatch(mode) is None:
        raise ValueError("multi-horizon mode contains unsupported characters")
    if len(expected_order) != 256 or set(expected_order) != set(numeric_order()):
        raise ValueError("multi-horizon order must cover every eight-bit prefix exactly once")
    if any(not isinstance(value, str) or len(value) != 8 for value in expected_order):
        raise ValueError("multi-horizon order entries must be eight-bit strings")
    if (
        not horizons
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in horizons
        )
        or any(right <= left for left, right in zip(horizons, horizons[1:], strict=False))
    ):
        raise ValueError("conflict horizons must be positive and strictly increasing")
    if (
        not isinstance(watchdog_seconds, (int, float))
        or isinstance(watchdog_seconds, bool)
        or not math.isfinite(float(watchdog_seconds))
        or watchdog_seconds <= 0
    ):
        raise ValueError("watchdog seconds must be finite and positive")
    return expected_order, horizons


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
                    raise RuntimeError(f"malformed multi-horizon JSON: {error}") from error
                if not isinstance(record, dict):
                    raise RuntimeError("multi-horizon JSON record must be an object")
                events.append((kind, record))
                break
        else:
            raise RuntimeError(f"unexpected multi-horizon output line: {line[:160]}")
    return events


def _is_int(value: Any, *, nonnegative: bool = False) -> bool:
    return (
        isinstance(value, int) and not isinstance(value, bool) and (not nonnegative or value >= 0)
    )


def _metric_vector(value: Any) -> bool:
    return (
        isinstance(value, list)
        and len(value) == 3
        and all(_is_int(item, nonnegative=True) for item in value)
    )


def _difference(after: Sequence[int], before: Sequence[int]) -> list[int]:
    return [right - left for left, right in zip(before, after, strict=True)]


def parse_multihorizon_output(
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
        raise RuntimeError(f"multi-horizon helper returned {returncode}")
    events = _parse_events(stdout)
    if not events or events[-1][0] != "summary":
        raise RuntimeError("multi-horizon summary is missing or misplaced")
    if any(kind == "summary" for kind, _ in events[:-1]):
        raise RuntimeError("multi-horizon summary must be the final record")

    assumption_one = [mapping[bit] for bit in range(19, 11, -1)]
    stage_rows: list[dict[str, Any]] = []
    cell_rows: list[dict[str, Any]] = []
    cursor = 0
    previous_cell: dict[str, Any] | None = None
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
            raise RuntimeError(f"multi-horizon cell block is incomplete at {cell_index}")
        cell = events[cursor][1]
        cursor += 1
        if len(current_stages) > len(horizons):
            raise RuntimeError(f"too many multi-horizon stages at cell {cell_index}")

        previous_stage: dict[str, Any] | None = None
        for stage_index, row in enumerate(current_stages):
            status = row.get("status")
            expected_increment = horizons[stage_index] - (
                horizons[stage_index - 1] if stage_index else 0
            )
            before = row.get("metrics_stage_before")
            after = row.get("metrics_stage_after")
            delta = row.get("metrics_stage_delta")
            cell_before = row.get("metrics_cell_before")
            cumulative = row.get("metrics_cell_cumulative_delta")
            elapsed = row.get("elapsed_seconds")
            row_watchdog_seconds = row.get("watchdog_seconds")
            if (
                set(row) != STAGE_FIELDS
                or row.get("mode") != mode
                or row.get("prefix8") != prefix8
                or not _is_int(row.get("cell_index"), nonnegative=True)
                or row.get("cell_index") != cell_index
                or not _is_int(row.get("stage_index"), nonnegative=True)
                or row.get("stage_index") != stage_index
                or not _is_int(row.get("horizon"), nonnegative=True)
                or row.get("horizon") != horizons[stage_index]
                or not _is_int(row.get("conflict_increment"), nonnegative=True)
                or row.get("conflict_increment") != expected_increment
                or status not in {"sat", "unsat", "unknown"}
                or not _is_int(row.get("returncode"), nonnegative=True)
                or row.get("returncode") != {"sat": 10, "unsat": 20, "unknown": 0}[status]
                or row.get("terminal") is not (status != "unknown")
                or not isinstance(row.get("assumptions"), list)
                or any(not _is_int(value) for value in row["assumptions"])
                or row.get("assumptions") != assumptions
                or row.get("metric_names") != list(METRIC_NAMES)
                or not all(
                    _metric_vector(value)
                    for value in (before, after, delta, cell_before, cumulative)
                )
                or delta != _difference(after, before)
                or cumulative != _difference(after, cell_before)
                or not isinstance(row.get("watchdog_fired"), bool)
                or not isinstance(row.get("conflict_budget_exhausted"), bool)
                or not isinstance(row_watchdog_seconds, (int, float))
                or isinstance(row_watchdog_seconds, bool)
                or not math.isfinite(float(row_watchdog_seconds))
                or float(row_watchdog_seconds) != float(watchdog_seconds)
                or not isinstance(elapsed, (int, float))
                or isinstance(elapsed, bool)
                or not math.isfinite(float(elapsed))
                or elapsed < 0
                or not isinstance(row.get("failed_assumptions"), list)
                or not isinstance(row.get("model_bits_bit0_through_bit19"), list)
            ):
                raise RuntimeError(
                    f"multi-horizon stage schema or identity gate failed at {cell_index}:{stage_index}"
                )
            if status == "unknown":
                if row["watchdog_fired"] is row["conflict_budget_exhausted"]:
                    raise RuntimeError(
                        f"multi-horizon UNKNOWN cause gate failed at {cell_index}:{stage_index}"
                    )
            elif row["watchdog_fired"] or row["conflict_budget_exhausted"]:
                raise RuntimeError(
                    f"multi-horizon terminal budget gate failed at {cell_index}:{stage_index}"
                )
            failed = row["failed_assumptions"]
            model = row["model_bits_bit0_through_bit19"]
            expected_model_prefix = [int(bit) for bit in reversed(prefix8)]
            if (
                any(not _is_int(value) for value in failed)
                or len(set(failed)) != len(failed)
                or any(literal not in assumptions for literal in failed)
                or (status != "unsat" and failed)
                or (
                    status == "sat"
                    and (
                        len(model) != 20
                        or any(not _is_int(value) or value not in {0, 1} for value in model)
                        or model[12:] != expected_model_prefix
                    )
                )
                or (status != "sat" and model)
            ):
                raise RuntimeError(
                    f"multi-horizon outcome semantics failed at {cell_index}:{stage_index}"
                )
            for stem in STATE_STEMS:
                stage_left = row.get(f"{stem}_stage_before")
                stage_right = row.get(f"{stem}_stage_after")
                stage_change = row.get(f"{stem}_stage_delta")
                cell_left = row.get(f"{stem}_cell_before")
                cell_change = row.get(f"{stem}_cell_cumulative_delta")
                if (
                    not all(
                        _is_int(value, nonnegative=True)
                        for value in (stage_left, stage_right, cell_left)
                    )
                    or not all(_is_int(value) for value in (stage_change, cell_change))
                    or stage_right - stage_left != stage_change
                    or stage_right - cell_left != cell_change
                ):
                    raise RuntimeError(
                        f"multi-horizon {stem} delta failed at {cell_index}:{stage_index}"
                    )
            if previous_stage is None:
                if cell_before != before or any(
                    row[f"{stem}_cell_before"] != row[f"{stem}_stage_before"]
                    for stem in STATE_STEMS
                ):
                    raise RuntimeError(
                        f"multi-horizon cell-start continuity failed at {cell_index}"
                    )
                if previous_cell is not None and (
                    before != previous_cell["metrics_after"]
                    or any(
                        row[f"{stem}_stage_before"] != previous_cell[f"{stem}_after"]
                        for stem in STATE_STEMS
                    )
                ):
                    raise RuntimeError(
                        f"multi-horizon between-cell continuity failed at {cell_index}"
                    )
            elif (
                before != previous_stage["metrics_stage_after"]
                or cell_before != previous_stage["metrics_cell_before"]
                or any(
                    row[f"{stem}_stage_before"] != previous_stage[f"{stem}_stage_after"]
                    or row[f"{stem}_cell_before"] != previous_stage[f"{stem}_cell_before"]
                    for stem in STATE_STEMS
                )
            ):
                raise RuntimeError(
                    f"multi-horizon within-cell continuity failed at {cell_index}:{stage_index}"
                )
            if previous_stage is not None and previous_stage["status"] != "unknown":
                raise RuntimeError(f"multi-horizon continued after terminal at cell {cell_index}")
            previous_stage = row

        final_stage = current_stages[-1]
        final_status = final_stage["status"]
        expected_terminal_index = len(current_stages) - 1 if final_status != "unknown" else None
        if final_status == "unknown" and len(current_stages) != len(horizons):
            raise RuntimeError(f"multi-horizon UNKNOWN cell stopped early at {cell_index}")
        if (
            set(cell) != CELL_FIELDS
            or cell.get("mode") != mode
            or cell.get("prefix8") != prefix8
            or not _is_int(cell.get("cell_index"), nonnegative=True)
            or cell.get("cell_index") != cell_index
            or not isinstance(cell.get("assumptions"), list)
            or any(not _is_int(value) for value in cell["assumptions"])
            or cell.get("assumptions") != assumptions
            or not _is_int(cell.get("stages_run"), nonnegative=True)
            or cell.get("stages_run") != len(current_stages)
            or cell.get("final_status") != final_status
            or (
                cell.get("terminal_stage_index") is not None
                and not _is_int(cell.get("terminal_stage_index"), nonnegative=True)
            )
            or cell.get("terminal_stage_index") != expected_terminal_index
            or not _is_int(cell.get("watchdog_fires"), nonnegative=True)
            or cell.get("watchdog_fires") != sum(row["watchdog_fired"] for row in current_stages)
            or cell.get("metric_names") != list(METRIC_NAMES)
            or not all(
                _metric_vector(cell.get(field))
                for field in ("metrics_before", "metrics_after", "metrics_delta")
            )
            or cell.get("metrics_before") != current_stages[0]["metrics_cell_before"]
            or cell.get("metrics_after") != final_stage["metrics_stage_after"]
            or cell.get("metrics_delta")
            != _difference(cell["metrics_after"], cell["metrics_before"])
        ):
            raise RuntimeError(
                f"multi-horizon cell schema or aggregate gate failed at {cell_index}"
            )
        for stem in STATE_STEMS:
            before_value = cell.get(f"{stem}_before")
            after_value = cell.get(f"{stem}_after")
            change = cell.get(f"{stem}_delta")
            if (
                not all(_is_int(value, nonnegative=True) for value in (before_value, after_value))
                or not _is_int(change)
                or before_value != current_stages[0][f"{stem}_cell_before"]
                or after_value != final_stage[f"{stem}_stage_after"]
                or after_value - before_value != change
            ):
                raise RuntimeError(f"multi-horizon cell {stem} gate failed at {cell_index}")
        stage_rows.extend(current_stages)
        cell_rows.append(cell)
        previous_cell = cell

    if cursor != len(events) - 1:
        raise RuntimeError("multi-horizon output contains misplaced or extra records")
    summary = events[-1][1]
    counts = Counter(cell["final_status"] for cell in cell_rows)
    observed_watchdogs = sum(cell["watchdog_fires"] for cell in cell_rows)
    summary_watchdog_seconds = summary.get("watchdog_seconds")
    if (
        set(summary) != SUMMARY_FIELDS
        or summary.get("signature") != "cadical-3.0.0"
        or summary.get("version") != "3.0.0"
        or summary.get("mode") != mode
        or not _is_int(summary.get("variables"), nonnegative=True)
        or not _is_int(summary.get("cells"), nonnegative=True)
        or summary.get("cells") != 256
        or summary.get("conflict_horizons") != horizons
        or not _is_int(summary.get("configured_stages_per_nonterminal_cell"), nonnegative=True)
        or summary.get("configured_stages_per_nonterminal_cell") != len(horizons)
        or not _is_int(summary.get("stages_emitted"), nonnegative=True)
        or summary.get("stages_emitted") != len(stage_rows)
        or not _is_int(summary.get("sat_cells"), nonnegative=True)
        or summary.get("sat_cells") != counts["sat"]
        or not _is_int(summary.get("unsat_cells"), nonnegative=True)
        or summary.get("unsat_cells") != counts["unsat"]
        or not _is_int(summary.get("unknown_cells"), nonnegative=True)
        or summary.get("unknown_cells") != counts["unknown"]
        or not isinstance(summary_watchdog_seconds, (int, float))
        or isinstance(summary_watchdog_seconds, bool)
        or not math.isfinite(float(summary_watchdog_seconds))
        or float(summary_watchdog_seconds) != float(watchdog_seconds)
        or not _is_int(summary.get("watchdog_fires"), nonnegative=True)
        or summary.get("watchdog_fires") != observed_watchdogs
        or summary.get("metric_names") != list(METRIC_NAMES)
        or observed_watchdogs != 0
    ):
        raise RuntimeError("multi-horizon summary gate failed")
    return {
        "mode": mode,
        "order": expected_order,
        "conflict_horizons": horizons,
        "watchdog_seconds_per_stage": float(watchdog_seconds),
        "stages": stage_rows,
        "cells": cell_rows,
        "summary": summary,
        "retained_state_continuity_verified": True,
        "all_watchdogs_clear": observed_watchdogs == 0,
    }


def run_multihorizon(
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
        raise ValueError("multi-horizon helper and CNF must be regular files")
    wrapper_sha_started = file_sha256(WRAPPER)
    source_sha_started = file_sha256(SOURCE)
    helper_sha_started = file_sha256(helper)
    cnf_sha_started = file_sha256(cnf)
    expected_helper_name = f"{BINARY.name}-{source_sha_started}-{helper_sha_started}"
    if helper.name != expected_helper_name:
        raise RuntimeError("multi-horizon helper is not the expected content-addressed artifact")
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
    finished_hashes = {
        "wrapper_sha256": file_sha256(WRAPPER),
        "source_sha256": file_sha256(SOURCE),
        "helper_sha256": file_sha256(helper),
        "cnf_sha256": file_sha256(cnf),
    }
    started_hashes = {
        "wrapper_sha256": wrapper_sha_started,
        "source_sha256": source_sha_started,
        "helper_sha256": helper_sha_started,
        "cnf_sha256": cnf_sha_started,
    }
    if finished_hashes != started_hashes:
        raise RuntimeError(
            f"multi-horizon launch artifact drift: started={started_hashes}, "
            f"finished={finished_hashes}"
        )
    if result.stderr:
        raise RuntimeError(f"multi-horizon helper emitted stderr: {result.stderr[:240]}")
    parsed = parse_multihorizon_output(
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
        "launch_artifact_hashes_started": started_hashes,
        "launch_artifact_hashes_finished": finished_hashes,
        "launch_identity_verified": True,
        "process_elapsed_seconds": time.perf_counter() - started,
        "stdout_sha256": _sha256(result.stdout.encode()),
        "stderr_sha256": _sha256(result.stderr.encode()),
        "helper_returncode": result.returncode,
    }
