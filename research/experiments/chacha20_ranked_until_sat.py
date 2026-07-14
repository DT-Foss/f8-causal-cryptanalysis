"""Strict build, execution, and parsing for ranked retained R20 recovery."""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
SOURCE = ROOT / "research/native/cadical_ranked_until_sat.cpp"
BINARY = ROOT / "research/native/build/cadical_ranked_until_sat"
RESULT_PREFIX = "R20_RANKED_RESULT "
SUMMARY_PREFIX = "R20_RANKED_SUMMARY "
METRIC_NAMES = ("conflicts", "decisions", "search_propagations")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def compile_helper(*, output: Path = BINARY) -> dict[str, Any]:
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "/usr/bin/clang++",
        "-std=c++17",
        "-O3",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I/opt/homebrew/include",
        str(SOURCE),
        "/opt/homebrew/lib/libcadical.a",
        "-lpthread",
        "-o",
        str(output),
    ]
    started = time.perf_counter()
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    observation = {
        "command": command,
        "returncode": result.returncode,
        "elapsed_seconds": time.perf_counter() - started,
        "stdout_sha256": _sha256(result.stdout.encode()),
        "stderr_sha256": _sha256(result.stderr.encode()),
        "source_sha256": file_sha256(SOURCE),
        "binary_sha256": file_sha256(output) if output.exists() else None,
    }
    if result.returncode != 0 or result.stdout or result.stderr or not output.exists():
        raise RuntimeError(f"ranked CaDiCaL helper build failed: {observation}")
    return observation


def _mapping_arguments(
    key_one_literals_bit0_through_bit19: Sequence[int],
) -> list[str]:
    mapping = [int(value) for value in key_one_literals_bit0_through_bit19]
    if len(mapping) != 20 or len({abs(value) for value in mapping}) != 20:
        raise ValueError("ranked R20 mapping must contain twenty distinct literals")
    return [
        "--assumption-one-literals",
        ",".join(str(mapping[bit]) for bit in range(19, 11, -1)),
        "--model-one-literals",
        ",".join(str(value) for value in mapping),
    ]


def _records(stdout: str, prefix: str) -> list[dict[str, Any]]:
    return [
        json.loads(line.removeprefix(prefix))
        for line in stdout.splitlines()
        if line.startswith(prefix)
    ]


def parse_ranked_output(
    *,
    stdout: str,
    returncode: int,
    mode: str,
    order: Sequence[str],
    key_one_literals_bit0_through_bit19: Sequence[int],
    seconds: float,
    max_cells: int,
) -> dict[str, Any]:
    expected_order = list(order)
    complete = {f"{value:08b}" for value in range(256)}
    if len(expected_order) != 256 or set(expected_order) != complete:
        raise ValueError("ranked R20 order must cover all prefixes")
    if seconds <= 0.0 or max_cells < 1 or max_cells > 256:
        raise ValueError("invalid ranked R20 budget")
    if returncode != 0:
        raise RuntimeError(f"ranked helper returned {returncode}")
    rows = _records(stdout, RESULT_PREFIX)
    summaries = _records(stdout, SUMMARY_PREFIX)
    if len(summaries) != 1 or not rows or len(rows) > max_cells:
        raise RuntimeError("ranked helper output is incomplete")
    mapping = [int(value) for value in key_one_literals_bit0_through_bit19]
    assumption_one = [mapping[bit] for bit in range(19, 11, -1)]
    previous: dict[str, Any] | None = None
    for index, row in enumerate(rows):
        prefix = expected_order[index]
        assumptions = [
            literal if bit == "1" else -literal
            for bit, literal in zip(prefix, assumption_one, strict=True)
        ]
        status = row.get("status")
        before = row.get("metrics_before")
        after = row.get("metrics_after")
        delta = row.get("metrics_delta")
        if (
            row.get("mode") != mode
            or row.get("prefix8") != prefix
            or row.get("cell_index") != index
            or status not in {"sat", "unsat", "unknown"}
            or row.get("returncode") != {"sat": 10, "unsat": 20, "unknown": 0}[status]
            or float(row.get("seconds_budget", -1)) != float(seconds)
            or row.get("metric_names") != list(METRIC_NAMES)
            or row.get("assumptions") != assumptions
            or not all(
                isinstance(values, list) and len(values) == 3 for values in (before, after, delta)
            )
            or any(
                right - left != change
                for left, right, change in zip(before, after, delta, strict=True)
            )
            or (status == "unknown") != (row.get("terminator_fired") is True)
            or not isinstance(row.get("failed_assumptions"), list)
            or not isinstance(row.get("model_bits_bit0_through_bit19"), list)
        ):
            raise RuntimeError(f"ranked helper row gate failed at {index}")
        failed = row["failed_assumptions"]
        model = row["model_bits_bit0_through_bit19"]
        if (
            len(set(failed)) != len(failed)
            or any(literal not in assumptions for literal in failed)
            or (status != "unsat" and failed)
            or (status == "sat" and (len(model) != 20 or set(model) - {0, 1}))
            or (status != "sat" and model)
        ):
            raise RuntimeError(f"ranked helper outcome semantics failed at {index}")
        if previous is not None and (
            before != previous["metrics_after"]
            or row["active_variables_before"] != previous["active_variables_after"]
            or row["irredundant_clauses_before"] != previous["irredundant_clauses_after"]
            or row["redundant_clauses_before"] != previous["redundant_clauses_after"]
        ):
            raise RuntimeError(f"ranked retained-state continuity failed at {index}")
        for stem in (
            "active_variables",
            "irredundant_clauses",
            "redundant_clauses",
        ):
            if row[f"{stem}_after"] - row[f"{stem}_before"] != row[f"{stem}_delta"]:
                raise RuntimeError(f"ranked {stem} delta failed at {index}")
        previous = row
    summary = summaries[0]
    counts = Counter(row["status"] for row in rows)
    sat_rows = [row for row in rows if row["status"] == "sat"]
    stopped = bool(sat_rows)
    if (
        summary.get("signature") != "cadical-3.0.0"
        or summary.get("version") != "3.0.0"
        or summary.get("mode") != mode
        or summary.get("planned_max_cells") != max_cells
        or summary.get("attempted_cells") != len(rows)
        or summary.get("sat") != counts["sat"]
        or summary.get("unsat") != counts["unsat"]
        or summary.get("unknown") != counts["unknown"]
        or summary.get("terminator_fires") != sum(row["terminator_fired"] for row in rows)
        or summary.get("stopped_after_sat") is not stopped
        or float(summary.get("seconds_budget", -1)) != float(seconds)
        or summary.get("metric_names") != list(METRIC_NAMES)
        or len(sat_rows) > 1
        or (stopped and rows[-1]["status"] != "sat")
        or (not stopped and len(rows) != max_cells)
    ):
        raise RuntimeError("ranked helper summary gate failed")
    return {
        "mode": mode,
        "order": expected_order,
        "seconds_budget_per_cell": seconds,
        "max_cells": max_cells,
        "rows": rows,
        "summary": summary,
        "sat_found": stopped,
        "sat_row": sat_rows[0] if sat_rows else None,
        "retained_state_continuity_verified": True,
    }


def run_ranked(
    *,
    helper: Path,
    cnf: Path,
    mode: str,
    order: Sequence[str],
    key_one_literals_bit0_through_bit19: Sequence[int],
    seconds: float,
    max_cells: int = 256,
    external_timeout_seconds: float | None = None,
) -> dict[str, Any]:
    command = [
        str(helper),
        "--cnf",
        str(cnf),
        "--mode",
        mode,
        *_mapping_arguments(key_one_literals_bit0_through_bit19),
        "--cell-order",
        ",".join(order),
        "--seconds",
        str(seconds),
        "--max-cells",
        str(max_cells),
    ]
    timeout = external_timeout_seconds or max_cells * seconds + 120.0
    started = time.perf_counter()
    result = subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    parsed = parse_ranked_output(
        stdout=result.stdout,
        returncode=result.returncode,
        mode=mode,
        order=order,
        key_one_literals_bit0_through_bit19=key_one_literals_bit0_through_bit19,
        seconds=seconds,
        max_cells=max_cells,
    )
    return {
        **parsed,
        "command": command,
        "process_elapsed_seconds": time.perf_counter() - started,
        "stdout_sha256": _sha256(result.stdout.encode()),
        "stderr_sha256": _sha256(result.stderr.encode()),
        "helper_returncode": result.returncode,
    }
