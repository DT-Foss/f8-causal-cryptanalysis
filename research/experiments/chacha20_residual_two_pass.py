#!/usr/bin/env python3
"""Build and validate the retained global/discovery/fallback R20 helper."""

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
SOURCE = ROOT / "research/native/cadical_residual_two_pass.cpp"
BINARY = ROOT / "research/native/build/cadical_residual_two_pass"
RESULT_PREFIX = "R20_RESIDUAL_RESULT "
SUMMARY_PREFIX = "R20_RESIDUAL_SUMMARY "
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
        raise RuntimeError(f"residual two-pass helper build failed: {observation}")
    return observation


def _mapping_arguments(key_one_literals_bit0_through_bit19: Sequence[int]) -> list[str]:
    mapping = [int(value) for value in key_one_literals_bit0_through_bit19]
    if len(mapping) != 20 or len({abs(value) for value in mapping}) != 20:
        raise ValueError("residual R20 mapping must contain twenty distinct literals")
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


def _assumptions(
    prefix: str, key_one_literals_bit0_through_bit19: Sequence[int]
) -> list[int]:
    mapping = [int(value) for value in key_one_literals_bit0_through_bit19]
    assumption_one = [mapping[bit] for bit in range(19, 11, -1)]
    return [
        literal if bit == "1" else -literal
        for bit, literal in zip(prefix, assumption_one, strict=True)
    ]


def _validate_row(
    *,
    row: dict[str, Any],
    index: int,
    mode: str,
    phase: str,
    cell_index: int,
    prefix: str | None,
    seconds: float,
    key_one_literals_bit0_through_bit19: Sequence[int],
    previous: dict[str, Any] | None,
) -> None:
    status = row.get("status")
    expected_assumptions = (
        []
        if prefix is None
        else _assumptions(prefix, key_one_literals_bit0_through_bit19)
    )
    before = row.get("metrics_before")
    after = row.get("metrics_after")
    delta = row.get("metrics_delta")
    if (
        row.get("mode") != mode
        or row.get("phase") != phase
        or row.get("attempt_index") != index
        or row.get("cell_index") != cell_index
        or row.get("prefix8") != prefix
        or status not in {"sat", "unsat", "unknown"}
        or row.get("returncode") != {"sat": 10, "unsat": 20, "unknown": 0}[status]
        or float(row.get("seconds_budget", -1)) != float(seconds)
        or row.get("metric_names") != list(METRIC_NAMES)
        or row.get("assumptions") != expected_assumptions
        or not all(
            isinstance(values, list) and len(values) == 3
            for values in (before, after, delta)
        )
        or any(
            right - left != change
            for left, right, change in zip(before, after, delta, strict=True)
        )
        or (status == "unknown") != (row.get("terminator_fired") is True)
        or not isinstance(row.get("failed_assumptions"), list)
        or not isinstance(row.get("model_bits_bit0_through_bit19"), list)
    ):
        raise RuntimeError(f"residual two-pass row gate failed at {index}")
    failed = row["failed_assumptions"]
    model = row["model_bits_bit0_through_bit19"]
    if (
        len(set(failed)) != len(failed)
        or any(literal not in expected_assumptions for literal in failed)
        or (status != "unsat" and failed)
        or (status == "sat" and (len(model) != 20 or set(model) - {0, 1}))
        or (status != "sat" and model)
    ):
        raise RuntimeError(f"residual two-pass outcome semantics failed at {index}")
    if previous is not None and (
        before != previous["metrics_after"]
        or row["active_variables_before"] != previous["active_variables_after"]
        or row["irredundant_clauses_before"]
        != previous["irredundant_clauses_after"]
        or row["redundant_clauses_before"] != previous["redundant_clauses_after"]
    ):
        raise RuntimeError(f"residual retained-state continuity failed at {index}")
    for stem in ("active_variables", "irredundant_clauses", "redundant_clauses"):
        if row[f"{stem}_after"] - row[f"{stem}_before"] != row[f"{stem}_delta"]:
            raise RuntimeError(f"residual {stem} delta failed at {index}")


def parse_output(
    *,
    stdout: str,
    returncode: int,
    mode: str,
    order: Sequence[str],
    key_one_literals_bit0_through_bit19: Sequence[int],
    global_seconds: float,
    discovery_seconds: float,
    fallback_seconds: float,
) -> dict[str, Any]:
    expected_order = list(order)
    if (
        len(expected_order) != 128
        or len(set(expected_order)) != 128
        or any(len(value) != 8 or set(value) - {"0", "1"} for value in expected_order)
        or min(global_seconds, discovery_seconds, fallback_seconds) <= 0.0
    ):
        raise ValueError("invalid residual two-pass contract")
    if returncode != 0:
        raise RuntimeError(f"residual two-pass helper returned {returncode}")
    rows = _records(stdout, RESULT_PREFIX)
    summaries = _records(stdout, SUMMARY_PREFIX)
    if len(summaries) != 1 or not rows:
        raise RuntimeError("residual two-pass helper output is incomplete")

    previous: dict[str, Any] | None = None
    cursor = 0
    _validate_row(
        row=rows[cursor],
        index=cursor,
        mode=mode,
        phase="global",
        cell_index=-1,
        prefix=None,
        seconds=global_seconds,
        key_one_literals_bit0_through_bit19=key_one_literals_bit0_through_bit19,
        previous=None,
    )
    previous = rows[cursor]
    global_status = rows[cursor]["status"]
    cursor += 1
    discovery_rows: list[dict[str, Any]] = []
    fallback_rows: list[dict[str, Any]] = []
    if global_status == "unknown":
        for cell_index, prefix in enumerate(expected_order):
            if cursor >= len(rows) or rows[cursor].get("phase") != "discovery":
                break
            _validate_row(
                row=rows[cursor],
                index=cursor,
                mode=mode,
                phase="discovery",
                cell_index=cell_index,
                prefix=prefix,
                seconds=discovery_seconds,
                key_one_literals_bit0_through_bit19=key_one_literals_bit0_through_bit19,
                previous=previous,
            )
            discovery_rows.append(rows[cursor])
            previous = rows[cursor]
            cursor += 1
            if previous["status"] == "sat":
                break
        if not discovery_rows:
            raise RuntimeError("residual discovery pass is missing")
        discovery_sat = any(row["status"] == "sat" for row in discovery_rows)
        if not discovery_sat and len(discovery_rows) != 128:
            raise RuntimeError("residual discovery pass ended before full cover")
        if not discovery_sat:
            expected_fallback = [
                row["prefix8"] for row in discovery_rows if row["status"] == "unknown"
            ]
            for prefix in expected_fallback:
                if cursor >= len(rows) or rows[cursor].get("phase") != "fallback":
                    break
                cell_index = expected_order.index(prefix)
                _validate_row(
                    row=rows[cursor],
                    index=cursor,
                    mode=mode,
                    phase="fallback",
                    cell_index=cell_index,
                    prefix=prefix,
                    seconds=fallback_seconds,
                    key_one_literals_bit0_through_bit19=key_one_literals_bit0_through_bit19,
                    previous=previous,
                )
                fallback_rows.append(rows[cursor])
                previous = rows[cursor]
                cursor += 1
                if previous["status"] == "sat":
                    break
            fallback_sat = any(row["status"] == "sat" for row in fallback_rows)
            if not fallback_sat and len(fallback_rows) != len(expected_fallback):
                raise RuntimeError("residual fallback pass ended before declared cover")
    if cursor != len(rows):
        raise RuntimeError("residual helper emitted an unexpected phase suffix")

    summary = summaries[0]
    phases = {
        name: [row for row in rows if row["phase"] == name]
        for name in ("global", "discovery", "fallback")
    }
    counts = {name: Counter(row["status"] for row in values) for name, values in phases.items()}
    sat_rows = [row for row in rows if row["status"] == "sat"]
    exact_unsat_prefixes = {
        str(row["prefix8"])
        for row in discovery_rows + fallback_rows
        if row["status"] == "unsat"
    }
    if (
        summary.get("signature") != "cadical-3.0.0"
        or summary.get("version") != "3.0.0"
        or summary.get("mode") != mode
        or summary.get("attempted_solves") != len(rows)
        or summary.get("global_sat") != counts["global"]["sat"]
        or summary.get("global_unsat") != counts["global"]["unsat"]
        or summary.get("global_unknown") != counts["global"]["unknown"]
        or summary.get("discovery_sat") != counts["discovery"]["sat"]
        or summary.get("discovery_unsat") != counts["discovery"]["unsat"]
        or summary.get("discovery_unknown") != counts["discovery"]["unknown"]
        or summary.get("fallback_sat") != counts["fallback"]["sat"]
        or summary.get("fallback_unsat") != counts["fallback"]["unsat"]
        or summary.get("fallback_unknown") != counts["fallback"]["unknown"]
        or summary.get("exact_unsat_prefixes") != len(exact_unsat_prefixes)
        or summary.get("terminator_fires")
        != sum(bool(row["terminator_fired"]) for row in rows)
        or summary.get("stopped_after_sat") is not bool(sat_rows)
        or float(summary.get("global_seconds", -1)) != float(global_seconds)
        or float(summary.get("discovery_seconds", -1)) != float(discovery_seconds)
        or float(summary.get("fallback_seconds", -1)) != float(fallback_seconds)
        or summary.get("metric_names") != list(METRIC_NAMES)
        or len(sat_rows) > 1
        or (sat_rows and rows[-1]["status"] != "sat")
    ):
        raise RuntimeError("residual two-pass summary gate failed")
    return {
        "mode": mode,
        "order": expected_order,
        "budgets": {
            "global_seconds": global_seconds,
            "discovery_seconds": discovery_seconds,
            "fallback_seconds": fallback_seconds,
        },
        "rows": rows,
        "summary": summary,
        "sat_found": bool(sat_rows),
        "sat_row": sat_rows[0] if sat_rows else None,
        "global_row": rows[0],
        "discovery_rows": discovery_rows,
        "fallback_rows": fallback_rows,
        "exact_unsat_prefixes": sorted(exact_unsat_prefixes),
        "retained_state_continuity_verified": True,
    }


def run_two_pass(
    *,
    helper: Path,
    cnf: Path,
    mode: str,
    order: Sequence[str],
    key_one_literals_bit0_through_bit19: Sequence[int],
    global_seconds: float,
    discovery_seconds: float,
    fallback_seconds: float,
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
        "--global-seconds",
        str(global_seconds),
        "--discovery-seconds",
        str(discovery_seconds),
        "--fallback-seconds",
        str(fallback_seconds),
    ]
    timeout = external_timeout_seconds or (
        global_seconds + 128 * (discovery_seconds + fallback_seconds) + 180.0
    )
    started = time.perf_counter()
    result = subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    parsed = parse_output(
        stdout=result.stdout,
        returncode=result.returncode,
        mode=mode,
        order=order,
        key_one_literals_bit0_through_bit19=key_one_literals_bit0_through_bit19,
        global_seconds=global_seconds,
        discovery_seconds=discovery_seconds,
        fallback_seconds=fallback_seconds,
    )
    return {
        **parsed,
        "command": command,
        "process_elapsed_seconds": time.perf_counter() - started,
        "stdout_sha256": _sha256(result.stdout.encode()),
        "stderr_sha256": _sha256(result.stderr.encode()),
        "helper_returncode": result.returncode,
    }
