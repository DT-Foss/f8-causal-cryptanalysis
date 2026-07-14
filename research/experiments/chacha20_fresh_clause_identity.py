"""Strict fresh-state CaDiCaL learned-clause identity collection."""

from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
BASE_WRAPPER_PATH = ROOT / "research/experiments/chacha20_fresh_multihorizon.py"
BASE_SOURCE = ROOT / "research/native/cadical_fresh_multihorizon.cpp"
SOURCE = ROOT / "research/native/cadical_fresh_clause_identity.cpp"
BINARY = ROOT / "research/native/build/cadical_fresh_clause_identity"
COMPILER = Path("/usr/bin/clang++")
CADICAL_HEADER = Path("/opt/homebrew/include/cadical.hpp")
CADICAL_LIBRARY = Path("/opt/homebrew/lib/libcadical.a")
EXECUTION_ENVIRONMENT = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
STAGE_PREFIX = "FRESH_CI_STAGE "
CELL_PREFIX = "FRESH_CI_CELL "
SUMMARY_PREFIX = "FRESH_CI_SUMMARY "
MAXIMUM_LEARNED_CLAUSE_SIZE = 64

STAGE_IDENTITY_FIELDS = {
    "learned_clause_maximum_size",
    "learned_clause_offered_stage",
    "learned_clause_accepted_stage",
    "learned_clause_rejected_large_stage",
    "learned_clause_accepted_cumulative",
    "learned_literal_count_stage",
    "learned_clause_lengths_stage",
    "learned_clauses_stage",
}
CELL_IDENTITY_FIELDS = {
    "learned_clause_offered_total",
    "learned_clause_accepted_total",
    "learned_clause_rejected_large_total",
}
SUMMARY_IDENTITY_FIELDS = {
    "bounded_variable_addition_enabled",
    "learned_clause_maximum_size",
    "learned_clause_offered_total",
    "learned_clause_accepted_total",
    "learned_clause_rejected_large_total",
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _load_base_wrapper() -> Any:
    name = "chacha20_fresh_multihorizon_for_clause_identity"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, BASE_WRAPPER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("fresh clause identity base wrapper is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def compile_helper(*, output_base: Path = BINARY) -> dict[str, Any]:
    output_base.parent.mkdir(parents=True, exist_ok=True)
    lock_path = output_base.with_name(f".{output_base.name}.compile.lock")
    temporary = output_base.with_name(f".{output_base.name}.deterministic-link")
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            temporary.unlink(missing_ok=True)
            source_started = file_sha256(SOURCE)
            base_source_started = file_sha256(BASE_SOURCE)
            bundle_started = _sha256(
                SOURCE.read_bytes() + b"\x00BASE\x00" + BASE_SOURCE.read_bytes()
            )
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
            source_finished = file_sha256(SOURCE)
            base_source_finished = file_sha256(BASE_SOURCE)
            bundle_finished = _sha256(
                SOURCE.read_bytes() + b"\x00BASE\x00" + BASE_SOURCE.read_bytes()
            )
            binary_sha = file_sha256(temporary) if temporary.exists() else None
            observation = {
                "command": command,
                "environment": EXECUTION_ENVIRONMENT,
                "returncode": result.returncode,
                "elapsed_seconds": time.perf_counter() - started,
                "stdout_sha256": _sha256(result.stdout.encode()),
                "stderr_sha256": _sha256(result.stderr.encode()),
                "source_sha256_started": source_started,
                "source_sha256_finished": source_finished,
                "base_source_sha256_started": base_source_started,
                "base_source_sha256_finished": base_source_finished,
                "source_bundle_sha256_started": bundle_started,
                "source_bundle_sha256_finished": bundle_finished,
                "compiler_sha256": file_sha256(COMPILER),
                "cadical_header_sha256": file_sha256(CADICAL_HEADER),
                "cadical_library_sha256": file_sha256(CADICAL_LIBRARY),
                "temporary_binary_sha256": binary_sha,
            }
            if (
                result.returncode != 0
                or result.stdout
                or result.stderr
                or binary_sha is None
                or source_started != source_finished
                or base_source_started != base_source_finished
                or bundle_started != bundle_finished
            ):
                raise RuntimeError(f"fresh clause identity helper build failed: {observation}")
            final = output_base.with_name(
                f"{output_base.name}-{bundle_started}-{binary_sha}"
            )
            try:
                os.link(temporary, final)
            except FileExistsError as error:
                if file_sha256(final) != binary_sha:
                    raise RuntimeError(
                        "fresh clause identity content-addressed binary differs"
                    ) from error
            final.chmod(0o755)
            if file_sha256(final) != binary_sha:
                raise RuntimeError("fresh clause identity binary hash gate failed")
            observation.update(
                {
                    "binary_path": str(final),
                    "binary_sha256": binary_sha,
                    "content_addressed_binary": True,
                }
            )
            return observation
        finally:
            temporary.unlink(missing_ok=True)
            fcntl.flock(lock, fcntl.LOCK_UN)


def _parse_events(stdout: str) -> list[tuple[str, dict[str, Any]]]:
    prefixes = (
        ("stage", STAGE_PREFIX),
        ("cell", CELL_PREFIX),
        ("summary", SUMMARY_PREFIX),
    )
    rows: list[tuple[str, dict[str, Any]]] = []
    for line in stdout.splitlines():
        if not line:
            continue
        for kind, prefix in prefixes:
            if line.startswith(prefix):
                try:
                    value = json.loads(line.removeprefix(prefix))
                except json.JSONDecodeError as error:
                    raise RuntimeError(
                        f"malformed fresh clause identity JSON: {error}"
                    ) from error
                if not isinstance(value, dict):
                    raise RuntimeError("fresh clause identity event must be an object")
                rows.append((kind, value))
                break
        else:
            raise RuntimeError(f"unexpected clause identity output: {line[:160]}")
    return rows


def _base_stdout(events: Sequence[tuple[str, Mapping[str, Any]]], base: Any) -> str:
    lines = []
    for kind, row in events:
        excluded = (
            STAGE_IDENTITY_FIELDS
            if kind == "stage"
            else CELL_IDENTITY_FIELDS
            if kind == "cell"
            else SUMMARY_IDENTITY_FIELDS
        )
        clean = {key: value for key, value in row.items() if key not in excluded}
        prefix = (
            base.STAGE_PREFIX
            if kind == "stage"
            else base.CELL_PREFIX
            if kind == "cell"
            else base.SUMMARY_PREFIX
        )
        lines.append(prefix + json.dumps(clean, separators=(",", ":")))
    return "\n".join(lines) + "\n"


def _canonical_clause(clause: Any, variables: int) -> bool:
    if not isinstance(clause, list):
        return False
    if any(
        not isinstance(literal, int)
        or isinstance(literal, bool)
        or literal == 0
        or abs(literal) > variables
        for literal in clause
    ):
        return False
    if clause != sorted(clause, key=lambda literal: (abs(literal), literal)):
        return False
    if len(set(clause)) != len(clause):
        return False
    literals = set(clause)
    return not any(-literal in literals for literal in clause)


def parse_clause_identity_output(
    *,
    stdout: str,
    returncode: int,
    mode: str,
    order: Sequence[str],
    key_one_literals_bit0_through_bit19: Sequence[int],
    conflict_horizons: Sequence[int],
    watchdog_seconds: float,
) -> dict[str, Any]:
    base = _load_base_wrapper()
    events = _parse_events(stdout)
    base_run = base.parse_fresh_output(
        stdout=_base_stdout(events, base),
        returncode=returncode,
        mode=mode,
        order=order,
        key_one_literals_bit0_through_bit19=key_one_literals_bit0_through_bit19,
        conflict_horizons=conflict_horizons,
        watchdog_seconds=watchdog_seconds,
    )
    if not events or events[-1][0] != "summary":
        raise RuntimeError("fresh clause identity summary is missing")
    summary = events[-1][1]
    variables = summary.get("variables")
    if not isinstance(variables, int) or isinstance(variables, bool) or variables <= 0:
        raise RuntimeError("fresh clause identity variable count is invalid")
    stage_rows = [row for kind, row in events if kind == "stage"]
    cell_rows = [row for kind, row in events if kind == "cell"]
    if len(stage_rows) != len(base_run["stages"]) or len(cell_rows) != 256:
        raise RuntimeError("fresh clause identity event count differs")

    cumulative_by_cell: dict[int, int] = {}
    accepted_sum = 0
    offered_sum = 0
    rejected_sum = 0
    for row, clean in zip(stage_rows, base_run["stages"], strict=True):
        if set(row) != base.STAGE_FIELDS | STAGE_IDENTITY_FIELDS:
            raise RuntimeError("fresh clause identity stage schema differs")
        clauses = row["learned_clauses_stage"]
        lengths = row["learned_clause_lengths_stage"]
        accepted = row["learned_clause_accepted_stage"]
        offered = row["learned_clause_offered_stage"]
        rejected = row["learned_clause_rejected_large_stage"]
        cumulative = row["learned_clause_accepted_cumulative"]
        literal_count = row["learned_literal_count_stage"]
        cell_index = row["cell_index"]
        previous = cumulative_by_cell.get(cell_index, 0)
        valid = (
            row["learned_clause_maximum_size"] == MAXIMUM_LEARNED_CLAUSE_SIZE
            and all(
                isinstance(value, int) and not isinstance(value, bool) and value >= 0
                for value in (accepted, offered, rejected, cumulative, literal_count)
            )
            and isinstance(clauses, list)
            and isinstance(lengths, list)
            and len(clauses) == len(lengths) == accepted
            and offered == accepted + rejected
            and cumulative == previous + accepted
            and all(
                isinstance(length, int)
                and not isinstance(length, bool)
                and 0 <= length <= MAXIMUM_LEARNED_CLAUSE_SIZE
                for length in lengths
            )
            and lengths == [len(clause) for clause in clauses]
            and literal_count == sum(lengths)
            and all(_canonical_clause(clause, variables) for clause in clauses)
        )
        if not valid:
            raise RuntimeError(
                f"fresh clause identity stage validation failed at cell {cell_index}"
            )
        cumulative_by_cell[cell_index] = cumulative
        clean.update({key: row[key] for key in STAGE_IDENTITY_FIELDS})
        accepted_sum += accepted
        offered_sum += offered
        rejected_sum += rejected

    for row, clean in zip(cell_rows, base_run["cells"], strict=True):
        if set(row) != base.CELL_FIELDS | CELL_IDENTITY_FIELDS:
            raise RuntimeError("fresh clause identity cell schema differs")
        cell_index = row["cell_index"]
        values = [row[key] for key in sorted(CELL_IDENTITY_FIELDS)]
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in values
        ) or (
            row["learned_clause_offered_total"]
            != row["learned_clause_accepted_total"]
            + row["learned_clause_rejected_large_total"]
        ) or row["learned_clause_accepted_total"] != cumulative_by_cell.get(cell_index, 0):
            raise RuntimeError(
                f"fresh clause identity cell accounting failed at {cell_index}"
            )
        clean.update({key: row[key] for key in CELL_IDENTITY_FIELDS})

    if set(summary) != base.SUMMARY_FIELDS | SUMMARY_IDENTITY_FIELDS:
        raise RuntimeError("fresh clause identity summary schema differs")
    if (
        summary["bounded_variable_addition_enabled"] is not False
        or
        summary["learned_clause_maximum_size"] != MAXIMUM_LEARNED_CLAUSE_SIZE
        or summary["learned_clause_accepted_total"] != accepted_sum
        or summary["learned_clause_offered_total"] != offered_sum
        or summary["learned_clause_rejected_large_total"] != rejected_sum
        or offered_sum != accepted_sum + rejected_sum
    ):
        raise RuntimeError("fresh clause identity global accounting differs")
    base_run["summary"].update(
        {key: summary[key] for key in SUMMARY_IDENTITY_FIELDS}
    )
    base_run.update(
        {
            "learned_clause_identity_complete": True,
            "learned_clause_canonical_order": "absolute_variable_then_signed_literal",
            "learned_clause_maximum_size": MAXIMUM_LEARNED_CLAUSE_SIZE,
            "bounded_variable_addition_enabled": False,
        }
    )
    return base_run


def run_fresh_clause_identity(
    *,
    helper: Path,
    cnf: Path,
    mode: str,
    order: Sequence[str],
    key_one_literals_bit0_through_bit19: Sequence[int],
    conflict_horizons: Sequence[int],
    watchdog_seconds: float,
    external_timeout_seconds: float,
) -> dict[str, Any]:
    base = _load_base_wrapper()
    expected_order, horizons = base._validate_inputs(
        mode=mode,
        order=order,
        conflict_horizons=conflict_horizons,
        watchdog_seconds=watchdog_seconds,
    )
    if not helper.is_file() or not cnf.is_file():
        raise ValueError("fresh clause identity helper and CNF must be regular files")
    command = [
        str(helper),
        "--cnf",
        str(cnf),
        "--mode",
        mode,
        *base._mapping_arguments(key_one_literals_bit0_through_bit19),
        "--cell-order",
        ",".join(expected_order),
        "--conflict-horizons",
        ",".join(str(value) for value in horizons),
        "--watchdog-seconds",
        format(float(watchdog_seconds), ".17g"),
    ]
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=external_timeout_seconds,
            env=EXECUTION_ENVIRONMENT,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("fresh clause identity external timeout fired") from error
    elapsed = time.perf_counter() - started
    if result.stderr:
        raise RuntimeError(f"fresh clause identity stderr is nonempty: {result.stderr[:400]}")
    parsed = parse_clause_identity_output(
        stdout=result.stdout,
        returncode=result.returncode,
        mode=mode,
        order=expected_order,
        key_one_literals_bit0_through_bit19=key_one_literals_bit0_through_bit19,
        conflict_horizons=horizons,
        watchdog_seconds=watchdog_seconds,
    )
    parsed.update(
        {
            "command": command,
            "process_elapsed_seconds": elapsed,
            "stdout_sha256": _sha256(result.stdout.encode()),
            "stderr_sha256": _sha256(result.stderr.encode()),
            "helper_sha256": file_sha256(helper),
            "cnf_sha256": file_sha256(cnf),
        }
    )
    return parsed
