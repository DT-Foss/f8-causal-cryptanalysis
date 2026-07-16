"""Fresh-state CaDiCaL clause identities with exact LRAT antecedent statistics."""

from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
IDENTITY_WRAPPER_PATH = ROOT / "research/experiments/chacha20_fresh_clause_identity.py"
BASE_SOURCE = ROOT / "research/native/cadical_fresh_multihorizon.cpp"
IDENTITY_SOURCE = ROOT / "research/native/cadical_fresh_clause_identity.cpp"
TRACER_HEADER = ROOT / "research/native/cadical_tracer_v3.hpp"
SOURCE = ROOT / "research/native/cadical_fresh_clause_antecedents.cpp"
BINARY = ROOT / "research/native/build/cadical_fresh_clause_antecedents"
COMPILER = Path("/usr/bin/clang++")
CADICAL_HEADER = Path("/opt/homebrew/include/cadical.hpp")
CADICAL_LIBRARY = Path("/opt/homebrew/lib/libcadical.a")
EXECUTION_ENVIRONMENT = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
COMPILATION_ENVIRONMENT = {
    **EXECUTION_ENVIRONMENT,
    "TMPDIR": os.environ.get("TMPDIR", "/private/tmp"),
}
STAGE_PREFIX = "FRESH_CA_STAGE "
CELL_PREFIX = "FRESH_CA_CELL "
SUMMARY_PREFIX = "FRESH_CA_SUMMARY "
_IDENTITY_LOAD_LOCK = threading.RLock()

STAGE_PROOF_FIELDS = {
    "proof_original_clause_count",
    "proof_derived_count_stage",
    "proof_derived_count_cumulative",
    "proof_antecedent_count_stage",
    "proof_missing_antecedent_count_stage",
    "proof_assumptions_stage",
    "proof_solve_queries_stage",
    "proof_assumption_resets_stage",
    "proof_deletions_stage",
    "proof_demotions_stage",
    "proof_weakenings_stage",
    "proof_strengthenings_stage",
    "proof_finalizations_stage",
    "proof_antecedent_statistics",
}
CELL_PROOF_FIELDS = {
    "proof_original_clause_count",
    "proof_restored_originals_total",
    "proof_derived_total",
    "proof_begin_event_count",
    "proof_status_event_count",
    "proof_assumption_clause_count",
    "proof_unsat_conclusions",
    "proof_sat_conclusions",
    "proof_unknown_conclusions",
    "proof_equivalences",
}
SUMMARY_PROOF_FIELDS = {
    "proof_antecedents_enabled",
    "proof_derived_total",
    "proof_antecedent_total",
    "proof_missing_antecedent_total",
}
AGGREGATE_COUNTERS = {
    "events",
    "witness_events",
    "direct_assumption_touch_events",
    "ancestry_assumption_touch_events",
    "direct_assumption_same_literals",
    "direct_assumption_opposite_literals",
    "parent_assumption_ancestry_edges",
    "recurrent_clause_events",
    "direct_assumption_position_union",
    "ancestry_assumption_position_union",
}
AGGREGATE_MOMENTS = {
    "clause_size",
    "antecedent_count",
    "proof_depth",
    "original_parent_count",
    "derived_parent_count",
    "missing_parent_count",
    "parent_clause_size",
    "parent_depth",
}
MOMENT_FIELDS = {"count", "sum", "sum_squares", "maximum"}
PARENT_REUSE_FIELDS = {
    "references",
    "unique_parents",
    "reused_references",
    "maximum_parent_use",
    "entropy_bits",
    "normalized_entropy",
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _load_identity_wrapper() -> Any:
    name = "chacha20_fresh_clause_identity_for_antecedents"
    with _IDENTITY_LOAD_LOCK:
        if existing := sys.modules.get(name):
            if not hasattr(existing, "_load_base_wrapper"):
                raise RuntimeError("fresh clause identity wrapper is partially initialized")
            base = existing._load_base_wrapper()  # noqa: SLF001
            if not hasattr(base, "_validate_inputs"):
                raise RuntimeError("fresh multihorizon wrapper is partially initialized")
            return existing
        spec = importlib.util.spec_from_file_location(name, IDENTITY_WRAPPER_PATH)
        if spec is None or spec.loader is None:
            raise RuntimeError("fresh clause identity wrapper is unavailable")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            if sys.modules.get(name) is module:
                del sys.modules[name]
            raise
        if not hasattr(module, "_load_base_wrapper"):
            del sys.modules[name]
            raise RuntimeError("fresh clause identity wrapper initialization is incomplete")
        base = module._load_base_wrapper()  # noqa: SLF001
        if not hasattr(base, "_validate_inputs"):
            del sys.modules[name]
            raise RuntimeError("fresh multihorizon wrapper initialization is incomplete")
        return module


def _source_bundle() -> bytes:
    return b"\0".join(
        path.read_bytes() for path in (SOURCE, TRACER_HEADER, IDENTITY_SOURCE, BASE_SOURCE)
    )


def compile_helper(*, output_base: Path = BINARY) -> dict[str, Any]:
    output_base.parent.mkdir(parents=True, exist_ok=True)
    lock_path = output_base.with_name(f".{output_base.name}.compile.lock")
    temporary = output_base.with_name(f".{output_base.name}.deterministic-link")
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            temporary.unlink(missing_ok=True)
            source_hashes_started = {
                path.name: file_sha256(path)
                for path in (SOURCE, TRACER_HEADER, IDENTITY_SOURCE, BASE_SOURCE)
            }
            bundle_started = _sha256(_source_bundle())
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
                env=COMPILATION_ENVIRONMENT,
            )
            source_hashes_finished = {
                path.name: file_sha256(path)
                for path in (SOURCE, TRACER_HEADER, IDENTITY_SOURCE, BASE_SOURCE)
            }
            bundle_finished = _sha256(_source_bundle())
            binary_sha = file_sha256(temporary) if temporary.exists() else None
            observation = {
                "command": command,
                "environment": COMPILATION_ENVIRONMENT,
                "returncode": result.returncode,
                "elapsed_seconds": time.perf_counter() - started,
                "stdout_sha256": _sha256(result.stdout.encode()),
                "stderr_sha256": _sha256(result.stderr.encode()),
                "source_hashes_started": source_hashes_started,
                "source_hashes_finished": source_hashes_finished,
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
                or source_hashes_started != source_hashes_finished
                or bundle_started != bundle_finished
            ):
                raise RuntimeError(f"fresh antecedent helper build failed: {observation}")
            final = output_base.with_name(
                f"{output_base.name}-{bundle_started}-{binary_sha}"
            )
            try:
                os.link(temporary, final)
            except FileExistsError as error:
                if file_sha256(final) != binary_sha:
                    raise RuntimeError("antecedent helper content-address differs") from error
            final.chmod(0o755)
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
    prefixes = (("stage", STAGE_PREFIX), ("cell", CELL_PREFIX), ("summary", SUMMARY_PREFIX))
    rows: list[tuple[str, dict[str, Any]]] = []
    for line in stdout.splitlines():
        if not line:
            continue
        for kind, prefix in prefixes:
            if line.startswith(prefix):
                try:
                    value = json.loads(line.removeprefix(prefix))
                except json.JSONDecodeError as error:
                    raise RuntimeError(f"malformed fresh antecedent JSON: {error}") from error
                if not isinstance(value, dict):
                    raise RuntimeError("fresh antecedent event must be an object")
                rows.append((kind, value))
                break
        else:
            raise RuntimeError(f"unexpected fresh antecedent output: {line[:160]}")
    return rows


def _identity_stdout(events: Sequence[tuple[str, Mapping[str, Any]]], identity: Any) -> str:
    lines: list[str] = []
    for kind, row in events:
        excluded = (
            STAGE_PROOF_FIELDS
            if kind == "stage"
            else CELL_PROOF_FIELDS
            if kind == "cell"
            else SUMMARY_PROOF_FIELDS
        )
        clean = {key: value for key, value in row.items() if key not in excluded}
        if kind == "summary":
            clean["base_copy_method"] = "cadical_copy_irredundant_units_options"
        prefix = (
            identity.STAGE_PREFIX
            if kind == "stage"
            else identity.CELL_PREFIX
            if kind == "cell"
            else identity.SUMMARY_PREFIX
        )
        lines.append(prefix + json.dumps(clean, separators=(",", ":")))
    return "\n".join(lines) + "\n"


def _natural(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _finite_nonnegative(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0


def _validate_moment(moment: Any, events: int, *, event_indexed: bool = True) -> None:
    if not isinstance(moment, dict) or set(moment) != MOMENT_FIELDS:
        raise RuntimeError("proof moment schema differs")
    if not all(_finite_nonnegative(value) for value in moment.values()):
        raise RuntimeError("proof moment contains an invalid value")
    if event_indexed and moment["count"] != events:
        raise RuntimeError("proof moment event cover differs")
    if moment["count"] == 0 and any(moment[key] != 0 for key in ("sum", "sum_squares", "maximum")):
        raise RuntimeError("empty proof moment is nonzero")


def _validate_aggregate(aggregate: Any) -> None:
    if not isinstance(aggregate, dict) or set(aggregate) != AGGREGATE_COUNTERS | AGGREGATE_MOMENTS:
        raise RuntimeError("proof aggregate schema differs")
    if not all(_natural(aggregate[key]) for key in AGGREGATE_COUNTERS):
        raise RuntimeError("proof aggregate counter differs")
    events = aggregate["events"]
    for key in AGGREGATE_MOMENTS:
        _validate_moment(
            aggregate[key],
            events,
            event_indexed=key not in {"parent_clause_size", "parent_depth"},
        )
    if aggregate["direct_assumption_touch_events"] > events or aggregate["ancestry_assumption_touch_events"] > events:
        raise RuntimeError("proof assumption-touch count exceeds events")
    if aggregate["direct_assumption_position_union"] > 255 or aggregate["ancestry_assumption_position_union"] > 255:
        raise RuntimeError("proof assumption-position mask differs")


def _validate_parent_reuse(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != PARENT_REUSE_FIELDS:
        raise RuntimeError("proof parent-reuse schema differs")
    for key in ("references", "unique_parents", "reused_references", "maximum_parent_use"):
        if not _natural(value[key]):
            raise RuntimeError("proof parent-reuse count differs")
    for key in ("entropy_bits", "normalized_entropy"):
        if not _finite_nonnegative(value[key]):
            raise RuntimeError("proof parent-reuse entropy differs")
    if value["references"] - value["unique_parents"] != value["reused_references"]:
        raise RuntimeError("proof parent-reuse accounting differs")
    if value["normalized_entropy"] > 1.000000000001:
        raise RuntimeError("proof parent-reuse normalized entropy exceeds one")


def _validate_statistics(value: Any) -> None:
    expected = {
        "all",
        "redundant",
        "irredundant",
        "parent_reuse_all",
        "parent_reuse_redundant",
        "event_stream_fnv1a64",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise RuntimeError("proof antecedent-statistics schema differs")
    for key in ("all", "redundant", "irredundant"):
        _validate_aggregate(value[key])
    if value["all"]["events"] != value["redundant"]["events"] + value["irredundant"]["events"]:
        raise RuntimeError("proof redundant event partition differs")
    _validate_parent_reuse(value["parent_reuse_all"])
    _validate_parent_reuse(value["parent_reuse_redundant"])
    digest = value["event_stream_fnv1a64"]
    if not isinstance(digest, str) or len(digest) != 16 or any(c not in "0123456789abcdef" for c in digest):
        raise RuntimeError("proof event-stream digest differs")


def parse_clause_antecedent_output(
    *,
    stdout: str,
    returncode: int,
    mode: str,
    order: Sequence[str],
    key_one_literals_bit0_through_bit19: Sequence[int],
    conflict_horizons: Sequence[int],
    watchdog_seconds: float,
) -> dict[str, Any]:
    identity = _load_identity_wrapper()
    events = _parse_events(stdout)
    base_run = identity.parse_clause_identity_output(
        stdout=_identity_stdout(events, identity),
        returncode=returncode,
        mode=mode,
        order=order,
        key_one_literals_bit0_through_bit19=key_one_literals_bit0_through_bit19,
        conflict_horizons=conflict_horizons,
        watchdog_seconds=watchdog_seconds,
    )
    stage_rows = [row for kind, row in events if kind == "stage"]
    cell_rows = [row for kind, row in events if kind == "cell"]
    summary = events[-1][1] if events and events[-1][0] == "summary" else None
    if not isinstance(summary, dict):
        raise RuntimeError("fresh antecedent summary is missing")
    cumulative_by_cell: dict[int, int] = {}
    derived_sum = antecedent_sum = missing_sum = 0
    for row, clean in zip(stage_rows, base_run["stages"], strict=True):
        if set(row) != set(clean) | STAGE_PROOF_FIELDS:
            raise RuntimeError("fresh antecedent stage schema differs")
        stats = row["proof_antecedent_statistics"]
        _validate_statistics(stats)
        values = [row[key] for key in STAGE_PROOF_FIELDS if key not in {"proof_assumptions_stage", "proof_antecedent_statistics"}]
        if not all(_natural(value) for value in values):
            raise RuntimeError("fresh antecedent stage count differs")
        if row["proof_assumptions_stage"] != row["assumptions"]:
            raise RuntimeError("proof assumption trace differs from solve assumptions")
        if row["proof_solve_queries_stage"] != 1:
            raise RuntimeError("proof solve-query count differs")
        if row["proof_derived_count_stage"] != stats["all"]["events"]:
            raise RuntimeError("proof stage event count differs")
        if row["proof_antecedent_count_stage"] != stats["all"]["antecedent_count"]["sum"]:
            raise RuntimeError("proof antecedent accounting differs")
        if row["proof_missing_antecedent_count_stage"] != stats["all"]["missing_parent_count"]["sum"]:
            raise RuntimeError("proof missing-parent accounting differs")
        cell = row["cell_index"]
        cumulative_by_cell[cell] = cumulative_by_cell.get(cell, 0) + row["proof_derived_count_stage"]
        if row["proof_derived_count_cumulative"] != cumulative_by_cell[cell]:
            raise RuntimeError("proof cumulative event count differs")
        clean.update({key: row[key] for key in STAGE_PROOF_FIELDS})
        derived_sum += row["proof_derived_count_stage"]
        antecedent_sum += row["proof_antecedent_count_stage"]
        missing_sum += row["proof_missing_antecedent_count_stage"]
    for row, clean in zip(cell_rows, base_run["cells"], strict=True):
        if set(row) != set(clean) | CELL_PROOF_FIELDS:
            raise RuntimeError("fresh antecedent cell schema differs")
        if not all(_natural(row[key]) for key in CELL_PROOF_FIELDS):
            raise RuntimeError("fresh antecedent cell count differs")
        if row["proof_derived_total"] != cumulative_by_cell[row["cell_index"]]:
            raise RuntimeError("fresh antecedent cell event total differs")
        clean.update({key: row[key] for key in CELL_PROOF_FIELDS})
    if set(summary) != set(base_run["summary"]) | SUMMARY_PROOF_FIELDS:
        raise RuntimeError("fresh antecedent summary schema differs")
    if (
        summary["proof_antecedents_enabled"] is not True
        or summary["proof_derived_total"] != derived_sum
        or summary["proof_antecedent_total"] != antecedent_sum
        or summary["proof_missing_antecedent_total"] != missing_sum
        or missing_sum != 0
    ):
        raise RuntimeError("fresh antecedent global accounting differs")
    base_run["summary"].update({key: summary[key] for key in SUMMARY_PROOF_FIELDS})
    base_run["summary"]["proof_base_copy_method"] = summary["base_copy_method"]
    base_run.update(
        {
            "proof_antecedent_identity_complete": True,
            "proof_antecedent_mode": "CaDiCaL_3_LRAT_exact_parent_ids_streaming_statistics",
            "proof_missing_antecedent_total": 0,
        }
    )
    return base_run


def run_fresh_clause_antecedents(
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
    identity = _load_identity_wrapper()
    base = identity._load_base_wrapper()  # noqa: SLF001
    expected_order, horizons = base._validate_inputs(  # noqa: SLF001
        mode=mode,
        order=order,
        conflict_horizons=conflict_horizons,
        watchdog_seconds=watchdog_seconds,
    )
    if not helper.is_file() or not cnf.is_file():
        raise ValueError("fresh antecedent helper and CNF must be regular files")
    command = [
        str(helper),
        "--cnf",
        str(cnf),
        "--mode",
        mode,
        *base._mapping_arguments(key_one_literals_bit0_through_bit19),  # noqa: SLF001
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
        raise RuntimeError("fresh antecedent external timeout fired") from error
    elapsed = time.perf_counter() - started
    if result.stderr:
        raise RuntimeError(f"fresh antecedent stderr is nonempty: {result.stderr[:400]}")
    parsed = parse_clause_antecedent_output(
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
