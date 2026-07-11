#!/usr/bin/env python3
"""Exact Z3 processing-strategy frontier for the canonical SHAKE128 R1 Reader."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_R1 = _import_sibling(
    "shake_symbolic_r1_scaling_reader.py",
    "shake_symbolic_r1_scaling_reader_z3_strategy_base",
)

# These are the exact formulation, parser, and independent verifier used by the
# A137/A138 chain.  In particular, the retained width-16 default measurement is
# imported below; _R1._trial is deliberately not called for width 16.
_A138_TRIAL = _R1._trial
_ENCODER = _R1._SPLIT._encode_problem
_PARSER = _R1._SMT
_VERIFY = _R1._PARTITION._verify_assignment
_BASE = _R1._BASE
_NATIVE = _R1._NATIVE
_WINDOW = _R1._WINDOW

A138_SHA256 = "428e17c9d959e425f417b0c3ce15bd1e9065b8284229ce78f7dd8cb4dce0b078"
WIDTH_SEEDS = {16: 89754028, 20: 89755037}
EXPECTED_FIRST_SMT_SHA256 = {
    16: "1670f07a90669eb83482f3c63aa28f1bc4b4e246ed5976eba2f6fd813ca9d9de",
    20: "66aa82020b4dd2b4d21f3065c99ca6f7c9224ab1ab9765f686121f2fe7f8618f",
}
EXPECTED_FIRST_SMT_BYTES = {16: 9_187_068, 20: 9_189_138}
WIDTH16_TIMEOUT_SECONDS = 60
WIDTH20_TIMEOUT_SECONDS = 120
SYNTAX_WIDTH = 4
SYNTAX_SEED = 89751001
SYNTAX_TIMEOUT_SECONDS = 30


@dataclass(frozen=True)
class Strategy:
    """A predeclared SMT-LIB logic/check-sat processing route."""

    name: str
    logic: str
    check_sat: str


STRATEGIES = (
    Strategy("qf_uf_default_retained", "QF_UF", "(check-sat)"),
    Strategy("qf_fd_default", "QF_FD", "(check-sat)"),
    Strategy(
        "aig_sat",
        "QF_UF",
        "(check-sat-using (then simplify solve-eqs aig sat))",
    ),
    Strategy(
        "aig_sat_chb",
        "QF_UF",
        "(check-sat-using (then simplify solve-eqs aig "
        "(using-params sat :branching.heuristic chb)))",
    ),
    Strategy(
        "aig_sat_cutxor",
        "QF_UF",
        "(check-sat-using (then simplify solve-eqs aig "
        "(using-params sat :cut true :cut.xor true :cut.force true)))",
    ),
    Strategy(
        "propagate_aig_sat",
        "QF_UF",
        "(check-sat-using (then simplify propagate-values solve-eqs aig sat))",
    ),
)
STRATEGY_BY_NAME = {row.name: row for row in STRATEGIES}


@dataclass
class CanonicalFormula:
    """In-memory canonical formula plus the objects required for verification."""

    window_bits: int
    seed: int
    problem: dict[str, Any]
    writer: Any
    inputs: list[str]
    encoding: dict[str, Any]
    raw: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()


def _strategy(value: Strategy | str) -> Strategy:
    if isinstance(value, Strategy):
        return value
    try:
        return STRATEGY_BY_NAME[value]
    except KeyError as error:
        raise ValueError(f"unknown strategy: {value}") from error


def _replace_line(line: bytes, replacement: str) -> bytes:
    if line.endswith(b"\r\n"):
        ending = b"\r\n"
    elif line.endswith(b"\n"):
        ending = b"\n"
    else:
        ending = b""
    return replacement.encode("ascii") + ending


def _render_strategy(canonical_raw: bytes, strategy: Strategy | str) -> bytes:
    """Replace only the canonical logic and check-sat lines."""

    route = _strategy(strategy)
    lines = canonical_raw.splitlines(keepends=True)
    logic_indices = [
        index for index, line in enumerate(lines) if line.rstrip(b"\r\n").startswith(b"(set-logic ")
    ]
    check_indices = [
        index for index, line in enumerate(lines) if line.rstrip(b"\r\n") == b"(check-sat)"
    ]
    if len(logic_indices) != 1 or len(check_indices) != 1:
        raise ValueError("canonical formula must contain one logic and one plain check-sat line")
    rendered = list(lines)
    rendered[logic_indices[0]] = _replace_line(
        lines[logic_indices[0]], f"(set-logic {route.logic})"
    )
    rendered[check_indices[0]] = _replace_line(lines[check_indices[0]], route.check_sat)
    return b"".join(rendered)


def _render_audit(canonical_raw: bytes, rendered_raw: bytes) -> dict[str, Any]:
    canonical = canonical_raw.splitlines(keepends=True)
    rendered = rendered_raw.splitlines(keepends=True)
    if len(canonical) != len(rendered):
        raise RuntimeError("strategy renderer changed the SMT-LIB line count")
    replaceable = [
        index
        for index, line in enumerate(canonical)
        if line.rstrip(b"\r\n").startswith(b"(set-logic ") or line.rstrip(b"\r\n") == b"(check-sat)"
    ]
    changed = [
        index
        for index, pair in enumerate(zip(canonical, rendered, strict=True))
        if pair[0] != pair[1]
    ]
    if any(index not in replaceable for index in changed):
        raise RuntimeError("strategy renderer changed a non-logic/non-check-sat line")
    preserved_canonical = b"".join(
        line for index, line in enumerate(canonical) if index not in replaceable
    )
    preserved_rendered = b"".join(
        line for index, line in enumerate(rendered) if index not in replaceable
    )
    if preserved_canonical != preserved_rendered:
        raise RuntimeError("strategy renderer failed the preserved-body byte gate")
    canonical_get_values = [line for line in canonical if line.lstrip().startswith(b"(get-value ")]
    rendered_get_values = [line for line in rendered if line.lstrip().startswith(b"(get-value ")]
    return {
        "line_count": len(canonical),
        "replaceable_line_indices_zero_based": replaceable,
        "changed_line_indices_zero_based": changed,
        "preserved_body_bytes": len(preserved_canonical),
        "preserved_body_sha256": hashlib.sha256(preserved_canonical).hexdigest(),
        "declaration_count": sum(line.lstrip().startswith(b"(declare-fun ") for line in canonical),
        "assertion_count": sum(line.lstrip().startswith(b"(assert ") for line in canonical),
        "get_value_count": len(canonical_get_values),
        "get_value_preserved_byte_exact": canonical_get_values == rendered_get_values,
    }


def _load_a138(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    observed = hashlib.sha256(raw).hexdigest()
    if observed != A138_SHA256:
        raise RuntimeError(f"A138 retained artifact hash differs for {path}: {observed}")
    payload = json.loads(raw)
    if payload.get("schema") != "shake-symbolic-r1-scaling-reader-v1":
        raise RuntimeError("A138 schema does not identify the retained R1 scaling run")
    for width, seed in WIDTH_SEEDS.items():
        matches = [row for row in payload.get("trials", []) if row.get("window_bits") == width]
        if len(matches) != 1 or matches[0].get("seed") != seed:
            raise RuntimeError(f"A138 width-{width} seed/trial gate failed")
        first_hash = matches[0].get("encoding", {}).get("first_smt_sha256")
        first_bytes = matches[0].get("encoding", {}).get("first_smt_bytes")
        if first_hash != EXPECTED_FIRST_SMT_SHA256[width]:
            raise RuntimeError(f"A138 width-{width} first-SMT hash gate failed")
        if first_bytes != EXPECTED_FIRST_SMT_BYTES[width]:
            raise RuntimeError(f"A138 width-{width} first-SMT byte gate failed")
    return payload


def _a138_trial(payload: dict[str, Any], width: int) -> dict[str, Any]:
    matches = [row for row in payload["trials"] if row["window_bits"] == width]
    if len(matches) != 1:
        raise RuntimeError(f"A138 must contain exactly one width-{width} trial")
    return matches[0]


def _canonical_formula(
    variant: Any,
    window_bits: int,
    seed: int,
    expected_first_smt_sha256: str | None = None,
) -> CanonicalFormula:
    problem = _NATIVE._problem(variant, window_bits, seed)
    writer, inputs, encoding = _ENCODER(problem, variant, seed, prefix_rounds=1)
    raw = writer.render(inputs, include_model=True)
    observed = hashlib.sha256(raw).hexdigest()
    if expected_first_smt_sha256 is not None and observed != expected_first_smt_sha256:
        raise RuntimeError(
            f"regenerated width-{window_bits} R1 formula differs from A138: {observed}"
        )
    return CanonicalFormula(
        window_bits=window_bits,
        seed=seed,
        problem=problem,
        writer=writer,
        inputs=inputs,
        encoding=encoding,
        raw=raw,
    )


def _formula_summary(formula: CanonicalFormula, retained: dict[str, Any]) -> dict[str, Any]:
    retained_hash = retained["encoding"]["first_smt_sha256"]
    return {
        "variant": "SHAKE128",
        "window_bits": formula.window_bits,
        "seed": formula.seed,
        "canonical_smt_bytes": len(formula.raw),
        "canonical_smt_sha256": formula.sha256,
        "retained_a138_first_smt_bytes": retained["encoding"]["first_smt_bytes"],
        "retained_a138_first_smt_sha256": retained_hash,
        "expected_first_smt_bytes": EXPECTED_FIRST_SMT_BYTES[formula.window_bits],
        "expected_first_smt_sha256": EXPECTED_FIRST_SMT_SHA256[formula.window_bits],
        "matches_retained_a138_first_smt": formula.sha256 == retained_hash,
        "matches_expected_first_smt": (
            len(formula.raw) == EXPECTED_FIRST_SMT_BYTES[formula.window_bits]
            and formula.sha256 == EXPECTED_FIRST_SMT_SHA256[formula.window_bits]
        ),
        "symbolic_prefix_rounds": formula.encoding["symbolic_prefix_rounds"],
        "total_variables": formula.encoding["total_variables"],
        "total_assertions": formula.encoding["total_assertions"],
        "output_assertions": formula.encoding["output_assertions"],
    }


_STAT_PATTERN = re.compile(
    r":(?P<key>[A-Za-z0-9_.-]+)\s+"
    r"(?P<value>-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)"
)


def _parse_all_stats(output: str) -> dict[str, float]:
    # Seed with the canonical A137 parser, then retain every numeric statistic
    # emitted by this local Z3 build (including sat-* tactic statistics).
    stats = dict(_PARSER._parse_stats(output))
    for match in _STAT_PATTERN.finditer(output):
        stats[match.group("key")] = float(match.group("value"))
    return dict(sorted(stats.items()))


def _selection_metric(stats: dict[str, float], metric: str) -> float | None:
    for key in (metric, f"sat-{metric}", f"sat.{metric}"):
        if key in stats:
            return float(stats[key])
    return None


def _decode_timeout_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def _run_z3(z3: Path, path: Path, timeout_seconds: int, inputs: list[str]) -> dict[str, Any]:
    command = [str(z3), "-smt2", "-st", f"-T:{timeout_seconds}", str(path)]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds + 15,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        return_code = completed.returncode
        external_timeout = False
    except subprocess.TimeoutExpired as error:
        stdout = _decode_timeout_output(error.stdout)
        stderr = _decode_timeout_output(error.stderr)
        return_code = None
        external_timeout = True
    output = stdout + stderr
    status = "unknown" if external_timeout else _PARSER._parse_status(output)
    assignment = _PARSER._parse_assignment(output, inputs) if status == "sat" else None
    stats = _parse_all_stats(output)
    diagnostics = [
        line.strip()
        for line in output.splitlines()
        if "error" in line.lower() or "unsupported" in line.lower()
    ]
    return {
        "status": status,
        "assignment": assignment,
        "stats": stats,
        "selection_metrics": {
            "decisions": _selection_metric(stats, "decisions"),
            "conflicts": _selection_metric(stats, "conflicts"),
        },
        "return_code": return_code,
        "external_timeout": external_timeout,
        "command": command,
        "timeout_seconds": timeout_seconds,
        "threads": 1,
        "stdout_bytes": len(stdout.encode()),
        "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
        "stderr_bytes": len(stderr.encode()),
        "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
        "combined_output_sha256": hashlib.sha256(output.encode()).hexdigest(),
        "diagnostics": diagnostics,
    }


def _verify_assignment(problem: dict[str, Any], variant: Any, assignment: int) -> dict[str, Any]:
    return _VERIFY(problem, variant, assignment)


def _execute_strategy(
    formula: CanonicalFormula,
    variant: Any,
    strategy: Strategy | str,
    timeout_seconds: int,
    z3: Path,
    work_dir: Path,
    keep_smt: bool,
    *,
    phase: str,
) -> dict[str, Any]:
    route = _strategy(strategy)
    rendered = _render_strategy(formula.raw, route)
    audit = _render_audit(formula.raw, rendered)
    path = work_dir / f"shake128_r1_w{formula.window_bits}_{phase}_{route.name}.smt2"
    path.write_bytes(rendered)
    try:
        solver = _run_z3(z3, path, timeout_seconds, formula.inputs)
    finally:
        if not keep_smt:
            path.unlink(missing_ok=True)
    assignment = solver["assignment"]
    verification = (
        _verify_assignment(formula.problem, variant, assignment) if assignment is not None else None
    )
    actual = _WINDOW._extract_window(
        formula.problem["base_state"], variant, formula.problem["positions"]
    )
    return {
        "strategy": route.name,
        "portfolio_index": next(index for index, row in enumerate(STRATEGIES) if row == route),
        "source": "new_equal_limit_measurement",
        "executed_in_this_run": True,
        "logic": route.logic,
        "check_sat_form": route.check_sat,
        "timeout_seconds": timeout_seconds,
        "threads": 1,
        "seed": formula.seed,
        "canonical_smt_sha256": formula.sha256,
        "rendered_smt_bytes": len(rendered),
        "rendered_smt_sha256": hashlib.sha256(rendered).hexdigest(),
        "render_audit": audit,
        "status": solver["status"],
        "return_code": solver["return_code"],
        "external_timeout": solver["external_timeout"],
        "stats": solver["stats"],
        "selection_metrics": solver["selection_metrics"],
        "assignment": assignment,
        "model_parsed": assignment is not None,
        "independent_verification": verification,
        "complete_rate_gate": bool(verification and verification["complete_rate_match"]),
        "matches_instrumented_assignment_posthoc": (
            assignment == actual if assignment is not None else None
        ),
        "ground_truth_used_for_strategy_selection": False,
        "solver_invocation": {
            "command": solver["command"],
            "stdout_bytes": solver["stdout_bytes"],
            "stdout_sha256": solver["stdout_sha256"],
            "stderr_bytes": solver["stderr_bytes"],
            "stderr_sha256": solver["stderr_sha256"],
            "combined_output_sha256": solver["combined_output_sha256"],
            "diagnostics": solver["diagnostics"],
        },
    }


def _retained_anchor(
    formula: CanonicalFormula,
    retained: dict[str, Any],
) -> dict[str, Any]:
    route = STRATEGIES[0]
    rendered = _render_strategy(formula.raw, route)
    if rendered != formula.raw:
        raise RuntimeError("retained default renderer does not reproduce the canonical formula")
    expected = {
        "status": "sat",
        "assignment": 35837,
        "decisions": 4701.0,
        "complete_rate_match": True,
    }
    if retained["first_solver"]["status"] != expected["status"]:
        raise RuntimeError("A138 width-16 anchor status gate failed")
    if retained["reconstructed_assignment"] != expected["assignment"]:
        raise RuntimeError("A138 width-16 anchor assignment gate failed")
    if retained["first_solver"]["stats"].get("decisions") != expected["decisions"]:
        raise RuntimeError("A138 width-16 anchor decision gate failed")
    verification = retained.get("independent_verification")
    if not verification or verification.get("complete_rate_match") is not True:
        raise RuntimeError("A138 width-16 anchor complete-rate gate failed")
    if len(rendered) != retained["encoding"]["first_smt_bytes"]:
        raise RuntimeError("A138 width-16 anchor formula byte gate failed")
    stats = dict(retained["first_solver"]["stats"])
    return {
        "strategy": route.name,
        "portfolio_index": 0,
        "source": "A138_hash_gated_retained_measurement",
        "executed_in_this_run": False,
        "logic": route.logic,
        "check_sat_form": route.check_sat,
        "timeout_seconds": retained["first_solver"]["command_parameters"]["timeout_seconds"],
        "frontier_new_strategy_timeout_seconds": WIDTH16_TIMEOUT_SECONDS,
        "threads": retained["first_solver"]["command_parameters"]["threads"],
        "seed": formula.seed,
        "canonical_smt_sha256": formula.sha256,
        "rendered_smt_bytes": len(rendered),
        "rendered_smt_sha256": hashlib.sha256(rendered).hexdigest(),
        "render_audit": _render_audit(formula.raw, rendered),
        "status": retained["first_solver"]["status"],
        "return_code": retained["first_solver"]["return_code"],
        "external_timeout": retained["first_solver"]["external_timeout"],
        "stats": stats,
        "selection_metrics": {
            "decisions": _selection_metric(stats, "decisions"),
            "conflicts": _selection_metric(stats, "conflicts"),
        },
        "assignment": retained["reconstructed_assignment"],
        "model_parsed": True,
        "independent_verification": verification,
        "complete_rate_gate": True,
        "matches_instrumented_assignment_posthoc": retained["matches_instrumented_assignment"],
        "ground_truth_used_for_strategy_selection": False,
        "solver_invocation": {
            "command": None,
            "stdout_bytes": None,
            "stdout_sha256": None,
            "stderr_bytes": None,
            "stderr_sha256": None,
            "combined_output_sha256": None,
            "diagnostics": [],
            "not_reexecuted_reason": (
                "The task requires the hash-gated A138 default width-16 measurement "
                "to be imported rather than recomputed."
            ),
        },
    }


def _eligible_strategy(row: dict[str, Any]) -> bool:
    verification = row.get("independent_verification")
    return bool(
        row.get("status") == "sat"
        and row.get("assignment") is not None
        and verification
        and verification.get("complete_rate_match") is True
    )


def _select_strategy(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Select using only verified SAT status, solver work, and declared order."""

    eligible = sorted(
        (row for row in rows if _eligible_strategy(row)),
        key=lambda row: row["portfolio_index"],
    )
    if not eligible:
        raise RuntimeError("no independently verified SAT strategy is eligible")

    decision_rows = [
        row for row in eligible if row["selection_metrics"].get("decisions") is not None
    ]
    conflict_rows = [
        row for row in eligible if row["selection_metrics"].get("conflicts") is not None
    ]
    if decision_rows:
        metric = "decisions"
        candidates = decision_rows
        reason = "minimum_decisions_among_verified_sat_results_with_decision_statistics"
    elif conflict_rows:
        metric = "conflicts"
        candidates = conflict_rows
        reason = "decision_statistics_absent_use_minimum_conflicts"
    else:
        metric = "portfolio_index"
        candidates = eligible
        reason = "decision_and_conflict_statistics_absent_use_portfolio_order"

    if metric == "portfolio_index":
        selected = min(candidates, key=lambda row: row["portfolio_index"])
        value: float | int = selected["portfolio_index"]
    else:
        selected = min(
            candidates,
            key=lambda row: (row["selection_metrics"][metric], row["portfolio_index"]),
        )
        value = selected["selection_metrics"][metric]
    return {
        "selected_strategy": selected["strategy"],
        "selection_metric": metric,
        "selection_metric_value": value,
        "selection_reason": reason,
        "eligible_strategies": [row["strategy"] for row in eligible],
        "metric_candidate_strategies": [row["strategy"] for row in candidates],
        "tie_break": "predeclared_portfolio_order",
        "wallclock_used": False,
        "instrumented_assignment_used": False,
        "selection_inputs": [
            "solver_status_sat",
            "independent_complete_1344_bit_rate_gate",
            metric,
            "predeclared_portfolio_order",
        ],
    }


def _z3_parameter_audit(z3: Path) -> dict[str, Any]:
    completed = subprocess.run([str(z3), "-p"], check=True, capture_output=True, text=True)
    raw = completed.stdout.encode()
    required = ("branching.heuristic", "cut", "cut.xor", "cut.force")
    entries = {}
    for name in required:
        matches = [
            line.strip()
            for line in completed.stdout.splitlines()
            if re.match(rf"^\s*{re.escape(name)}\s+\(", line)
        ]
        if len(matches) != 1:
            raise RuntimeError(f"local Z3 parameter audit failed for {name}")
        entries[name] = matches[0]
    return {
        "command": [str(z3), "-p"],
        "return_code": completed.returncode,
        "stdout_bytes": len(raw),
        "stdout_sha256": hashlib.sha256(raw).hexdigest(),
        "required_parameter_entries": entries,
        "all_required_parameters_present": True,
        "silently_dropped_parameters": [],
    }


def _syntax_validation(
    variant: Any,
    z3: Path,
    work_dir: Path,
    keep_smt: bool,
    timeout_seconds: int = SYNTAX_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    formula = _canonical_formula(variant, SYNTAX_WIDTH, SYNTAX_SEED)
    results = []
    for route in STRATEGIES:
        row = _execute_strategy(
            formula,
            variant,
            route,
            timeout_seconds,
            z3,
            work_dir,
            keep_smt,
            phase="syntax",
        )
        if (
            row["status"] != "sat"
            or row["return_code"] != 0
            or row["solver_invocation"]["diagnostics"]
            or not row["complete_rate_gate"]
            or row["matches_instrumented_assignment_posthoc"] is not True
        ):
            raise RuntimeError(f"width-4 syntax/correctness validation failed for {route.name}")
        results.append(row)
    return {
        "window_bits": SYNTAX_WIDTH,
        "seed": SYNTAX_SEED,
        "timeout_seconds_per_strategy": timeout_seconds,
        "canonical_smt_bytes": len(formula.raw),
        "canonical_smt_sha256": formula.sha256,
        "all_six_syntactically_executable_and_correct": True,
        "used_for_width16_strategy_selection": False,
        "results": results,
    }


def _width20_transfer(
    formula: CanonicalFormula,
    variant: Any,
    selected_strategy: str,
    z3: Path,
    work_dir: Path,
    keep_smt: bool,
) -> dict[str, Any]:
    route = _strategy(selected_strategy)
    first = _execute_strategy(
        formula,
        variant,
        route,
        WIDTH20_TIMEOUT_SECONDS,
        z3,
        work_dir,
        keep_smt,
        phase="transfer_first",
    )
    second = None
    if first["status"] == "sat":
        assignment = first["assignment"]
        if assignment is None:
            raise RuntimeError("width-20 SAT response did not contain the requested model")
        blocked_canonical = formula.writer.render(
            formula.inputs,
            blocked_assignment=assignment,
            include_model=False,
        )
        blocked_rendered = _render_strategy(blocked_canonical, route)
        path = work_dir / f"shake128_r1_w20_transfer_blocked_{route.name}.smt2"
        path.write_bytes(blocked_rendered)
        try:
            solver = _run_z3(z3, path, WIDTH20_TIMEOUT_SECONDS, formula.inputs)
        finally:
            if not keep_smt:
                path.unlink(missing_ok=True)
        second = {
            "strategy": route.name,
            "logic": route.logic,
            "check_sat_form": route.check_sat,
            "timeout_seconds": WIDTH20_TIMEOUT_SECONDS,
            "threads": 1,
            "blocked_assignment": assignment,
            "get_value_requested": False,
            "canonical_blocked_smt_bytes": len(blocked_canonical),
            "canonical_blocked_smt_sha256": hashlib.sha256(blocked_canonical).hexdigest(),
            "rendered_smt_bytes": len(blocked_rendered),
            "rendered_smt_sha256": hashlib.sha256(blocked_rendered).hexdigest(),
            "render_audit": _render_audit(blocked_canonical, blocked_rendered),
            "status": solver["status"],
            "return_code": solver["return_code"],
            "external_timeout": solver["external_timeout"],
            "stats": solver["stats"],
            "selection_metrics": solver["selection_metrics"],
            "solver_invocation": {
                "command": solver["command"],
                "stdout_bytes": solver["stdout_bytes"],
                "stdout_sha256": solver["stdout_sha256"],
                "stderr_bytes": solver["stderr_bytes"],
                "stderr_sha256": solver["stderr_sha256"],
                "combined_output_sha256": solver["combined_output_sha256"],
                "diagnostics": solver["diagnostics"],
            },
        }
    return {
        "selected_strategy": route.name,
        "same_strategy_as_width16_winner": first["strategy"] == selected_strategy,
        "timeout_seconds_per_query": WIDTH20_TIMEOUT_SECONDS,
        "first_query": first,
        "first_sat_independent_complete_rate_gate": (
            first["complete_rate_gate"] if first["status"] == "sat" else None
        ),
        "blocked_second_query_required": first["status"] == "sat",
        "blocked_second_query": second,
        "unique_assignment_proved": second["status"] == "unsat" if second else None,
    }


def _build_graph(
    path: Path,
    width16_sha256: str,
    width20_sha256: str,
    selected_strategy: str,
    selection_metric: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r1_z3_strategy_frontier",
        parameters={
            "variant": "shake128",
            "symbolic_prefix_rounds": 1,
            "width16_seed": WIDTH_SEEDS[16],
            "width20_seed": WIDTH_SEEDS[20],
            "width16_smt_sha256": width16_sha256,
            "width20_smt_sha256": width20_sha256,
            "portfolio": [row.name for row in STRATEGIES],
            "selected_strategy": selected_strategy,
            "selection_metric": selection_metric,
        },
    )
    formula_id = "r1-hash-gated-identical-formulas"
    portfolio_id = "r1-predeclared-z3-strategy-portfolio"
    transfer_id = "r1-selected-strategy-width20-followup"
    builder.add_triplet(
        edge_id=formula_id,
        trigger="A138:hash_gated_R1_width16_and_width20_trials",
        mechanism="regenerate_exact_A137_R1_SMT_and_match_stored_first_smt_sha256",
        outcome="SHAKE128:identical_unpartitioned_R1_formulas",
        confidence=1.0,
        evidence_kind="A138_file_hash_plus_two_first_SMT_hash_gates",
        source="A137_encoder_and_A138_retained_artifact",
        attrs={
            "reader_recipe": {
                "a138_sha256": A138_SHA256,
                "width_seeds": {"16": WIDTH_SEEDS[16], "20": WIDTH_SEEDS[20]},
                "formula_sha256": {"16": width16_sha256, "20": width20_sha256},
                "formulation_module": "shake_symbolic_r1_scaling_reader.py",
            }
        },
    )
    builder.add_triplet(
        edge_id=portfolio_id,
        trigger="SHAKE128:identical_unpartitioned_R1_formulas",
        mechanism="execute_predeclared_equal_seed_single_thread_Z3_processing_portfolio",
        outcome="SHAKE128:width16_strategy_frontier_observations",
        confidence=1.0,
        evidence_kind="exact_models_plus_complete_1344_bit_checks_and_solver_statistics",
        source="Z3_strategy_measurements_with_A138_default_anchor",
        provenance=[formula_id],
        attrs={
            "reader_recipe": {
                "portfolio_order": [row.name for row in STRATEGIES],
                "new_strategy_timeout_seconds": WIDTH16_TIMEOUT_SECONDS,
                "solver_threads": 1,
                "selection_metric": selection_metric,
                "wallclock_selector": None,
                "instrumented_assignment_selector": None,
            }
        },
    )
    builder.add_triplet(
        edge_id=transfer_id,
        trigger="SHAKE128:width16_strategy_frontier_observations",
        mechanism="select_deterministically_then_transfer_exact_processing_path_to_width20",
        outcome="SHAKE128:deterministic_width20_followup_observation",
        confidence=1.0,
        evidence_kind="120_second_status_and_conditional_model_and_blocked_query_checks",
        source="selected_Z3_path_plus_independent_bit_sliced_core",
        provenance=[portfolio_id],
        attrs={
            "reader_recipe": {
                "selected_strategy": selected_strategy,
                "timeout_seconds_per_query": WIDTH20_TIMEOUT_SECONDS,
                "first_sat_requires_complete_rate_check": True,
                "first_sat_requires_blocked_second_query": True,
            }
        },
    )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    chain_ok = (
        len(rows) == 3
        and set(by_id) == {formula_id, portfolio_id, transfer_id}
        and by_id[portfolio_id]["provenance"] == [formula_id]
        and by_id[transfer_id]["provenance"] == [portfolio_id]
        and by_id[portfolio_id]["trigger"] == by_id[formula_id]["outcome"]
        and by_id[transfer_id]["trigger"] == by_id[portfolio_id]["outcome"]
    )
    gate = {
        "reader_verify_provenance": reader.verify_provenance(),
        "explicit_triplet_count": len(rows),
        "exact_three_edge_chain": chain_ok,
        "reader_file_sha256": reader.file_sha256,
        "reader_graph_sha256": reader.graph_sha256,
        "passed": reader.verify_provenance() and chain_ok,
    }
    if not gate["passed"]:
        raise RuntimeError("Z3 strategy frontier causal Reader gate failed")
    return stats, rows, gate


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--z3", type=Path, default=Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    )
    parser.add_argument(
        "--a138",
        type=Path,
        default=Path("research/results/v1/shake_symbolic_r1_scaling_reader_v1.json"),
    )
    parser.add_argument(
        "--work-dir", type=Path, default=Path("build/shake-symbolic-r1-z3-strategies")
    )
    parser.add_argument("--keep-smt", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("research/results/v1/shake_symbolic_r1_z3_strategy_frontier_v1.json"),
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=Path("research/results/v1/shake_symbolic_r1_z3_strategy_frontier_v1.causal"),
    )
    args = parser.parse_args()

    z3 = Path(shutil.which(str(args.z3)) or args.z3)
    if not z3.is_file():
        raise FileNotFoundError(f"Z3 executable not found: {args.z3}")
    version = subprocess.run(
        [str(z3), "-version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    args.work_dir.mkdir(parents=True, exist_ok=True)
    args.causal_output.parent.mkdir(parents=True, exist_ok=True)

    a138 = _load_a138(args.a138)
    variant = _BASE.VARIANTS["shake128"]
    parameter_audit = _z3_parameter_audit(z3)
    print("validating all six strategies on canonical width 4", flush=True)
    syntax = _syntax_validation(variant, z3, args.work_dir, args.keep_smt)

    retained16 = _a138_trial(a138, 16)
    retained20 = _a138_trial(a138, 20)
    formula16 = _canonical_formula(
        variant,
        16,
        WIDTH_SEEDS[16],
        retained16["encoding"]["first_smt_sha256"],
    )
    formula20 = _canonical_formula(
        variant,
        20,
        WIDTH_SEEDS[20],
        retained20["encoding"]["first_smt_sha256"],
    )

    width16_results = [_retained_anchor(formula16, retained16)]
    for route in STRATEGIES[1:]:
        print(f"width16 strategy={route.name} timeout=60s", flush=True)
        width16_results.append(
            _execute_strategy(
                formula16,
                variant,
                route,
                WIDTH16_TIMEOUT_SECONDS,
                z3,
                args.work_dir,
                args.keep_smt,
                phase="frontier",
            )
        )
    selection = _select_strategy(width16_results)
    print(
        f"selected {selection['selected_strategy']} by {selection['selection_metric']}",
        flush=True,
    )
    transfer = _width20_transfer(
        formula20,
        variant,
        selection["selected_strategy"],
        z3,
        args.work_dir,
        args.keep_smt,
    )

    causal, reader_triplets, reader_gate = _build_graph(
        args.causal_output,
        formula16.sha256,
        formula20.sha256,
        selection["selected_strategy"],
        selection["selection_metric"],
    )
    payload = {
        "schema": "shake-symbolic-r1-z3-strategy-frontier-v1",
        "evidence_stage": "EXACT_HASH_GATED_Z3_PROCESSING_STRATEGY_FRONTIER",
        "result": (
            "A predeclared six-route Z3 processing frontier was measured on the exact "
            "A138 width-16 R1 formula; the deterministic independently verified winner "
            "was transferred unchanged to the exact A138 width-20 formula."
        ),
        "scope": (
            "Unpartitioned canonical SHAKE128 known-complement R1 state-window Reader; "
            "strategy selection excludes wallclock and the instrumented assignment."
        ),
        "parameters": {
            "solver": version,
            "solver_threads": 1,
            "width16_new_strategy_timeout_seconds": WIDTH16_TIMEOUT_SECONDS,
            "width20_timeout_seconds_per_query": WIDTH20_TIMEOUT_SECONDS,
            "syntax_validation_width": SYNTAX_WIDTH,
            "syntax_validation_seed": SYNTAX_SEED,
            "syntax_validation_timeout_seconds": SYNTAX_TIMEOUT_SECONDS,
            "width_seeds": {"16": WIDTH_SEEDS[16], "20": WIDTH_SEEDS[20]},
            "symbolic_prefix_rounds": 1,
            "a138_sha256": A138_SHA256,
            "retained_default_width16_reexecuted": False,
            "portfolio_declared_before_measurement": True,
            "actual_assignment_used_for_strategy_selection": False,
            "wallclock_used_for_strategy_selection": False,
        },
        "strategy_portfolio": [
            {
                "portfolio_index": index,
                "strategy": route.name,
                "logic": route.logic,
                "check_sat_form": route.check_sat,
            }
            for index, route in enumerate(STRATEGIES)
        ],
        "z3_parameter_audit": parameter_audit,
        "syntax_validation": syntax,
        "formula_gates": {
            "width16": _formula_summary(formula16, retained16),
            "width20": _formula_summary(formula20, retained20),
            "both_match_a138": all(
                formula.sha256 == retained["encoding"]["first_smt_sha256"]
                and formula.sha256 == EXPECTED_FIRST_SMT_SHA256[formula.window_bits]
                and len(formula.raw) == EXPECTED_FIRST_SMT_BYTES[formula.window_bits]
                for formula, retained in ((formula16, retained16), (formula20, retained20))
            ),
        },
        "width16_strategy_results": width16_results,
        "selection": selection,
        "width20_transfer": transfer,
        "kat": _BASE._kat(),
        "causal": causal,
        "reader_triplets": reader_triplets,
        "reader_gate": reader_gate,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "json_sha256": hashlib.sha256(raw).hexdigest(),
                "causal_output": str(args.causal_output),
                "causal_sha256": causal["file_sha256"],
                "graph_sha256": causal["graph_sha256"],
                "selected_strategy": selection["selected_strategy"],
                "selection_metric": selection["selection_metric"],
                "selection_metric_value": selection["selection_metric_value"],
                "width20_first_status": transfer["first_query"]["status"],
                "width20_complete_rate_gate": transfer["first_sat_independent_complete_rate_gate"],
                "width20_second_status": (
                    transfer["blocked_second_query"]["status"]
                    if transfer["blocked_second_query"]
                    else None
                ),
                "reader_gate": reader_gate,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
