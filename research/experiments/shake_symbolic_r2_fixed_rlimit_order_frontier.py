#!/usr/bin/env python3
"""Replay the exact A158 weighted-order formulas at one fixed Z3 rlimit."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
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


_A158 = _import_sibling(
    "shake_symbolic_r2_weighted_input_order_frontier.py",
    "shake_symbolic_r2_fixed_rlimit_a158_base",
)
_A156 = _A158._A156

ATTEMPT_ID = "A159"
SCHEMA = "shake-symbolic-r2-fixed-rlimit-order-frontier-v1"
SEED = _A158.SEED
WINDOW_BITS = _A158.WINDOW_BITS
A158_FILENAME = _A158.RESULT_FILENAME
A158_SHA256 = "f8852a160b11094a5d5b3a2a4c193575a849f15c4e6f489527df391566ff9382"
Z3_RLIMIT = 500_000_000
EXTERNAL_SAFETY_TIMEOUT_SECONDS = 300
RESULT_FILENAME = "shake_symbolic_r2_fixed_rlimit_order_frontier_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r2_fixed_rlimit_order_frontier_v1.causal"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    )


def _load_a158_gate(results_dir: Path) -> dict[str, Any]:
    payload = _A156._load_json_gate(results_dir / A158_FILENAME, A158_SHA256, _A158.SCHEMA)
    if (
        payload.get("status_counts") != {"error": 0, "sat": 0, "unknown": 4, "unsat": 0}
        or payload.get("formula_plan_sha256")
        != "aca15c4f43d960814f86a58d459f9f1a38714dab8152483eeb68f4c58eb08911"
        or payload.get("orders_sha256")
        != "f92fbe97375e284626ed4632bdd7b064b2f04531b8a87fbb59375bd33823208e"
    ):
        raise RuntimeError("A158 fixed-resource replay gate failed")
    return payload


def _parse_stats(output: str) -> dict[str, int | float]:
    stats: dict[str, int | float] = {}
    for key in (
        "rlimit-count",
        "decisions",
        "conflicts",
        "propagations",
        "binary-propagations",
        "restarts",
    ):
        match = re.search(rf":{re.escape(key)}\s+([0-9.]+)", output)
        if match:
            raw = match.group(1)
            stats[key] = float(raw) if "." in raw else int(raw)
    return stats


def _run_z3_rlimit(z3: Path, path: Path, inputs: list[str]) -> dict[str, Any]:
    command = [str(z3), "-smt2", "-st", f"rlimit={Z3_RLIMIT}", str(path)]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=EXTERNAL_SAFETY_TIMEOUT_SECONDS,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        return_code = completed.returncode
        external_timeout = False
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return_code = None
        external_timeout = True
    if external_timeout:
        raise RuntimeError("external safety timeout fired before the fixed Z3 rlimit completed")
    combined = stdout + stderr
    status = _A156._SMT._parse_status(combined)
    assignment = _A156._SMT._parse_assignment(combined, inputs) if status == "sat" else None
    stats = _parse_stats(combined)
    if status == "unknown" and stats.get("rlimit-count", 0) < Z3_RLIMIT:
        raise RuntimeError("Z3 returned unknown before the declared rlimit")
    canonical_observation = {
        "status": status,
        "solver_basis_assignment": assignment,
        "stats": stats,
        "return_code": return_code,
    }
    return {
        **canonical_observation,
        "external_timeout": external_timeout,
        "termination": (
            "fixed_rlimit_exhausted" if status == "unknown" else "solved_before_fixed_rlimit"
        ),
        "canonical_observation_sha256": _canonical_sha256(canonical_observation),
        "volatile_wallclock_and_memory_statistics_retained": False,
        "command_parameters": {
            "rlimit": Z3_RLIMIT,
            "threads": 1,
            "representation": "Boolean_SMT_native_nary_XOR_shared_R2_fixed_rlimit",
            "wallclock_solver_limit_used": False,
            "external_safety_timeout_seconds": EXTERNAL_SAFETY_TIMEOUT_SECONDS,
        },
    }


def _execute_fixed_frontier(
    *,
    formula_rows: Sequence[dict[str, Any]],
    formulas: dict[str, bytes],
    problem: dict[str, Any],
    variant: Any,
    z3: Path,
    work_dir: Path,
) -> list[dict[str, Any]]:
    work_dir.mkdir(parents=True, exist_ok=True)
    if any(work_dir.iterdir()):
        raise ValueError("fixed-rlimit work directory must be empty")
    results = []
    try:
        for row in formula_rows:
            raw = formulas[row["name"]]
            if len(raw) != row["formula_bytes"] or _sha256(raw) != row["formula_sha256"]:
                raise RuntimeError(f"{row['name']} formula differs before fixed-rlimit replay")
            path = work_dir / f"{row['execution_order']:02d}_{row['name']}.smt2"
            path.write_bytes(raw)
            if path.read_bytes() != raw:
                raise RuntimeError(f"{row['name']} formula write/reopen gate failed")
            result = _run_z3_rlimit(z3, path, row["solver_input_names"])
            path.unlink(missing_ok=True)
            status = result["status"]
            return_code = result["return_code"]
            expected_resource_stop = (
                status == "unknown"
                and return_code in (0, 1)
                and result["stats"].get("rlimit-count", 0) >= Z3_RLIMIT
                and result["termination"] == "fixed_rlimit_exhausted"
            )
            solved = status in ("sat", "unsat") and return_code == 0
            if not (expected_resource_stop or solved):
                raise RuntimeError(f"{row['name']} fixed-rlimit execution failed: {result}")
            results.append(_A156._verify_solver_row(dict(row), result, problem, variant))
    finally:
        for path in work_dir.glob("*.smt2"):
            path.unlink(missing_ok=True)
    if any(work_dir.iterdir()):
        raise RuntimeError("fixed-rlimit formula cleanup failed")
    return results


def _fixed_formula_plan(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "name": row["name"],
            "execution_order": row["execution_order"],
            "formula_bytes": row["formula_bytes"],
            "formula_sha256": row["formula_sha256"],
            "rlimit": Z3_RLIMIT,
            "wallclock_solver_limit_used": False,
        }
        for row in analysis["rows"]
    ]


def _execution_summary(executions: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": row["name"],
            "status": row["solver"]["status"],
            "return_code": row["solver"]["return_code"],
            "termination": row["solver"]["termination"],
            "canonical_observation_sha256": row["solver"]["canonical_observation_sha256"],
            "stats": row["solver"]["stats"],
            "independently_confirmed_model": row["independently_confirmed_model"],
        }
        for row in executions
    ]


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r2_fixed_rlimit_order_frontier",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "rlimit_per_formula": Z3_RLIMIT,
            "formula_count": len(_A158.ORDER_NAMES),
        },
    )
    ids = [
        "shake128-a158-time-bounded-order-separation",
        "shake128-a159-fixed-resource-formula-plan",
        "shake128-a159-fixed-resource-execution",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A158:weighted_input_order_solver_frontier_observation",
        mechanism="hash_gate_all_four_retained_formula_bytes_and_time_bounded_unknown_outcomes",
        outcome="A159:fixed_resource_replay_requirement",
        confidence=1.0,
        evidence_kind="retained_formula_and_solver_artifact_hashes",
        source=A158_SHA256,
        attrs={"A158_gate": payload["anchor_gate"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A159:fixed_resource_replay_requirement",
        mechanism="assign_one_identical_Z3_rlimit_without_a_solver_wallclock_limit_to_each_formula",
        outcome="A159:four_byte_exact_fixed_resource_queries",
        confidence=1.0,
        evidence_kind="deterministic_resource_plan_and_formula_hashes",
        source=payload["fixed_resource_plan_sha256"],
        provenance=[ids[0]],
        attrs={"fixed_resource_plan": payload["fixed_resource_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A159:four_byte_exact_fixed_resource_queries",
        mechanism="execute_sequentially_and_independently_check_every_complete_model",
        outcome="A159:deterministic_resource_unit_order_frontier",
        confidence=1.0,
        evidence_kind="fixed_rlimit_solver_execution_and_independent_complete_rate_gate",
        source="Z3_4.15.4_plus_independent_NumPy_lane_core",
        provenance=[ids[1]],
        attrs={
            "execution_summary": payload["execution_summary"],
            "status_counts": payload["status_counts"],
            "confirmed_models": payload["confirmed_models"],
            "posthoc": payload["posthoc"],
        },
    )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    if (
        len(rows) != len(ids)
        or set(by_id) != set(ids)
        or not reader.verify_provenance()
        or [by_id[edge_id]["provenance"] for edge_id in ids] != [[], [ids[0]], [ids[1]]]
        or any(
            by_id[left]["outcome"] != by_id[right]["trigger"]
            for left, right in zip(ids[:-1], ids[1:], strict=True)
        )
    ):
        raise RuntimeError("A159 Causal provenance chain failed validation")
    return {
        "stats": stats,
        "explicit_triplets": len(rows),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def analyze(results_dir: Path) -> dict[str, Any]:
    a158 = _load_a158_gate(results_dir)
    analysis = _A158.analyze(results_dir)
    if (
        analysis["formula_plan"] != a158["formula_frontier"]
        or analysis["formula_plan_sha256"] != a158["formula_plan_sha256"]
    ):
        raise RuntimeError("A159 regenerated formulas differ from retained A158 bytes")
    plan = _fixed_formula_plan(analysis)
    return {
        **analysis,
        "anchor": a158,
        "fixed_resource_plan": plan,
        "fixed_resource_plan_sha256": _canonical_sha256(plan),
    }


def run(
    *,
    results_dir: Path,
    output: Path,
    causal_output: Path,
    work_dir: Path,
    z3: Path,
) -> dict[str, Any]:
    analysis = analyze(results_dir)
    solver_version = _A156._z3_version_gate(z3)
    executions = _execute_fixed_frontier(
        formula_rows=analysis["rows"],
        formulas=analysis["formulas"],
        problem=analysis["problem"],
        variant=analysis["variant"],
        z3=z3,
        work_dir=work_dir,
    )
    posthoc = _A156._posthoc_summary(analysis["problem"], analysis["variant"], executions)
    status_counts = {
        status: sum(row["solver"]["status"] == status for row in executions)
        for status in ("sat", "unsat", "unknown", "error")
    }
    confirmed_models = [
        {
            "name": row["name"],
            "solver_basis_assignment": row["solver"]["solver_basis_assignment"],
            "input_coordinate_assignment": row["input_coordinate_assignment"],
            "independent_complete_rate_check": row["independent_complete_rate_check"],
        }
        for row in executions
        if row["independently_confirmed_model"]
    ]
    execution_summary = _execution_summary(executions)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FIXED_RLIMIT_R2_ORDER_FRONTIER_EXECUTED",
        "result": (
            "Each of the four exact A158 weighted-order formulas is replayed "
            "byte-for-byte under one identical Z3 resource limit without a solver "
            "wallclock limit."
        ),
        "scope": (
            "The retained A152 SHAKE128 width-24 target relation in four weighted "
            "shared-R2 input orders, 22 suffix rounds, and all 1,344 rate bits."
        ),
        "parameters": {
            "variant": "SHAKE128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "rlimit_per_formula": Z3_RLIMIT,
            "formula_count": len(_A158.ORDER_NAMES),
            "execution_mode": "sequential_one_thread_per_formula",
            "solver": solver_version,
            "solver_wallclock_limit_used": False,
            "external_safety_timeout_seconds": EXTERNAL_SAFETY_TIMEOUT_SECONDS,
            "wallclock_excluded_from_canonical_result": True,
            "global_uniqueness_claimed": False,
        },
        "anchor_gate": {
            "A158_artifact_sha256": A158_SHA256,
            "A158_formula_plan_sha256": analysis["anchor"]["formula_plan_sha256"],
            "A158_orders_sha256": analysis["anchor"]["orders_sha256"],
            "A158_status_counts": analysis["anchor"]["status_counts"],
        },
        "fixed_resource_plan": analysis["fixed_resource_plan"],
        "fixed_resource_plan_sha256": analysis["fixed_resource_plan_sha256"],
        "execution": executions,
        "execution_summary": execution_summary,
        "status_counts": status_counts,
        "confirmed_models": confirmed_models,
        "posthoc": posthoc,
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _atomic_write(output, raw)
    reader = CryptoCausalReader(causal_output)
    if (
        _sha256(output.read_bytes()) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or reader.graph_sha256 != causal["graph_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A159 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "status_counts": status_counts,
        "confirmed_model_count": len(confirmed_models),
        "confirmed_input_assignments": sorted(
            {row["input_coordinate_assignment"] for row in confirmed_models}
        ),
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument("--results-dir", type=Path, default=research_root / "results" / "v1")
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument(
        "--output", type=Path, default=research_root / "results" / "v1" / RESULT_FILENAME
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=research_root / "results" / "v1" / CAUSAL_FILENAME,
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=Path(__file__).parents[2] / "build" / "shake-r2-a159",
    )
    parser.add_argument(
        "--z3", type=Path, default=Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    )
    args = parser.parse_args(argv)
    if args.analyze_only:
        analysis = analyze(args.results_dir.resolve())
        print(
            json.dumps(
                {
                    "fixed_resource_plan": analysis["fixed_resource_plan"],
                    "fixed_resource_plan_sha256": analysis["fixed_resource_plan_sha256"],
                    "solver_started": False,
                },
                sort_keys=True,
            )
        )
        return
    z3 = Path(shutil.which(str(args.z3)) or args.z3)
    if not z3.is_file():
        raise FileNotFoundError(f"Z3 executable not found: {args.z3}")
    if args.output.resolve() == args.causal_output.resolve():
        raise ValueError("JSON and Causal output paths must be distinct")
    print(
        json.dumps(
            run(
                results_dir=args.results_dir.resolve(),
                output=args.output.resolve(),
                causal_output=args.causal_output.resolve(),
                work_dir=args.work_dir.resolve(),
                z3=z3.resolve(),
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
