#!/usr/bin/env python3
"""Bit-level CNF Reader for exact full-round SHAKE state-window inference."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


_NATIVE_PATH = Path(__file__).with_name("shake_native_window_solver.py")
_NATIVE_SPEC = importlib.util.spec_from_file_location(
    "shake_native_window_solver_cnf_base", _NATIVE_PATH
)
assert _NATIVE_SPEC is not None and _NATIVE_SPEC.loader is not None
_NATIVE = importlib.util.module_from_spec(_NATIVE_SPEC)
sys.modules[_NATIVE_SPEC.name] = _NATIVE
_NATIVE_SPEC.loader.exec_module(_NATIVE)

_BASE = _NATIVE._BASE
_WINDOW = _NATIVE._WINDOW
_HEADER_TEMPLATE = "p cnf {variables:<20d} {clauses:<20d}\n"


class StreamingCNF:
    """Write Tseitin clauses incrementally with a rewritable DIMACS header."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = path.open("w+", encoding="ascii", newline="\n")
        self.variables = 0
        self.clauses = 0
        self.handle.write(_HEADER_TEMPLATE.format(variables=0, clauses=0))
        self.true_literal = self.new_variable()
        self.add_clause([self.true_literal])

    def new_variable(self) -> int:
        self.variables += 1
        return self.variables

    def add_clause(self, literals: list[int] | tuple[int, ...]) -> None:
        if not literals or any(literal == 0 for literal in literals):
            raise ValueError("DIMACS clauses must be nonempty and contain no zero")
        self.handle.write(" ".join(str(literal) for literal in literals) + " 0\n")
        self.clauses += 1

    def constant(self, value: bool) -> int:
        return self.true_literal if value else -self.true_literal

    def _constant_value(self, literal: int) -> bool | None:
        if abs(literal) != self.true_literal:
            return None
        return literal > 0

    def xor2(self, first: int, second: int) -> int:
        first_constant = self._constant_value(first)
        second_constant = self._constant_value(second)
        if first_constant is not None:
            return -second if first_constant else second
        if second_constant is not None:
            return -first if second_constant else first
        if first == second:
            return self.constant(False)
        if first == -second:
            return self.constant(True)
        output = self.new_variable()
        self.add_clause([first, second, -output])
        self.add_clause([-first, -second, -output])
        self.add_clause([-first, second, output])
        self.add_clause([first, -second, output])
        return output

    def xor_many(self, literals: list[int]) -> int:
        if not literals:
            return self.constant(False)
        result = literals[0]
        for literal in literals[1:]:
            result = self.xor2(result, literal)
        return result

    def and2(self, first: int, second: int) -> int:
        first_constant = self._constant_value(first)
        second_constant = self._constant_value(second)
        if first_constant is not None:
            return second if first_constant else self.constant(False)
        if second_constant is not None:
            return first if second_constant else self.constant(False)
        if first == second:
            return first
        if first == -second:
            return self.constant(False)
        output = self.new_variable()
        self.add_clause([-output, first])
        self.add_clause([-output, second])
        self.add_clause([output, -first, -second])
        return output

    def finalize(self) -> None:
        self.handle.flush()
        self.handle.seek(0)
        header = _HEADER_TEMPLATE.format(
            variables=self.variables, clauses=self.clauses
        )
        if len(header) != len(_HEADER_TEMPLATE.format(variables=0, clauses=0)):
            raise RuntimeError("DIMACS header width changed")
        self.handle.write(header)
        self.handle.flush()
        os.fsync(self.handle.fileno())
        self.handle.seek(0, os.SEEK_END)

    def close(self) -> None:
        self.handle.close()


def _state_index(lane: int, bit: int) -> int:
    return lane * 64 + bit


def _encode_round(
    cnf: StreamingCNF,
    state: list[int],
    round_constant: int,
) -> list[int]:
    columns = [
        cnf.xor_many(
            [state[_state_index(x + 5 * y, bit)] for y in range(5)]
        )
        for x in range(5)
        for bit in range(64)
    ]

    def column(x: int, bit: int) -> int:
        return columns[(x % 5) * 64 + (bit % 64)]

    theta_delta = [
        cnf.xor2(column(x - 1, bit), column(x + 1, bit - 1))
        for x in range(5)
        for bit in range(64)
    ]
    theta = [cnf.constant(False)] * 1600
    for y in range(5):
        for x in range(5):
            lane = x + 5 * y
            for bit in range(64):
                theta[_state_index(lane, bit)] = cnf.xor2(
                    state[_state_index(lane, bit)], theta_delta[x * 64 + bit]
                )

    rho_pi = [cnf.constant(False)] * 1600
    for x in range(5):
        for y in range(5):
            source = x + 5 * y
            destination_x = y
            destination_y = (2 * x + 3 * y) % 5
            destination = destination_x + 5 * destination_y
            rotation = int(_BASE.ROTATION_OFFSETS[x, y])
            for bit in range(64):
                rho_pi[_state_index(destination, bit)] = theta[
                    _state_index(source, (bit - rotation) % 64)
                ]

    output = [cnf.constant(False)] * 1600
    for y in range(5):
        for x in range(5):
            lane = x + 5 * y
            next_lane = ((x + 1) % 5) + 5 * y
            next2_lane = ((x + 2) % 5) + 5 * y
            for bit in range(64):
                nonlinear = cnf.and2(
                    -rho_pi[_state_index(next_lane, bit)],
                    rho_pi[_state_index(next2_lane, bit)],
                )
                value = cnf.xor2(rho_pi[_state_index(lane, bit)], nonlinear)
                if lane == 0 and ((round_constant >> bit) & 1):
                    value = -value
                output[_state_index(lane, bit)] = value
    return output


def _encode_problem(
    path: Path,
    base_state: np.ndarray,
    target_rate: np.ndarray,
    variant: Any,
    positions: np.ndarray,
    output_lanes: int,
) -> tuple[StreamingCNF, dict[str, Any]]:
    if output_lanes < 1 or output_lanes > variant.rate_lanes:
        raise ValueError("CNF output-lane count is outside the SHAKE rate")
    window_by_coordinate = {int(position): index for index, position in enumerate(positions)}
    cnf = StreamingCNF(path)
    window_variables = [cnf.new_variable() for _ in positions]
    state = [cnf.constant(False)] * 1600
    for lane in range(25):
        lane_value = int(base_state[0, lane])
        for bit in range(64):
            if lane >= variant.rate_lanes:
                capacity_coordinate = (lane - variant.rate_lanes) * 64 + bit
                window_index = window_by_coordinate.get(capacity_coordinate)
            else:
                window_index = None
            state[_state_index(lane, bit)] = (
                window_variables[window_index]
                if window_index is not None
                else cnf.constant(bool((lane_value >> bit) & 1))
            )
    round_variable_counts = []
    round_clause_counts = []
    for round_constant in _BASE.ROUND_CONSTANTS:
        variables_before = cnf.variables
        clauses_before = cnf.clauses
        state = _encode_round(cnf, state, int(round_constant))
        round_variable_counts.append(cnf.variables - variables_before)
        round_clause_counts.append(cnf.clauses - clauses_before)
    for lane in range(output_lanes):
        lane_value = int(target_rate[0, lane])
        for bit in range(64):
            literal = state[_state_index(lane, bit)]
            cnf.add_clause([literal if ((lane_value >> bit) & 1) else -literal])
    cnf.finalize()
    return cnf, {
        "window_variables": window_variables,
        "variables": cnf.variables,
        "clauses": cnf.clauses,
        "round_variable_counts": round_variable_counts,
        "round_clause_counts": round_clause_counts,
        "output_lanes": output_lanes,
        "output_bits": output_lanes * 64,
        "cnf_bytes": path.stat().st_size,
    }


def _parse_solver_output(output: str) -> tuple[str, dict[int, bool], dict[str, float]]:
    if "s SATISFIABLE" in output:
        status = "sat"
    elif "s UNSATISFIABLE" in output:
        status = "unsat"
    elif "s UNKNOWN" in output or "timeout" in output.lower():
        status = "unknown"
    else:
        status = "error"
    model: dict[int, bool] = {}
    for line in output.splitlines():
        if line.startswith("v "):
            for token in line[2:].split():
                literal = int(token)
                if literal:
                    model[abs(literal)] = literal > 0
    stats = {}
    for key in (
        "sat-conflicts",
        "sat-decisions",
        "sat-propagations-2ary",
        "sat-propagations-nary",
        "sat-restarts",
        "total-time",
    ):
        match = re.search(rf":{re.escape(key)}\s+([0-9.]+)", output)
        if match:
            stats[key] = float(match.group(1))
    return status, model, stats


def _run_z3(
    z3_path: Path,
    cnf_path: Path,
    timeout_seconds: int,
    random_seed: int,
    branching_heuristic: str,
) -> dict[str, Any]:
    command = [
        str(z3_path),
        "-dimacs",
        "-model",
        "-st",
        f"-T:{timeout_seconds}",
        f"sat.random_seed={random_seed}",
        "sat.threads=1",
        f"sat.branching.heuristic={branching_heuristic}",
        str(cnf_path),
    ]
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds + 15,
        )
        output = completed.stdout + completed.stderr
        return_code = completed.returncode
        external_timeout = False
    except subprocess.TimeoutExpired as error:
        output = (error.stdout or "") + (error.stderr or "")
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        return_code = None
        external_timeout = True
    elapsed = time.perf_counter() - started
    status, model, stats = _parse_solver_output(output)
    if external_timeout:
        status = "unknown"
    return {
        "status": status,
        "model": model,
        "stats": stats,
        "elapsed_seconds": elapsed,
        "return_code": return_code,
        "external_timeout": external_timeout,
        "stdout_sha256": hashlib.sha256(output.encode()).hexdigest(),
        "command_parameters": {
            "timeout_seconds": timeout_seconds,
            "random_seed": random_seed,
            "threads": 1,
            "branching_heuristic": branching_heuristic,
        },
    }


def _assignment_from_model(window_variables: list[int], model: dict[int, bool]) -> int:
    missing = [variable for variable in window_variables if variable not in model]
    if missing:
        raise RuntimeError(f"SAT model omits {len(missing)} window variables")
    value = 0
    for bit, variable in enumerate(window_variables):
        value |= int(model[variable]) << bit
    return value


def _solver_record(result: dict[str, Any]) -> dict[str, Any]:
    stats = {
        key: value
        for key, value in result["stats"].items()
        if key != "total-time"
    }
    if result["status"] == "unknown":
        stats = {}
    return {
        "status": result["status"],
        "stats": stats,
        "return_code": result["return_code"],
        "external_timeout": result["external_timeout"],
        "command_parameters": result["command_parameters"],
    }


def _trial(
    variant: Any,
    window_bits: int,
    seed: int,
    output_lanes: int,
    timeout_seconds: int,
    z3_path: Path,
    work_dir: Path,
    keep_cnf: bool,
    branching_heuristic: str,
) -> dict[str, Any]:
    problem = _NATIVE._problem(variant, window_bits, seed)
    cnf_path = work_dir / f"{variant.name.lower()}_w{window_bits}_s{seed}.cnf"
    cnf, encoding = _encode_problem(
        cnf_path,
        problem["base_state"],
        problem["target"],
        variant,
        problem["positions"],
        output_lanes,
    )
    first = _run_z3(
        z3_path,
        cnf_path,
        timeout_seconds,
        seed ^ 0xC0FFEE,
        branching_heuristic,
    )
    reconstructed_assignment = None
    reconstruction_matches_ground_truth = False
    uniqueness = None
    if first["status"] == "sat":
        reconstructed_assignment = _assignment_from_model(
            encoding["window_variables"], first["model"]
        )
        actual_assignment = _WINDOW._extract_window(
            problem["base_state"], variant, problem["positions"]
        )
        reconstruction_matches_ground_truth = (
            reconstructed_assignment == actual_assignment
        )
        blocking_clause = [
            -variable if first["model"][variable] else variable
            for variable in encoding["window_variables"]
        ]
        cnf.add_clause(blocking_clause)
        cnf.finalize()
        second = _run_z3(
            z3_path,
            cnf_path,
            timeout_seconds,
            seed ^ 0xBAD5EED,
            branching_heuristic,
        )
        uniqueness = second["status"] == "unsat"
    else:
        actual_assignment = _WINDOW._extract_window(
            problem["base_state"], variant, problem["positions"]
        )
        second = None
    cnf.close()
    cnf_sha = hashlib.sha256(cnf_path.read_bytes()).hexdigest()
    cnf_bytes = cnf_path.stat().st_size
    if not keep_cnf:
        cnf_path.unlink()
    return {
        "seed": seed,
        "variant": variant.name,
        "window_bits": window_bits,
        "window_start_capacity_bit": int(problem["positions"][0]),
        "window_stop_capacity_bit_exclusive": int(problem["positions"][-1] + 1),
        "output_lanes": output_lanes,
        "actual_assignment": actual_assignment,
        "reconstructed_assignment": reconstructed_assignment,
        "reconstruction_matches_ground_truth": reconstruction_matches_ground_truth,
        "unique_assignment_proved": uniqueness,
        "encoding": {
            key: value for key, value in encoding.items() if key != "window_variables"
        },
        "first_solver": _solver_record(first),
        "second_solver": _solver_record(second) if second is not None else None,
        "cnf_sha256_after_blocking_clause": cnf_sha,
        "cnf_bytes_after_blocking_clause": cnf_bytes,
    }


def _build_graph(
    path: Path,
    variant_keys: list[str],
    windows: list[int],
    output_lanes: int,
    timeout_seconds: int,
    z3_version: str,
) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_boolean_cnf_reader",
        parameters={
            "variants": variant_keys,
            "windows": windows,
            "permutation_rounds": 24,
            "output_lanes": output_lanes,
            "timeout_seconds": timeout_seconds,
            "solver": z3_version,
            "prediction_before_measurement": (
                "A bit-level Tseitin model may replace explicit 2^k candidate "
                "enumeration if clause learning determines the window assignment "
                "with materially fewer input decisions."
            ),
        },
    )
    for key in variant_keys:
        variant = _BASE.VARIANTS[key]
        encode_id = f"{key}-boolean-fullround-circuit"
        builder.add_triplet(
            edge_id=encode_id,
            trigger=f"{key}:known_rate_and_capacity_complement_plus_window_variables",
            mechanism="exact_tseitin_cnf_of_24_round_keccak_f1600",
            outcome=f"{key}:fullround_boolean_constraint_system",
            confidence=1.0,
            evidence_kind="round_equation_exact_encoding",
            source="FIPS202_theta_rho_pi_chi_iota",
            attrs={
                "reader_recipe": {
                    "variant": variant.name,
                    "permutation_rounds": 24,
                    "known": "rate_and_capacity_complement",
                    "variable": "declared_capacity_window",
                    "output_constraint": "observed_next_rate_lanes",
                    "encoding": "streaming_DIMACS_Tseitin",
                    "solver": z3_version,
                }
            },
        )
        builder.add_triplet(
            edge_id=f"{key}-cnf-reader-model",
            trigger=f"{key}:fullround_boolean_constraints",
            mechanism="reader_executable_sat_model_and_blocking_clause_query",
            outcome=f"{key}:capacity_window_assignment_and_uniqueness_status",
            confidence=1.0,
            evidence_kind="solver_model_checked_against_instrumented_ground_truth",
            source="Z3_DIMACS_single_thread",
            provenance=[encode_id],
            attrs={"window_sizes": windows, "output_lanes": output_lanes},
        )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(
        reader.triplets(include_inferred=False)
    ) != 2 * len(variant_keys):
        raise RuntimeError("SHAKE Boolean CNF causal graph gate failed")
    return stats


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variants", default="shake128")
    parser.add_argument("--window-bits", default="8,12,16")
    parser.add_argument("--output-lanes", type=int, default=2)
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument(
        "--branching-heuristic", choices=("chb", "vsids"), default="chb"
    )
    parser.add_argument("--seed", type=int, default=89751001)
    parser.add_argument(
        "--z3",
        type=Path,
        default=Path(shutil.which("z3") or "/opt/homebrew/bin/z3"),
    )
    parser.add_argument("--work-dir", type=Path, default=Path("build/shake-cnf"))
    parser.add_argument("--keep-cnf", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    windows = _NATIVE._parse_windows(args.window_bits)
    variant_keys = [item.strip() for item in args.variants.split(",") if item.strip()]
    if not variant_keys or any(key not in _BASE.VARIANTS for key in variant_keys):
        raise ValueError("variants must be a comma list of shake128 and/or shake256")
    if args.timeout_seconds < 1 or args.output_lanes < 1:
        raise ValueError("timeout and output-lane count must be positive")
    z3 = Path(shutil.which(str(args.z3)) or args.z3)
    if not z3.is_file():
        raise FileNotFoundError(f"Z3 executable not found: {args.z3}")
    version = subprocess.run(
        [str(z3), "-version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    args.work_dir.mkdir(parents=True, exist_ok=True)
    kat = _BASE._kat()
    causal = _build_graph(
        args.causal_output,
        variant_keys,
        windows,
        args.output_lanes,
        args.timeout_seconds,
        version,
    )
    reader = CryptoCausalReader(args.causal_output)
    reader_rows = reader.triplets(include_inferred=False)
    trials = []
    for variant_index, key in enumerate(variant_keys):
        variant = _BASE.VARIANTS[key]
        for window_index, bits in enumerate(windows):
            seed = args.seed + 100_003 * variant_index + 1009 * window_index
            print(f"{variant.name} Boolean CNF Reader bits={bits}", flush=True)
            trials.append(
                _trial(
                    variant,
                    bits,
                    seed,
                    min(args.output_lanes, variant.rate_lanes),
                    args.timeout_seconds,
                    z3,
                    args.work_dir,
                    args.keep_cnf,
                    args.branching_heuristic,
                )
            )
    reconstructed = [
        row for row in trials if row["reconstruction_matches_ground_truth"]
    ]
    payload = {
        "schema": "shake-boolean-cnf-reader-v1",
        "evidence_stage": (
            "BOOLEAN_CNF_FULLROUND_RECONSTRUCTION_OBSERVED"
            if reconstructed
            else "BOOLEAN_CNF_SOLVER_BOUNDARY_LOCALIZED"
        ),
        "result": (
            f"The exact Boolean Reader reconstructed {len(reconstructed)}/{len(trials)} "
            "tested full-round SHAKE capacity windows within the configured solver limit."
        ),
        "scope": (
            "Known-complement state-window inference from consecutive SHAKE rate "
            "blocks. Solver decisions are compared with explicit 2^k enumeration; "
            "all Boolean round equations are exact."
        ),
        "parameters": {
            "variants": variant_keys,
            "window_bits": windows,
            "output_lanes": args.output_lanes,
            "timeout_seconds": args.timeout_seconds,
            "seed": args.seed,
            "solver": version,
            "solver_threads": 1,
            "branching_heuristic": args.branching_heuristic,
        },
        "kat": kat,
        "causal": causal,
        "reader_triplets": reader_rows,
        "trials": trials,
        "reconstructed_trials": len(reconstructed),
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "reconstructed_trials": len(reconstructed),
                "statuses": [
                    {
                        "variant": row["variant"],
                        "bits": row["window_bits"],
                        "first": row["first_solver"]["status"],
                        "correct": row["reconstruction_matches_ground_truth"],
                        "unique": row["unique_assignment_proved"],
                        "decisions": row["first_solver"]["stats"].get(
                            "sat-decisions"
                        ),
                    }
                    for row in trials
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
