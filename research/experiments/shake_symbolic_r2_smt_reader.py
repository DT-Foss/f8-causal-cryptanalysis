#!/usr/bin/env python3
"""Native-XOR SMT Reader for the symbolic SHAKE R2 round split."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


_CNF_PATH = Path(__file__).with_name("shake_boolean_cnf_reader.py")
_CNF_SPEC = importlib.util.spec_from_file_location(
    "shake_boolean_cnf_reader_smt_baseline", _CNF_PATH
)
assert _CNF_SPEC is not None and _CNF_SPEC.loader is not None
_CNF = importlib.util.module_from_spec(_CNF_SPEC)
sys.modules[_CNF_SPEC.name] = _CNF
_CNF_SPEC.loader.exec_module(_CNF)

_SYMBOLIC_PATH = Path(__file__).with_name("shake_symbolic_anf_frontier.py")
_SYMBOLIC_SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_anf_frontier_smt_base", _SYMBOLIC_PATH
)
assert _SYMBOLIC_SPEC is not None and _SYMBOLIC_SPEC.loader is not None
_SYMBOLIC = importlib.util.module_from_spec(_SYMBOLIC_SPEC)
sys.modules[_SYMBOLIC_SPEC.name] = _SYMBOLIC
_SYMBOLIC_SPEC.loader.exec_module(_SYMBOLIC)

_BASE = _CNF._BASE
_NATIVE = _CNF._NATIVE
_WINDOW = _CNF._WINDOW
BASELINE_SHA256 = "4281b0ab9eb6156cc428b34cd14216cf5c465ba786c85a0332bb8f71eb0e92dc"


class BooleanSMT:
    """Build a Boolean SMT-LIB circuit with native n-ary XOR equations."""

    def __init__(self, seed: int):
        self.lines = [
            "(set-logic QF_UF)",
            f"(set-option :smt.random_seed {seed})",
            f"(set-option :sat.random_seed {seed})",
        ]
        self.variables = 0
        self.assertions = 0

    def declare(self, prefix: str = "v") -> str:
        name = f"{prefix}{self.variables}"
        self.variables += 1
        self.lines.append(f"(declare-fun {name} () Bool)")
        return name

    def define(self, expression: str, prefix: str = "v") -> str:
        name = self.declare(prefix)
        self.lines.append(f"(assert (= {name} {expression}))")
        self.assertions += 1
        return name

    @staticmethod
    def xor(expressions: Iterable[str]) -> str:
        values = list(expressions)
        if not values:
            return "false"
        if len(values) == 1:
            return values[0]
        return f"(xor {' '.join(values)})"

    def constrain(self, expression: str) -> None:
        self.lines.append(f"(assert {expression})")
        self.assertions += 1

    def render(
        self,
        inputs: list[str],
        blocked_assignment: int | None = None,
        include_model: bool = True,
    ) -> bytes:
        lines = list(self.lines)
        if blocked_assignment is not None:
            alternatives = [
                f"(not {name})" if ((blocked_assignment >> bit) & 1) else name
                for bit, name in enumerate(inputs)
            ]
            lines.append(f"(assert (or {' '.join(alternatives)}))")
        lines.append("(check-sat)")
        if include_model:
            lines.append(f"(get-value ({' '.join(inputs)}))")
        lines.append("(exit)")
        return ("\n".join(lines) + "\n").encode()


def _compile_symbolic_r2(
    writer: BooleanSMT,
    template: Any,
    variant: Any,
    positions: Any,
) -> tuple[list[str], list[str], dict[str, Any]]:
    inputs = [writer.declare("x") for _ in positions]
    polynomials = _SYMBOLIC._initial_symbolic_state(template, variant, positions)
    polynomials = _SYMBOLIC._symbolic_round(
        polynomials, int(_BASE.ROUND_CONSTANTS[0])
    )
    polynomials = _SYMBOLIC._symbolic_round(
        polynomials, int(_BASE.ROUND_CONSTANTS[1])
    )
    monomials: dict[int, str] = {0: "true"}

    def monomial(mask: int) -> str:
        if mask in monomials:
            return monomials[mask]
        variables = [inputs[index] for index in range(len(inputs)) if (mask >> index) & 1]
        value = (
            variables[0]
            if len(variables) == 1
            else writer.define(f"(and {' '.join(variables)})", "m")
        )
        monomials[mask] = value
        return value

    state = [
        writer.define(
            writer.xor(monomial(mask) for mask in sorted(polynomial)), "s"
        )
        for polynomial in polynomials
    ]
    return inputs, state, {
        "r2_symbolic_monomials": len(monomials),
        "r2_variables": writer.variables,
        "r2_assertions": writer.assertions,
        "r2_polynomial_state_sha256": _SYMBOLIC._poly_hash(
            polynomials, len(positions)
        ),
    }


def _compile_suffix(
    writer: BooleanSMT, state: list[str], output_rounds: list[int]
) -> tuple[list[str], dict[str, Any]]:
    round_variables = []
    round_assertions = []
    for round_index in output_rounds:
        variables_before = writer.variables
        assertions_before = writer.assertions
        columns = [
            writer.define(
                writer.xor(state[(x + 5 * y) * 64 + bit] for y in range(5)),
                "c",
            )
            for x in range(5)
            for bit in range(64)
        ]
        delta = [
            writer.define(
                writer.xor(
                    [
                        columns[((x - 1) % 5) * 64 + bit],
                        columns[((x + 1) % 5) * 64 + ((bit - 1) % 64)],
                    ]
                ),
                "d",
            )
            for x in range(5)
            for bit in range(64)
        ]
        theta = ["false"] * 1600
        for y in range(5):
            for x in range(5):
                lane = x + 5 * y
                for bit in range(64):
                    theta[lane * 64 + bit] = writer.define(
                        writer.xor(
                            [state[lane * 64 + bit], delta[x * 64 + bit]]
                        ),
                        "t",
                    )
        rho_pi = ["false"] * 1600
        for x in range(5):
            for y in range(5):
                source = x + 5 * y
                destination = y + 5 * ((2 * x + 3 * y) % 5)
                rotation = int(_BASE.ROTATION_OFFSETS[x, y])
                for bit in range(64):
                    rho_pi[destination * 64 + bit] = theta[
                        source * 64 + ((bit - rotation) % 64)
                    ]
        output = ["false"] * 1600
        round_constant = int(_BASE.ROUND_CONSTANTS[round_index])
        for y in range(5):
            for x in range(5):
                lane = x + 5 * y
                next_lane = ((x + 1) % 5) + 5 * y
                next2_lane = ((x + 2) % 5) + 5 * y
                for bit in range(64):
                    nonlinear = writer.define(
                        f"(and (not {rho_pi[next_lane * 64 + bit]}) "
                        f"{rho_pi[next2_lane * 64 + bit]})",
                        "a",
                    )
                    value = writer.define(
                        writer.xor([rho_pi[lane * 64 + bit], nonlinear]), "o"
                    )
                    output[lane * 64 + bit] = (
                        f"(not {value})"
                        if lane == 0 and ((round_constant >> bit) & 1)
                        else value
                    )
        state = output
        round_variables.append(writer.variables - variables_before)
        round_assertions.append(writer.assertions - assertions_before)
    return state, {
        "suffix_rounds": output_rounds,
        "round_variable_counts": round_variables,
        "round_assertion_counts": round_assertions,
    }


def _encode_problem(
    problem: dict[str, Any], variant: Any, seed: int
) -> tuple[BooleanSMT, list[str], dict[str, Any]]:
    writer = BooleanSMT(seed)
    template = _WINDOW._clear_window(
        problem["base_state"], variant, problem["positions"]
    )
    inputs, state, prefix = _compile_symbolic_r2(
        writer, template, variant, problem["positions"]
    )
    state, suffix = _compile_suffix(writer, state, list(range(2, 24)))
    output_assertions_before = writer.assertions
    for lane in range(variant.rate_lanes):
        lane_value = int(problem["target"][0, lane])
        for bit in range(64):
            literal = state[lane * 64 + bit]
            writer.constrain(
                literal if ((lane_value >> bit) & 1) else f"(not {literal})"
            )
    return writer, inputs, {
        **prefix,
        **suffix,
        "total_variables": writer.variables,
        "total_assertions": writer.assertions,
        "output_assertions": writer.assertions - output_assertions_before,
        "native_xor_equations": True,
    }


def _parse_status(output: str) -> str:
    for line in output.splitlines():
        if line.strip() in {"sat", "unsat", "unknown"}:
            return line.strip()
    if "timeout" in output.lower():
        return "unknown"
    return "error"


def _parse_assignment(output: str, inputs: list[str]) -> int | None:
    values = {
        name: value == "true"
        for name, value in re.findall(r"\((x\d+)\s+(true|false)\)", output)
    }
    if any(name not in values for name in inputs):
        return None
    assignment = 0
    for bit, name in enumerate(inputs):
        assignment |= int(values[name]) << bit
    return assignment


def _parse_stats(output: str) -> dict[str, float]:
    stats = {}
    for key in (
        "decisions",
        "conflicts",
        "propagations",
        "binary-propagations",
        "restarts",
    ):
        match = re.search(rf":{re.escape(key)}\s+([0-9.]+)", output)
        if match:
            stats[key] = float(match.group(1))
    return stats


def _run_z3(
    z3: Path, path: Path, timeout_seconds: int, inputs: list[str]
) -> dict[str, Any]:
    command = [str(z3), "-smt2", "-st", f"-T:{timeout_seconds}", str(path)]
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
    status = "unknown" if external_timeout else _parse_status(output)
    return {
        "status": status,
        "assignment": _parse_assignment(output, inputs) if status == "sat" else None,
        "stats": _parse_stats(output) if status not in {"unknown", "error"} else {},
        "return_code": return_code,
        "external_timeout": external_timeout,
        "command_parameters": {
            "timeout_seconds": timeout_seconds,
            "threads": 1,
            "representation": "Boolean_SMT_native_nary_XOR",
        },
    }


def _load_baseline(path: Path) -> dict[int, dict[str, Any]]:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != BASELINE_SHA256:
        raise RuntimeError("A128 baseline hash differs from the canonical artifact")
    payload = json.loads(raw)
    return {int(row["window_bits"]): row for row in payload["trials"]}


def _solver_summary(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": result["status"],
        "stats": result["stats"],
        "return_code": result["return_code"],
        "external_timeout": result["external_timeout"],
        "command_parameters": result["command_parameters"],
    }


def _trial(
    variant: Any,
    window_bits: int,
    seed: int,
    timeout_seconds: int,
    z3: Path,
    work_dir: Path,
    keep_smt: bool,
    baseline: dict[str, Any] | None,
) -> dict[str, Any]:
    problem = _NATIVE._problem(variant, window_bits, seed)
    writer, inputs, encoding = _encode_problem(problem, variant, seed)
    first_path = work_dir / f"{variant.name.lower()}_symbolic_r2_w{window_bits}_first.smt2"
    first_raw = writer.render(inputs, include_model=True)
    first_path.write_bytes(first_raw)
    first = _run_z3(z3, first_path, timeout_seconds, inputs)
    actual = _WINDOW._extract_window(
        problem["base_state"], variant, problem["positions"]
    )
    reconstructed = first["assignment"]
    matches = reconstructed == actual if reconstructed is not None else False
    second = None
    second_sha = None
    second_bytes = None
    if reconstructed is not None:
        second_path = work_dir / (
            f"{variant.name.lower()}_symbolic_r2_w{window_bits}_blocked.smt2"
        )
        second_raw = writer.render(
            inputs, blocked_assignment=reconstructed, include_model=False
        )
        second_path.write_bytes(second_raw)
        second = _run_z3(z3, second_path, timeout_seconds, inputs)
        second_sha = hashlib.sha256(second_raw).hexdigest()
        second_bytes = len(second_raw)
        if not keep_smt:
            second_path.unlink()
    if not keep_smt:
        first_path.unlink()
    native_decisions = first["stats"].get("decisions")
    baseline_decisions = (
        baseline["first_solver"]["stats"].get("sat-decisions")
        if baseline is not None
        else None
    )
    return {
        "variant": variant.name,
        "window_bits": window_bits,
        "seed": seed,
        "window_start_capacity_bit": int(problem["positions"][0]),
        "window_stop_capacity_bit_exclusive": int(problem["positions"][-1] + 1),
        "actual_assignment": actual,
        "reconstructed_assignment": reconstructed,
        "reconstruction_matches_ground_truth": matches,
        "unique_assignment_proved": second["status"] == "unsat" if second else None,
        "encoding": {
            **encoding,
            "first_smt_bytes": len(first_raw),
            "first_smt_sha256": hashlib.sha256(first_raw).hexdigest(),
            "blocked_smt_bytes": second_bytes,
            "blocked_smt_sha256": second_sha,
        },
        "first_solver": _solver_summary(first),
        "second_solver": _solver_summary(second) if second else None,
        "canonical_cnf_baseline": (
            {
                "status": baseline["first_solver"]["status"],
                "decisions": baseline_decisions,
                "variables": baseline["encoding"]["variables"],
                "clauses": baseline["encoding"]["clauses"],
                "cnf_bytes": baseline["encoding"]["cnf_bytes"],
            }
            if baseline is not None
            else None
        ),
        "native_xor_decision_ratio_vs_cnf": (
            native_decisions / baseline_decisions
            if native_decisions is not None and baseline_decisions
            else None
        ),
    }


def _build_graph(path: Path, windows: list[int], timeout_seconds: int) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r2_native_xor_smt_reader",
        parameters={
            "variant": "shake128",
            "window_bits": windows,
            "symbolic_prefix_rounds": 2,
            "explicit_suffix_rounds": 22,
            "timeout_seconds": timeout_seconds,
            "prediction_before_measurement": (
                "Preserving the symbolic R2 interface as native n-ary XOR "
                "equations should avoid the Tseitin-chain expansion and reduce "
                "the solver decision frontier relative to canonical A128."
            ),
        },
    )
    compile_id = "shake128-symbolic-r2-native-xor"
    solve_id = "shake128-r3-r24-smt-reader"
    builder.add_triplet(
        edge_id=compile_id,
        trigger="shake128:known_complement_plus_symbolic_capacity_window",
        mechanism="exact_R2_boolean_ring_compilation_to_native_nary_xor",
        outcome="shake128:native_xor_R2_interface",
        confidence=1.0,
        evidence_kind="symbolic_equation_identity",
        source="A134_symbolic_anf_compiler",
    )
    builder.add_triplet(
        edge_id=solve_id,
        trigger="shake128:native_xor_R2_interface_plus_complete_next_rate",
        mechanism="reader_encode_exact_R3_through_R24_boolean_suffix",
        outcome="shake128:window_assignment_model",
        confidence=1.0,
        evidence_kind="fullround_smt_model_checked_against_ground_truth",
        source="Z3_Boolean_SMT",
        provenance=[compile_id],
        attrs={
            "reader_recipe": {
                "prefix": "exact_symbolic_R2",
                "suffix_rounds": list(range(2, 24)),
                "linear_operator": "native_nary_xor",
                "nonlinear_operator": "Boolean_and_not",
            }
        },
    )
    builder.add_triplet(
        edge_id="shake128-blocking-clause-uniqueness",
        trigger="shake128:window_assignment_model",
        mechanism="reader_add_exact_assignment_block_and_resolve",
        outcome="shake128:uniqueness_status",
        confidence=1.0,
        evidence_kind="second_solver_query",
        source="Z3_Boolean_SMT",
        provenance=[solve_id],
    )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 3:
        raise RuntimeError("SHAKE symbolic SMT causal graph gate failed")
    return stats


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--window-bits", default="4,8,12,16")
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--seed", type=int, default=89751001)
    parser.add_argument(
        "--z3", type=Path, default=Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    )
    parser.add_argument("--work-dir", type=Path, default=Path("build/shake-symbolic-smt"))
    parser.add_argument("--keep-smt", action="store_true")
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path("research/results/v1/shake_boolean_cnf_reader_v1.json"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    windows = _NATIVE._parse_windows(args.window_bits)
    if args.timeout_seconds < 1:
        raise ValueError("timeout must be positive")
    z3 = Path(shutil.which(str(args.z3)) or args.z3)
    if not z3.is_file():
        raise FileNotFoundError(f"Z3 executable not found: {args.z3}")
    version = subprocess.run(
        [str(z3), "-version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    baselines = _load_baseline(args.baseline)
    args.work_dir.mkdir(parents=True, exist_ok=True)
    causal = _build_graph(args.causal_output, windows, args.timeout_seconds)
    reader = CryptoCausalReader(args.causal_output)
    variant = _BASE.VARIANTS["shake128"]
    trials = []
    canonical_offsets = {4: 0, 8: 1009, 12: 2018, 16: 3027}
    for index, bits in enumerate(windows):
        seed = args.seed + canonical_offsets.get(bits, 1009 * index)
        print(f"SHAKE128 symbolic-R2 native-XOR SMT bits={bits}", flush=True)
        trials.append(
            _trial(
                variant,
                bits,
                seed,
                args.timeout_seconds,
                z3,
                args.work_dir,
                args.keep_smt,
                baselines.get(bits),
            )
        )
    reconstructed = [row for row in trials if row["reconstruction_matches_ground_truth"]]
    payload = {
        "schema": "shake-symbolic-r2-native-xor-smt-reader-v1",
        "evidence_stage": "FULLROUND_NATIVE_XOR_ROUND_SPLIT_RECONSTRUCTION_OBSERVED",
        "result": (
            f"The native-XOR round-split Reader reconstructed {len(reconstructed)}/"
            f"{len(trials)} tested full-round SHAKE128 windows."
        ),
        "scope": (
            "Known-complement capacity-window inference from the complete next-rate "
            "block; exact symbolic R2 prefix and exact Boolean R3--R24 suffix."
        ),
        "parameters": {
            "variant": "shake128",
            "window_bits": windows,
            "timeout_seconds": args.timeout_seconds,
            "seed": args.seed,
            "solver": version,
            "solver_threads": 1,
            "baseline_sha256": BASELINE_SHA256,
        },
        "kat": _BASE._kat(),
        "causal": causal,
        "reader_triplets": reader.triplets(include_inferred=False),
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
                "trials": [
                    {
                        "bits": row["window_bits"],
                        "first": row["first_solver"]["status"],
                        "second": (
                            row["second_solver"]["status"]
                            if row["second_solver"]
                            else None
                        ),
                        "correct": row["reconstruction_matches_ground_truth"],
                        "unique": row["unique_assignment_proved"],
                        "decisions": row["first_solver"]["stats"].get("decisions"),
                        "ratio_vs_cnf": row["native_xor_decision_ratio_vs_cnf"],
                    }
                    for row in trials
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
