#!/usr/bin/env python3
"""Compare exact SHAKE symbolic-prefix split points without rerunning R2 anchors."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


_SMT_PATH = Path(__file__).with_name("shake_symbolic_r2_smt_reader.py")
_SMT_SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_smt_reader_split_base", _SMT_PATH
)
assert _SMT_SPEC is not None and _SMT_SPEC.loader is not None
_SMT = importlib.util.module_from_spec(_SMT_SPEC)
sys.modules[_SMT_SPEC.name] = _SMT
_SMT_SPEC.loader.exec_module(_SMT)

_PARTITION_PATH = Path(__file__).with_name("shake_symbolic_r2_partition_reader.py")
_PARTITION_SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_partition_reader_split_base", _PARTITION_PATH
)
assert _PARTITION_SPEC is not None and _PARTITION_SPEC.loader is not None
_PARTITION = importlib.util.module_from_spec(_PARTITION_SPEC)
sys.modules[_PARTITION_SPEC.name] = _PARTITION
_PARTITION_SPEC.loader.exec_module(_PARTITION)

_BASE = _SMT._BASE
_NATIVE = _SMT._NATIVE
_WINDOW = _SMT._WINDOW
_SYMBOLIC = _SMT._SYMBOLIC

A135_SHA256 = "239098b2944535bb1d8544783ce8e1f1b11efbe48aa9dbb0a4ec9ee61c637b71"
A136_SHA256 = "7a09b0e72c46072baead5de18587cbe4706495ed7636733356903db0b6cff5c4"


def _load_hashed_json(path: Path, expected_sha256: str) -> dict[str, Any]:
    raw = path.read_bytes()
    observed = hashlib.sha256(raw).hexdigest()
    if observed != expected_sha256:
        raise RuntimeError(
            f"retained artifact hash differs for {path}: {observed}"
        )
    return json.loads(raw)


def _symbolic_prefix_polynomials(
    template: Any,
    variant: Any,
    positions: Any,
    prefix_rounds: int,
) -> list[Any]:
    if prefix_rounds < 1 or prefix_rounds > 3:
        raise ValueError("symbolic prefix must contain one, two, or three rounds")
    polynomials = _SYMBOLIC._initial_symbolic_state(template, variant, positions)
    for round_index in range(prefix_rounds):
        polynomials = _SYMBOLIC._symbolic_round(
            polynomials, int(_BASE.ROUND_CONSTANTS[round_index])
        )
    return polynomials


def _compile_symbolic_prefix(
    writer: Any,
    template: Any,
    variant: Any,
    positions: Any,
    prefix_rounds: int,
) -> tuple[list[str], list[str], dict[str, Any]]:
    inputs = [writer.declare("x") for _ in positions]
    polynomials = _symbolic_prefix_polynomials(
        template, variant, positions, prefix_rounds
    )
    monomials: dict[int, str] = {0: "true"}

    def monomial(mask: int) -> str:
        if mask in monomials:
            return monomials[mask]
        variables = [
            inputs[index]
            for index in range(len(inputs))
            if (mask >> index) & 1
        ]
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
    masks = set().union(*polynomials)
    return inputs, state, {
        "symbolic_prefix_rounds": prefix_rounds,
        "symbolic_monomials": len(monomials),
        "nonconstant_symbolic_monomials": len(monomials) - int(0 in monomials),
        "coordinate_coefficients": sum(len(polynomial) for polynomial in polynomials),
        "maximum_degree": max((int(mask).bit_count() for mask in masks), default=0),
        "prefix_variables": writer.variables,
        "prefix_assertions": writer.assertions,
        "polynomial_state_sha256": _SYMBOLIC._poly_hash(
            polynomials, len(positions)
        ),
    }


def _encode_problem(
    problem: dict[str, Any], variant: Any, seed: int, prefix_rounds: int
) -> tuple[Any, list[str], dict[str, Any]]:
    writer = _SMT.BooleanSMT(seed)
    template = _WINDOW._clear_window(
        problem["base_state"], variant, problem["positions"]
    )
    inputs, state, prefix = _compile_symbolic_prefix(
        writer, template, variant, problem["positions"], prefix_rounds
    )
    state, suffix = _SMT._compile_suffix(
        writer, state, list(range(prefix_rounds, 24))
    )
    before_outputs = writer.assertions
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
        "output_assertions": writer.assertions - before_outputs,
        "native_xor_equations": True,
    }


def _render_query(
    writer: Any,
    inputs: list[str],
    fixed_prefix_bits: int,
    fixed_prefix_value: int | None,
) -> bytes:
    if fixed_prefix_bits == 0:
        return writer.render(inputs, include_model=True)
    if fixed_prefix_value is None:
        raise ValueError("a fixed prefix value is required")
    lines = list(writer.lines)
    for bit in range(fixed_prefix_bits):
        literal = (
            inputs[bit]
            if ((fixed_prefix_value >> bit) & 1)
            else f"(not {inputs[bit]})"
        )
        lines.append(f"(assert {literal})")
    lines.extend(
        [
            "(check-sat)",
            f"(get-value ({' '.join(inputs)}))",
            "(exit)",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def _new_trial(
    variant: Any,
    window_bits: int,
    seed: int,
    prefix_rounds: int,
    fixed_prefix_bits: int,
    fixed_prefix_value: int | None,
    timeout_seconds: int,
    z3: Path,
    work_dir: Path,
    keep_smt: bool,
) -> dict[str, Any]:
    problem = _NATIVE._problem(variant, window_bits, seed)
    writer, inputs, encoding = _encode_problem(
        problem, variant, seed, prefix_rounds
    )
    raw = _render_query(
        writer, inputs, fixed_prefix_bits, fixed_prefix_value
    )
    path = work_dir / (
        f"{variant.name.lower()}_w{window_bits}_r{prefix_rounds}_"
        f"p{fixed_prefix_bits}.smt2"
    )
    path.write_bytes(raw)
    solver = _SMT._run_z3(z3, path, timeout_seconds, inputs)
    if not keep_smt:
        path.unlink()
    actual = _WINDOW._extract_window(
        problem["base_state"], variant, problem["positions"]
    )
    assignment = solver["assignment"]
    verification = (
        _PARTITION._verify_assignment(problem, variant, assignment)
        if assignment is not None
        else None
    )
    return {
        "source": "A137_new_measurement",
        "variant": variant.name,
        "window_bits": window_bits,
        "seed": seed,
        "symbolic_prefix_rounds": prefix_rounds,
        "fixed_prefix_bits": fixed_prefix_bits,
        "fixed_prefix_value": fixed_prefix_value,
        "fixed_prefix_source": (
            "none" if fixed_prefix_bits == 0 else "A136_verified_model_branch"
        ),
        "actual_assignment_posthoc": actual,
        "actual_prefix_posthoc": (
            actual & ((1 << fixed_prefix_bits) - 1)
            if fixed_prefix_bits
            else None
        ),
        "assignment": assignment,
        "matches_instrumented_assignment": assignment == actual,
        "independent_verification": verification,
        "encoding": {
            **encoding,
            "smt_bytes": len(raw),
            "smt_sha256": hashlib.sha256(raw).hexdigest(),
        },
        "solver": _SMT._solver_summary(solver),
    }


def _retained_r2_trials(
    a135: dict[str, Any], a136: dict[str, Any]
) -> list[dict[str, Any]]:
    row12 = next(row for row in a135["trials"] if row["window_bits"] == 12)
    problem12 = _NATIVE._problem(
        _BASE.VARIANTS["shake128"], row12["window_bits"], row12["seed"]
    )
    verification12 = _PARTITION._verify_assignment(
        problem12, _BASE.VARIANTS["shake128"], row12["reconstructed_assignment"]
    )

    trial16 = a136["trial"]
    model16 = next(
        row for row in trial16["branches_detail"] if row["solver"]["status"] == "sat"
    )
    return [
        {
            "source": "A135_retained_hash_gated_artifact",
            "variant": row12["variant"],
            "window_bits": row12["window_bits"],
            "seed": row12["seed"],
            "symbolic_prefix_rounds": 2,
            "fixed_prefix_bits": 0,
            "fixed_prefix_value": None,
            "fixed_prefix_source": "none",
            "actual_assignment_posthoc": row12["actual_assignment"],
            "actual_prefix_posthoc": None,
            "assignment": row12["reconstructed_assignment"],
            "matches_instrumented_assignment": row12[
                "reconstruction_matches_ground_truth"
            ],
            "independent_verification": verification12,
            "encoding": row12["encoding"],
            "solver": row12["first_solver"],
        },
        {
            "source": "A136_retained_hash_gated_artifact",
            "variant": trial16["variant"],
            "window_bits": trial16["window_bits"],
            "seed": trial16["seed"],
            "symbolic_prefix_rounds": 2,
            "fixed_prefix_bits": trial16["partition_bits"],
            "fixed_prefix_value": model16["fixed_prefix"],
            "fixed_prefix_source": "A136_verified_model_branch",
            "actual_assignment_posthoc": trial16["actual_assignment_posthoc"],
            "actual_prefix_posthoc": trial16["actual_prefix_posthoc"],
            "assignment": model16["assignment"],
            "matches_instrumented_assignment": model16[
                "matches_instrumented_assignment"
            ],
            "independent_verification": model16["independent_verification"],
            "encoding": trial16["encoding"],
            "solver": model16["solver"],
        },
    ]


def _select(trials: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    eligible = [
        row
        for row in trials
        if row["matches_instrumented_assignment"]
        and row["independent_verification"]
        and row["independent_verification"]["complete_rate_match"]
        and row["solver"]["stats"].get("decisions") is not None
    ]
    if not eligible:
        return None
    best = min(
        eligible,
        key=lambda row: (
            row["solver"]["stats"]["decisions"],
            row["symbolic_prefix_rounds"],
        ),
    )
    return {
        "symbolic_prefix_rounds": best["symbolic_prefix_rounds"],
        "decisions": best["solver"]["stats"]["decisions"],
        "source": best["source"],
    }


def _build_graph(
    path: Path, prefix_rounds: list[int], timeout_seconds: int
) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_prefix_split_frontier",
        parameters={
            "variant": "shake128",
            "symbolic_prefix_rounds": prefix_rounds,
            "comparison_windows": [12, 16],
            "timeout_seconds": timeout_seconds,
            "prediction_before_measurement": (
                "R2 should minimize total Reader work: R1 leaves one additional "
                "explicit round, while R3 expands the shared symbolic dictionary."
            ),
        },
    )
    compile_id = "shake128-symbolic-prefix-split-family"
    solve_id = "shake128-split-family-complete-suffix-reader"
    builder.add_triplet(
        edge_id=compile_id,
        trigger="shake128:known_complement_plus_variable_capacity_window",
        mechanism="compile_exact_R1_R2_R3_boolean_ring_interfaces",
        outcome="shake128:symbolic_prefix_split_family",
        confidence=1.0,
        evidence_kind="exact_round_equations",
        source="A134_symbolic_compiler",
        attrs={"prefix_rounds": prefix_rounds},
    )
    builder.add_triplet(
        edge_id=solve_id,
        trigger="shake128:symbolic_prefix_split_family_plus_complete_next_rate",
        mechanism="attach_exact_remaining_rounds_and_measure_reader_work",
        outcome="shake128:split_indexed_models_and_solver_statistics",
        confidence=1.0,
        evidence_kind="complete_rate_models_with_independent_round_gate",
        source="Z3_Boolean_SMT",
        provenance=[compile_id],
    )
    builder.add_triplet(
        edge_id="shake128-minimum-decision-split-selection",
        trigger="shake128:split_indexed_models_and_solver_statistics",
        mechanism="select_minimum_decisions_among_exact_verified_models",
        outcome="shake128:retained_symbolic_split",
        confidence=1.0,
        evidence_kind="deterministic_exact_representation_comparison",
        source="A135_A136_hash_gated_plus_A137",
        provenance=[solve_id],
    )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 3:
        raise RuntimeError("SHAKE symbolic split causal graph gate failed")
    return stats


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix-rounds", default="1,2,3")
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument(
        "--z3", type=Path, default=Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    )
    parser.add_argument(
        "--a135",
        type=Path,
        default=Path("research/results/v1/shake_symbolic_r2_smt_reader_v1.json"),
    )
    parser.add_argument(
        "--a136",
        type=Path,
        default=Path("research/results/v1/shake_symbolic_r2_partition_reader_v1.json"),
    )
    parser.add_argument(
        "--work-dir", type=Path, default=Path("build/shake-symbolic-split")
    )
    parser.add_argument("--keep-smt", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()

    rounds = sorted({int(value) for value in args.prefix_rounds.split(",")})
    if rounds != [1, 2, 3]:
        raise ValueError("the canonical frontier compares symbolic splits R1, R2, R3")
    if args.timeout_seconds < 1:
        raise ValueError("timeout must be positive")
    z3 = Path(shutil.which(str(args.z3)) or args.z3)
    if not z3.is_file():
        raise FileNotFoundError(f"Z3 executable not found: {args.z3}")
    version = subprocess.run(
        [str(z3), "-version"], check=True, capture_output=True, text=True
    ).stdout.strip()

    a135 = _load_hashed_json(args.a135, A135_SHA256)
    a136 = _load_hashed_json(args.a136, A136_SHA256)
    retained = _retained_r2_trials(a135, a136)
    args.work_dir.mkdir(parents=True, exist_ok=True)
    causal = _build_graph(args.causal_output, rounds, args.timeout_seconds)
    reader = CryptoCausalReader(args.causal_output)
    variant = _BASE.VARIANTS["shake128"]

    trials = list(retained)
    cases = [
        {
            "window_bits": 12,
            "seed": 89753019,
            "fixed_prefix_bits": 0,
            "fixed_prefix_value": None,
        },
        {
            "window_bits": 16,
            "seed": 89754028,
            "fixed_prefix_bits": 4,
            "fixed_prefix_value": 13,
        },
    ]
    for case in cases:
        for prefix_rounds in (1, 3):
            print(
                "SHAKE128 symbolic split "
                f"window={case['window_bits']} prefix_rounds={prefix_rounds}",
                flush=True,
            )
            trials.append(
                _new_trial(
                    variant=variant,
                    prefix_rounds=prefix_rounds,
                    timeout_seconds=args.timeout_seconds,
                    z3=z3,
                    work_dir=args.work_dir,
                    keep_smt=args.keep_smt,
                    **case,
                )
            )
    trials.sort(key=lambda row: (row["window_bits"], row["symbolic_prefix_rounds"]))
    selections = {
        str(bits): _select(row for row in trials if row["window_bits"] == bits)
        for bits in (12, 16)
    }
    payload = {
        "schema": "shake-symbolic-prefix-split-frontier-v1",
        "evidence_stage": "EXACT_SYMBOLIC_SPLIT_FRONTIER_MEASURED",
        "result": (
            "Exact R1/R2/R3 symbolic interfaces were compared against the same "
            "complete remaining-round state-consistency queries."
        ),
        "scope": (
            "SHAKE128 known-complement state windows; monolithic width 12 and "
            "the independently verified A136 width-16 model branch."
        ),
        "parameters": {
            "solver": version,
            "solver_threads": 1,
            "timeout_seconds": args.timeout_seconds,
            "symbolic_prefix_rounds": rounds,
            "a135_sha256": A135_SHA256,
            "a136_sha256": A136_SHA256,
            "r2_measurements_reused_not_rerun": True,
        },
        "causal": causal,
        "reader_triplets": reader.triplets(include_inferred=False),
        "trials": trials,
        "minimum_decision_split_by_window": selections,
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
                        "window_bits": row["window_bits"],
                        "prefix_rounds": row["symbolic_prefix_rounds"],
                        "source": row["source"],
                        "status": row["solver"]["status"],
                        "correct": row["matches_instrumented_assignment"],
                        "decisions": row["solver"]["stats"].get("decisions"),
                        "monomials": row["encoding"].get(
                            "symbolic_monomials",
                            row["encoding"].get("r2_symbolic_monomials"),
                        ),
                    }
                    for row in trials
                ],
                "minimum_decision_split_by_window": selections,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
