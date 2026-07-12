#!/usr/bin/env python3
"""Prospective external-CNF variable-order transfer over the ChaCha10 cover."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
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


_A202 = _import_sibling(
    "chacha20_round10_b8_global_cse.py",
    "chacha20_round10_external_cnf_a202_anchor",
)
_A203 = _import_sibling(
    "chacha20_round10_b8_lane_major.py",
    "chacha20_round10_external_cnf_a203_anchor",
)
_A198 = _A202._A198
_A188 = _A198._A188

ATTEMPT_ID = "A204"
SCHEMA = "chacha20-round10-external-cnf-reverse-v1"
PROTOCOL_SCHEMA = "chacha20-round10-external-cnf-reverse-protocol-v1"
PROTOCOL_FILENAME = "chacha20_round10_external_cnf_reverse_v1.json"
PROTOCOL_SHA256 = "82b62901d1925e6d7eda5d5f01bbdb2677c289ffccf1501605e2ddcdaf3b28b4"
RESULT_FILENAME = "chacha20_round10_external_cnf_reverse_v1.json"
CAUSAL_FILENAME = "chacha20_round10_external_cnf_reverse_v1.causal"

A188_FILENAME = _A188.RESULT_FILENAME
A188_SHA256 = "d1a75d6456f75257cbd0be41864fad0810540508aa5c30239b16bd3998eef73a"
A188_CAUSAL_FILENAME = _A188.CAUSAL_FILENAME
A188_CAUSAL_SHA256 = "a717e615cfc005fe985a24059f7e6bedcd8008c460b274bb313f6ddfc53e7c78"
A202_FILENAME = _A202.RESULT_FILENAME
A202_SHA256 = "4fbfc950984d3cb8eee85ba5532217cab2edae43e7ed8444ff2363259d3e990b"
A202_CAUSAL_FILENAME = _A202.CAUSAL_FILENAME
A202_CAUSAL_SHA256 = "fb2dd421e7a6ff89c668f908d6760a53a91728f2ce5881cde8188bff10522ac3"
A203_FILENAME = _A203.RESULT_FILENAME
A203_SHA256 = "65fb21c0aec9cfe1b599b3c2c73ed9a2e34f0640899db3b31099b3c6d1d37d35"
A203_CAUSAL_FILENAME = _A203.CAUSAL_FILENAME
A203_CAUSAL_SHA256 = "a8bfda40ac3220da210fe36847f5c71e9b2e79bed5aeac13c691d89488667c22"

ROUNDS = 10
BLOCK_COUNT = 8
UNKNOWN_KEY_BITS = 20
FREE_BITS = 15
LOW_MASK = (1 << UNKNOWN_KEY_BITS) - 1
PREFIXES = tuple(f"{value:05b}" for value in range(32))
VARIANTS = tuple(f"cse_prefix_{prefix}" for prefix in PREFIXES)
MAX_PARALLEL_WORKERS = 4
CNF_EXPORT_LIMIT_MS = 3_000
SOLVER_LIMIT_SECONDS = 10
EXTERNAL_TIMEOUT_SECONDS = 13
A188_SOLVER_LIMIT_SECONDS = 5
A188_EXTERNAL_TIMEOUT_SECONDS = 8
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A202._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A202._file_sha256(path)


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    if _file_sha256(path) != PROTOCOL_SHA256:
        raise RuntimeError("A204 frozen protocol hash differs")
    protocol = json.loads(path.read_bytes())
    boundary = protocol.get("information_boundary", {})
    calibration = protocol.get("A188_external_cnf_calibration", {})
    freeze = protocol.get("A202_round10_cnf_freeze", {})
    plan = protocol.get("execution_plan", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A188_external_CNF_solver_calibration_and_A202_CNF_structure_mapping_before_any_A204_round10_solver_execution"
        or calibration.get("tested_configuration_count") != 26
        or calibration.get("selected_variant") != "cadical_reverse"
        or sum(row.get("status_at_5000ms") == "sat" for row in calibration.get("outcomes", [])) != 1
        or freeze.get("cell_count") != 32
        or freeze.get("free_bits_per_cell") != FREE_BITS
        or freeze.get("common_header") != "p cnf 232191 734180"
        or freeze.get("common_normalized_sha256")
        != "a9cd80dc9e7934f3c29681a78e4d734d598205e81b9796e9413b78be85e4fa2b"
        or len(freeze.get("per_cell_manifest", [])) != 32
        or plan.get("partition_prefix_order") != list(PREFIXES)
        or plan.get("solver_time_limit_seconds_per_cell") != SOLVER_LIMIT_SECONDS
        or plan.get("max_parallel_workers") != MAX_PARALLEL_WORKERS
        or boundary.get("A204_round10_solver_outcomes_used_before_protocol_freeze") is not False
        or boundary.get("all_32_round10_CNF_hashes_known_before_execution") is not True
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
        or boundary.get("unknown_assignment_available_to_runner_before_execution") is not False
        or boundary.get("mapping_or_cell_order_or_budget_changed_after_any_A204_outcome")
        is not False
        or boundary.get("early_stop_permitted") is not False
    ):
        raise RuntimeError("A204 frozen protocol identity gate failed")
    return protocol


def _load_anchor(
    results_dir: Path,
    *,
    label: str,
    result_name: str,
    result_sha256: str,
    causal_name: str,
    causal_sha256: str,
    evidence_stage: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    result_path = results_dir / result_name
    causal_path = results_dir / causal_name
    if _file_sha256(result_path) != result_sha256 or _file_sha256(causal_path) != causal_sha256:
        raise RuntimeError(f"A204 {label} anchor hash gate failed")
    payload = json.loads(result_path.read_bytes())
    reader = CryptoCausalReader(causal_path)
    if (
        payload.get("evidence_stage") != evidence_stage
        or reader.file_sha256 != causal_sha256
        or reader.graph_sha256 != payload.get("causal", {}).get("graph_sha256")
        or not reader.verify_provenance()
    ):
        raise RuntimeError(f"A204 {label} anchor content gate failed")
    return payload, {
        f"{label}_result_sha256": result_sha256,
        f"{label}_causal_sha256": causal_sha256,
        f"{label}_causal_graph_sha256": reader.graph_sha256,
        f"{label}_causal_provenance_verified": True,
    }


def _load_anchor_gates(results_dir: Path) -> dict[str, Any]:
    a188, gates188 = _load_anchor(
        results_dir,
        label="A188",
        result_name=A188_FILENAME,
        result_sha256=A188_SHA256,
        causal_name=A188_CAUSAL_FILENAME,
        causal_sha256=A188_CAUSAL_SHA256,
        evidence_stage="CROSS_ENGINE_ROUND5_RECOVERY_BOUNDARY_RETAINED",
    )
    a202, gates202 = _load_anchor(
        results_dir,
        label="A202",
        result_name=A202_FILENAME,
        result_sha256=A202_SHA256,
        causal_name=A202_CAUSAL_FILENAME,
        causal_sha256=A202_CAUSAL_SHA256,
        evidence_stage="ROUND10_GLOBAL_CSE_COMPLETE_PARTITION_BOUNDARY_RETAINED",
    )
    a203, gates203 = _load_anchor(
        results_dir,
        label="A203",
        result_name=A203_FILENAME,
        result_sha256=A203_SHA256,
        causal_name=A203_CAUSAL_FILENAME,
        causal_sha256=A203_CAUSAL_SHA256,
        evidence_stage="ROUND10_LANE_MAJOR_COMPLETE_PARTITION_BOUNDARY_RETAINED",
    )
    confirmations = a188.get("confirmations", [])
    if (
        len(confirmations) != 1
        or confirmations[0].get("combined_assignment") != 357645702403
        or confirmations[0].get("all_blocks_match") is not True
        or confirmations[0].get("control_first_block_match") is not False
        or a202.get("comparisons", {}).get("status_counts")
        != {"sat": 0, "unsat": 0, "unknown": 32, "invalid": 0}
        or a203.get("comparisons", {}).get("status_counts")
        != {"sat": 0, "unsat": 0, "unknown": 32, "invalid": 0}
    ):
        raise RuntimeError("A204 retained anchor semantic gate failed")
    return {
        **gates188,
        **gates202,
        **gates203,
        "A188_full_40bit_recovery_confirmation_retained": True,
        "A202_A203_complete_round10_covers_all_unknown": True,
    }


def _solver_gates(protocol: dict[str, Any]) -> dict[str, dict[str, Any]]:
    identities: dict[str, dict[str, Any]] = {}
    for name in ("bitwuzla", "cadical", "kissat", "cryptominisat5", "minisat"):
        raw_path = shutil.which(name)
        if raw_path is None:
            raise FileNotFoundError(f"A204 solver executable not found: {name}")
        path = Path(raw_path)
        expected = protocol["solver_binaries"][name]
        observed_hash = _file_sha256(path)
        if observed_hash != expected["executable_sha256"]:
            raise RuntimeError(f"A204 frozen {name} executable identity gate failed")
        identities[name] = {
            "path": str(path),
            "version": expected["version"],
            "executable_sha256": observed_hash,
        }
    bitwuzla_version = (
        subprocess.run(
            [identities["bitwuzla"]["path"], "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
        .stdout.strip()
        .splitlines()[0]
    )
    cadical_version = (
        subprocess.run(
            [identities["cadical"]["path"], "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
        .stdout.strip()
        .splitlines()[0]
    )
    if bitwuzla_version != "0.9.1" or cadical_version != "3.0.0":
        raise RuntimeError("A204 selected solver version gate failed")
    return identities


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    anchors = _load_anchor_gates(results_dir)
    a202_analysis = _A202.analyze(results_dir)
    a188_analysis = _A188.analyze(results_dir)
    if (
        tuple(a202_analysis["formulas"]) != VARIANTS
        or a202_analysis["public_challenge"]["unknown_assignment_included"] is not False
        or a202_analysis["public_challenge"]["unknown_key_word0_low_value_included"] is not False
        or a188_analysis["public_challenge"]["unknown_assignment_included"] is not False
        or a188_analysis["public_challenge"]["unknown_key_word0_included"] is not False
    ):
        raise RuntimeError("A204 public challenge boundary gate failed")
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "public_challenge": a202_analysis["public_challenge"],
        "a188_public_challenge": a188_analysis["public_challenge"],
        "a188_formula": a188_analysis["formulas"]["bitwuzla_bitblast_b8"],
        "formulas": a202_analysis["formulas"],
        "formula_plan": a202_analysis["formula_plan"],
        "solver_execution_started": False,
    }


def _normalized_cnf(raw: bytes) -> tuple[str, list[int], str]:
    lines = raw.splitlines(keepends=True)
    if len(lines) < 6:
        raise RuntimeError("A204 CNF is truncated")
    header = lines[0].decode().strip()
    tail_units = []
    normalized_tail = []
    for line in lines[-5:]:
        fields = line.split()
        if len(fields) != 2 or fields[1] != b"0":
            raise RuntimeError("A204 CNF prefix tail is not five unit clauses")
        literal = int(fields[0])
        tail_units.append(literal)
        normalized_tail.append(f"{abs(literal)} 0\n".encode())
    normalized = b"".join([*lines[:-5], *normalized_tail])
    return header, tail_units, _sha256(normalized)


def _export_cnf(
    *,
    variant: str,
    formula: str,
    output: Path,
    bitwuzla_path: str,
    limit_ms: int,
) -> dict[str, Any]:
    command = [
        bitwuzla_path,
        "--lang",
        "smt2",
        "--time-limit",
        str(limit_ms),
        "--bv-solver",
        "bitblast",
        "--sat-solver",
        "cadical",
        f"--write-cnf={output}",
    ]
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            input=formula,
            text=True,
            capture_output=True,
            timeout=limit_ms / 1000 + 5,
            check=False,
        )
        externally_timed_out = False
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        externally_timed_out = True
        stdout, stderr, returncode = _as_text(error.stdout), _as_text(error.stderr), None
    if not output.exists():
        raise RuntimeError(f"A204 {variant} CNF export did not produce a file")
    raw = output.read_bytes()
    header, tail_units, normalized_sha256 = _normalized_cnf(raw)
    status = next(
        (line for line in stdout.splitlines() if line in {"sat", "unsat", "unknown"}),
        "invalid",
    )
    return {
        "variant": variant,
        "prefix": variant[-5:] if variant.startswith("cse_prefix_") else None,
        "path": str(output),
        "bytes": len(raw),
        "sha256": _sha256(raw),
        "header": header,
        "normalized_sha256": normalized_sha256,
        "tail_units": tail_units,
        "command": command,
        "export_status": status,
        "returncode": returncode,
        "externally_timed_out": externally_timed_out,
        "volatile_seconds": time.perf_counter() - started,
        "stdout_sha256": _sha256(stdout.encode()),
        "stderr_sha256": _sha256(stderr.encode()),
    }


def _parse_cadical_witness(stdout: str) -> dict[int, int]:
    literals = [
        int(raw)
        for line in stdout.splitlines()
        if line.startswith("v ")
        for raw in line[2:].split()
        if raw != "0"
    ]
    values: dict[int, int] = {}
    for literal in literals:
        variable = abs(literal)
        value = int(literal > 0)
        if variable in values and values[variable] != value:
            raise RuntimeError("A204 CaDiCaL witness assigns a variable twice inconsistently")
        values[variable] = value
    return values


def _cadical_status(stdout: str, returncode: int | None) -> str:
    status_lines = [
        line.strip()
        for line in stdout.splitlines()
        if line.strip() in {"s SATISFIABLE", "s UNSATISFIABLE", "s UNKNOWN"}
    ]
    if len(status_lines) > 1:
        return "invalid"
    if not status_lines:
        return (
            "unknown"
            if returncode == 0
            and any(line.startswith("c Timeout reached!") for line in stdout.splitlines())
            else "invalid"
        )
    status = {
        "s SATISFIABLE": "sat",
        "s UNSATISFIABLE": "unsat",
        "s UNKNOWN": "unknown",
    }[status_lines[0]]
    expected_returncode = {"sat": 10, "unsat": 20, "unknown": 0}[status]
    return status if returncode == expected_returncode else "invalid"


def _kissat_status(stdout: str, returncode: int | None) -> str:
    status_lines = [
        line.strip()
        for line in stdout.splitlines()
        if line.strip() in {"s SATISFIABLE", "s UNSATISFIABLE", "s UNKNOWN"}
    ]
    if len(status_lines) > 1:
        return "invalid"
    if not status_lines:
        clean_shutdown = (
            "c ---- [ shutting down ]" in stdout and "c exit 0" in stdout and returncode == 0
        )
        return "unknown" if clean_shutdown else "invalid"
    status = {
        "s SATISFIABLE": "sat",
        "s UNSATISFIABLE": "unsat",
        "s UNKNOWN": "unknown",
    }[status_lines[0]]
    expected_returncode = {"sat": 10, "unsat": 20, "unknown": 0}[status]
    return status if returncode == expected_returncode else "invalid"


def _run_cadical(
    *,
    variant: str,
    cnf_path: Path,
    cadical_path: str,
    limit_seconds: int,
    external_timeout_seconds: int,
) -> tuple[dict[str, Any], dict[int, int]]:
    command = [cadical_path, "--reverse=true", "-t", str(limit_seconds), str(cnf_path)]
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=external_timeout_seconds,
            check=False,
        )
        externally_timed_out = False
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        externally_timed_out = True
        stdout, stderr, returncode = _as_text(error.stdout), _as_text(error.stderr), None
    status = _cadical_status(stdout, returncode)
    witness = _parse_cadical_witness(stdout) if status == "sat" else {}
    status_lines = [line.strip() for line in stdout.splitlines() if line.startswith("s ")]
    return (
        {
            "variant": variant,
            "command": command,
            "status": status,
            "status_line": status_lines[0] if len(status_lines) == 1 else None,
            "internal_timeout_marker": any(
                line.startswith("c Timeout reached!") for line in stdout.splitlines()
            ),
            "returncode": returncode,
            "externally_timed_out": externally_timed_out,
            "volatile_seconds": time.perf_counter() - started,
            "witness_assignment_count": len(witness),
            "stdout_sha256": _sha256(stdout.encode()),
            "stderr_sha256": _sha256(stderr.encode()),
        },
        witness,
    )


def _decode_literals(values: dict[int, int], one_literals: Sequence[int]) -> int:
    missing = [abs(literal) for literal in one_literals if abs(literal) not in values]
    if missing:
        raise RuntimeError(f"A204 witness misses mapped variables: {missing}")
    result = 0
    for bit, one_literal in enumerate(one_literals):
        variable_value = values[abs(one_literal)]
        bit_value = variable_value if one_literal > 0 else 1 - variable_value
        result |= bit_value << bit
    return result


def _calibration_specs(
    identities: dict[str, dict[str, Any]], cnf_path: Path, directory: Path
) -> list[dict[str, Any]]:
    cadical = identities["cadical"]["path"]
    kissat = identities["kissat"]["path"]
    cms = identities["cryptominisat5"]["path"]
    minisat = identities["minisat"]["path"]
    specs = [
        ("cadical_default", "cadical", [cadical, "-t", "5", str(cnf_path)]),
        ("kissat_default", "kissat", [kissat, "--time=5", str(cnf_path)]),
        (
            "cryptominisat_default",
            "cryptominisat5",
            [cms, "--verb", "0", "--maxtime", "5", "--threads", "1", str(cnf_path)],
        ),
        ("minisat_default", "minisat", [minisat, "-verb=0", "-cpu-lim=5", str(cnf_path)]),
        ("cadical_sat", "cadical", [cadical, "--sat", "-t", "5", str(cnf_path)]),
        ("cadical_plain", "cadical", [cadical, "--plain", "-t", "5", str(cnf_path)]),
        (
            "cadical_phase_false",
            "cadical",
            [cadical, "--phase=false", "-t", "5", str(cnf_path)],
        ),
        (
            "cadical_target2",
            "cadical",
            [cadical, "--target=2", "-t", "5", str(cnf_path)],
        ),
        (
            "cadical_reverse",
            "cadical",
            [cadical, "--reverse=true", "-t", "5", str(cnf_path)],
        ),
        ("cadical_seed1", "cadical", [cadical, "--seed=1", "-t", "5", str(cnf_path)]),
        ("cadical_seed2", "cadical", [cadical, "--seed=2", "-t", "5", str(cnf_path)]),
        ("kissat_sat", "kissat", [kissat, "--sat", "--time=5", str(cnf_path)]),
        ("kissat_plain", "kissat", [kissat, "--plain", "--time=5", str(cnf_path)]),
        (
            "kissat_phase_false",
            "kissat",
            [kissat, "--phase=false", "--time=5", str(cnf_path)],
        ),
        (
            "kissat_stable0",
            "kissat",
            [kissat, "--stable=0", "--time=5", str(cnf_path)],
        ),
        ("kissat_seed1", "kissat", [kissat, "--seed=1", "--time=5", str(cnf_path)]),
        ("kissat_seed2", "kissat", [kissat, "--seed=2", "--time=5", str(cnf_path)]),
        (
            "cms_polar_true",
            "cryptominisat5",
            [
                cms,
                "--verb",
                "0",
                "--maxtime",
                "5",
                "--threads",
                "1",
                "--polar",
                "true",
                str(cnf_path),
            ],
        ),
        (
            "cms_polar_false",
            "cryptominisat5",
            [
                cms,
                "--verb",
                "0",
                "--maxtime",
                "5",
                "--threads",
                "1",
                "--polar",
                "false",
                str(cnf_path),
            ],
        ),
        (
            "cms_polar_rnd",
            "cryptominisat5",
            [
                cms,
                "--verb",
                "0",
                "--maxtime",
                "5",
                "--threads",
                "1",
                "--polar",
                "rnd",
                str(cnf_path),
            ],
        ),
        (
            "cms_polar_stable",
            "cryptominisat5",
            [
                cms,
                "--verb",
                "0",
                "--maxtime",
                "5",
                "--threads",
                "1",
                "--polar",
                "stable",
                str(cnf_path),
            ],
        ),
        (
            "cms_branch_vsids",
            "cryptominisat5",
            [
                cms,
                "--verb",
                "0",
                "--maxtime",
                "5",
                "--threads",
                "1",
                "--branchstr",
                "vsids",
                str(cnf_path),
            ],
        ),
        (
            "cms_branch_vmtf",
            "cryptominisat5",
            [
                cms,
                "--verb",
                "0",
                "--maxtime",
                "5",
                "--threads",
                "1",
                "--branchstr",
                "vmtf",
                str(cnf_path),
            ],
        ),
        (
            "minisat_rnd_init",
            "minisat",
            [minisat, "-verb=0", "-cpu-lim=5", "-rnd-init", str(cnf_path)],
        ),
        (
            "minisat_phase0",
            "minisat",
            [minisat, "-verb=0", "-cpu-lim=5", "-phase-saving=0", str(cnf_path)],
        ),
        (
            "minisat_phase1",
            "minisat",
            [minisat, "-verb=0", "-cpu-lim=5", "-phase-saving=1", str(cnf_path)],
        ),
    ]
    result = []
    for variant, engine, command in specs:
        witness_path = directory / f"{variant}.result" if engine == "minisat" else None
        if witness_path is not None:
            command = [*command, str(witness_path)]
        result.append(
            {
                "variant": variant,
                "engine": engine,
                "command": command,
                "witness_path": witness_path,
            }
        )
    return result


def _generic_solver_status(text: str, returncode: int | None) -> str:
    if "UNSATISFIABLE" in text or text.startswith("UNSAT"):
        return "unsat"
    if "SATISFIABLE" in text or text.startswith("SAT"):
        return "sat"
    if "INDETERMINATE" in text or "UNKNOWN" in text:
        return "unknown"
    return "invalid"


def _parse_generic_witness(text: str) -> dict[int, int]:
    literals = []
    for line in text.splitlines():
        if line.startswith("v "):
            literals.extend(int(raw) for raw in line[2:].split() if raw != "0")
    lines = text.splitlines()
    if lines and lines[0] == "SAT" and len(lines) >= 2:
        literals.extend(int(raw) for raw in lines[1].split() if raw != "0")
    values: dict[int, int] = {}
    for literal in literals:
        variable = abs(literal)
        value = int(literal > 0)
        if variable in values and values[variable] != value:
            raise RuntimeError("A204 calibration witness is internally inconsistent")
        values[variable] = value
    return values


def _run_calibration_spec(
    spec: dict[str, Any], *, external_timeout_seconds: int
) -> tuple[dict[str, Any], dict[int, int]]:
    witness_path = spec["witness_path"]
    if witness_path is not None and witness_path.exists():
        witness_path.unlink()
    started = time.perf_counter()
    try:
        result = subprocess.run(
            spec["command"],
            text=True,
            capture_output=True,
            timeout=external_timeout_seconds,
            check=False,
        )
        externally_timed_out = False
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        externally_timed_out = True
        stdout, stderr, returncode = _as_text(error.stdout), _as_text(error.stderr), None
    witness_text = (
        witness_path.read_text() if witness_path is not None and witness_path.exists() else ""
    )
    combined = stdout + stderr + witness_text
    if spec["engine"] == "cadical":
        status = _cadical_status(stdout, returncode)
    elif spec["engine"] == "kissat":
        status = _kissat_status(stdout, returncode)
    else:
        status = _generic_solver_status(combined, returncode)
    witness = _parse_generic_witness(stdout + witness_text) if status == "sat" else {}
    return (
        {
            "variant": spec["variant"],
            "engine": spec["engine"],
            "command": spec["command"],
            "status": status,
            "status_line": next(
                (line.strip() for line in combined.splitlines() if line.startswith("s ")), None
            ),
            "internal_timeout_marker": (
                any(line.startswith("c Timeout reached!") for line in stdout.splitlines())
                if spec["engine"] == "cadical"
                else (
                    "c ---- [ shutting down ]" in stdout and "c exit 0" in stdout
                    if spec["engine"] == "kissat"
                    else "INDETERMINATE" in combined
                )
            ),
            "returncode": returncode,
            "externally_timed_out": externally_timed_out,
            "volatile_seconds": time.perf_counter() - started,
            "witness_assignment_count": len(witness),
            "stdout_sha256": _sha256(stdout.encode()),
            "stderr_sha256": _sha256(stderr.encode()),
            "witness_sha256": _sha256(witness_text.encode()),
        },
        witness,
    )


def _replay_a188_calibration(
    analysis: dict[str, Any], identities: dict[str, dict[str, Any]], directory: Path
) -> dict[str, Any]:
    protocol = analysis["protocol"]
    calibration = protocol["A188_external_cnf_calibration"]
    cnf_path = directory / "A188.cnf"
    exported = _export_cnf(
        variant="A188_bitwuzla_bitblast_b8",
        formula=analysis["a188_formula"],
        output=cnf_path,
        bitwuzla_path=identities["bitwuzla"]["path"],
        limit_ms=1_000,
    )
    if (
        exported["sha256"] != calibration["cnf_sha256"]
        or exported["bytes"] != calibration["cnf_bytes"]
        or exported["header"] != calibration["cnf_header"]
    ):
        raise RuntimeError("A204 A188 replay CNF identity gate failed")
    observations = []
    specs = _calibration_specs(identities, cnf_path, directory)
    for spec in specs:
        observation, witness = _run_calibration_spec(
            spec, external_timeout_seconds=A188_EXTERNAL_TIMEOUT_SECONDS
        )
        observations.append(observation)
    expected_outcomes = calibration["outcomes"]
    observed_outcomes = [
        {"variant": row["variant"], "status_at_5000ms": row["status"]} for row in observations
    ]
    frozen_outcomes_match = observed_outcomes == expected_outcomes
    selected_variant = calibration["selected_variant"]
    nonselected_sat = [
        row["variant"]
        for row in observations
        if row["status"] == "sat" and row["variant"] != selected_variant
    ]
    if (
        [row["variant"] for row in observed_outcomes]
        != [row["variant"] for row in expected_outcomes]
        or any(row["status"] == "invalid" or row["externally_timed_out"] for row in observations)
        or nonselected_sat
    ):
        differences = [
            {"expected": expected, "observed": observed}
            for expected, observed in zip(expected_outcomes, observed_outcomes, strict=True)
            if expected != observed
        ]
        raise RuntimeError(
            "A204 full calibration selector replay gate failed: "
            + json.dumps(differences, sort_keys=True)
        )
    selected_matrix_observation = next(
        row for row in observations if row["variant"] == selected_variant
    )
    selected_spec = next(spec for spec in specs if spec["variant"] == selected_variant)
    selected_replicates = []
    selected_witnesses = []
    for replicate_index in range(3):
        observation, witness = _run_calibration_spec(
            selected_spec, external_timeout_seconds=A188_EXTERNAL_TIMEOUT_SECONDS
        )
        observation["replicate_index"] = replicate_index
        selected_replicates.append(observation)
        selected_witnesses.append(witness)
    if any(
        row["status"] == "invalid" or row["externally_timed_out"] for row in selected_replicates
    ):
        raise RuntimeError(
            "A204 selected calibration replicate was invalid or externally timed out"
        )
    sat_replicates = [
        (row, witness)
        for row, witness in zip(selected_replicates, selected_witnesses, strict=True)
        if row["status"] == "sat"
    ]
    if not sat_replicates:
        raise RuntimeError(
            "A204 selected calibration returned no SAT across three fixed replicates"
        )
    mapping = calibration["key_bit_one_literal_mapping"]
    expected = calibration["recovered_model"]
    confirmed_replicates = []
    for observation, witness in sat_replicates:
        key_word0 = _decode_literals(witness, mapping["k0"])
        key_word1_low_value = _decode_literals(witness, mapping["lo8"])
        model = {
            "key_word0": key_word0,
            "key_word1_low_value": key_word1_low_value,
            "combined_assignment": (key_word1_low_value << 32) | key_word0,
        }
        confirmation = _A188._A187._confirm_model(
            analysis["a188_public_challenge"], BLOCK_COUNT, model
        )
        if (
            model["key_word0"] != expected["key_word0"]
            or model["key_word1_low_value"] != expected["key_word1_low_value"]
            or confirmation["all_blocks_match"] is not True
            or confirmation["control_first_block_match"] is not False
            or confirmation["output_bits_checked"] != 4096
        ):
            raise RuntimeError("A204 A188 external calibration replay model failed")
        confirmed_replicates.append(
            {
                "replicate_index": observation["replicate_index"],
                "model": model,
                "confirmation": confirmation,
            }
        )
    model = confirmed_replicates[0]["model"]
    confirmation = confirmed_replicates[0]["confirmation"]
    return {
        "export": {key: value for key, value in exported.items() if key != "path"},
        "observations": observations,
        "frozen_outcomes_match": frozen_outcomes_match,
        "selected_matrix_observation": selected_matrix_observation,
        "selected_replicates": selected_replicates,
        "selected_sat_replicate_count": len(sat_replicates),
        "selected_confirmed_replicates": confirmed_replicates,
        "selected_observation": sat_replicates[0][0],
        "model": model,
        "confirmation": confirmation,
        "retained": True,
    }


def _export_round10_cnfs(
    analysis: dict[str, Any], identities: dict[str, dict[str, Any]], directory: Path
) -> tuple[list[dict[str, Any]], dict[str, Path]]:
    protocol_manifest = analysis["protocol"]["A202_round10_cnf_freeze"]["per_cell_manifest"]
    expected_by_variant = {row["variant"]: row for row in protocol_manifest}

    def export(variant: str) -> dict[str, Any]:
        return _export_cnf(
            variant=variant,
            formula=analysis["formulas"][variant],
            output=directory / f"{variant}.cnf",
            bitwuzla_path=identities["bitwuzla"]["path"],
            limit_ms=CNF_EXPORT_LIMIT_MS,
        )

    observations = []
    for start in range(0, len(VARIANTS), MAX_PARALLEL_WORKERS):
        wave = VARIANTS[start : start + MAX_PARALLEL_WORKERS]
        with ThreadPoolExecutor(max_workers=MAX_PARALLEL_WORKERS) as executor:
            observations.extend(executor.map(export, wave))
    for row in observations:
        expected = expected_by_variant[row["variant"]]
        retained = {
            key: row[key]
            for key in (
                "variant",
                "prefix",
                "bytes",
                "sha256",
                "header",
                "normalized_sha256",
                "tail_units",
            )
        }
        if retained != expected:
            raise RuntimeError(f"A204 {row['variant']} frozen CNF manifest gate failed")
    return observations, {row["variant"]: Path(row["path"]) for row in observations}


def _cnf_body_sha256(path: Path, *, drop_last: bool = False) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        stream.readline()
        previous = None
        for line in stream:
            if previous is not None:
                digest.update(previous)
            previous = line
        if not drop_last and previous is not None:
            digest.update(previous)
    return digest.hexdigest()


def _probe_mapping_bit(
    *,
    label: str,
    formula: str,
    symbol: str,
    bit: int,
    expected_literal: int,
    base_path: Path,
    base_body_sha256: str,
    output: Path,
    bitwuzla_path: str,
    limit_ms: int,
) -> dict[str, Any]:
    assertion = f"(assert (= ((_ extract {bit} {bit}) {symbol}) #b1))"
    probe_formula = formula.replace("(check-sat)", assertion + "\n(check-sat)", 1)
    exported = _export_cnf(
        variant=label,
        formula=probe_formula,
        output=output,
        bitwuzla_path=bitwuzla_path,
        limit_ms=limit_ms,
    )
    with output.open("rb") as stream:
        probe_header = stream.readline().decode().strip()
        last_line = None
        for line in stream:
            last_line = line
    if last_line is None or len(last_line.split()) != 2 or last_line.split()[1] != b"0":
        raise RuntimeError(f"A204 {label} mapping probe has no final unit clause")
    added_literal = int(last_line.split()[0])
    base_header = base_path.open().readline().strip()
    base_fields = base_header.split()
    probe_fields = probe_header.split()
    exact_one_clause_delta = (
        base_fields[:3] == probe_fields[:3]
        and int(probe_fields[3]) == int(base_fields[3]) + 1
        and _cnf_body_sha256(output, drop_last=True) == base_body_sha256
    )
    if not exact_one_clause_delta or added_literal != expected_literal:
        raise RuntimeError(f"A204 {label} exact one-unit mapping gate failed")
    output.unlink()
    return {
        "label": label,
        "symbol": symbol,
        "bit": bit,
        "expected_one_literal": expected_literal,
        "observed_added_literal": added_literal,
        "base_header": base_header,
        "probe_header": probe_header,
        "base_body_sha256": base_body_sha256,
        "probe_body_without_added_unit_sha256": base_body_sha256,
        "probe_cnf_sha256": exported["sha256"],
        "probe_cnf_bytes": exported["bytes"],
        "export_status": exported["export_status"],
        "returncode": exported["returncode"],
        "externally_timed_out": exported["externally_timed_out"],
        "stdout_sha256": exported["stdout_sha256"],
        "stderr_sha256": exported["stderr_sha256"],
        "exactly_one_unit_clause_added": True,
    }


def _replay_mapping_derivation(
    analysis: dict[str, Any],
    identities: dict[str, dict[str, Any]],
    directory: Path,
    cnf_paths: dict[str, Path],
) -> dict[str, Any]:
    calibration = analysis["protocol"]["A188_external_cnf_calibration"]
    freeze = analysis["protocol"]["A202_round10_cnf_freeze"]
    bitwuzla_path = identities["bitwuzla"]["path"]
    a188_base = directory / "A188.cnf"
    a188_base_body = _cnf_body_sha256(a188_base)
    a188_jobs = [
        (symbol, bit, literal)
        for symbol in ("k0", "lo8")
        for bit, literal in enumerate(calibration["key_bit_one_literal_mapping"][symbol])
    ]

    def replay_a188(job: tuple[str, int, int]) -> dict[str, Any]:
        symbol, bit, literal = job
        return _probe_mapping_bit(
            label=f"A188_map_{symbol}_{bit}",
            formula=analysis["a188_formula"],
            symbol=symbol,
            bit=bit,
            expected_literal=literal,
            base_path=a188_base,
            base_body_sha256=a188_base_body,
            output=directory / f"A188_map_{symbol}_{bit}.cnf",
            bitwuzla_path=bitwuzla_path,
            limit_ms=1_000,
        )

    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_WORKERS) as executor:
        a188_rows = list(executor.map(replay_a188, a188_jobs))

    endpoints = freeze["mapping_verified_on_prefix_endpoints"]
    round10_jobs = [
        (prefix, bit, literal)
        for prefix in endpoints
        for bit, literal in enumerate(freeze["free_k0_bit_one_literal_mapping"])
    ]
    round10_base_body = {
        prefix: _cnf_body_sha256(cnf_paths[f"cse_prefix_{prefix}"]) for prefix in endpoints
    }

    def replay_round10(job: tuple[str, int, int]) -> dict[str, Any]:
        prefix, bit, literal = job
        variant = f"cse_prefix_{prefix}"
        return _probe_mapping_bit(
            label=f"A202_{prefix}_map_k0_{bit}",
            formula=analysis["formulas"][variant],
            symbol="k0",
            bit=bit,
            expected_literal=literal,
            base_path=cnf_paths[variant],
            base_body_sha256=round10_base_body[prefix],
            output=directory / f"A202_{prefix}_map_k0_{bit}.cnf",
            bitwuzla_path=bitwuzla_path,
            limit_ms=CNF_EXPORT_LIMIT_MS,
        )

    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_WORKERS) as executor:
        round10_rows = list(executor.map(replay_round10, round10_jobs))
    if [row["observed_added_literal"] for row in round10_rows[:FREE_BITS]] != [
        row["observed_added_literal"] for row in round10_rows[FREE_BITS:]
    ]:
        raise RuntimeError("A204 Round10 endpoint literal maps differ")
    return {
        "method": calibration["mapping_derivation"],
        "A188_base_cnf_sha256": _file_sha256(a188_base),
        "A188_base_body_sha256": a188_base_body,
        "A188_probe_count": len(a188_rows),
        "A188_probes": a188_rows,
        "Round10_endpoint_prefixes": endpoints,
        "Round10_base_body_sha256": round10_base_body,
        "Round10_probe_count": len(round10_rows),
        "Round10_probes": round10_rows,
        "Round10_endpoint_maps_identical": True,
        "all_70_probes_exactly_one_unit_clause": True,
    }


def _decode_round10_model(
    *,
    challenge: dict[str, Any],
    prefix: str,
    witness: dict[int, int],
    mapping: Sequence[int],
) -> dict[str, int]:
    free_value = _decode_literals(witness, mapping)
    key_word0 = challenge["known_key_word0_upper12"] | (int(prefix, 2) << FREE_BITS) | free_value
    key_word1_low_value = challenge["known_key_word1"] & 0xFF
    return {
        "key_word0": key_word0,
        "key_word1_low_value": key_word1_low_value,
        "combined_assignment": (key_word1_low_value << 32) | key_word0,
        "recovered_unknown_low20": key_word0 & LOW_MASK,
    }


def _execute_round10(
    analysis: dict[str, Any], identities: dict[str, dict[str, Any]], cnf_paths: dict[str, Path]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    mapping = analysis["protocol"]["A202_round10_cnf_freeze"]["free_k0_bit_one_literal_mapping"]
    observations = []
    confirmations = []
    waves = []
    for wave_index, start in enumerate(range(0, len(VARIANTS), MAX_PARALLEL_WORKERS)):
        wave = VARIANTS[start : start + MAX_PARALLEL_WORKERS]

        def execute(variant: str) -> tuple[dict[str, Any], dict[int, int]]:
            return _run_cadical(
                variant=variant,
                cnf_path=cnf_paths[variant],
                cadical_path=identities["cadical"]["path"],
                limit_seconds=SOLVER_LIMIT_SECONDS,
                external_timeout_seconds=EXTERNAL_TIMEOUT_SECONDS,
            )

        with ThreadPoolExecutor(max_workers=MAX_PARALLEL_WORKERS) as executor:
            rows = list(executor.map(execute, wave))
        for (observation, witness), variant in zip(rows, wave, strict=True):
            prefix = variant[-5:]
            observation.update(
                {
                    "prefix": prefix,
                    "free_bits": FREE_BITS,
                    "candidate_count": 1 << FREE_BITS,
                    "cnf_sha256": _file_sha256(cnf_paths[variant]),
                }
            )
            if observation["status"] == "sat":
                model = _decode_round10_model(
                    challenge=analysis["public_challenge"],
                    prefix=prefix,
                    witness=witness,
                    mapping=mapping,
                )
                confirmation = {
                    "variant": variant,
                    "prefix": prefix,
                    **_A198._confirm_model(analysis["public_challenge"], model),
                }
                if (
                    confirmation["known_key_constraints_match"] is not True
                    or confirmation["all_blocks_match"] is not True
                    or confirmation["control_first_block_match"] is not False
                    or confirmation["output_bits_checked"] != 4096
                ):
                    raise RuntimeError(
                        f"A204 {variant} decoded model failed independent confirmation"
                    )
                observation["model"] = model
                confirmations.append(confirmation)
            else:
                observation["model"] = None
            observations.append(observation)
        waves.append(
            {
                "wave_index": wave_index,
                "variants": list(wave),
                "statuses": [row[0]["status"] for row in rows],
                "maximum_volatile_seconds": max(row[0]["volatile_seconds"] for row in rows),
            }
        )
    if [row["variant"] for row in observations] != list(VARIANTS):
        raise RuntimeError("A204 did not execute the complete frozen variant plan")
    execution = {
        "variant_order": list(VARIANTS),
        "complete_variant_plan_executed": True,
        "early_stop_used": False,
        "observations": observations,
        "wave_observations": waves,
        "returned_model_count": len(confirmations),
        "unknown_assignment_available_to_runner_before_execution": False,
    }
    return execution, confirmations


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_round10_external_cnf_reverse",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "shared_key_blocks": BLOCK_COUNT,
            "cells": len(VARIANTS),
        },
    )
    ids = [
        "chacha20-a204-a188-recovery-anchor",
        "chacha20-a204-external-cnf-calibration",
        "chacha20-a204-exact-witness-map",
        "chacha20-a204-round10-boundary",
        "chacha20-a204-complete-cnf-cover",
        "chacha20-a204-reverse-order-execution",
        "chacha20-a204-independent-confirmation",
    ]
    rows = [
        (
            "A188:confirmed_40bit_round5_recovery",
            "retain_the_exact_eight_block_public_challenge_and_confirmation",
            "A204:known_positive_recovery_anchor",
            "retained_recovery_anchor",
            A188_CAUSAL_SHA256,
            [],
            {"anchor_gates": payload["anchor_gates"]},
        ),
        (
            "A204:known_positive_recovery_anchor",
            "export_one_identical_CNF_and_run_26_frozen_external_configurations",
            "A204:unique_cadical_reverse_selector",
            "external_solver_calibration",
            payload["calibration_replay_sha256"],
            [ids[0]],
            {
                "calibration": payload["calibration"],
                "calibration_replay": payload["calibration_replay"],
            },
        ),
        (
            "A204:unique_cadical_reverse_selector",
            "derive_each_key_bit_variable_by_exact_single_unit_clause_intervention",
            "A204:independently_decodable_external_witness",
            "exact_CNF_literal_mapping",
            payload["mapping_replay_sha256"],
            [ids[1]],
            {"mapping": payload["mapping"], "mapping_replay": payload["mapping_replay"]},
        ),
        (
            "A204:independently_decodable_external_witness",
            "anchor_A202_and_A203_complete_all_unknown_round10_covers",
            "A204:prospective_frontend_backend_transfer_question",
            "retained_round10_boundary",
            A203_CAUSAL_SHA256,
            [ids[2]],
            {"anchor_gates": payload["anchor_gates"]},
        ),
        (
            "A204:prospective_frontend_backend_transfer_question",
            "export_all_32_frozen_prefix_CNF_cells_with_one_common_normalized_skeleton",
            "A204:complete_external_CNF_cover",
            "complete_CNF_partition",
            payload["cnf_export_sha256"],
            [ids[3]],
            {"cnf_export": payload["cnf_export"]},
        ),
        (
            "A204:complete_external_CNF_cover",
            "execute_external_cadical_reverse_on_every_cell_at_10_seconds",
            "A204:complete_reverse_order_execution",
            "prospective_external_solver_execution",
            payload["execution_sha256"],
            [ids[4]],
            {"execution": payload["execution"]},
        ),
        (
            "A204:complete_reverse_order_execution",
            "decode_the_frozen_literal_map_and_recompute_all_4096_target_bits",
            "A204:prospective_external_CNF_result",
            "independent_model_confirmation",
            payload["comparison_sha256"],
            [ids[5]],
            {"confirmations": payload["confirmations"], "comparisons": payload["comparisons"]},
        ),
    ]
    for index, row in enumerate(rows):
        trigger, mechanism, outcome, kind, source, provenance, attrs = row
        builder.add_triplet(
            edge_id=ids[index],
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            evidence_kind=kind,
            source=source,
            provenance=provenance,
            attrs=attrs,
        )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = CryptoCausalReader(path)
    if len(reader.triplets(include_inferred=False)) != len(ids) or not reader.verify_provenance():
        raise RuntimeError("A204 Causal Reader provenance gate failed")
    return {
        "stats": stats,
        "explicit_triplets": len(ids),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def run(*, results_dir: Path, output: Path, causal_output: Path) -> dict[str, Any]:
    analysis = analyze(results_dir)
    identities = _solver_gates(analysis["protocol"])
    with tempfile.TemporaryDirectory(prefix="a204-external-cnf-") as raw_directory:
        directory = Path(raw_directory)
        calibration_replay = _replay_a188_calibration(analysis, identities, directory)
        cnf_exports, cnf_paths = _export_round10_cnfs(analysis, identities, directory)
        mapping_replay = _replay_mapping_derivation(analysis, identities, directory, cnf_paths)
        execution, confirmations = _execute_round10(analysis, identities, cnf_paths)

    status_counts = {
        status: sum(row["status"] == status for row in execution["observations"])
        for status in ("sat", "unsat", "unknown", "invalid")
    }
    recovered = sorted({row["recovered_unknown_low20"] for row in confirmations})
    resolved = status_counts["sat"] + status_counts["unsat"]
    primary = len(confirmations) >= 1
    secondary = resolved >= 1
    complete_recovery = (
        status_counts == {"sat": 1, "unsat": 31, "unknown": 0, "invalid": 0} and len(recovered) == 1
    )
    comparisons = {
        "A202_A203_baselines_reexecuted": False,
        "A202_A203_status": "all_32_unknown_at_10s",
        "complete_domain_candidate_count": 1 << UNKNOWN_KEY_BITS,
        "partition_complete_and_disjoint_by_construction": True,
        "status_counts": status_counts,
        "resolved_sat_plus_unsat_cell_count": resolved,
        "confirmed_variants": [row["variant"] for row in confirmations],
        "recovered_unknown_low20_assignments": recovered,
        "primary_prediction_retained": primary,
        "secondary_prediction_retained": secondary,
        "complete_recovery_gate_retained": complete_recovery,
        "statuses": {row["variant"]: row["status"] for row in execution["observations"]},
    }
    evidence_stage = (
        "ROUND10_EXTERNAL_CNF_COMPLETE_RECOVERY_RETAINED"
        if complete_recovery
        else (
            "ROUND10_EXTERNAL_CNF_CONFIRMED_RECOVERY_RETAINED"
            if primary
            else (
                "ROUND10_EXTERNAL_CNF_RESOLUTION_RETAINED"
                if secondary
                else "ROUND10_EXTERNAL_CNF_COMPLETE_PARTITION_BOUNDARY_RETAINED"
            )
        )
    )
    clean_exports = [
        {key: value for key, value in row.items() if key != "path"} for row in cnf_exports
    ]
    calibration = analysis["protocol"]["A188_external_cnf_calibration"]
    mapping = {
        "A188_key_bit_one_literal_mapping": calibration["key_bit_one_literal_mapping"],
        "A202_free_k0_bit_one_literal_mapping": analysis["protocol"]["A202_round10_cnf_freeze"][
            "free_k0_bit_one_literal_mapping"
        ],
        "derivation": calibration["mapping_derivation"],
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "A unique externally calibrated CNF variable-order rule is transferred "
            "prospectively to the complete ChaCha10 numeric-prefix cover."
        ),
        "scope": "Reduced ChaCha10 width-20 partial-key recovery over eight shared-key blocks.",
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": analysis["protocol"]["protocol_state"],
            "information_boundary": analysis["protocol"]["information_boundary"],
            "prospective_predictions": analysis["protocol"]["prospective_predictions"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "solver_identities": identities,
        "calibration": calibration,
        "calibration_sha256": _canonical_sha256(calibration),
        "calibration_replay": calibration_replay,
        "calibration_replay_sha256": _canonical_sha256(calibration_replay),
        "mapping": mapping,
        "mapping_sha256": _canonical_sha256(mapping),
        "mapping_replay": mapping_replay,
        "mapping_replay_sha256": _canonical_sha256(mapping_replay),
        "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": _A198.PUBLIC_CHALLENGE_SHA256,
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": _canonical_sha256(analysis["formula_plan"]),
        "cnf_export": clean_exports,
        "cnf_export_sha256": _canonical_sha256(clean_exports),
        "execution_plan": analysis["protocol"]["execution_plan"],
        "execution_plan_sha256": _canonical_sha256(analysis["protocol"]["execution_plan"]),
        "execution": execution,
        "execution_sha256": _canonical_sha256(execution),
        "confirmations": confirmations,
        "confirmation_sha256": _canonical_sha256(confirmations),
        "comparisons": comparisons,
        "comparison_sha256": _canonical_sha256(comparisons),
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _A198._A185._atomic_write(output, raw)
    reader = CryptoCausalReader(causal_output)
    if (
        _file_sha256(output) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A204 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "calibration_replay_retained": calibration_replay["retained"],
        "status_counts": status_counts,
        "recovered_unknown_low20_assignments": recovered,
        "primary_prediction_retained": primary,
        "secondary_prediction_retained": secondary,
        "complete_recovery_gate_retained": complete_recovery,
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
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
    args = parser.parse_args(argv)
    if args.analyze_only:
        analysis = analyze(args.results_dir.resolve())
        summary = {
            "protocol_sha256": PROTOCOL_SHA256,
            "formula_plan_sha256": _canonical_sha256(analysis["formula_plan"]),
            "variants": len(analysis["formulas"]),
            "calibration_variants": len(
                analysis["protocol"]["A188_external_cnf_calibration"]["outcomes"]
            ),
            "solver_execution_started": analysis["solver_execution_started"],
        }
    else:
        summary = run(
            results_dir=args.results_dir.resolve(),
            output=args.output.resolve(),
            causal_output=args.causal_output.resolve(),
        )
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
