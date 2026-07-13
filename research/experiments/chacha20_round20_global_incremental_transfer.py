#!/usr/bin/env python3
"""Transfer the retained A211 global-learning protocol to the frozen R20 pilot."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import time
from collections import deque
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import numpy as np
from scipy.sparse import coo_matrix

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
PHASE2_RUNNER = (
    RESEARCH
    / "pilots"
    / "chacha20_round20_partition_v1"
    / "phase2_split18_10s"
    / "runner.py"
)


def _import_phase2() -> Any:
    spec = importlib.util.spec_from_file_location("r20_global_phase2_anchor", PHASE2_RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


P2 = _import_phase2()
P1 = P2.P1

ATTEMPT_ID = "R20-A211-TRANSFER-V1"
SCHEMA = "chacha20-round20-global-incremental-transfer-v1"
PROTOCOL_SCHEMA = "chacha20-round20-global-incremental-transfer-protocol-v1"
PROTOCOL_FILENAME = "chacha20_round20_global_incremental_transfer_v1.json"
PROTOCOL_SHA256 = "64470896de99dacabb0b53f81d8c94c2da82e7088be09c8e1b4d38665ae09946"
RESULT_FILENAME = "chacha20_round20_global_incremental_transfer_v1.json"
CAUSAL_FILENAME = "chacha20_round20_global_incremental_transfer_v1.causal"
REPORT_FILENAME = "CAUSAL_CHACHA20_ROUND20_GLOBAL_INCREMENTAL_TRANSFER_V1.md"

METRIC_NAMES = ("conflicts", "decisions", "search_propagations")
SOLVER_LIMIT_SECONDS = 10
MODE_EXTERNAL_TIMEOUT_SECONDS = 3050
PROBE_WORKERS = 8
TWO_COPY_MARGIN_BYTES = 2 * 1024**3


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_sha256(value: Any) -> str:
    return _sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    )


def _numeric_order() -> list[str]:
    return [f"{value:08b}" for value in range(256)]


def _gray8_order() -> list[str]:
    return [f"{value ^ (value >> 1):08b}" for value in range(256)]


def _mode_orders(protocol: dict[str, Any]) -> dict[str, list[str]]:
    orders = {
        "numeric_global_incremental": _numeric_order(),
        "reflected_gray8_global_incremental": _gray8_order(),
    }
    if list(orders) != [row["name"] for row in protocol["incremental_modes"]]:
        raise RuntimeError("R20 transfer mode names differ from freeze")
    complete = set(_numeric_order())
    for row in protocol["incremental_modes"]:
        order = orders[row["name"]]
        if _canonical_sha256(order) != row["order_sha256"] or set(order) != complete:
            raise RuntimeError(f"R20 transfer {row['name']} order gate failed")
    return orders


def _load_protocol_gate() -> dict[str, Any]:
    path = RESEARCH / "configs" / PROTOCOL_FILENAME
    if _file_sha256(path) != PROTOCOL_SHA256:
        raise RuntimeError("R20 transfer frozen protocol hash differs")
    protocol = json.loads(path.read_bytes())
    selection = protocol.get("selection_basis", {})
    source = protocol.get("source_formula_and_CNF_preflight", {})
    signed = protocol.get("signed_literal_derivation", {})
    order = protocol.get("R20_specific_BFS_far_preflight", {})
    helper = protocol.get("native_helper", {})
    rss = protocol.get("load_only_RSS_preflight", {})
    plan = protocol.get("execution_plan", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_complete_split18_and_R20_specific_export_mapping_reindex_helper_and_load_RSS_preflight_before_any_R20_global_incremental_solver_execution"
        or selection.get("public_challenge_sha256")
        != "98d375fb9432e17b9a701137617a6384ebc60a0ac9054ec203f2364a5338d762"
        or selection.get("rounds") != 20
        or selection.get("split") != 18
        or selection.get("unknown_key_bits") != 20
        or selection.get("any_R20_global_incremental_solver_outcome_known_at_selection")
        is not False
        or source.get("source_formula_sha256")
        != "11fa85e683034b7b8141bad3361240c932c67fba3f37e3bdb3ce64fcc727c291"
        or source.get("base_header") != "p cnf 68783 216461"
        or source.get("base_original_sha256")
        != "df051ca805414ea33f065627573aea791d8bee073d0f7ed5b020ce89c953dbea"
        or signed.get("probe_count") != 40
        or signed.get("source_one_literals_bit0_through_bit19")
        != [16, 15, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 55, 60]
        or signed.get("all_40_exact_one_unit_delta_gates_passed_before_freeze") is not True
        or signed.get("all_20_opposite_polarity_gates_passed_before_freeze") is not True
        or order.get("order_sha256")
        != "e397b58fdaee44d6306f714ef9b280dc547019662f0ef4ac9cfbd2b60114dfee"
        or order.get("transformed_sha256")
        != "2c33afd9f78ed3e1a2180313571918af51d5eaf2e1cd3b09fb588b86745f19b1"
        or order.get("bijection_proved") is not True
        or order.get("inverse_reindex_byte_identical") is not True
        or order.get("explicitly_not_reused_from_R10") is not True
        or len(order.get("transformed_one_literals_bit0_through_bit19", [])) != 20
        or len(order.get("transformed_prefix_one_literals_bits19_through12", [])) != 8
        or helper.get("source_sha256")
        != "016fc73b402fc02e0ecf83639ae75950a5971ad3207c1ea66e980268343fbef3"
        or helper.get("compiled_binary_sha256")
        != "1b451b3c6e6aa579753acc5229e1b90d04e40869012317f6eb9897e86c2ad822"
        or helper.get("signed_assumption_and_model_literal_support") is not True
        or helper.get("dynamic_CNF_variable_count") is not True
        or helper.get("R20_helper_solver_execution_completed_before_freeze") is not False
        or rss.get("two_copy_margin_safe_at_freeze") is not True
        or rss.get("load_only_does_not_call_solve") is not True
        or plan.get("mode_run_count") != 2
        or plan.get("cells_per_mode") != 256
        or plan.get("cell_observation_count") != 512
        or plan.get("solver_time_limit_seconds_per_cell") != SOLVER_LIMIT_SECONDS
        or plan.get("external_timeout_seconds_per_mode")
        != MODE_EXTERNAL_TIMEOUT_SECONDS
        or plan.get("early_stop_permitted") is not False
        or plan.get("unknown_is_not_unsat") is not True
        or boundary.get("unknown_assignment_available_to_runner_or_helper_before_execution")
        is not False
        or boundary.get("correct_prefix_known_before_execution") is not False
        or boundary.get("any_R20_global_incremental_helper_solve_outcome_known_before_freeze")
        is not False
        or boundary.get("early_stop_permitted") is not False
    ):
        raise RuntimeError("R20 transfer frozen protocol identity gate failed")
    _mode_orders(protocol)
    return protocol


def _source_formula(challenge: dict[str, Any]) -> str:
    old_split = P1.SPLIT
    try:
        P1.SPLIT = 18
        formula = P1._base_formula(challenge)
    finally:
        P1.SPLIT = old_split
    return formula


def _anchor_gates(protocol: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    phase_dir = PHASE2_RUNNER.parent
    declared = protocol["anchors"]["round20_split18"]
    paths = {
        "config_sha256": phase_dir / "config.json",
        "runner_sha256": PHASE2_RUNNER,
        "formula_plan_sha256": phase_dir / "formula_plan.json",
        "hash_ledger_sha256": phase_dir / "hash_ledger.json",
        "result_sha256": phase_dir / "result.json",
        "causal_sha256": phase_dir / "result.causal",
    }
    observed = {name: _file_sha256(path) for name, path in paths.items()}
    if any(observed[name] != declared[name] for name in observed):
        raise RuntimeError("R20 transfer split18 byte anchor gate failed")
    phase_result = json.loads(paths["result_sha256"].read_bytes())
    phase_reader = CryptoCausalReader(paths["causal_sha256"])
    if (
        phase_result.get("public_challenge_sha256")
        != protocol["selection_basis"]["public_challenge_sha256"]
        or phase_result.get("comparisons", {}).get("phase2_status_counts")
        != declared["status_counts"]
        or phase_result.get("execution", {}).get("complete_variant_plan_executed")
        is not True
        or phase_result.get("execution", {}).get("early_stop_used") is not False
        or phase_result.get("confirmations") != []
        or phase_reader.graph_sha256 != declared["causal_graph_sha256"]
        or not phase_reader.verify_provenance()
    ):
        raise RuntimeError("R20 transfer split18 semantic anchor gate failed")

    a184 = protocol["anchors"]["prior_stronger_A184_fullround_width40"]
    a184_result_path = ROOT / a184["result"]
    a184_causal_path = ROOT / a184["causal"]
    a184_result = json.loads(a184_result_path.read_bytes())
    a184_reader = CryptoCausalReader(a184_causal_path)
    if (
        _file_sha256(a184_result_path) != a184["result_sha256"]
        or _file_sha256(a184_causal_path) != a184["causal_sha256"]
        or a184_result.get("evidence_stage") != a184["evidence_stage"]
        or not a184_reader.verify_provenance()
    ):
        raise RuntimeError("R20 transfer A184 stronger prior anchor gate failed")

    phase_config = json.loads((phase_dir / "config.json").read_bytes())
    challenge = phase_config["public_challenge"]
    P1._validate_challenge(challenge)
    if _canonical_sha256(challenge) != protocol["selection_basis"]["public_challenge_sha256"]:
        raise RuntimeError("R20 transfer public challenge hash differs")
    return challenge, {
        **observed,
        "phase2_causal_graph_sha256": phase_reader.graph_sha256,
        "phase2_causal_provenance_verified": True,
        "phase2_complete_32_unknown_boundary_retained": True,
        "A184_result_sha256": a184["result_sha256"],
        "A184_causal_sha256": a184["causal_sha256"],
        "A184_causal_graph_sha256": a184_reader.graph_sha256,
        "A184_causal_provenance_verified": True,
        "A184_prior_stronger_fullround_width40_recovery_retained": True,
    }


def _toolchain_gates(protocol: dict[str, Any]) -> dict[str, Any]:
    helper = protocol["native_helper"]
    source = protocol["source_formula_and_CNF_preflight"]
    paths = {
        "bitwuzla": Path(source["Bitwuzla_path"]),
        "source": ROOT / helper["source"],
        "compiler": Path(helper["compiler"]),
        "cadical_header": Path(helper["cadical_header"]),
        "cadical_static_library": Path(helper["cadical_static_library"]),
    }
    expected = {
        "bitwuzla": source["Bitwuzla_sha256"],
        "source": helper["source_sha256"],
        "compiler": helper["compiler_sha256"],
        "cadical_header": helper["cadical_header_sha256"],
        "cadical_static_library": helper["cadical_static_library_sha256"],
    }
    if any(_file_sha256(paths[name]) != digest for name, digest in expected.items()):
        raise RuntimeError("R20 transfer toolchain file gate failed")
    bitwuzla = subprocess.run(
        [str(paths["bitwuzla"]), "--version"], text=True, capture_output=True, check=False
    )
    compiler = subprocess.run(
        [str(paths["compiler"]), "--version"], text=True, capture_output=True, check=False
    )
    compiler_first = compiler.stdout.splitlines()[0] if compiler.stdout.splitlines() else ""
    if (
        bitwuzla.returncode != 0
        or bitwuzla.stdout.strip() != source["Bitwuzla_version"]
        or compiler.returncode != 0
        or compiler_first != helper["compiler_version_first_line"]
    ):
        raise RuntimeError("R20 transfer toolchain version gate failed")
    return {
        **{f"{name}_sha256": digest for name, digest in expected.items()},
        "bitwuzla_version": bitwuzla.stdout.strip(),
        "compiler_version_first_line": compiler_first,
        "compiled_binary_expected_sha256": helper["compiled_binary_sha256"],
        "R20_helper_solve_execution_started": False,
    }


def analyze() -> dict[str, Any]:
    protocol = _load_protocol_gate()
    challenge, anchors = _anchor_gates(protocol)
    formula = _source_formula(challenge)
    source = protocol["source_formula_and_CNF_preflight"]
    if len(formula.encode()) != source["source_formula_bytes"] or _sha256(
        formula.encode()
    ) != source["source_formula_sha256"]:
        raise RuntimeError("R20 transfer deterministic source formula differs")
    return {
        "protocol": protocol,
        "public_challenge": challenge,
        "public_challenge_sha256": _canonical_sha256(challenge),
        "anchor_gates": anchors,
        "toolchain_gates": _toolchain_gates(protocol),
        "source_formula": formula,
        "mode_orders": _mode_orders(protocol),
        "solver_execution_started": False,
    }


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def _export_cnf(
    *, label: str, formula: str, output: Path, protocol: dict[str, Any]
) -> dict[str, Any]:
    source = protocol["source_formula_and_CNF_preflight"]
    command = [
        source["Bitwuzla_path"],
        "--lang",
        "smt2",
        "--time-limit",
        str(source["Bitwuzla_export_time_limit_milliseconds"]),
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
            timeout=6,
            check=False,
        )
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
        externally_timed_out = False
    except subprocess.TimeoutExpired as error:
        stdout, stderr, returncode = _as_text(error.stdout), _as_text(error.stderr), None
        externally_timed_out = True
    if not output.exists():
        raise RuntimeError(f"R20 transfer {label} CNF export produced no file")
    raw = output.read_bytes()
    lines = raw.splitlines()
    if not lines:
        raise RuntimeError(f"R20 transfer {label} CNF export is empty")
    return {
        "label": label,
        "path": str(output),
        "bytes": len(raw),
        "sha256": _sha256(raw),
        "header": lines[0].decode(),
        "command": command,
        "returncode": returncode,
        "externally_timed_out": externally_timed_out,
        "export_status": next(
            (line for line in stdout.splitlines() if line in {"sat", "unsat", "unknown"}),
            "invalid",
        ),
        "stdout_sha256": _sha256(stdout.encode()),
        "stderr_sha256": _sha256(stderr.encode()),
        "volatile_seconds": time.perf_counter() - started,
    }


def _derive_signed_mapping(
    *, formula: str, protocol: dict[str, Any], directory: Path
) -> tuple[dict[str, Any], Path]:
    source = protocol["source_formula_and_CNF_preflight"]
    signed = protocol["signed_literal_derivation"]
    base_path = directory / "r20_split18_prefix_free.cnf"
    base_export = _export_cnf(
        label="R20_split18_prefix_free", formula=formula, output=base_path, protocol=protocol
    )
    base_raw = base_path.read_bytes()
    base_lines = base_raw.splitlines(keepends=True)
    base_body = b"".join(base_lines[1:])
    base_body_sha256 = _sha256(base_body)
    if (
        base_export["header"] != source["base_header"]
        or base_export["bytes"] != source["base_original_bytes"]
        or base_export["sha256"] != source["base_original_sha256"]
        or base_body_sha256 != source["base_body_sha256"]
        or base_export["returncode"] != 0
        or base_export["externally_timed_out"]
        or base_export["export_status"] != "unknown"
    ):
        raise RuntimeError("R20 transfer prefix-free CNF export gate failed")

    def probe(item: tuple[int, int]) -> dict[str, Any]:
        bit, value = item
        assertion = f"(assert (= ((_ extract {bit} {bit}) k0) #b{value}))"
        probe_formula = formula.replace(
            "(check-sat)", assertion + "\n(check-sat)", 1
        )
        output = directory / f"r20_probe_bit{bit}_value{value}.cnf"
        exported = _export_cnf(
            label=f"R20_k0_bit{bit}_value{value}",
            formula=probe_formula,
            output=output,
            protocol=protocol,
        )
        raw = output.read_bytes()
        lines = raw.splitlines(keepends=True)
        fields = lines[-1].split() if lines else []
        if len(fields) != 2 or fields[1] != b"0":
            raise RuntimeError(f"R20 transfer bit {bit} value {value} has no final unit")
        base_header_fields = source["base_header"].split()
        probe_header_fields = lines[0].decode().split()
        body_without_unit = b"".join(lines[1:-1])
        exact = (
            probe_header_fields[:3] == base_header_fields[:3]
            and int(probe_header_fields[3]) == int(base_header_fields[3]) + 1
            and _sha256(body_without_unit) == base_body_sha256
            and exported["returncode"] == 0
            and exported["externally_timed_out"] is False
            and exported["export_status"] == "unknown"
        )
        if not exact:
            raise RuntimeError(f"R20 transfer bit {bit} value {value} exact delta gate failed")
        output.unlink()
        return {
            "bit": bit,
            "value": value,
            "added_literal": int(fields[0]),
            "probe_header": lines[0].decode().strip(),
            "probe_cnf_bytes": exported["bytes"],
            "probe_cnf_sha256": exported["sha256"],
            "probe_body_without_added_unit_sha256": _sha256(body_without_unit),
            "exactly_one_unit_clause_added": True,
            "returncode": exported["returncode"],
            "externally_timed_out": exported["externally_timed_out"],
            "export_status": exported["export_status"],
            "stdout_sha256": exported["stdout_sha256"],
            "stderr_sha256": exported["stderr_sha256"],
        }

    items = [(bit, value) for bit in range(20) for value in (0, 1)]
    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as executor:
        rows = list(executor.map(probe, items))
    by_pair = {(row["bit"], row["value"]): row for row in rows}
    one_literals = []
    polarity = []
    for bit in range(20):
        zero = by_pair[(bit, 0)]["added_literal"]
        one = by_pair[(bit, 1)]["added_literal"]
        if zero != -one:
            raise RuntimeError(f"R20 transfer bit {bit} polarity gate failed")
        one_literals.append(one)
        polarity.append({"bit": bit, "value0_literal": zero, "value1_literal": one})
    if one_literals != signed["source_one_literals_bit0_through_bit19"]:
        raise RuntimeError("R20 transfer derived signed source mapping differs")
    manifest = {
        "source_formula_bytes": len(formula.encode()),
        "source_formula_sha256": _sha256(formula.encode()),
        "base_export": {key: value for key, value in base_export.items() if key != "path"},
        "base_body_sha256": base_body_sha256,
        "probe_count": len(rows),
        "probe_rows": rows,
        "all_exact_one_unit_delta_gates_passed": True,
        "polarity_rows": polarity,
        "all_opposite_polarity_gates_passed": True,
        "source_one_literals_bit0_through_bit19": one_literals,
    }
    return manifest, base_path


def _parse_cnf(raw: bytes) -> dict[str, Any]:
    lines = raw.splitlines()
    header = lines[0].split()
    if len(header) != 4 or header[:2] != [b"p", b"cnf"]:
        raise RuntimeError("R20 transfer invalid DIMACS header")
    variables = int(header[2])
    declared = int(header[3])
    rows: list[int] = []
    columns: list[int] = []
    units: list[int] = []
    length_counts: dict[str, int] = {}
    for line in lines[1:]:
        values = [int(value) for value in line.split()]
        if not values or values[-1] != 0:
            raise RuntimeError("R20 transfer malformed DIMACS clause")
        absolute = [abs(value) for value in values[:-1]]
        length_counts[str(len(absolute))] = length_counts.get(str(len(absolute)), 0) + 1
        if len(absolute) == 1:
            units.append(absolute[0])
        for left_index in range(len(absolute)):
            for right_index in range(left_index + 1, len(absolute)):
                left, right = absolute[left_index] - 1, absolute[right_index] - 1
                rows.extend((left, right))
                columns.extend((right, left))
    if len(lines) - 1 != declared:
        raise RuntimeError("R20 transfer DIMACS clause count differs")
    graph = coo_matrix(
        (np.ones(len(rows), dtype=np.uint8), (rows, columns)),
        shape=(variables, variables),
    ).tocsr()
    graph.sum_duplicates()
    graph.data[:] = 1
    return {
        "variable_count": variables,
        "clause_count": declared,
        "units": np.array(sorted(set(units)), dtype=np.int64),
        "graph": graph,
        "length_counts": length_counts,
    }


def _multi_source_bfs(graph: Any, sources_one_based: np.ndarray) -> np.ndarray:
    distances = np.full(graph.shape[0], -1, dtype=np.int64)
    queue: deque[int] = deque()
    for source in sources_one_based:
        index = int(source) - 1
        if distances[index] == -1:
            distances[index] = 0
            queue.append(index)
    while queue:
        current = queue.popleft()
        start, end = graph.indptr[current], graph.indptr[current + 1]
        for neighbor in graph.indices[start:end]:
            if distances[neighbor] == -1:
                distances[neighbor] = distances[current] + 1
                queue.append(int(neighbor))
    distances[distances < 0] = graph.shape[0] + 1
    return distances


def _old_to_new(order: np.ndarray) -> np.ndarray:
    mapping = np.zeros(len(order) + 1, dtype=np.int64)
    mapping[order] = np.arange(1, len(order) + 1, dtype=np.int64)
    return mapping


def _reindex_cnf(raw: bytes, mapping: np.ndarray) -> bytes:
    lines = raw.splitlines()
    output = bytearray(lines[0] + b"\n")
    for line in lines[1:]:
        values = [int(value) for value in line.split()]
        if not values or values[-1] != 0:
            raise RuntimeError("R20 transfer cannot reindex malformed DIMACS")
        mapped = [
            int(mapping[abs(literal)]) if literal > 0 else -int(mapping[abs(literal)])
            for literal in values[:-1]
        ]
        output.extend((" ".join(str(value) for value in [*mapped, 0]) + "\n").encode())
    return bytes(output)


def _build_R20_specific_global_base(
    *, base_path: Path, mapping_manifest: dict[str, Any], protocol: dict[str, Any], directory: Path
) -> tuple[dict[str, Any], Path]:
    expected = protocol["R20_specific_BFS_far_preflight"]
    raw = base_path.read_bytes()
    source_literals = mapping_manifest["source_one_literals_bit0_through_bit19"]
    representative_literals = [source_literals[bit] for bit in range(19, 11, -1)]
    lines = raw.splitlines(keepends=True)
    fields = lines[0].decode().split()
    representative = (
        f"p cnf {fields[2]} {int(fields[3]) + 8}\n".encode()
        + b"".join(lines[1:])
        + b"".join(f"{literal} 0\n".encode() for literal in representative_literals)
    )
    parsed = _parse_cnf(representative)
    ids = np.arange(1, parsed["variable_count"] + 1, dtype=np.int64)
    distances = _multi_source_bfs(parsed["graph"], parsed["units"])
    order = ids[np.lexsort((ids, -distances))]
    mapping = _old_to_new(order)
    inverse = np.zeros_like(mapping)
    inverse[mapping[1:]] = ids
    if not np.array_equal(np.sort(order), ids) or not np.array_equal(
        inverse[mapping[1:]], ids
    ):
        raise RuntimeError("R20 transfer BFS-far order is not a bijection")
    transformed = _reindex_cnf(raw, mapping)
    restored = _reindex_cnf(transformed, inverse)
    if restored != raw:
        raise RuntimeError("R20 transfer inverse reindex is not byte exact")
    transformed_literals = [
        int(mapping[abs(literal)]) if literal > 0 else -int(mapping[abs(literal)])
        for literal in source_literals
    ]
    transformed_assumptions = [transformed_literals[bit] for bit in range(19, 11, -1)]
    base_units = {
        abs(int(line.split()[0]))
        for line in transformed.splitlines()[1:]
        if len(line.split()) == 2
    }
    manifest = {
        "derivation_representative": expected["derivation_representative"],
        "representative_header": representative.splitlines()[0].decode(),
        "representative_added_one_literals_bits19_through12": representative_literals,
        "variable_count": parsed["variable_count"],
        "base_clause_count": int(fields[3]),
        "representative_clause_count": parsed["clause_count"],
        "unit_source_count": len(parsed["units"]),
        "unit_distance_minimum": int(distances.min()),
        "unit_distance_maximum": int(distances.max()),
        "unit_distance_sha256": _sha256(distances.astype("<i8", copy=False).tobytes()),
        "order_sha256": _sha256(order.astype("<u4", copy=False).tobytes()),
        "old_to_new_sha256": _sha256(mapping.astype("<u4", copy=False).tobytes()),
        "inverse_sha256": _sha256(inverse.astype("<u4", copy=False).tobytes()),
        "bijection_proved": True,
        "inverse_reindex_byte_identical": True,
        "inverse_restored_sha256": _sha256(restored),
        "transformed_header": transformed.splitlines()[0].decode(),
        "transformed_bytes": len(transformed),
        "transformed_sha256": _sha256(transformed),
        "transformed_one_literals_bit0_through_bit19": transformed_literals,
        "transformed_prefix_one_literals_bits19_through12": transformed_assumptions,
        "transformed_assumption_variables_absent_from_base_units": not bool(
            {abs(value) for value in transformed_assumptions} & base_units
        ),
        "representative_clause_length_counts": parsed["length_counts"],
        "explicitly_not_reused_from_R10": True,
    }
    for key in (
        "representative_header",
        "representative_added_one_literals_bits19_through12",
        "unit_source_count",
        "unit_distance_minimum",
        "unit_distance_maximum",
        "unit_distance_sha256",
        "order_sha256",
        "old_to_new_sha256",
        "inverse_sha256",
        "bijection_proved",
        "inverse_reindex_byte_identical",
        "inverse_restored_sha256",
        "transformed_header",
        "transformed_bytes",
        "transformed_sha256",
        "transformed_one_literals_bit0_through_bit19",
        "transformed_prefix_one_literals_bits19_through12",
        "transformed_assumption_variables_absent_from_base_units",
        "explicitly_not_reused_from_R10",
    ):
        if manifest[key] != expected[key]:
            raise RuntimeError(f"R20 transfer BFS-far preflight differs at {key}")
    output = directory / "r20_split18_global_bfs_far.cnf"
    output.write_bytes(transformed)
    return manifest, output


def _compile_helper(
    protocol: dict[str, Any], *, directory: Path
) -> tuple[Path, dict[str, Any]]:
    helper = protocol["native_helper"]
    output = directory / "cadical_global_incremental_signed"
    command = [helper["compiler"], *helper["compile_arguments"], "-o", str(output)]
    started = time.perf_counter()
    result = subprocess.run(
        command, cwd=ROOT, text=True, capture_output=True, check=False
    )
    observation = {
        "command": command,
        "returncode": result.returncode,
        "volatile_seconds": time.perf_counter() - started,
        "stdout_sha256": _sha256(result.stdout.encode()),
        "stderr_sha256": _sha256(result.stderr.encode()),
        "binary_sha256": _file_sha256(output) if output.exists() else None,
    }
    if (
        result.returncode != 0
        or result.stdout
        or result.stderr
        or observation["binary_sha256"] != helper["compiled_binary_sha256"]
    ):
        raise RuntimeError("R20 transfer native helper compilation gate failed")
    return output, observation


def _helper_mapping_args(protocol: dict[str, Any]) -> list[str]:
    mapping = protocol["R20_specific_BFS_far_preflight"]
    return [
        "--assumption-one-literals",
        ",".join(str(value) for value in mapping["transformed_prefix_one_literals_bits19_through12"]),
        "--model-one-literals",
        ",".join(str(value) for value in mapping["transformed_one_literals_bit0_through_bit19"]),
    ]


def _load_only_RSS_gate(
    *, base_path: Path, helper_path: Path, protocol: dict[str, Any]
) -> dict[str, Any]:
    command = [
        "/usr/bin/time",
        "-l",
        str(helper_path),
        "--cnf",
        str(base_path),
        "--mode",
        "R20_load_only",
        *_helper_mapping_args(protocol),
        "--load-only",
        "1",
    ]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    load_lines = [
        line.removeprefix("R20_XFER_LOAD ")
        for line in result.stdout.splitlines()
        if line.startswith("R20_XFER_LOAD ")
    ]
    maximum = re.search(r"^\s*(\d+)\s+maximum resident set size$", result.stderr, re.M)
    peak = re.search(r"^\s*(\d+)\s+peak memory footprint$", result.stderr, re.M)
    pressure = subprocess.run(
        ["/usr/bin/memory_pressure", "-Q"], text=True, capture_output=True, check=False
    )
    percentage_match = re.search(
        r"System-wide memory free percentage:\s*(\d+)%", pressure.stdout
    )
    total_run = subprocess.run(
        ["/usr/sbin/sysctl", "-n", "hw.memsize"],
        text=True,
        capture_output=True,
        check=False,
    )
    if (
        result.returncode != 0
        or len(load_lines) != 1
        or maximum is None
        or peak is None
        or pressure.returncode != 0
        or percentage_match is None
        or total_run.returncode != 0
    ):
        raise RuntimeError("R20 transfer load-only RSS measurement failed")
    load = json.loads(load_lines[0])
    maximum_bytes = int(maximum.group(1))
    peak_bytes = int(peak.group(1))
    free_percentage = int(percentage_match.group(1))
    total_bytes = int(total_run.stdout.strip())
    available_bytes = total_bytes * free_percentage // 100
    required_bytes = 2 * maximum_bytes + TWO_COPY_MARGIN_BYTES
    safe = required_bytes <= available_bytes
    if (
        load.get("signature") != "cadical-3.0.0"
        or load.get("version") != "3.0.0"
        or load.get("variables")
        != protocol["source_formula_and_CNF_preflight"]["base_variable_count"]
    ):
        raise RuntimeError("R20 transfer load-only helper identity gate failed")
    return {
        "command": command,
        "returncode": result.returncode,
        "load_record": load,
        "maximum_resident_set_bytes": maximum_bytes,
        "peak_memory_footprint_bytes": peak_bytes,
        "system_total_memory_bytes": total_bytes,
        "memory_pressure_free_percentage": free_percentage,
        "estimated_available_bytes": available_bytes,
        "two_copy_fixed_margin_bytes": TWO_COPY_MARGIN_BYTES,
        "two_copy_required_bytes": required_bytes,
        "two_copy_margin_safe": safe,
        "selected_max_parallel_mode_runs": 2 if safe else 1,
        "selected_execution": "concurrent" if safe else "sequential",
        "load_only_solve_calls": 0,
        "stdout_sha256": _sha256(result.stdout.encode()),
        "stderr_sha256": _sha256(result.stderr.encode()),
    }


def _decode_model(challenge: dict[str, Any], model_bits: Sequence[int]) -> dict[str, int]:
    if len(model_bits) != 20 or any(value not in {0, 1} for value in model_bits):
        raise RuntimeError("R20 transfer helper SAT model is not twenty Boolean bits")
    low20 = sum(value << bit for bit, value in enumerate(model_bits))
    key_word0 = challenge["known_key_word0_upper12"] | low20
    return {
        "combined_assignment": key_word0,
        "key_word0": key_word0,
        "key_word1_low_value": challenge["known_key_words_1_through_7"][0] & 0xFF,
        "recovered_unknown_low20": low20,
    }


def _confirm_model(
    challenge: dict[str, Any], *, mode: str, prefix8: str, model: dict[str, int]
) -> dict[str, Any]:
    key_words = [model["key_word0"], *challenge["known_key_words_1_through_7"]]
    candidate_blocks = [
        P1._chacha_block(
            key_words=key_words,
            counter=(challenge["counter_start"] + index) & 0xFFFFFFFF,
            nonce_words=challenge["nonce_words"],
            rounds=20,
        )
        for index in range(challenge["block_count"])
    ]
    block_matches = [
        candidate == target
        for candidate, target in zip(candidate_blocks, challenge["target_words"], strict=True)
    ]
    hashes = [_sha256(P1._word_bytes(block)) for block in candidate_blocks]
    return {
        **model,
        "variant": f"{mode}__prefix_{prefix8}",
        "mode": mode,
        "prefix8": prefix8,
        "prefix8_match": ((model["key_word0"] >> 12) & 0xFF) == int(prefix8, 2),
        "known_key_constraints_match": (
            model["key_word0"] & ~P1.LOW_MASK
            == challenge["known_key_word0_upper12"]
            and model["key_word1_low_value"]
            == challenge["known_key_words_1_through_7"][0] & 0xFF
        ),
        "block_count_checked": len(candidate_blocks),
        "block_matches": block_matches,
        "all_blocks_match": all(block_matches),
        "candidate_block_sha256": hashes,
        "control_first_block_match": hashes[0]
        == challenge["control_target_block_sha256"],
        "output_bits_checked": len(candidate_blocks) * 512,
        "implementation": "independent_pure_Python_standard_ChaCha20_block",
    }


def _invalid_cell(*, mode: str, prefix8: str, index: int, reason: str) -> dict[str, Any]:
    return {
        "variant": f"{mode}__prefix_{prefix8}",
        "mode": mode,
        "prefix8": prefix8,
        "cell_index": index,
        "status": "invalid",
        "returncode": None,
        "elapsed_seconds": None,
        "terminator_fired": False,
        "assumptions": [],
        "failed_assumptions": [],
        "metrics_before": {},
        "metrics_after": {},
        "metrics_delta": {},
        "active_variables": None,
        "irredundant_clauses": None,
        "redundant_clauses": None,
        "model": None,
        "invalid_reason": reason,
    }


def _parse_mode_output(
    *,
    mode: str,
    order: list[str],
    stdout: str,
    helper_returncode: int | None,
    externally_timed_out: bool,
    challenge: dict[str, Any],
    protocol: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any] | None]:
    parsed: dict[str, dict[str, Any]] = {}
    summary = None
    malformed = False
    for line in stdout.splitlines():
        try:
            if line.startswith("R20_XFER_RESULT "):
                row = json.loads(line.removeprefix("R20_XFER_RESULT "))
                if row["prefix8"] in parsed:
                    malformed = True
                parsed[row["prefix8"]] = row
            elif line.startswith("R20_XFER_SUMMARY "):
                if summary is not None:
                    malformed = True
                summary = json.loads(line.removeprefix("R20_XFER_SUMMARY "))
            elif line.strip():
                malformed = True
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            malformed = True
    reason = None
    if externally_timed_out:
        reason = "external_mode_timeout"
    elif helper_returncode != 0:
        reason = "invalid_helper_returncode"
    elif malformed or set(parsed) != set(order):
        reason = "malformed_or_incomplete_helper_output"
    assumption_one = protocol["R20_specific_BFS_far_preflight"][
        "transformed_prefix_one_literals_bits19_through12"
    ]
    observations: list[dict[str, Any]] = []
    confirmations: list[dict[str, Any]] = []
    previous_after = None
    if reason is None:
        for index, prefix8 in enumerate(order):
            raw = parsed[prefix8]
            expected_assumptions = [
                literal if bit == "1" else -literal
                for bit, literal in zip(prefix8, assumption_one, strict=True)
            ]
            status = raw.get("status")
            before, after, delta = (
                raw.get("metrics_before"),
                raw.get("metrics_after"),
                raw.get("metrics_delta"),
            )
            failed = raw.get("failed_assumptions")
            if (
                raw.get("mode") != mode
                or raw.get("cell_index") != index
                or raw.get("metric_names") != list(METRIC_NAMES)
                or raw.get("assumptions") != expected_assumptions
                or status not in {"sat", "unsat", "unknown"}
                or raw.get("returncode") != {"sat": 10, "unsat": 20, "unknown": 0}[status]
                or not all(isinstance(values, list) and len(values) == 3 for values in (before, after, delta))
                or any(
                    right - left != difference
                    for left, right, difference in zip(before, after, delta, strict=True)
                )
                or any(value < 0 for value in [*before, *after, *delta])
                or (previous_after is not None and before != previous_after)
                or (status == "unknown") != (raw.get("terminator_fired") is True)
                or not isinstance(failed, list)
                or len(set(failed)) != len(failed)
                or any(literal not in expected_assumptions for literal in failed)
                or (status != "unsat" and failed != [])
                or (status == "sat" and len(raw.get("model_bits_bit0_through_bit19", [])) != 20)
                or (status != "sat" and raw.get("model_bits_bit0_through_bit19") != [])
            ):
                reason = "helper_semantic_gate_failed"
                break
            previous_after = after
            model = None
            if status == "sat":
                model = _decode_model(challenge, raw["model_bits_bit0_through_bit19"])
                confirmation = _confirm_model(
                    challenge, mode=mode, prefix8=prefix8, model=model
                )
                if (
                    confirmation["prefix8_match"] is not True
                    or confirmation["known_key_constraints_match"] is not True
                    or confirmation["all_blocks_match"] is not True
                    or confirmation["control_first_block_match"] is not False
                    or confirmation["output_bits_checked"] != 4096
                ):
                    raise RuntimeError("R20 transfer SAT model failed independent confirmation")
                confirmations.append(confirmation)
            observations.append(
                {
                    "variant": f"{mode}__prefix_{prefix8}",
                    "mode": mode,
                    "prefix8": prefix8,
                    "cell_index": index,
                    "status": status,
                    "returncode": raw["returncode"],
                    "elapsed_seconds": raw["elapsed_seconds"],
                    "terminator_fired": raw["terminator_fired"],
                    "assumptions": raw["assumptions"],
                    "failed_assumptions": raw["failed_assumptions"],
                    "metrics_before": dict(zip(METRIC_NAMES, before, strict=True)),
                    "metrics_after": dict(zip(METRIC_NAMES, after, strict=True)),
                    "metrics_delta": dict(zip(METRIC_NAMES, delta, strict=True)),
                    "active_variables": raw["active_variables"],
                    "irredundant_clauses": raw["irredundant_clauses"],
                    "redundant_clauses": raw["redundant_clauses"],
                    "model": model,
                    "invalid_reason": None,
                }
            )
    if reason is None:
        counts = {
            status: sum(row["status"] == status for row in observations)
            for status in ("sat", "unsat", "unknown")
        }
        expected_variables = protocol["source_formula_and_CNF_preflight"]["base_variable_count"]
        if (
            len(observations) != 256
            or summary is None
            or summary.get("signature") != "cadical-3.0.0"
            or summary.get("version") != "3.0.0"
            or summary.get("mode") != mode
            or summary.get("variables") != expected_variables
            or summary.get("cells") != 256
            or summary.get("metric_names") != list(METRIC_NAMES)
            or {status: summary.get(status) for status in counts} != counts
        ):
            reason = "helper_summary_gate_failed"
    if reason is not None:
        observations = [
            _invalid_cell(mode=mode, prefix8=prefix8, index=index, reason=reason)
            for index, prefix8 in enumerate(order)
        ]
        confirmations = []
    return observations, confirmations, summary


def _run_mode(
    *, mode: str, order: list[str], base_path: Path, helper_path: Path,
    challenge: dict[str, Any], protocol: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    command = [
        str(helper_path),
        "--cnf", str(base_path),
        "--mode", mode,
        *_helper_mapping_args(protocol),
        "--cell-order", ",".join(order),
        "--seconds", str(SOLVER_LIMIT_SECONDS),
    ]
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command, text=True, capture_output=True,
            timeout=MODE_EXTERNAL_TIMEOUT_SECONDS, check=False
        )
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
        externally_timed_out = False
    except subprocess.TimeoutExpired as error:
        stdout, stderr, returncode = _as_text(error.stdout), _as_text(error.stderr), None
        externally_timed_out = True
    observations, confirmations, summary = _parse_mode_output(
        mode=mode, order=order, stdout=stdout, helper_returncode=returncode,
        externally_timed_out=externally_timed_out, challenge=challenge, protocol=protocol
    )
    return {
        "mode": mode,
        "command": command,
        "returncode": returncode,
        "externally_timed_out": externally_timed_out,
        "volatile_seconds": time.perf_counter() - started,
        "stdout_sha256": _sha256(stdout.encode()),
        "stderr_sha256": _sha256(stderr.encode()),
        "summary": summary,
        "valid_cell_count": sum(row["status"] != "invalid" for row in observations),
        "status_sequence": [row["status"] for row in observations],
    }, observations, confirmations


def _execute(
    *, base_path: Path, helper_path: Path, challenge: dict[str, Any],
    protocol: dict[str, Any], orders: dict[str, list[str]], rss_gate: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    def execute(item: tuple[str, list[str]]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        return _run_mode(
            mode=item[0], order=item[1], base_path=base_path, helper_path=helper_path,
            challenge=challenge, protocol=protocol
        )

    if rss_gate["selected_max_parallel_mode_runs"] == 2:
        with ThreadPoolExecutor(max_workers=2) as executor:
            rows = list(executor.map(execute, orders.items()))
    else:
        rows = [execute(item) for item in orders.items()]
    mode_runs = [row[0] for row in rows]
    observations = [cell for row in rows for cell in row[1]]
    confirmations = [item for row in rows for item in row[2]]
    expected = [
        {"mode": mode, "prefix8": prefix8}
        for mode, order in orders.items() for prefix8 in order
    ]
    if [{"mode": row["mode"], "prefix8": row["prefix8"]} for row in observations] != expected:
        raise RuntimeError("R20 transfer complete execution order differs from freeze")
    valid_modes = all(
        row["returncode"] == 0
        and row["externally_timed_out"] is False
        and row["valid_cell_count"] == 256
        for row in mode_runs
    )
    return {
        "mode_run_order": list(orders),
        "cell_observation_order": expected,
        "selected_execution": rss_gate["selected_execution"],
        "selected_max_parallel_mode_runs": rss_gate["selected_max_parallel_mode_runs"],
        "mode_plan_materialized": len(mode_runs) == 2,
        "cell_plan_materialized": len(observations) == 512,
        "complete_valid_mode_plan_executed": len(mode_runs) == 2 and valid_modes,
        "complete_valid_cell_plan_executed": len(observations) == 512 and valid_modes
        and all(row["status"] != "invalid" for row in observations),
        "early_stop_used": False,
        "mode_runs": mode_runs,
        "observations": observations,
        "returned_model_count": len(confirmations),
        "unknown_assignment_available_to_runner_or_helper_before_execution": False,
    }, confirmations


def _ratio_summary(rows: list[dict[str, Any]], metric: str) -> dict[str, Any]:
    matched = [
        row
        for row in rows
        if metric in row.get("gray8_metrics_delta", {})
        and metric in row.get("numeric_metrics_delta", {})
    ]
    numerator = sum(row["gray8_metrics_delta"][metric] for row in matched)
    denominator = sum(row["numeric_metrics_delta"][metric] for row in matched)
    return {
        "candidate_prefix_count": len(rows),
        "matched_valid_prefix_count": len(matched),
        "numeric_total": denominator,
        "gray8_total": numerator,
        "gray8_over_numeric": numerator / denominator if denominator else None,
        "different_prefix_count": sum(
            row["gray8_metrics_delta"][metric] != row["numeric_metrics_delta"][metric]
            for row in matched
        ),
    }


def _comparative_metrics(
    observations: list[dict[str, Any]], orders: dict[str, list[str]]
) -> dict[str, Any]:
    by_mode = {
        mode: {row["prefix8"]: row for row in observations if row["mode"] == mode}
        for mode in orders
    }
    numeric = by_mode["numeric_global_incremental"]
    gray = by_mode["reflected_gray8_global_incremental"]
    rows = [
        {
            "prefix8": prefix8,
            "numeric_cell_index": numeric[prefix8]["cell_index"],
            "gray8_cell_index": gray[prefix8]["cell_index"],
            "numeric_status": numeric[prefix8]["status"],
            "gray8_status": gray[prefix8]["status"],
            "numeric_metrics_delta": numeric[prefix8]["metrics_delta"],
            "gray8_metrics_delta": gray[prefix8]["metrics_delta"],
        }
        for prefix8 in _numeric_order()
    ]
    return {
        "old_split18_complete_cover_status_counts": {
            "sat": 0, "unsat": 0, "unknown": 32, "invalid": 0, "external_timeout": 0
        },
        "old_split18_used_fresh_Bitwuzla_state_per_cell": True,
        "new_modes_retain_one_CaDiCaL_state_per_256_cells": True,
        "global_order_paired_rows": rows,
        "global_order_paired_summary": {
            "status_difference_prefixes": [
                row["prefix8"] for row in rows
                if row["numeric_status"] != row["gray8_status"]
            ],
            "metric_summaries": {
                metric: _ratio_summary(rows, metric) for metric in METRIC_NAMES
            },
        },
    }


def _compare(
    *, execution: dict[str, Any], confirmations: list[dict[str, Any]],
    comparative: dict[str, Any], modes: list[str]
) -> dict[str, Any]:
    observations = execution["observations"]
    per_mode = {
        mode: {
            status: sum(row["mode"] == mode and row["status"] == status for row in observations)
            for status in ("sat", "unsat", "unknown", "invalid")
        }
        for mode in modes
    }
    confirmed = {mode: [row for row in confirmations if row["mode"] == mode] for mode in modes}
    confirmed_prefixes = {
        mode: sorted({row["prefix8"] for row in rows}) for mode, rows in confirmed.items()
    }
    unsat_prefixes = {
        mode: sorted({row["prefix8"] for row in observations if row["mode"] == mode and row["status"] == "unsat"})
        for mode in modes
    }
    complete_candidates = [
        mode for mode, counts in per_mode.items()
        if counts == {"sat": 1, "unsat": 255, "unknown": 0, "invalid": 0}
    ]
    contradictory = sorted(
        (set(confirmed_prefixes[modes[0]]) & set(unsat_prefixes[modes[1]]))
        | (set(confirmed_prefixes[modes[1]]) & set(unsat_prefixes[modes[0]]))
    )
    complete = [
        mode for mode in complete_candidates if len(confirmed[mode]) == 1 and not contradictory
    ]
    valid = {
        mode: counts["invalid"] == 0 and sum(counts.values()) == 256
        for mode, counts in per_mode.items()
    }
    paired = comparative["global_order_paired_rows"]
    order_evaluated = all(valid.values()) and len(paired) == 256
    matched_paired = [
        row
        for row in paired
        if all(
            metric in row.get("numeric_metrics_delta", {})
            and metric in row.get("gray8_metrics_delta", {})
            for metric in METRIC_NAMES
        )
    ]
    metric_differences = {
        metric: sum(
            row["numeric_metrics_delta"][metric] != row["gray8_metrics_delta"][metric]
            for row in matched_paired
        )
        for metric in METRIC_NAMES
    }
    order_status_diff = sum(
        row["numeric_status"] != row["gray8_status"] for row in matched_paired
    )
    order_evaluated = order_evaluated and len(matched_paired) == 256
    order_effect = order_evaluated and (
        per_mode[modes[0]] != per_mode[modes[1]] or any(metric_differences.values())
    )
    complete_execution = (
        execution["complete_valid_mode_plan_executed"] is True
        and execution["complete_valid_cell_plan_executed"] is True
        and all(valid.values())
    )
    return {
        "mode_run_count": len(execution["mode_runs"]),
        "cell_observation_count": len(observations),
        "complete_predeclared_execution": complete_execution,
        "early_stop_used": False,
        "per_mode_status_counts": per_mode,
        "valid_complete_domain_observation_by_mode": valid,
        "terminal_cell_counts": {
            mode: counts["sat"] + counts["unsat"] for mode, counts in per_mode.items()
        },
        "confirmed_variants": [row["variant"] for row in confirmations],
        "confirmed_prefixes_by_mode": confirmed_prefixes,
        "confirmed_key_word0_assignments": sorted({row["key_word0"] for row in confirmations}),
        "recovered_unknown_low20_assignments": sorted(
            {row["recovered_unknown_low20"] for row in confirmations}
        ),
        "confirmed_recovery_retained": bool(confirmations),
        "complete_domain_resolution_candidate_modes": complete_candidates,
        "cross_mode_contradictory_confirmed_unsat_prefixes": contradictory,
        "complete_domain_resolution_modes": complete,
        "complete_domain_resolution_retained": bool(complete),
        "global_terminal_transfer_retained": any(
            counts["sat"] + counts["unsat"] > 0 for counts in per_mode.values()
        ),
        "true_gray8_order_effect_prediction": {
            "evaluated": order_evaluated,
            "matched_valid_prefix_count": len(matched_paired),
            "status_difference_count": order_status_diff,
            "metric_difference_prefix_counts": metric_differences,
            "retained": order_effect,
        },
        "true_gray8_order_effect_retained": order_effect,
        "complete_domain_covered_once_per_mode": complete_execution,
        "complete_domain_candidate_count": 1 << 20,
        "unknown_is_not_unsat": True,
        "uniqueness_established": bool(complete),
        "prior_stronger_A184_fullround_width40_recovery_retained": True,
        "first_fullround_recovery_claimed": False,
        "novelty_scope": "R20_specific_SAT_representation_and_retained_learned_state_transfer",
        "statuses": {row["variant"]: row["status"] for row in observations},
    }


def _evidence_stage(comparison: dict[str, Any]) -> str:
    if comparison["complete_domain_resolution_retained"]:
        return "FULLROUND_R20_GLOBAL_INCREMENTAL_COMPLETE_DOMAIN_RESOLUTION_RETAINED"
    if comparison["confirmed_recovery_retained"]:
        return "FULLROUND_R20_GLOBAL_INCREMENTAL_CONFIRMED_RECOVERY_RETAINED"
    if comparison["global_terminal_transfer_retained"]:
        return "FULLROUND_R20_GLOBAL_INCREMENTAL_TERMINAL_TRANSFER_RETAINED"
    if comparison["true_gray8_order_effect_retained"]:
        return "FULLROUND_R20_GLOBAL_INCREMENTAL_ORDER_EFFECT_RETAINED"
    if not comparison["complete_predeclared_execution"]:
        return "FULLROUND_R20_GLOBAL_INCREMENTAL_INVALID_EXECUTION_RETAINED"
    return "FULLROUND_R20_GLOBAL_INCREMENTAL_COMPLETE_BOUNDARY_RETAINED"


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_round20_global_incremental_transfer",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": 20,
            "split": 18,
            "modes": 2,
            "cells_per_mode": 256,
        },
    )
    ids = [
        "r20-xfer-split18-anchor",
        "r20-xfer-prefix-free-cnf",
        "r20-xfer-signed-literal-mapping",
        "r20-xfer-specific-bfs-far",
        "r20-xfer-signed-native-helper",
        "r20-xfer-load-rss-policy",
        "r20-xfer-complete-execution",
        "r20-xfer-independent-confirmation",
        "r20-xfer-result",
    ]
    rows = [
        ("split18:complete_32_UNKNOWN_boundary", "retain_old_R20_challenge_and_A184_scope", "R20:global_learning_transfer_question", "retained_anchor", payload["anchor_gates"], []),
        ("R20:global_learning_transfer_question", "rebuild_prefix_free_split18_and_export_exact_DIMACS", "R20:single_common_CNF", "exact_CNF_export", payload["preflight"]["source_CNF_export"], [ids[0]]),
        ("R20:single_common_CNF", "derive_each_key_bit_with_value0_and_value1_exact_unit_probes", "R20:signed_key_literal_map", "signed_literal_derivation", payload["preflight"]["signed_mapping"], [ids[1]]),
        ("R20:signed_key_literal_map", "derive_R20_specific_unit_BFS_far_bijection_and_inverse", "R20:reindexed_global_CNF", "R20_specific_structural_order", payload["preflight"]["BFS_far"], [ids[2]]),
        ("R20:reindexed_global_CNF", "compile_hash_gated_signed_dynamic_CaDiCaL_helper", "R20:global_incremental_primitive", "native_helper_identity", payload["native_helper"], [ids[3]]),
        ("R20:global_incremental_primitive", "measure_load_only_RSS_and_apply_frozen_two_copy_policy", "R20:safe_mode_schedule", "load_only_RSS_gate", payload["load_only_RSS_gate"], [ids[4]]),
        ("R20:safe_mode_schedule", "execute_numeric_and_true_Gray8_complete_covers_without_early_stop", "R20:complete_global_execution", "predeclared_execution", payload["execution"], [ids[5]]),
        ("R20:complete_global_execution", "recompute_every_SAT_model_over_all_4096_bits_and_flipped_control", "R20:confirmed_models_or_boundary", "independent_confirmation", payload["confirmations"], [ids[6]]),
        ("R20:confirmed_models_or_boundary", "separate_R20_state_transfer_from_prior_A184_width40_recovery", "R20:prospective_transfer_result", "prospective_comparison", payload["comparisons"], [ids[7]]),
    ]
    for edge_id, row in zip(ids, rows, strict=True):
        trigger, mechanism, outcome, kind, attrs, provenance = row
        builder.add_triplet(
            edge_id=edge_id,
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            evidence_kind=kind,
            source=_canonical_sha256(attrs),
            provenance=provenance,
            attrs=attrs,
        )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = CryptoCausalReader(path)
    if len(reader.triplets(include_inferred=False)) != len(ids) or not reader.verify_provenance():
        raise RuntimeError("R20 transfer Causal Reader provenance gate failed")
    return {
        "stats": stats,
        "explicit_triplets": len(ids),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def run(*, output: Path, causal_output: Path) -> dict[str, Any]:
    analysis = analyze()
    protocol = analysis["protocol"]
    with tempfile.TemporaryDirectory(prefix="r20-global-transfer-") as raw_directory:
        directory = Path(raw_directory)
        mapping_manifest, original_base_path = _derive_signed_mapping(
            formula=analysis["source_formula"], protocol=protocol, directory=directory
        )
        bfs_manifest, transformed_base_path = _build_R20_specific_global_base(
            base_path=original_base_path,
            mapping_manifest=mapping_manifest,
            protocol=protocol,
            directory=directory,
        )
        helper_path, compilation = _compile_helper(protocol, directory=directory)
        rss_gate = _load_only_RSS_gate(
            base_path=transformed_base_path, helper_path=helper_path, protocol=protocol
        )
        execution, confirmations = _execute(
            base_path=transformed_base_path,
            helper_path=helper_path,
            challenge=analysis["public_challenge"],
            protocol=protocol,
            orders=analysis["mode_orders"],
            rss_gate=rss_gate,
        )
    comparative = _comparative_metrics(execution["observations"], analysis["mode_orders"])
    comparisons = _compare(
        execution=execution,
        confirmations=confirmations,
        comparative=comparative,
        modes=list(analysis["mode_orders"]),
    )
    evidence_stage = _evidence_stage(comparisons)
    preflight = {
        "source_CNF_export": mapping_manifest["base_export"],
        "source_CNF_export_sha256": _canonical_sha256(mapping_manifest["base_export"]),
        "signed_mapping": mapping_manifest,
        "signed_mapping_sha256": _canonical_sha256(mapping_manifest),
        "BFS_far": bfs_manifest,
        "BFS_far_sha256": _canonical_sha256(bfs_manifest),
    }
    native_helper = {
        "protocol_identity": protocol["native_helper"],
        "toolchain_gates": analysis["toolchain_gates"],
        "compilation": compilation,
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": "The prospectively frozen R20 transfer rebuilds the old split18 challenge as one common CNF and retains one learned CaDiCaL state across each complete Numeric and true reflected-Gray8 cover.",
        "scope": "Standard 20-round ChaCha20 width20 partial-key recovery representation and learned-state transfer; not the first fullround recovery because A184 already retains width40 recovery.",
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": protocol["protocol_state"],
            "information_boundary": protocol["information_boundary"],
            "prospective_predictions": protocol["prospective_predictions"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "selection_basis": protocol["selection_basis"],
        "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": analysis["public_challenge_sha256"],
        "preflight": preflight,
        "preflight_sha256": _canonical_sha256(preflight),
        "native_helper": native_helper,
        "native_helper_sha256": _canonical_sha256(native_helper),
        "load_only_RSS_gate": rss_gate,
        "load_only_RSS_gate_sha256": _canonical_sha256(rss_gate),
        "incremental_modes": protocol["incremental_modes"],
        "mode_orders": analysis["mode_orders"],
        "execution_plan": protocol["execution_plan"],
        "execution": execution,
        "execution_sha256": _canonical_sha256(execution),
        "confirmations": confirmations,
        "confirmation_sha256": _canonical_sha256(confirmations),
        "comparative_metrics": comparative,
        "comparative_metrics_sha256": _canonical_sha256(comparative),
        "comparisons": comparisons,
        "comparison_sha256": _canonical_sha256(comparisons),
    }
    causal_temporary = causal_output.with_name(f".{causal_output.name}.tmp")
    causal = _build_causal(causal_temporary, payload)
    P1._atomic_write(causal_output, causal_temporary.read_bytes())
    causal_temporary.unlink()
    payload["causal"] = causal
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    P1._atomic_write(output, raw)
    reader = CryptoCausalReader(causal_output)
    if _file_sha256(output) != _sha256(raw) or not reader.verify_provenance():
        raise RuntimeError("R20 transfer final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "selected_execution": rss_gate["selected_execution"],
        "per_mode_status_counts": comparisons["per_mode_status_counts"],
        "confirmed_variants": comparisons["confirmed_variants"],
        "recovered_unknown_low20_assignments": comparisons["recovered_unknown_low20_assignments"],
        "complete_domain_resolution_modes": comparisons["complete_domain_resolution_modes"],
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument(
        "--output", type=Path, default=RESEARCH / "results" / "v1" / RESULT_FILENAME
    )
    parser.add_argument(
        "--causal-output", type=Path,
        default=RESEARCH / "results" / "v1" / CAUSAL_FILENAME
    )
    args = parser.parse_args(argv)
    if args.analyze_only:
        analysis = analyze()
        summary = {
            "protocol_sha256": PROTOCOL_SHA256,
            "public_challenge_sha256": analysis["public_challenge_sha256"],
            "modes": list(analysis["mode_orders"]),
            "mode_runs": analysis["protocol"]["execution_plan"]["mode_run_count"],
            "cell_observations": analysis["protocol"]["execution_plan"]["cell_observation_count"],
            "seconds_per_cell": SOLVER_LIMIT_SECONDS,
            "solver_execution_started": analysis["solver_execution_started"],
        }
    else:
        summary = run(output=args.output.resolve(), causal_output=args.causal_output.resolve())
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
