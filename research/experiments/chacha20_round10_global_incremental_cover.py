#!/usr/bin/env python3
"""Test one retained CaDiCaL state across complete ChaCha10 prefix covers."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
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


_A210 = _import_sibling(
    "chacha20_round10_incremental_sibling_learning.py",
    "chacha20_a211_a210_anchor",
)
_A209 = _A210._A209
_A208 = _A210._A208
_A205 = _A210._A205
_A204 = _A210._A204
_A198 = _A210._A198

ATTEMPT_ID = "A211"
SCHEMA = "chacha20-round10-global-incremental-cover-v1"
PROTOCOL_SCHEMA = "chacha20-round10-global-incremental-cover-protocol-v1"
PROTOCOL_FILENAME = "chacha20_round10_global_incremental_cover_v1.json"
PROTOCOL_SHA256 = "680346b1740173c2708a9debb90bb653387ac636bb876022e010c8857e50bd6e"
RESULT_FILENAME = "chacha20_round10_global_incremental_cover_v1.json"
CAUSAL_FILENAME = "chacha20_round10_global_incremental_cover_v1.causal"

A210_RESULT_FILENAME = _A210.RESULT_FILENAME
A210_RESULT_SHA256 = "1765ddabcec9c35d778bbb6e4c4e4aadc66277e7d9255d1f2a8ffdcd7b8152ce"
A210_CAUSAL_FILENAME = _A210.CAUSAL_FILENAME
A210_CAUSAL_SHA256 = "ff7f2019001d4c0e8478dd35476d975dde5b6faa1110c0383fbffba9091a6586"
A210_CAUSAL_GRAPH_SHA256 = "cc450abd4035fc9f823234a8001a37f59cd1a7ec8a6e2839a366d8b34a229363"

METRIC_NAMES = ("conflicts", "decisions", "search_propagations")
COMPARABLE_METRICS = ("conflicts", "decisions")
SOLVER_LIMIT_SECONDS = 10
MODE_EXTERNAL_TIMEOUT_SECONDS = 3050
MAX_PARALLEL_MODE_RUNS = 2


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A204._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A204._file_sha256(path)


def _numeric_order() -> list[str]:
    return [f"{value:08b}" for value in range(256)]


def _gray8_order() -> list[str]:
    return [f"{value ^ (value >> 1):08b}" for value in range(256)]


def _mode_orders(protocol: dict[str, Any]) -> dict[str, list[str]]:
    generated = {
        "numeric_global_incremental": _numeric_order(),
        "reflected_gray8_global_incremental": _gray8_order(),
    }
    expected_names = [mode["name"] for mode in protocol["incremental_modes"]]
    if list(generated) != expected_names:
        raise RuntimeError("A211 mode names or order differ")
    for mode in protocol["incremental_modes"]:
        order = generated[mode["name"]]
        if _canonical_sha256(order) != mode["order_sha256"] or set(order) != set(
            _numeric_order()
        ):
            raise RuntimeError(f"A211 {mode['name']} order gate failed")
    return generated


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    if _file_sha256(path) != PROTOCOL_SHA256:
        raise RuntimeError("A211 frozen protocol hash differs")
    protocol = json.loads(path.read_bytes())
    selection = protocol.get("selection_basis", {})
    base = protocol.get("global_base_preflight", {})
    mapping = protocol.get("assumption_and_model_mapping", {})
    helper = protocol.get("native_helper", {})
    execution = protocol.get("execution_plan", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_complete_A210_local_incremental_boundary_and_global_base_preflight_before_any_A211_round10_helper_execution"
        or selection.get("public_challenge_sha256") != _A198.PUBLIC_CHALLENGE_SHA256
        or selection.get("A210_per_mode_status_counts")
        != {
            "numeric_incremental": {"sat": 0, "unsat": 0, "unknown": 256, "invalid": 0},
            "gray_incremental": {"sat": 0, "unsat": 0, "unknown": 256, "invalid": 0},
        }
        or selection.get("any_A211_round10_global_incremental_outcome_known_at_selection")
        is not False
        or base.get("global_header") != "p cnf 232191 734175"
        or base.get("global_original_sha256")
        != "581e891ec1433a6075b8de8b15869ae11da590d9e7dfe3f181c5f555c3bb1720"
        or base.get("global_transformed_sha256")
        != "138ceb0a8f47dae3fd2c25e8b93165c08862a3951f7c0b4f4022e47750125e8e"
        or base.get("order_sha256")
        != "814798f19a33a3a397a6af9f6fa126207e1e10e092d8ee80dcaba4ef3bae95c8"
        or base.get("old_to_new_sha256")
        != "50d03bfd6520685c3b17ec822ad08f4b5cce80f91c771a2b1b6377fffab2f30b"
        or mapping.get("prefix_bits_descending") != list(range(19, 11, -1))
        or mapping.get("transformed_prefix_one_literals_descending")
        != [225290, 225289, 225288, 225287, 225286, 225285, 225284, 225283]
        or len(mapping.get("transformed_model_one_literals_bit0_through_bit19", []))
        != 20
        or helper.get("source_sha256")
        != "3b4a5aa0a8d537d6599ec20d9e17d173db0c7b5fbddf8864859346b5fd4a497c"
        or helper.get("compiled_binary_sha256")
        != "fb822acdd0453a36bf6e5f6df763a72a7b999710e47ac9329160f28603d1ce84"
        or helper.get("toy_validation_completed_before_freeze") is not True
        or helper.get("round10_helper_execution_completed_before_freeze") is not False
        or execution.get("mode_run_count") != 2
        or execution.get("cells_per_mode") != 256
        or execution.get("child_observation_count") != 512
        or execution.get("solver_time_limit_seconds_per_cell") != SOLVER_LIMIT_SECONDS
        or execution.get("external_timeout_seconds_per_mode")
        != MODE_EXTERNAL_TIMEOUT_SECONDS
        or execution.get("max_parallel_mode_runs") != MAX_PARALLEL_MODE_RUNS
        or execution.get("early_stop_permitted") is not False
        or boundary.get("any_A211_round10_helper_or_solver_outcome_known_before_freeze")
        is not False
        or boundary.get("unknown_assignment_available_to_runner_or_helper_before_execution")
        is not False
        or boundary.get("correct_prefix_known_before_execution") is not False
        or boundary.get("numeric_outcomes_used_to_change_Gray8_execution") is not False
        or boundary.get("early_stop_permitted") is not False
    ):
        raise RuntimeError("A211 frozen protocol identity gate failed")
    _mode_orders(protocol)
    return protocol


def _toolchain_gates(protocol: dict[str, Any]) -> dict[str, Any]:
    repo_root = Path(__file__).parents[2]
    helper = protocol["native_helper"]
    paths = {
        "source": repo_root / helper["source"],
        "toy_fixture": repo_root / helper["toy_fixture"],
        "base_unsat_toy_fixture": repo_root / helper["base_unsat_toy_fixture"],
        "compiler": Path(helper["compiler"]),
        "cadical_header": Path(helper["cadical_header"]),
        "cadical_static_library": Path(helper["cadical_static_library"]),
    }
    expected = {
        "source": helper["source_sha256"],
        "toy_fixture": helper["toy_fixture_sha256"],
        "base_unsat_toy_fixture": helper["base_unsat_toy_fixture_sha256"],
        "compiler": helper["compiler_sha256"],
        "cadical_header": helper["cadical_header_sha256"],
        "cadical_static_library": helper["cadical_static_library_sha256"],
    }
    if any(_file_sha256(paths[name]) != digest for name, digest in expected.items()):
        raise RuntimeError("A211 toolchain file gate failed")
    version = subprocess.run(
        [str(paths["compiler"]), "--version"], text=True, capture_output=True, check=False
    )
    first_line = version.stdout.splitlines()[0] if version.stdout.splitlines() else ""
    if version.returncode != 0 or first_line != helper["compiler_version_first_line"]:
        raise RuntimeError("A211 compiler identity gate failed")
    return {
        **{f"{name}_sha256": digest for name, digest in expected.items()},
        "compiler_version_first_line": first_line,
        "compiled_binary_expected_sha256": helper["compiled_binary_sha256"],
        "round10_helper_execution_started": False,
    }


def _load_a210_gate(
    results_dir: Path, protocol: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    research_root = Path(__file__).parents[1]
    result_path = results_dir / A210_RESULT_FILENAME
    causal_path = results_dir / A210_CAUSAL_FILENAME
    a210_protocol = research_root / "configs" / _A210.PROTOCOL_FILENAME
    a210_runner = Path(__file__).with_name("chacha20_round10_incremental_sibling_learning.py")
    a210_native = research_root.parent / protocol["anchors"]["A210"].get(
        "native_source", "research/native/cadical_incremental_assumptions.cpp"
    )
    if (
        _file_sha256(result_path) != A210_RESULT_SHA256
        or _file_sha256(causal_path) != A210_CAUSAL_SHA256
        or _file_sha256(a210_protocol) != protocol["anchors"]["A210"]["protocol_sha256"]
        or _file_sha256(a210_runner) != protocol["anchors"]["A210"]["runner_sha256"]
        or _file_sha256(a210_native) != protocol["anchors"]["A210"]["native_source_sha256"]
    ):
        raise RuntimeError("A211 A210 byte anchor gate failed")
    a210 = json.loads(result_path.read_bytes())
    reader = CryptoCausalReader(causal_path)
    selection = protocol["selection_basis"]
    comparisons = a210["comparisons"]
    if (
        comparisons["per_mode_status_counts"] != selection["A210_per_mode_status_counts"]
        or comparisons["confirmed_variants"] != []
        or comparisons["complete_predeclared_execution"] is not True
        or comparisons["early_stop_used"] is not False
        or len(a210["execution"]["parent_runs"]) != 64
        or len(a210["execution"]["observations"]) != 512
        or any(row["status"] != "unknown" for row in a210["execution"]["observations"])
        or any(row["valid_child_count"] != 8 for row in a210["execution"]["parent_runs"])
        or any(row["externally_timed_out"] for row in a210["execution"]["parent_runs"])
        or reader.graph_sha256 != A210_CAUSAL_GRAPH_SHA256
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A211 A210 semantic selection gate failed")
    analysis = _A210.analyze(results_dir)
    if analysis["solver_execution_started"] is not False:
        raise RuntimeError("A211 A210 analysis unexpectedly starts a solver")
    gates = {
        "A210_result_sha256": A210_RESULT_SHA256,
        "A210_causal_sha256": A210_CAUSAL_SHA256,
        "A210_causal_graph_sha256": A210_CAUSAL_GRAPH_SHA256,
        "A210_causal_provenance_verified": True,
        "A210_complete_512_unknown_boundary_retained": True,
        "A210_systematic_sibling_state_transfer_retained": True,
    }
    return a210, analysis, gates


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    a210, a210_analysis, anchor = _load_a210_gate(results_dir, protocol)
    a209 = a210_analysis["a209_result"]
    if (
        a210["public_challenge_sha256"] != _A198.PUBLIC_CHALLENGE_SHA256
        or a210["public_challenge"]["unknown_assignment_included"] is not False
        or len(a209["execution"]["observations"]) != 256
        or any(row["status"] != "unknown" for row in a209["execution"]["observations"])
    ):
        raise RuntimeError("A211 challenge or A209 baseline boundary gate failed")
    return {
        "protocol": protocol,
        "toolchain_gates": _toolchain_gates(protocol),
        "anchor_gates": anchor,
        "a210_result": a210,
        "a210_analysis": a210_analysis,
        "a209_result": a209,
        "public_challenge": a210["public_challenge"],
        "mode_orders": _mode_orders(protocol),
        "solver_execution_started": False,
    }


def _strip_parent_units(raw: bytes, protocol: dict[str, Any]) -> tuple[bytes, list[int]]:
    preflight = protocol["global_base_preflight"]
    lines = raw.splitlines(keepends=True)
    if not lines or lines[0].decode().strip() != preflight["source_header"]:
        raise RuntimeError("A211 source CNF header differs")
    tail = lines[-preflight["source_parent_unit_clause_count"] :]
    literals = []
    for line in tail:
        fields = line.split()
        if len(fields) != 2 or fields[1] != b"0":
            raise RuntimeError("A211 parent tail is not five unit clauses")
        literals.append(int(fields[0]))
    if [abs(value) for value in literals] != preflight[
        "source_parent_unit_variables_in_tail_order"
    ]:
        raise RuntimeError("A211 parent unit variables differ")
    header = (preflight["global_header"] + "\n").encode()
    return header + b"".join(lines[1:-5]), literals


def _clause_length_counts(raw: bytes) -> dict[str, int]:
    counts = {"unit": 0, "binary": 0, "ternary": 0}
    for line in raw.splitlines()[1:]:
        length = len(line.split()) - 1
        name = {1: "unit", 2: "binary", 3: "ternary"}.get(length)
        if name is None:
            raise RuntimeError("A211 global base has an unexpected clause length")
        counts[name] += 1
    return counts


def _build_global_base(
    *, analysis: dict[str, Any], identities: dict[str, dict[str, Any]], directory: Path
) -> tuple[list[dict[str, Any]], dict[str, Any], Path]:
    protocol = analysis["protocol"]
    preflight = protocol["global_base_preflight"]
    a209_analysis = analysis["a210_analysis"]["a209_analysis"]
    a204_analysis = a209_analysis["a208_analysis"]["a207_analysis"]["a206_analysis"][
        "a204_analysis"
    ]
    source_exports, source_paths = _A204._export_round10_cnfs(
        a204_analysis, identities, directory
    )
    free_mapping = a209_analysis["a208_analysis"]["protocol"]["round10_source"][
        "free_k0_bit_one_literal_mapping"
    ]
    representative = _A209._refine_cnf(
        source_paths["cse_prefix_11111"].read_bytes(),
        prefix8="11111111",
        free_mapping=free_mapping,
    )
    _, mapping, inverse, transformed_model15, diagnostics = _A209._derive_refined_order(
        representative, free_mapping, a209_analysis["protocol"]
    )
    expected_model20 = protocol["assumption_and_model_mapping"][
        "transformed_model_one_literals_bit0_through_bit19"
    ]
    source_model20 = protocol["assumption_and_model_mapping"][
        "source_model_one_literals_bit0_through_bit19"
    ]
    if (
        transformed_model15 != expected_model20[:15]
        or [mapping[value] for value in source_model20] != expected_model20
        or diagnostics["order_sha256"] != preflight["order_sha256"]
        or diagnostics["old_to_new_sha256"] != preflight["old_to_new_sha256"]
    ):
        raise RuntimeError("A211 frozen permutation or model mapping differs")

    originals: list[bytes] = []
    transformed: list[bytes] = []
    tail_manifest = []
    transformed_direct_reference = None
    for prefix5 in _A208.PREFIXES:
        raw = source_paths[f"cse_prefix_{prefix5}"].read_bytes()
        base, tail = _strip_parent_units(raw, protocol)
        transformed_cell = _A205._reindex_cnf(raw, mapping)
        transformed_base, transformed_tail = _strip_parent_units(
            transformed_cell,
            {
                **protocol,
                "global_base_preflight": {
                    **preflight,
                    "source_parent_unit_variables_in_tail_order": [
                        mapping[value]
                        for value in preflight["source_parent_unit_variables_in_tail_order"]
                    ],
                },
            },
        )
        if transformed_direct_reference is None:
            transformed_direct_reference = _A205._reindex_cnf(base, mapping)
        if transformed_base != transformed_direct_reference:
            raise RuntimeError("A211 transformed stripped base differs")
        reconstructed = (
            (preflight["source_header"] + "\n").encode()
            + b"".join(base.splitlines(keepends=True)[1:])
            + b"".join(f"{value} 0\n".encode() for value in tail)
        )
        transformed_reconstructed = (
            (preflight["source_header"] + "\n").encode()
            + b"".join(transformed_base.splitlines(keepends=True)[1:])
            + b"".join(f"{value} 0\n".encode() for value in transformed_tail)
        )
        if reconstructed != raw or transformed_reconstructed != transformed_cell:
            raise RuntimeError("A211 stripped cell reconstruction differs")
        originals.append(base)
        transformed.append(transformed_base)
        tail_manifest.append(
            {
                "prefix5": prefix5,
                "source_tail_units": tail,
                "transformed_tail_units": transformed_tail,
            }
        )
    original = originals[0]
    transformed_base = transformed[0]
    unit_variables = {
        abs(int(line.split()[0]))
        for line in transformed_base.splitlines()[1:]
        if len(line.split()) == 2
    }
    assumptions = set(
        protocol["assumption_and_model_mapping"][
            "transformed_prefix_one_literals_descending"
        ]
    )
    if (
        any(raw != original for raw in originals)
        or any(raw != transformed_base for raw in transformed)
        or len(original) != preflight["global_original_bytes"]
        or _sha256(original) != preflight["global_original_sha256"]
        or len(transformed_base) != preflight["global_transformed_bytes"]
        or _sha256(transformed_base) != preflight["global_transformed_sha256"]
        or _A205._reindex_cnf(transformed_base, inverse) != original
        or _clause_length_counts(original) != preflight["global_clause_length_counts"]
        or assumptions & unit_variables
    ):
        raise RuntimeError("A211 complete global base preflight gate failed")
    output = directory / "a211_global_bfs_far.cnf"
    output.write_bytes(transformed_base)
    clean_sources = [
        {key: value for key, value in row.items() if key != "path"} for row in source_exports
    ]
    manifest = {
        "source_exports_sha256": _canonical_sha256(clean_sources),
        "tail_manifest": tail_manifest,
        "tail_manifest_sha256": _canonical_sha256(tail_manifest),
        "all_32_original_bases_byte_identical": True,
        "all_32_transformed_bases_byte_identical": True,
        "all_32_cells_reconstructed_byte_identically": True,
        "global_original_bytes": len(original),
        "global_original_sha256": _sha256(original),
        "global_transformed_bytes": len(transformed_base),
        "global_transformed_sha256": _sha256(transformed_base),
        "clause_length_counts": _clause_length_counts(original),
        "assumption_variables_absent_from_base_units": True,
        "inverse_reindex_byte_identical": True,
        "order_sha256": diagnostics["order_sha256"],
        "old_to_new_sha256": diagnostics["old_to_new_sha256"],
    }
    return clean_sources, manifest, output


def _compile_helper(
    protocol: dict[str, Any], *, repo_root: Path, directory: Path
) -> tuple[Path, dict[str, Any]]:
    helper = protocol["native_helper"]
    output = directory / "cadical_global_incremental_assumptions"
    command = [helper["compiler"], *helper["compile_arguments"], "-o", str(output)]
    started = time.perf_counter()
    result = subprocess.run(
        command, cwd=repo_root, text=True, capture_output=True, check=False
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
        raise RuntimeError("A211 native helper compilation gate failed")
    return output, observation


def _decode_model(challenge: dict[str, Any], model_bits: Sequence[int]) -> dict[str, int]:
    if len(model_bits) != 20 or any(value not in {0, 1} for value in model_bits):
        raise RuntimeError("A211 helper SAT model is not twenty Boolean bits")
    low20 = sum(value << bit for bit, value in enumerate(model_bits))
    key_word0 = challenge["known_key_word0_upper12"] | low20
    key_word1_low_value = challenge["known_key_word1"] & 0xFF
    return {
        "key_word0": key_word0,
        "key_word1_low_value": key_word1_low_value,
        "combined_assignment": (key_word1_low_value << 32) | key_word0,
        "recovered_unknown_low20": low20,
    }


def _invalid_cell(*, mode: str, prefix8: str, cell_index: int, reason: str) -> dict[str, Any]:
    return {
        "variant": f"{mode}__prefix_{prefix8}",
        "mode": mode,
        "prefix8": prefix8,
        "cell_index": cell_index,
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
            if line.startswith("A211_RESULT "):
                row = json.loads(line.removeprefix("A211_RESULT "))
                prefix8 = row["prefix8"]
                if prefix8 in parsed:
                    malformed = True
                parsed[prefix8] = row
            elif line.startswith("A211_SUMMARY "):
                if summary is not None:
                    malformed = True
                summary = json.loads(line.removeprefix("A211_SUMMARY "))
            elif line.strip():
                malformed = True
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            malformed = True
    if externally_timed_out:
        invalid_reason = "external_mode_timeout"
    elif helper_returncode != 0:
        invalid_reason = "invalid_helper_returncode"
    elif malformed or set(parsed) != set(order):
        invalid_reason = "malformed_or_incomplete_helper_output"
    else:
        invalid_reason = None
    valid_mode = invalid_reason is None
    observations: list[dict[str, Any]] = []
    confirmations: list[dict[str, Any]] = []
    previous_after = None
    assumption_vars = protocol["assumption_and_model_mapping"][
        "transformed_prefix_one_literals_descending"
    ]
    for cell_index, prefix8 in enumerate(order):
        raw = parsed.get(prefix8)
        if raw is None or not valid_mode:
            observations.append(
                _invalid_cell(
                    mode=mode,
                    prefix8=prefix8,
                    cell_index=cell_index,
                    reason=invalid_reason or "missing_helper_cell",
                )
            )
            continue
        expected_assumptions = [
            variable if bit == "1" else -variable
            for bit, variable in zip(prefix8, assumption_vars, strict=True)
        ]
        status = raw.get("status")
        failed = raw.get("failed_assumptions")
        before = raw.get("metrics_before")
        after = raw.get("metrics_after")
        delta = raw.get("metrics_delta")
        if (
            raw.get("mode") != mode
            or raw.get("cell_index") != cell_index
            or raw.get("metric_names") != list(METRIC_NAMES)
            or raw.get("assumptions") != expected_assumptions
            or status not in {"sat", "unsat", "unknown"}
            or raw.get("returncode") != {"sat": 10, "unsat": 20, "unknown": 0}[status]
            or not isinstance(before, list)
            or not isinstance(after, list)
            or not isinstance(delta, list)
            or len(before) != 3
            or len(after) != 3
            or len(delta) != 3
            or any(
                after_value - before_value != delta_value
                for before_value, after_value, delta_value in zip(
                    before, after, delta, strict=True
                )
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
            valid_mode = False
            invalid_reason = "helper_semantic_gate_failed"
            break
        previous_after = after
        model = None
        if status == "sat":
            model = _decode_model(challenge, raw["model_bits_bit0_through_bit19"])
            confirmation = {
                "variant": f"{mode}__prefix_{prefix8}",
                "mode": mode,
                "prefix8": prefix8,
                "prefix8_match": ((model["key_word0"] >> 12) & 0xFF) == int(prefix8, 2),
                **_A198._confirm_model(challenge, model),
            }
            if (
                confirmation["prefix8_match"] is not True
                or confirmation["known_key_constraints_match"] is not True
                or confirmation["all_blocks_match"] is not True
                or confirmation["control_first_block_match"] is not False
                or confirmation["output_bits_checked"] != 4096
            ):
                raise RuntimeError("A211 helper SAT model failed independent confirmation")
            confirmations.append(confirmation)
        observations.append(
            {
                "variant": f"{mode}__prefix_{prefix8}",
                "mode": mode,
                "prefix8": prefix8,
                "cell_index": cell_index,
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
    if valid_mode:
        counts = {
            status: sum(row["status"] == status for row in observations)
            for status in ("sat", "unsat", "unknown")
        }
        if (
            len(observations) != 256
            or summary is None
            or summary.get("signature") != "cadical-3.0.0"
            or summary.get("version") != "3.0.0"
            or summary.get("mode") != mode
            or summary.get("variables") != 232191
            or summary.get("cells") != 256
            or summary.get("metric_names") != list(METRIC_NAMES)
            or {status: summary.get(status) for status in counts} != counts
        ):
            valid_mode = False
            invalid_reason = "helper_summary_gate_failed"
    if not valid_mode:
        observations = [
            _invalid_cell(
                mode=mode,
                prefix8=prefix8,
                cell_index=index,
                reason=invalid_reason or "invalid_mode_output",
            )
            for index, prefix8 in enumerate(order)
        ]
        confirmations = []
    return observations, confirmations, summary


def _run_mode(
    *,
    mode: str,
    order: list[str],
    base_path: Path,
    helper_path: Path,
    protocol: dict[str, Any],
    challenge: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    mapping = protocol["assumption_and_model_mapping"]
    command = [
        str(helper_path),
        "--cnf",
        str(base_path),
        "--mode",
        mode,
        "--assumption-vars",
        ",".join(str(value) for value in mapping["transformed_prefix_one_literals_descending"]),
        "--model-vars",
        ",".join(
            str(value) for value in mapping["transformed_model_one_literals_bit0_through_bit19"]
        ),
        "--cell-order",
        ",".join(order),
        "--seconds",
        str(SOLVER_LIMIT_SECONDS),
    ]
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=MODE_EXTERNAL_TIMEOUT_SECONDS,
            check=False,
        )
        externally_timed_out = False
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        externally_timed_out = True
        stdout = _A204._as_text(error.stdout)
        stderr = _A204._as_text(error.stderr)
        returncode = None
    observations, confirmations, summary = _parse_mode_output(
        mode=mode,
        order=order,
        stdout=stdout,
        helper_returncode=returncode,
        externally_timed_out=externally_timed_out,
        challenge=challenge,
        protocol=protocol,
    )
    mode_run = {
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
    }
    return mode_run, observations, confirmations


def _execute(
    *,
    base_path: Path,
    helper_path: Path,
    protocol: dict[str, Any],
    challenge: dict[str, Any],
    orders: dict[str, list[str]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    def execute(item: tuple[str, list[str]]) -> tuple[
        dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]
    ]:
        mode, order = item
        return _run_mode(
            mode=mode,
            order=order,
            base_path=base_path,
            helper_path=helper_path,
            protocol=protocol,
            challenge=challenge,
        )

    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_MODE_RUNS) as executor:
        rows = list(executor.map(execute, orders.items()))
    mode_runs = [row[0] for row in rows]
    observations = [cell for row in rows for cell in row[1]]
    confirmations = [confirmation for row in rows for confirmation in row[2]]
    expected = [
        {"mode": mode, "prefix8": prefix8}
        for mode, order in orders.items()
        for prefix8 in order
    ]
    if [
        {"mode": row["mode"], "prefix8": row["prefix8"]} for row in observations
    ] != expected:
        raise RuntimeError("A211 complete execution order differs from freeze")
    complete_valid_modes = all(
        row["returncode"] == 0
        and row["externally_timed_out"] is False
        and row["valid_cell_count"] == 256
        for row in mode_runs
    )
    complete_valid_cells = complete_valid_modes and all(
        row["status"] != "invalid" for row in observations
    )
    return {
        "mode_run_order": list(orders),
        "cell_observation_order": expected,
        "mode_plan_materialized": len(mode_runs) == 2,
        "cell_plan_materialized": len(observations) == 512,
        "complete_valid_mode_plan_executed": len(mode_runs) == 2 and complete_valid_modes,
        "complete_valid_cell_plan_executed": len(observations) == 512
        and complete_valid_cells,
        "early_stop_used": False,
        "mode_runs": mode_runs,
        "observations": observations,
        "returned_model_count": len(confirmations),
        "round10_unknown_assignment_available_to_runner_or_helper_before_execution": False,
    }, confirmations


def _ratio_summary(
    rows: list[dict[str, Any]], numerator: str, denominator: str, metric: str
) -> dict[str, Any]:
    return _A210._metric_ratio_summary(rows, numerator, denominator, metric)


def _hamming_profile(order: list[str]) -> dict[str, Any]:
    distances = [
        sum(left != right for left, right in zip(previous, current, strict=True))
        for previous, current in zip(order, order[1:], strict=False)
    ]
    return {
        "transition_count": len(distances),
        "distance_counts": {
            str(distance): distances.count(distance) for distance in sorted(set(distances))
        },
        "minimum": min(distances),
        "maximum": max(distances),
        "total": sum(distances),
    }


def _position_bins(
    observations: list[dict[str, Any]], orders: dict[str, list[str]]
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for mode in orders:
        rows = [row for row in observations if row["mode"] == mode]
        bins = []
        for start in range(0, 256, 32):
            selected = rows[start : start + 32]
            bins.append(
                {
                    "start_index": start,
                    "end_index_inclusive": start + 31,
                    "first_prefix8": selected[0]["prefix8"],
                    "last_prefix8": selected[-1]["prefix8"],
                    "status_counts": {
                        status: sum(row["status"] == status for row in selected)
                        for status in ("sat", "unsat", "unknown", "invalid")
                    },
                    "metric_totals": {
                        metric: sum(row["metrics_delta"].get(metric, 0) for row in selected)
                        for metric in METRIC_NAMES
                    },
                    "mean_elapsed_seconds": sum(
                        row["elapsed_seconds"] or 0.0 for row in selected
                    )
                    / 32,
                    "mean_active_variables": sum(
                        row["active_variables"] or 0 for row in selected
                    )
                    / 32,
                    "mean_redundant_clauses": sum(
                        row["redundant_clauses"] or 0 for row in selected
                    )
                    / 32,
                }
            )
        result[mode] = bins
    return result


def _comparative_metrics(
    *,
    observations: list[dict[str, Any]],
    a209_observations: list[dict[str, Any]],
    a210_observations: list[dict[str, Any]],
    orders: dict[str, list[str]],
) -> dict[str, Any]:
    a209 = {row["prefix8"]: row for row in a209_observations}
    a210_numeric = {
        row["prefix8"]: row
        for row in a210_observations
        if row["mode"] == "numeric_incremental"
    }
    by_mode = {
        mode: [row for row in observations if row["mode"] == mode] for mode in orders
    }
    mode_vs_a209_rows: dict[str, list[dict[str, Any]]] = {}
    for mode, rows in by_mode.items():
        mode_vs_a209_rows[mode] = [
            {
                "mode": mode,
                "prefix8": row["prefix8"],
                "cell_index": row["cell_index"],
                "status": row["status"],
                "global_metrics_delta": row["metrics_delta"],
                "A209_fresh_metrics": a209[row["prefix8"]]["metrics"],
            }
            for row in rows
        ]
    mode_vs_a209_summaries = {
        mode: {
            metric: _ratio_summary(rows, "global_metrics_delta", "A209_fresh_metrics", metric)
            for metric in COMPARABLE_METRICS
        }
        for mode, rows in mode_vs_a209_rows.items()
    }

    numeric_rows = []
    for row in by_mode["numeric_global_incremental"]:
        local = a210_numeric[row["prefix8"]]
        numeric_rows.append(
            {
                "prefix8": row["prefix8"],
                "global_cell_index": row["cell_index"],
                "A210_parent_child_index": local["child_index"],
                "global_metrics_delta": row["metrics_delta"],
                "A210_local_metrics_delta": local["metrics_delta"],
                "global_status": row["status"],
                "A210_status": local["status"],
            }
        )
    numeric_vs_a210 = {
        metric: _ratio_summary(
            numeric_rows, "global_metrics_delta", "A210_local_metrics_delta", metric
        )
        for metric in METRIC_NAMES
    }
    numeric_by_local_position = []
    for position in range(8):
        selected = [
            row for row in numeric_rows if row["A210_parent_child_index"] == position
        ]
        numeric_by_local_position.append(
            {
                "A210_parent_child_index": position,
                "cell_count": len(selected),
                "global_over_A210": {
                    metric: _ratio_summary(
                        selected,
                        "global_metrics_delta",
                        "A210_local_metrics_delta",
                        metric,
                    )
                    for metric in METRIC_NAMES
                },
            }
        )

    numeric = {row["prefix8"]: row for row in by_mode["numeric_global_incremental"]}
    gray = {
        row["prefix8"]: row for row in by_mode["reflected_gray8_global_incremental"]
    }
    paired_rows = [
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
    paired_summary = {
        "status_difference_prefixes": [
            row["prefix8"]
            for row in paired_rows
            if row["numeric_status"] != row["gray8_status"]
        ],
        "gray8_over_numeric": {
            metric: _ratio_summary(
                paired_rows, "gray8_metrics_delta", "numeric_metrics_delta", metric
            )
            for metric in METRIC_NAMES
        },
    }
    return {
        "A209_comparison_scope": list(COMPARABLE_METRICS),
        "search_propagations_not_compared_to_A209_CLI_total_propagations": True,
        "mode_vs_A209_rows": mode_vs_a209_rows,
        "mode_vs_A209_summaries": mode_vs_a209_summaries,
        "numeric_global_vs_A210_local_rows": numeric_rows,
        "numeric_global_vs_A210_local_summary": numeric_vs_a210,
        "numeric_global_vs_A210_by_local_position": numeric_by_local_position,
        "global_order_paired_rows": paired_rows,
        "global_order_paired_summary": paired_summary,
        "position_bins_32": _position_bins(observations, orders),
        "order_hamming_profiles": {
            mode: _hamming_profile(order) for mode, order in orders.items()
        },
    }


def _compare(
    *,
    execution: dict[str, Any],
    confirmations: list[dict[str, Any]],
    comparative: dict[str, Any],
    modes: list[str],
) -> dict[str, Any]:
    observations = execution["observations"]
    per_mode = {
        mode: {
            status: sum(
                row["mode"] == mode and row["status"] == status for row in observations
            )
            for status in ("sat", "unsat", "unknown", "invalid")
        }
        for mode in modes
    }
    confirmed = {
        mode: [row for row in confirmations if row["mode"] == mode] for mode in modes
    }
    confirmed_prefixes = {
        mode: sorted({row["prefix8"] for row in rows}) for mode, rows in confirmed.items()
    }
    unsat_prefixes = {
        mode: sorted(
            {
                row["prefix8"]
                for row in observations
                if row["mode"] == mode and row["status"] == "unsat"
            }
        )
        for mode in modes
    }
    complete_candidates = [
        mode
        for mode, counts in per_mode.items()
        if counts == {"sat": 1, "unsat": 255, "unknown": 0, "invalid": 0}
    ]
    contradictory = sorted(
        (set(confirmed_prefixes[modes[0]]) & set(unsat_prefixes[modes[1]]))
        | (set(confirmed_prefixes[modes[1]]) & set(unsat_prefixes[modes[0]]))
    )
    complete = [
        mode
        for mode in complete_candidates
        if len(confirmed[mode]) == 1 and not contradictory
    ]
    valid_by_mode = {
        mode: counts["invalid"] == 0 and sum(counts.values()) == 256
        for mode, counts in per_mode.items()
    }
    complete_valid_execution = (
        execution.get("complete_valid_mode_plan_executed") is True
        and execution.get("complete_valid_cell_plan_executed") is True
        and all(valid_by_mode.values())
    )
    state_rows = comparative["numeric_global_vs_A210_local_rows"]
    matched_state_rows = [
        row
        for row in state_rows
        if row.get("global_status") != "invalid"
        and row.get("A210_status") != "invalid"
        and all(
            metric in row.get("global_metrics_delta", {})
            and metric in row.get("A210_local_metrics_delta", {})
            for metric in ("conflicts", "decisions")
        )
    ]
    state_difference_counts = {
        metric: sum(
            row["global_metrics_delta"][metric]
            != row["A210_local_metrics_delta"][metric]
            for row in matched_state_rows
        )
        for metric in ("conflicts", "decisions")
    }
    state_status_difference_count = sum(
        row["global_status"] != row["A210_status"] for row in matched_state_rows
    )
    state_evaluated = (
        valid_by_mode["numeric_global_incremental"] and len(matched_state_rows) == 256
    )
    state_retained = state_evaluated and any(state_difference_counts.values())
    order_rows = comparative["global_order_paired_rows"]
    matched_order_rows = [
        row
        for row in order_rows
        if row.get("numeric_status") != "invalid"
        and row.get("gray8_status") != "invalid"
        and all(
            metric in row.get("numeric_metrics_delta", {})
            and metric in row.get("gray8_metrics_delta", {})
            for metric in METRIC_NAMES
        )
    ]
    order_difference_counts = {
        metric: sum(
            row["gray8_metrics_delta"][metric] != row["numeric_metrics_delta"][metric]
            for row in matched_order_rows
        )
        for metric in METRIC_NAMES
    }
    order_status_difference_count = sum(
        row["gray8_status"] != row["numeric_status"] for row in matched_order_rows
    )
    order_status_counts_differ = per_mode[modes[0]] != per_mode[modes[1]]
    order_evaluated = all(valid_by_mode.values()) and len(matched_order_rows) == 256
    order_retained = order_evaluated and (
        order_status_counts_differ or any(order_difference_counts.values())
    )
    return {
        "mode_run_count": len(execution["mode_runs"]),
        "cell_observation_count": len(observations),
        "mode_plan_materialized": len(execution["mode_runs"]) == 2,
        "cell_plan_materialized": len(observations) == 512,
        "complete_predeclared_execution": complete_valid_execution,
        "early_stop_used": False,
        "per_mode_status_counts": per_mode,
        "valid_complete_domain_observation_by_mode": valid_by_mode,
        "terminal_cell_counts": {
            mode: counts["sat"] + counts["unsat"] for mode, counts in per_mode.items()
        },
        "confirmed_variants": [row["variant"] for row in confirmations],
        "confirmed_prefixes_by_mode": confirmed_prefixes,
        "confirmed_combined_assignments": sorted(
            {row["combined_assignment"] for row in confirmations}
        ),
        "recovered_unknown_low20_assignments": sorted(
            {row["recovered_unknown_low20"] for row in confirmations}
        ),
        "confirmed_recovery_retained": bool(confirmations),
        "complete_domain_resolution_candidate_modes": complete_candidates,
        "cross_mode_contradictory_confirmed_unsat_prefixes": contradictory,
        "complete_domain_resolution_modes": complete,
        "complete_domain_resolution_retained": bool(complete),
        "global_resolution_transfer_retained": any(
            counts["sat"] + counts["unsat"] > 0 for counts in per_mode.values()
        ),
        "global_state_transfer_prediction": {
            "evaluated": state_evaluated,
            "candidate_cell_count": len(state_rows),
            "matched_valid_cell_count": len(matched_state_rows),
            "status_difference_count": state_status_difference_count,
            "metric_difference_prefix_counts": state_difference_counts,
            "retained": state_retained,
        },
        "global_state_transfer_retained": state_retained,
        "true_gray8_order_effect_prediction": {
            "evaluated": order_evaluated,
            "candidate_cell_count": len(order_rows),
            "matched_valid_cell_count": len(matched_order_rows),
            "per_mode_status_counts_differ": order_status_counts_differ,
            "status_difference_count": order_status_difference_count,
            "metric_difference_prefix_counts": order_difference_counts,
            "retained": order_retained,
        },
        "true_gray8_order_effect_retained": order_retained,
        "complete_domain_covered_once_per_mode": complete_valid_execution,
        "complete_domain_candidate_count": 1 << 20,
        "statuses": {row["variant"]: row["status"] for row in observations},
    }


def _evidence_stage(comparisons: dict[str, Any]) -> str:
    if comparisons["complete_domain_resolution_retained"]:
        return (
            "ROUND10_GLOBAL_INCREMENTAL_COMPLETE_DOMAIN_RESOLUTION_RETAINED"
            if comparisons["complete_predeclared_execution"]
            else "ROUND10_GLOBAL_INCREMENTAL_COMPLETE_DOMAIN_RESOLUTION_WITH_INCOMPLETE_FACTORIAL_RETAINED"
        )
    if comparisons["confirmed_recovery_retained"]:
        return (
            "ROUND10_GLOBAL_INCREMENTAL_CONFIRMED_RECOVERY_RETAINED"
            if comparisons["complete_predeclared_execution"]
            else "ROUND10_GLOBAL_INCREMENTAL_CONFIRMED_RECOVERY_WITH_INCOMPLETE_FACTORIAL_RETAINED"
        )
    if comparisons["global_resolution_transfer_retained"]:
        return (
            "ROUND10_GLOBAL_INCREMENTAL_TERMINAL_TRANSFER_RETAINED"
            if comparisons["complete_predeclared_execution"]
            else "ROUND10_GLOBAL_INCREMENTAL_TERMINAL_TRANSFER_WITH_INCOMPLETE_FACTORIAL_RETAINED"
        )
    if (
        comparisons["global_state_transfer_retained"]
        and comparisons["true_gray8_order_effect_retained"]
    ):
        return "ROUND10_GLOBAL_INCREMENTAL_STATE_AND_ORDER_EFFECT_RETAINED"
    if comparisons["global_state_transfer_retained"]:
        return (
            "ROUND10_GLOBAL_INCREMENTAL_STATE_TRANSFER_RETAINED"
            if comparisons["complete_predeclared_execution"]
            else "ROUND10_GLOBAL_INCREMENTAL_STATE_TRANSFER_WITH_INCOMPLETE_FACTORIAL_RETAINED"
        )
    if comparisons["true_gray8_order_effect_retained"]:
        return "ROUND10_GLOBAL_INCREMENTAL_ORDER_EFFECT_RETAINED"
    if not comparisons["complete_predeclared_execution"]:
        return "ROUND10_GLOBAL_INCREMENTAL_INVALID_EXECUTION_RETAINED"
    return "ROUND10_GLOBAL_INCREMENTAL_COMPLETE_BOUNDARY_RETAINED"


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_round10_global_incremental_cover",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": 10,
            "modes": 2,
            "cells_per_mode": 256,
            "cell_observations": 512,
        },
    )
    ids = [
        "chacha20-a211-a210-local-state-anchor",
        "chacha20-a211-global-base-identity",
        "chacha20-a211-global-key-mapping",
        "chacha20-a211-native-global-helper",
        "chacha20-a211-ordered-global-factorial",
        "chacha20-a211-complete-global-execution",
        "chacha20-a211-independent-confirmation",
        "chacha20-a211-comparative-profile",
        "chacha20-a211-global-result",
    ]
    rows = [
        (
            "A210:complete_local_incremental_boundary",
            "retain_the_systematic_post_first_sibling_learned_state_transfer",
            "A211:global_incremental_selection_anchor",
            "retained_A210_local_state_transfer",
            A210_CAUSAL_SHA256,
            [],
            {
                "anchor_gates": payload["anchor_gates"],
                "selection_basis": payload["selection_basis"],
            },
        ),
        (
            "A211:global_incremental_selection_anchor",
            "remove_exactly_the_five_parent_units_from_all_32_byte_matched_CNF_cells",
            "A211:single_common_round10_base",
            "exact_global_base_derivation",
            payload["global_base_manifest_sha256"],
            [ids[0]],
            {"global_base_manifest": payload["global_base_manifest"]},
        ),
        (
            "A211:single_common_round10_base",
            "apply_the_frozen_A209_BFS_far_bijection_and_gate_all_twenty_key_literals",
            "A211:global_assumption_model_mapping",
            "exact_global_key_mapping",
            payload["mapping_sha256"],
            [ids[1]],
            {"assumption_and_model_mapping": payload["assumption_and_model_mapping"]},
        ),
        (
            "A211:global_assumption_model_mapping",
            "compile_and_hash_gate_the_CaDiCaL_3_global_assumption_helper",
            "A211:exact_global_incremental_primitive",
            "native_helper_identity",
            payload["native_helper_sha256"],
            [ids[2]],
            {"native_helper": payload["native_helper"]},
        ),
        (
            "A211:exact_global_incremental_primitive",
            "freeze_numeric_and_true_reflected_Gray8_complete_ordered_update_sequences",
            "A211:two_mode_global_T01_factorial",
            "T01_global_ordered_noncommutative_update_transfer",
            payload["incremental_modes_sha256"],
            [ids[3]],
            {"incremental_modes": payload["incremental_modes"]},
        ),
        (
            "A211:two_mode_global_T01_factorial",
            "attempt_both_complete_covers_and_atomically_retain_each_valid_or_invalid_mode_record",
            "A211:global_incremental_execution_record",
            "predeclared_global_execution_record",
            payload["execution_sha256"],
            [ids[4]],
            {"execution": payload["execution"]},
        ),
        (
            "A211:global_incremental_execution_record",
            "decode_every_SAT_model_and_recompute_all_4096_target_bits",
            "A211:independently_confirmed_models_or_boundary",
            "independent_model_confirmation",
            payload["confirmation_sha256"],
            [ids[5]],
            {"confirmations": payload["confirmations"]},
        ),
        (
            "A211:independently_confirmed_models_or_boundary",
            "compare_global_numeric_with_A210_local_numeric_A209_fresh_and_true_Gray8",
            "A211:global_learning_and_order_profile",
            "matched_global_incremental_comparison",
            payload["comparative_metrics_sha256"],
            [ids[6]],
            {"comparative_metrics": payload["comparative_metrics"]},
        ),
        (
            "A211:global_learning_and_order_profile",
            "evaluate_recovery_resolution_global_transfer_and_order_predictions",
            "A211:prospective_global_incremental_result",
            "prospective_global_incremental_comparison",
            payload["comparison_sha256"],
            [ids[7]],
            {"comparisons": payload["comparisons"]},
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
        raise RuntimeError("A211 Causal Reader provenance gate failed")
    return {
        "stats": stats,
        "explicit_triplets": len(ids),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def run(*, results_dir: Path, output: Path, causal_output: Path) -> dict[str, Any]:
    analysis = analyze(results_dir)
    protocol = analysis["protocol"]
    repo_root = Path(__file__).parents[2]
    identities = _A204._solver_gates(_A204._load_protocol_gate())
    with tempfile.TemporaryDirectory(prefix="a211-global-incremental-") as raw_directory:
        directory = Path(raw_directory)
        helper_path, compilation = _compile_helper(
            protocol, repo_root=repo_root, directory=directory
        )
        source_exports, base_manifest, base_path = _build_global_base(
            analysis=analysis, identities=identities, directory=directory
        )
        execution, confirmations = _execute(
            base_path=base_path,
            helper_path=helper_path,
            protocol=protocol,
            challenge=analysis["public_challenge"],
            orders=analysis["mode_orders"],
        )
    comparative = _comparative_metrics(
        observations=execution["observations"],
        a209_observations=analysis["a209_result"]["execution"]["observations"],
        a210_observations=analysis["a210_result"]["execution"]["observations"],
        orders=analysis["mode_orders"],
    )
    mode_names = list(analysis["mode_orders"])
    comparisons = _compare(
        execution=execution,
        confirmations=confirmations,
        comparative=comparative,
        modes=mode_names,
    )
    evidence_stage = _evidence_stage(comparisons)
    native_helper = {
        "protocol_identity": protocol["native_helper"],
        "toolchain_gates": analysis["toolchain_gates"],
        "compilation": compilation,
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "The predeclared two-mode experiment atomically records each valid or "
            "invalid single-state cover and evaluates globally retained learning "
            "under numeric and true reflected-Gray8 orders."
        ),
        "scope": "Reduced ChaCha10 20-bit partial-key recovery over eight shared-key blocks.",
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": protocol["protocol_state"],
            "information_boundary": protocol["information_boundary"],
            "prospective_predictions": protocol["prospective_predictions"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "selection_basis": protocol["selection_basis"],
        "selection_basis_sha256": _canonical_sha256(protocol["selection_basis"]),
        "solver_identities": {
            "bitwuzla": identities["bitwuzla"],
            "cadical_cli_anchor": identities["cadical"],
        },
        "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": _A198.PUBLIC_CHALLENGE_SHA256,
        "formula_transfer_family": protocol["selection_basis"]["formula_transfer_family"],
        "source_exports": source_exports,
        "source_exports_sha256": _canonical_sha256(source_exports),
        "global_base_manifest": base_manifest,
        "global_base_manifest_sha256": _canonical_sha256(base_manifest),
        "assumption_and_model_mapping": protocol["assumption_and_model_mapping"],
        "mapping_sha256": _canonical_sha256(protocol["assumption_and_model_mapping"]),
        "native_helper": native_helper,
        "native_helper_sha256": _canonical_sha256(native_helper),
        "incremental_modes": protocol["incremental_modes"],
        "incremental_modes_sha256": _canonical_sha256(protocol["incremental_modes"]),
        "mode_orders": analysis["mode_orders"],
        "mode_orders_sha256": _canonical_sha256(analysis["mode_orders"]),
        "execution_plan": protocol["execution_plan"],
        "execution_plan_sha256": _canonical_sha256(protocol["execution_plan"]),
        "execution": execution,
        "execution_sha256": _canonical_sha256(execution),
        "confirmations": confirmations,
        "confirmation_sha256": _canonical_sha256(confirmations),
        "comparative_metrics": comparative,
        "comparative_metrics_sha256": _canonical_sha256(comparative),
        "comparisons": comparisons,
        "comparison_sha256": _canonical_sha256(comparisons),
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _A204._A198._A185._atomic_write(output, raw)
    reader = CryptoCausalReader(causal_output)
    if (
        _file_sha256(output) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A211 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "per_mode_status_counts": comparisons["per_mode_status_counts"],
        "confirmed_variants": comparisons["confirmed_variants"],
        "recovered_unknown_low20_assignments": comparisons[
            "recovered_unknown_low20_assignments"
        ],
        "complete_domain_resolution_modes": comparisons[
            "complete_domain_resolution_modes"
        ],
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
            "modes": list(analysis["mode_orders"]),
            "mode_runs": analysis["protocol"]["execution_plan"]["mode_run_count"],
            "cell_observations": analysis["protocol"]["execution_plan"][
                "child_observation_count"
            ],
            "seconds_per_cell": analysis["protocol"]["execution_plan"][
                "solver_time_limit_seconds_per_cell"
            ],
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
