#!/usr/bin/env python3
"""Compose the retained Width-12 partition with the A208 BFS-far mechanism."""

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
from fractions import Fraction
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_A208 = _import_sibling(
    "chacha20_round10_bfs_far_long_budget.py",
    "chacha20_a209_a208_anchor",
)
_A207 = _A208._A207
_A206 = _A208._A206
_A205 = _A208._A205
_A204 = _A208._A204
_A198 = _A208._A198

ATTEMPT_ID = "A209"
SCHEMA = "chacha20-round10-bfs-far-width12-refinement-v1"
PROTOCOL_SCHEMA = "chacha20-round10-bfs-far-width12-refinement-protocol-v1"
PROTOCOL_FILENAME = "chacha20_round10_bfs_far_width12_refinement_v1.json"
PROTOCOL_SHA256 = "48ccb1bdbd69a2de0db29eab4dabe8939c8ed98c633b757b0a911738ba3b958f"
RESULT_FILENAME = "chacha20_round10_bfs_far_width12_refinement_v1.json"
CAUSAL_FILENAME = "chacha20_round10_bfs_far_width12_refinement_v1.causal"

A197_PROTOCOL_FILENAME = "chacha20_bitwuzla_round10_width12_refinement_v1.json"
A197_PROTOCOL_SHA256 = "041782b106f6d956dd74f5051c285d7aebe00abc7e614c44790dc6fe525d5b2e"
A197_RUNNER_FILENAME = "chacha20_bitwuzla_round10_width12_refinement.py"
A197_RUNNER_SHA256 = "df45551daa0abb67337061bded931f54b3c18d6dedecf6a1f40f09104eab2fa6"
A197_RESULT_FILENAME = "chacha20_bitwuzla_round10_width12_refinement_v1.json"
A197_RESULT_SHA256 = "177a76c130d3705e8e3ebcd35f517486b204c6f7d501adaae1cdba8dca90060c"
A197_CAUSAL_FILENAME = "chacha20_bitwuzla_round10_width12_refinement_v1.causal"
A197_CAUSAL_SHA256 = "f180d14b244a91d5dcbe22acd4972590d9facfb8099ee8846fb3d0d5cae92561"
A197_CAUSAL_GRAPH_SHA256 = "c533fd9ce46f3db8cbe444d24cb0228391ee325cf09ad7cc4d74477658b28879"

A208_RESULT_FILENAME = _A208.RESULT_FILENAME
A208_RESULT_SHA256 = "58af841aa508978857f629c43c3fdb679e620eb9ec365b5211b4f708d287203c"
A208_CAUSAL_FILENAME = _A208.CAUSAL_FILENAME
A208_CAUSAL_SHA256 = "9e5e35ec7a3a005f8bd10d1608dd078b7b79aaaf9bd1e4e77ac5e7201c4a0993"
A208_CAUSAL_GRAPH_SHA256 = "cc938bef2e6cfed1f629c5b034987676817be80b0f46c140b32617bd5901e21e"

PREFIXES = tuple(f"{value:08b}" for value in range(256))
VARIANTS = tuple(f"bfs_far_width12_prefix_{prefix}" for prefix in PREFIXES)
CHILD_SUFFIXES = tuple(f"{value:03b}" for value in range(8))
ADDED_BIT_POSITIONS = (14, 13, 12)
SOLVER_MODE = "reverse"
SOLVER_LIMIT_SECONDS = 10
EXTERNAL_TIMEOUT_SECONDS = 13
MAX_PARALLEL_WORKERS = 4


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A204._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A204._file_sha256(path)


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    if _file_sha256(path) != PROTOCOL_SHA256:
        raise RuntimeError("A209 frozen protocol hash differs")
    protocol = json.loads(path.read_bytes())
    composition = protocol.get("composition_basis", {})
    phase = protocol.get("A208_phase_anchor", {})
    refinement = protocol.get("refinement", {})
    preflight = protocol.get("refined_CNF_and_order_preflight", {})
    plan = protocol.get("execution_plan", {})
    boundary = protocol.get("information_boundary", {})
    parent_child = [
        {
            "prefix8": prefix,
            "parent_prefix5": prefix[:5],
            "child_suffix3": prefix[5:],
        }
        for prefix in PREFIXES
    ]
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_complete_A208_phase_boundary_and_exact_width12_composition_preflight_before_any_A209_solver_execution"
        or composition.get("public_challenge_sha256") != _A198.PUBLIC_CHALLENGE_SHA256
        or composition.get("same_public_challenge_in_A197_and_A208") is not True
        or composition.get("this_exact_composition_executed_before_freeze") is not False
        or phase.get("late_10_to_60_second_increments")
        != {
            "conflicts": 190326,
            "decisions": 247834,
            "propagations": 9211736631,
            "restarts": 9227,
        }
        or phase.get("late50_density_over_early10_density_exact_fractions", {}).get(
            "decisions_per_propagation"
        )
        != "245315730720758/8306250555382593"
        or refinement.get("target_fixed_prefix_bits") != 8
        or refinement.get("target_free_bits") != 12
        or refinement.get("target_cell_count") != len(PREFIXES)
        or refinement.get("added_k0_bit_positions_descending") != list(ADDED_BIT_POSITIONS)
        or refinement.get("added_source_one_literals_descending") != [42, 40, 38]
        or refinement.get("child_suffix_order") != list(CHILD_SUFFIXES)
        or refinement.get("child_suffix_order_sha256") != _canonical_sha256(list(CHILD_SUFFIXES))
        or refinement.get("full_prefix_order_sha256") != _canonical_sha256(list(PREFIXES))
        or refinement.get("parent_child_manifest_sha256") != _canonical_sha256(parent_child)
        or preflight.get("order_sha256")
        != "814798f19a33a3a397a6af9f6fa126207e1e10e092d8ee80dcaba4ef3bae95c8"
        or preflight.get("old_to_new_sha256")
        != "50d03bfd6520685c3b17ec822ad08f4b5cce80f91c771a2b1b6377fffab2f30b"
        or preflight.get("transformed_free_mapping_sha256")
        != "cf460a84866266e64365facace638bbc35147f34f1e45d6aee7762f1b6ec2f51"
        or plan.get("solver_time_limit_seconds_per_cell") != SOLVER_LIMIT_SECONDS
        or plan.get("external_timeout_seconds_per_cell") != EXTERNAL_TIMEOUT_SECONDS
        or plan.get("max_parallel_workers") != MAX_PARALLEL_WORKERS
        or plan.get("cell_count") != len(PREFIXES)
        or plan.get("wave_count") != len(PREFIXES) // MAX_PARALLEL_WORKERS
        or plan.get("variant_order_sha256") != _canonical_sha256(list(VARIANTS))
        or plan.get("early_stop_permitted") is not False
        or boundary.get("any_A209_solver_outcome_known_before_freeze") is not False
        or boundary.get("round10_unknown_assignment_in_protocol_source_order_or_archive")
        is not False
        or boundary.get("round10_unknown_assignment_available_to_runner_before_execution")
        is not False
        or boundary.get("correct_8bit_prefix_known_before_execution") is not False
        or boundary.get(
            "refinement_order_budget_wave_order_or_predictions_changed_after_any_A209_outcome"
        )
        is not False
        or boundary.get("early_stop_permitted") is not False
    ):
        raise RuntimeError("A209 frozen protocol identity gate failed")
    return protocol


def _fraction(raw: str) -> Fraction:
    numerator, denominator = raw.split("/", 1)
    return Fraction(int(numerator), int(denominator))


def _load_anchor_gates(
    results_dir: Path, protocol: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    research_root = Path(__file__).parents[1]
    a197_protocol = research_root / "configs" / A197_PROTOCOL_FILENAME
    a197_runner = Path(__file__).with_name(A197_RUNNER_FILENAME)
    a197_result_path = results_dir / A197_RESULT_FILENAME
    a197_causal_path = results_dir / A197_CAUSAL_FILENAME
    a208_protocol = research_root / "configs" / _A208.PROTOCOL_FILENAME
    a208_runner = Path(__file__).with_name("chacha20_round10_bfs_far_long_budget.py")
    a208_result_path = results_dir / A208_RESULT_FILENAME
    a208_causal_path = results_dir / A208_CAUSAL_FILENAME
    if (
        _file_sha256(a197_protocol) != A197_PROTOCOL_SHA256
        or _file_sha256(a197_runner) != A197_RUNNER_SHA256
        or _file_sha256(a197_result_path) != A197_RESULT_SHA256
        or _file_sha256(a197_causal_path) != A197_CAUSAL_SHA256
        or _file_sha256(a208_protocol) != _A208.PROTOCOL_SHA256
        or _file_sha256(a208_runner)
        != protocol["anchors"]["A208_bfs_far_long_boundary"]["runner_sha256"]
        or _file_sha256(a208_result_path) != A208_RESULT_SHA256
        or _file_sha256(a208_causal_path) != A208_CAUSAL_SHA256
    ):
        raise RuntimeError("A209 A197/A208 anchor hash gate failed")
    a197 = json.loads(a197_result_path.read_bytes())
    a208 = json.loads(a208_result_path.read_bytes())
    a197_reader = CryptoCausalReader(a197_causal_path)
    a208_reader = CryptoCausalReader(a208_causal_path)
    a197_statuses = list(a197.get("comparisons", {}).get("statuses", {}).values())
    a208_statuses = a208.get("comparisons", {}).get("status_counts")
    if (
        len(a197_statuses) != 256
        or set(a197_statuses) != {"unknown"}
        or a197.get("public_challenge_sha256") != _A198.PUBLIC_CHALLENGE_SHA256
        or a197.get("public_challenge") != a208.get("public_challenge")
        or a197_reader.graph_sha256 != A197_CAUSAL_GRAPH_SHA256
        or not a197_reader.verify_provenance()
        or a208_statuses != {"sat": 0, "unsat": 0, "unknown": 32, "invalid": 0}
        or a208.get("confirmations") != []
        or a208_reader.graph_sha256 != A208_CAUSAL_GRAPH_SHA256
        or not a208_reader.verify_provenance()
    ):
        raise RuntimeError("A209 A197/A208 retained boundary gate failed")

    early = protocol["A208_phase_anchor"]["early_0_to_10_second_totals"]
    cumulative = protocol["A208_phase_anchor"]["cumulative_0_to_60_second_totals"]
    late = protocol["A208_phase_anchor"]["late_10_to_60_second_increments"]
    observed_totals = a208["rate_comparison"]["total_metrics"]
    for metric in early:
        if (
            observed_totals[metric]["A207_total"] != early[metric]
            or observed_totals[metric]["A208_total"] != cumulative[metric]
            or cumulative[metric] - early[metric] != late[metric]
        ):
            raise RuntimeError(f"A209 A208 {metric} phase anchor differs")
    phase_fractions = protocol["A208_phase_anchor"]["late50_rate_over_early10_rate_exact_fractions"]
    for metric in early:
        if _fraction(phase_fractions[metric]) != Fraction(late[metric], 5 * early[metric]):
            raise RuntimeError(f"A209 A208 {metric} phase fraction differs")
    if _fraction(
        protocol["A208_phase_anchor"]["late50_density_over_early10_density_exact_fractions"][
            "conflicts_per_propagation"
        ]
    ) != Fraction(
        late["conflicts"] * early["propagations"],
        late["propagations"] * early["conflicts"],
    ) or _fraction(
        protocol["A208_phase_anchor"]["late50_density_over_early10_density_exact_fractions"][
            "decisions_per_propagation"
        ]
    ) != Fraction(
        late["decisions"] * early["propagations"],
        late["propagations"] * early["decisions"],
    ):
        raise RuntimeError("A209 exact A208 phase-density fractions differ")
    gates = {
        "A197_result_sha256": A197_RESULT_SHA256,
        "A197_causal_sha256": A197_CAUSAL_SHA256,
        "A197_causal_graph_sha256": A197_CAUSAL_GRAPH_SHA256,
        "A197_causal_provenance_verified": True,
        "A197_complete_256_width12_unknown_boundary_retained": True,
        "A208_result_sha256": A208_RESULT_SHA256,
        "A208_causal_sha256": A208_CAUSAL_SHA256,
        "A208_causal_graph_sha256": A208_CAUSAL_GRAPH_SHA256,
        "A208_causal_provenance_verified": True,
        "A208_complete_32_long_budget_unknown_boundary_retained": True,
        "A208_exact_phase_transition_retained": True,
        "same_public_challenge_retained": True,
    }
    return a197, a208, gates


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    a197, a208, gates = _load_anchor_gates(results_dir, protocol)
    a208_analysis = _A208.analyze(results_dir)
    challenge = a208_analysis["public_challenge"]
    baseline_observations = a208_analysis["baseline_observations"]
    if (
        challenge["unknown_assignment_included"] is not False
        or challenge["unknown_key_word0_low_value_included"] is not False
        or a208_analysis["solver_execution_started"] is not False
        or len(baseline_observations) != 32
        or [row["prefix"] for row in baseline_observations] != list(_A208.PREFIXES)
        or any(row["candidate"] != _A208.SELECTED_CANDIDATE for row in baseline_observations)
        or any(row["solver_mode"] != SOLVER_MODE for row in baseline_observations)
    ):
        raise RuntimeError("A209 public challenge information boundary gate failed")
    return {
        "protocol": protocol,
        "anchor_gates": gates,
        "a197_result": a197,
        "a208_result": a208,
        "a208_analysis": a208_analysis,
        "public_challenge": challenge,
        "formulas": a208_analysis["formulas"],
        "formula_plan": a208_analysis["formula_plan"],
        "baseline_observations": baseline_observations,
        "solver_execution_started": False,
    }


def _refine_cnf(raw: bytes, *, prefix8: str, free_mapping: Sequence[int]) -> bytes:
    if len(prefix8) != 8 or any(bit not in "01" for bit in prefix8):
        raise RuntimeError("A209 prefix is not exactly eight binary bits")
    header, body = raw.split(b"\n", 1)
    if header != b"p cnf 232191 734180" or not raw.endswith(b"\n"):
        raise RuntimeError("A209 source CNF header or final newline differs")
    added_literals = [free_mapping[bit] for bit in ADDED_BIT_POSITIONS]
    added_units = b"".join(
        f"{literal if value == '1' else -literal} 0\n".encode()
        for value, literal in zip(prefix8[5:], added_literals, strict=True)
    )
    return b"p cnf 232191 734183\n" + body + added_units


def _normalized_refined_cnf(raw: bytes) -> tuple[str, list[int], str]:
    lines = raw.splitlines(keepends=True)
    header = lines[0].decode().strip()
    tail = lines[-8:]
    if header != "p cnf 232191 734183" or len(tail) != 8:
        raise RuntimeError("A209 refined CNF header or tail count differs")
    tail_literals = []
    normalized_tail = []
    for line in tail:
        fields = line.split()
        if len(fields) != 2 or fields[1] != b"0":
            raise RuntimeError("A209 refined CNF tail is not eight unit clauses")
        literal = int(fields[0])
        tail_literals.append(literal)
        normalized_tail.append(f"{abs(literal)} 0\n".encode())
    normalized = b"".join([*lines[:-8], *normalized_tail])
    return header, tail_literals, _sha256(normalized)


def _derive_refined_order(
    representative_refined: bytes,
    free_mapping: Sequence[int],
    protocol: dict[str, Any],
) -> tuple[np.ndarray, np.ndarray, np.ndarray, list[int], dict[str, Any]]:
    parsed = _A205._parse_cnf(representative_refined)
    ids = np.arange(1, parsed["variable_count"] + 1, dtype=np.int64)
    unit_distance = _A205._multi_source_bfs(parsed["graph"], parsed["units"])
    order = ids[np.lexsort((ids, -unit_distance))]
    mapping = _A205._old_to_new(order)
    inverse = np.zeros_like(mapping)
    inverse[mapping[1:]] = ids
    transformed_free_mapping = [
        int(mapping[abs(literal)]) if literal > 0 else -int(mapping[abs(literal)])
        for literal in free_mapping
    ]
    preflight = protocol["refined_CNF_and_order_preflight"]
    diagnostics = {
        "candidate": "output_unit_bfs_far",
        "solver_mode": SOLVER_MODE,
        "variable_count": parsed["variable_count"],
        "clause_count": parsed["clause_count"],
        "unit_source_count": len(parsed["units"]),
        "unit_distance_minimum": int(unit_distance.min()),
        "unit_distance_maximum": int(unit_distance.max()),
        "unit_distance_sha256": _sha256(unit_distance.astype("<i8", copy=False).tobytes()),
        "order_sha256": _sha256(order.astype("<u4", copy=False).tobytes()),
        "old_to_new_sha256": _sha256(mapping.astype("<u4", copy=False).tobytes()),
        "transformed_free_k0_bit_one_literal_mapping": transformed_free_mapping,
        "transformed_free_mapping_sha256": _canonical_sha256(transformed_free_mapping),
    }
    expected = {
        "candidate": "output_unit_bfs_far",
        "solver_mode": SOLVER_MODE,
        "variable_count": preflight["variable_count"],
        "clause_count": preflight["clause_count"],
        "unit_source_count": preflight["unit_source_count"],
        "unit_distance_minimum": preflight["unit_distance_minimum"],
        "unit_distance_maximum": preflight["unit_distance_maximum"],
        "unit_distance_sha256": preflight["unit_distance_sha256"],
        "order_sha256": preflight["order_sha256"],
        "old_to_new_sha256": preflight["old_to_new_sha256"],
        "transformed_free_k0_bit_one_literal_mapping": preflight[
            "transformed_free_k0_bit_one_literal_mapping"
        ],
        "transformed_free_mapping_sha256": preflight["transformed_free_mapping_sha256"],
    }
    if diagnostics != expected:
        raise RuntimeError("A209 refined BFS-far order preflight differs")
    return order, mapping, inverse, transformed_free_mapping, diagnostics


def _build_refined_transforms(
    *,
    source_paths: dict[str, Path],
    free_mapping: Sequence[int],
    protocol: dict[str, Any],
    directory: Path,
) -> tuple[
    list[dict[str, Any]],
    dict[str, Path],
    list[int],
    dict[str, Any],
]:
    representative_raw = source_paths["cse_prefix_11111"].read_bytes()
    representative_refined = _refine_cnf(
        representative_raw,
        prefix8="11111111",
        free_mapping=free_mapping,
    )
    _, mapping, inverse, transformed_free_mapping, diagnostics = _derive_refined_order(
        representative_refined,
        free_mapping,
        protocol,
    )
    preflight = protocol["refined_CNF_and_order_preflight"]
    manifest = []
    transformed_paths = {}
    inverse_prefixes = set(preflight["inverse_restore_prefix_endpoints"])
    for prefix8, variant in zip(PREFIXES, VARIANTS, strict=True):
        parent_prefix5 = prefix8[:5]
        child_suffix3 = prefix8[5:]
        source_variant = f"cse_prefix_{parent_prefix5}"
        source_raw = source_paths[source_variant].read_bytes()
        refined = _refine_cnf(source_raw, prefix8=prefix8, free_mapping=free_mapping)
        refined_header, refined_tail, refined_normalized_sha256 = _normalized_refined_cnf(refined)
        if refined_normalized_sha256 != preflight["refined_common_normalized_sha256"]:
            raise RuntimeError(f"A209 {prefix8} refined normalization differs")
        transformed = _A205._reindex_cnf(refined, mapping)
        transformed_header, transformed_tail, transformed_normalized_sha256 = (
            _normalized_refined_cnf(transformed)
        )
        if transformed_normalized_sha256 != preflight["transformed_common_normalized_sha256"]:
            raise RuntimeError(f"A209 {prefix8} transformed normalization differs")
        inverse_checked = prefix8 in inverse_prefixes
        inverse_restored_sha256 = None
        if inverse_checked:
            restored = _A205._reindex_cnf(transformed, inverse)
            if restored != refined:
                raise RuntimeError(f"A209 {prefix8} inverse endpoint gate failed")
            inverse_restored_sha256 = _sha256(restored)
        output = directory / f"{variant}.cnf"
        output.write_bytes(transformed)
        manifest.append(
            {
                "variant": variant,
                "prefix8": prefix8,
                "parent_prefix5": parent_prefix5,
                "child_suffix3": child_suffix3,
                "source_variant": source_variant,
                "source_cnf_sha256": _sha256(source_raw),
                "refined_cnf_sha256": _sha256(refined),
                "refined_cnf_bytes": len(refined),
                "refined_header": refined_header,
                "refined_tail_units": refined_tail,
                "refined_normalized_sha256": refined_normalized_sha256,
                "transformed_cnf_sha256": _sha256(transformed),
                "transformed_cnf_bytes": len(transformed),
                "transformed_header": transformed_header,
                "transformed_tail_units": transformed_tail,
                "transformed_normalized_sha256": transformed_normalized_sha256,
                "inverse_endpoint_checked": inverse_checked,
                "inverse_restored_sha256": inverse_restored_sha256,
            }
        )
        transformed_paths[variant] = output
    representative = manifest[-1]
    if (
        representative["prefix8"] != preflight["representative_prefix"]
        or representative["refined_cnf_sha256"] != preflight["representative_refined_cnf_sha256"]
        or representative["transformed_cnf_sha256"]
        != preflight["representative_transformed_cnf_sha256"]
        or representative["transformed_cnf_bytes"]
        != preflight["representative_transformed_cnf_bytes"]
        or sum(row["inverse_endpoint_checked"] for row in manifest) != 2
        or len({row["transformed_cnf_sha256"] for row in manifest}) != 256
    ):
        raise RuntimeError("A209 representative or complete transform gate failed")
    return manifest, transformed_paths, transformed_free_mapping, diagnostics


def _run_cell(
    *,
    variant: str,
    cnf_path: Path,
    transformed_mapping: Sequence[int],
    challenge: dict[str, Any],
    cadical_path: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    prefix8 = variant[-8:]
    parent_prefix5 = prefix8[:5]
    child_suffix3 = prefix8[5:]
    command = [
        cadical_path,
        "--reverse=true",
        "-t",
        str(SOLVER_LIMIT_SECONDS),
        str(cnf_path),
    ]
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=EXTERNAL_TIMEOUT_SECONDS,
            check=False,
        )
        externally_timed_out = False
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        externally_timed_out = True
        stdout = _A204._as_text(error.stdout)
        stderr = _A204._as_text(error.stderr)
        returncode = None
    status = _A204._cadical_status(stdout, returncode)
    status_lines = [line.strip() for line in stdout.splitlines() if line.startswith("s ")]
    recognized_unknown = status == "unknown" and (
        status_lines == ["s UNKNOWN"]
        or any(line.startswith("c Timeout reached!") for line in stdout.splitlines())
    )
    invalid_reason = None
    if externally_timed_out:
        status = "invalid"
        invalid_reason = "external_timeout"
    elif status == "unknown" and (returncode != 0 or not recognized_unknown):
        status = "invalid"
        invalid_reason = "unrecognized_unknown_boundary"
    elif status == "invalid":
        invalid_reason = "invalid_solver_status_or_returncode"
    witness = _A204._parse_cadical_witness(stdout) if status == "sat" else {}
    model = None
    confirmation = None
    if status == "sat":
        model = _A204._decode_round10_model(
            challenge=challenge,
            prefix=parent_prefix5,
            witness=witness,
            mapping=transformed_mapping,
        )
        confirmation = {
            "variant": variant,
            "prefix8": prefix8,
            "parent_prefix5": parent_prefix5,
            "child_suffix3": child_suffix3,
            "refinement_prefix_match": ((model["key_word0"] >> 12) & 0xFF) == int(prefix8, 2),
            **_A198._confirm_model(challenge, model),
        }
        if (
            confirmation["refinement_prefix_match"] is not True
            or confirmation["known_key_constraints_match"] is not True
            or confirmation["all_blocks_match"] is not True
            or confirmation["control_first_block_match"] is not False
            or confirmation["output_bits_checked"] != 4096
        ):
            raise RuntimeError(f"A209 {variant} decoded model failed independent confirmation")
    observation = {
        "variant": variant,
        "prefix8": prefix8,
        "parent_prefix5": parent_prefix5,
        "child_suffix3": child_suffix3,
        "solver_mode": SOLVER_MODE,
        "command": command,
        "status": status,
        "status_line": status_lines[0] if len(status_lines) == 1 else None,
        "internal_timeout_marker": any(
            line.startswith("c Timeout reached!") for line in stdout.splitlines()
        ),
        "returncode": returncode,
        "externally_timed_out": externally_timed_out,
        "invalid_reason": invalid_reason,
        "volatile_seconds": time.perf_counter() - started,
        "witness_assignment_count": len(witness),
        "metrics": _A205._solver_metrics(stdout),
        "model": model,
        "transformed_cnf_sha256": _file_sha256(cnf_path),
        "stdout_sha256": _sha256(stdout.encode()),
        "stderr_sha256": _sha256(stderr.encode()),
    }
    return observation, confirmation


def _execute(
    *,
    transformed_paths: dict[str, Path],
    transformed_mapping: Sequence[int],
    challenge: dict[str, Any],
    cadical_path: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    observations = []
    confirmations = []
    waves = []
    for wave_index, start in enumerate(range(0, len(VARIANTS), MAX_PARALLEL_WORKERS)):
        wave = VARIANTS[start : start + MAX_PARALLEL_WORKERS]

        def execute(variant: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
            return _run_cell(
                variant=variant,
                cnf_path=transformed_paths[variant],
                transformed_mapping=transformed_mapping,
                challenge=challenge,
                cadical_path=cadical_path,
            )

        with ThreadPoolExecutor(max_workers=MAX_PARALLEL_WORKERS) as executor:
            rows = list(executor.map(execute, wave))
        for observation, confirmation in rows:
            observations.append(observation)
            if confirmation is not None:
                confirmations.append(confirmation)
        waves.append(
            {
                "wave_index": wave_index,
                "variants": [row[0]["variant"] for row in rows],
                "statuses": [row[0]["status"] for row in rows],
                "maximum_volatile_seconds": max(row[0]["volatile_seconds"] for row in rows),
            }
        )
    if [row["variant"] for row in observations] != list(VARIANTS):
        raise RuntimeError("A209 complete execution order differs from freeze")
    return {
        "variant_order": list(VARIANTS),
        "complete_cell_plan_executed": len(observations) == 256,
        "early_stop_used": False,
        "observations": observations,
        "wave_observations": waves,
        "returned_model_count": len(confirmations),
        "round10_unknown_assignment_available_to_runner_before_execution": False,
    }, confirmations


def _phase_reset_comparison(
    observations: list[dict[str, Any]], baseline_observations: list[dict[str, Any]]
) -> dict[str, Any]:
    baseline = {row["prefix"]: row for row in baseline_observations}
    metrics = ("conflicts", "decisions", "propagations", "restarts")
    cell_rows = []
    for observation in observations:
        parent = baseline[observation["parent_prefix5"]]
        ratios = {}
        for metric in metrics:
            child_value = observation["metrics"].get(metric)
            parent_value = parent["metrics"].get(metric)
            ratios[metric] = (
                child_value / parent_value
                if child_value is not None and parent_value not in {None, 0}
                else None
            )
        cell_rows.append(
            {
                "variant": observation["variant"],
                "prefix8": observation["prefix8"],
                "parent_prefix5": observation["parent_prefix5"],
                "child_suffix3": observation["child_suffix3"],
                "A207_parent_variant": parent["variant"],
                "child_metrics": observation["metrics"],
                "A207_parent_metrics": parent["metrics"],
                "child_over_A207_parent_ratio": ratios,
            }
        )
    parent_summaries = []
    for parent_prefix5 in _A208.PREFIXES:
        rows = [row for row in cell_rows if row["parent_prefix5"] == parent_prefix5]
        metric_summary = {}
        for metric in metrics:
            child_values = [
                row["child_metrics"].get(metric)
                for row in rows
                if row["child_metrics"].get(metric) is not None
            ]
            parent_value = rows[0]["A207_parent_metrics"].get(metric)
            ratios = [
                row["child_over_A207_parent_ratio"][metric]
                for row in rows
                if row["child_over_A207_parent_ratio"][metric] is not None
            ]
            child_total = sum(child_values) if child_values else None
            complete_eight_child_total = child_total if len(child_values) == 8 else None
            repeated_matched_parent_total = (
                len(child_values) * parent_value
                if child_values and parent_value not in {None, 0}
                else None
            )
            metric_summary[metric] = {
                "observed_child_total": child_total,
                "complete_eight_child_total": complete_eight_child_total,
                "A207_parent_total": parent_value,
                "child_metric_observation_count": len(child_values),
                "child_metric_missing_count": len(rows) - len(child_values),
                "repeated_matched_parent_total": repeated_matched_parent_total,
                "complete_eight_child_total_over_parent": (
                    complete_eight_child_total / parent_value
                    if complete_eight_child_total is not None and parent_value not in {None, 0}
                    else None
                ),
                "compute_normalized_mean_child_over_parent": (
                    child_total / repeated_matched_parent_total
                    if child_total is not None and repeated_matched_parent_total not in {None, 0}
                    else None
                ),
                "child_ratio_min": min(ratios) if ratios else None,
                "child_ratio_median": float(np.median(ratios)) if ratios else None,
                "child_ratio_max": max(ratios) if ratios else None,
            }
        parent_summaries.append(
            {
                "parent_prefix5": parent_prefix5,
                "A207_parent_variant": rows[0]["A207_parent_variant"],
                "metrics": metric_summary,
            }
        )
    total_summary = {}
    for metric in metrics:
        child_values = [
            row["child_metrics"].get(metric)
            for row in cell_rows
            if row["child_metrics"].get(metric) is not None
        ]
        baseline_values = [row["metrics"].get(metric) for row in baseline_observations]
        matched_pairs = [
            (
                row["child_metrics"].get(metric),
                row["A207_parent_metrics"].get(metric),
            )
            for row in cell_rows
            if row["child_metrics"].get(metric) is not None
            and row["A207_parent_metrics"].get(metric) is not None
        ]
        matched_child_total = sum(child for child, _ in matched_pairs) if matched_pairs else None
        repeated_matched_parent_total = (
            sum(parent for _, parent in matched_pairs) if matched_pairs else None
        )
        full_baseline_total = (
            sum(value for value in baseline_values if value is not None)
            if any(value is not None for value in baseline_values)
            else None
        )
        total_summary[metric] = {
            "A209_matched_child_total": matched_child_total,
            "A207_repeated_matched_parent_total": repeated_matched_parent_total,
            "A209_all_observed_child_total": sum(child_values) if child_values else None,
            "A207_full_32_parent_total": full_baseline_total,
            "matched_child_parent_count": len(matched_pairs),
            "A209_metric_observation_count": len(child_values),
            "A209_metric_missing_count": len(cell_rows) - len(child_values),
            "A207_metric_observation_count": sum(value is not None for value in baseline_values),
            "A207_metric_missing_count": sum(value is None for value in baseline_values),
            "matched_child_over_repeated_parent_ratio": (
                matched_child_total / repeated_matched_parent_total
                if matched_child_total is not None
                and repeated_matched_parent_total not in {None, 0}
                else None
            ),
            "compute_normalized_mean_child_over_parent": (
                matched_child_total / repeated_matched_parent_total
                if matched_child_total is not None
                and repeated_matched_parent_total not in {None, 0}
                else None
            ),
        }
    return {
        "baseline": "A207_output_unit_bfs_far_reverse_same_parent_prefix_at_10_seconds",
        "same_nominal_seconds_per_child_and_parent": True,
        "children_per_parent": 8,
        "cell_rows": cell_rows,
        "parent_summaries": parent_summaries,
        "total_metrics": total_summary,
    }


def _compare(execution: dict[str, Any], confirmations: list[dict[str, Any]]) -> dict[str, Any]:
    observations = execution["observations"]
    status_counts = {
        status: sum(row["status"] == status for row in observations)
        for status in ("sat", "unsat", "unknown", "invalid")
    }
    recovered = sorted({row["recovered_unknown_low20"] for row in confirmations})
    complete = (
        status_counts == {"sat": 1, "unsat": 255, "unknown": 0, "invalid": 0}
        and len(recovered) == 1
    )
    return {
        "complete_cell_count": len(observations),
        "complete_predeclared_execution": len(observations) == 256,
        "early_stop_used": False,
        "status_counts": status_counts,
        "confirmed_variants": [row["variant"] for row in confirmations],
        "confirmed_prefixes8": sorted({row["prefix8"] for row in confirmations}),
        "confirmed_combined_assignments": sorted(
            {row["combined_assignment"] for row in confirmations}
        ),
        "recovered_unknown_low20_assignments": recovered,
        "confirmed_recovery_retained": len(confirmations) >= 1,
        "complete_domain_resolution_retained": complete,
        "complete_partition_and_disjoint_by_construction": True,
        "complete_domain_candidate_count": 1 << 20,
        "statuses": {row["variant"]: row["status"] for row in observations},
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_round10_bfs_far_width12_refinement",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": 10,
            "unknown_key_bits": 20,
            "fixed_prefix_bits": 8,
            "cells": 256,
        },
    )
    ids = [
        "chacha20-a209-a197-width12-anchor",
        "chacha20-a209-a208-phase-anchor",
        "chacha20-a209-composition-selection",
        "chacha20-a209-refined-bfs-far-order",
        "chacha20-a209-complete-refined-transforms",
        "chacha20-a209-complete-width12-execution",
        "chacha20-a209-independent-confirmation",
        "chacha20-a209-phase-reset-comparison",
        "chacha20-a209-width12-result",
    ]
    rows = [
        (
            "A197:complete_width12_partition_boundary",
            "retain_the_same_challenge_256_cell_width12_boundary",
            "A209:width12_composition_anchor",
            "retained_A197_width12_boundary",
            A197_CAUSAL_SHA256,
            [],
            {"A197_anchor": payload["anchor_gates"]},
        ),
        (
            "A208:complete_long_budget_phase_boundary",
            "retain_exact_early_and_late_integer_search_metrics",
            "A209:phase_reset_selection_anchor",
            "retained_A208_phase_boundary",
            A208_CAUSAL_SHA256,
            [],
            {"phase_anchor": payload["A208_phase_anchor"]},
        ),
        (
            "A209:width12_composition_anchor+A209:phase_reset_selection_anchor",
            "compose_width12_refinement_with_eight_block_CSE_BFS_far_reverse",
            "A209:frozen_width12_BFS_far_composition",
            "prospective_mechanism_composition",
            payload["composition_sha256"],
            [ids[0], ids[1]],
            {"composition_basis": payload["composition_basis"]},
        ),
        (
            "A209:frozen_width12_BFS_far_composition",
            "recompute_multi_source_BFS_far_after_three_new_key_unit_sources",
            "A209:exact_refined_BFS_far_order",
            "T04_multisource_graph_distance_transfer",
            payload["order_diagnostics_sha256"],
            [ids[2]],
            {"order_diagnostics": payload["order_diagnostics"]},
        ),
        (
            "A209:exact_refined_BFS_far_order",
            "construct_and_inverse_check_the_complete_256_cell_bijective_CNF_cover",
            "A209:complete_semantics_preserved_width12_cover",
            "exact_refined_CNF_transform",
            payload["transform_manifest_sha256"],
            [ids[3]],
            {"transform_manifest": payload["transform_manifest"]},
        ),
        (
            "A209:complete_semantics_preserved_width12_cover",
            "execute_all_256_cells_in_64_frozen_four_worker_waves",
            "A209:complete_width12_execution",
            "complete_predeclared_solver_execution",
            payload["execution_sha256"],
            [ids[4]],
            {"execution": payload["execution"]},
        ),
        (
            "A209:complete_width12_execution",
            "decode_every_SAT_witness_and_recompute_all_4096_target_bits",
            "A209:independently_confirmed_models_or_boundary",
            "independent_model_confirmation",
            payload["confirmation_sha256"],
            [ids[5]],
            {"confirmations": payload["confirmations"]},
        ),
        (
            "A209:independently_confirmed_models_or_boundary",
            "compare_each_fresh_child_and_each_parent_to_the_exact_A207_10_second_parent",
            "A209:width12_phase_reset_profile",
            "same_parent_phase_reset_comparison",
            payload["phase_reset_comparison_sha256"],
            [ids[6]],
            {"phase_reset_comparison": payload["phase_reset_comparison"]},
        ),
        (
            "A209:width12_phase_reset_profile",
            "evaluate_confirmed_recovery_and_complete_domain_resolution_predictions",
            "A209:prospective_width12_composition_result",
            "prospective_width12_comparison",
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
        raise RuntimeError("A209 Causal Reader provenance gate failed")
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
    identities = _A204._solver_gates(_A204._load_protocol_gate())
    free_mapping = protocol["refinement"]["added_source_one_literals_descending"]
    if free_mapping != [42, 40, 38]:
        raise RuntimeError("A209 added source literal gate differs")
    full_free_mapping = analysis["a208_analysis"]["protocol"]["round10_source"][
        "free_k0_bit_one_literal_mapping"
    ]
    with tempfile.TemporaryDirectory(prefix="a209-bfs-far-width12-") as raw_directory:
        directory = Path(raw_directory)
        source_exports, source_paths = _A204._export_round10_cnfs(
            analysis["a208_analysis"]["a207_analysis"]["a206_analysis"]["a204_analysis"],
            identities,
            directory,
        )
        transform_manifest, transformed_paths, transformed_mapping, order_diagnostics = (
            _build_refined_transforms(
                source_paths=source_paths,
                free_mapping=full_free_mapping,
                protocol=protocol,
                directory=directory,
            )
        )
        execution, confirmations = _execute(
            transformed_paths=transformed_paths,
            transformed_mapping=transformed_mapping,
            challenge=analysis["public_challenge"],
            cadical_path=identities["cadical"]["path"],
        )

    phase_reset_comparison = _phase_reset_comparison(
        execution["observations"], analysis["baseline_observations"]
    )
    comparisons = _compare(execution, confirmations)
    if comparisons["complete_domain_resolution_retained"]:
        evidence_stage = "ROUND10_BFS_FAR_WIDTH12_COMPLETE_DOMAIN_RESOLUTION_RETAINED"
    elif comparisons["confirmed_recovery_retained"]:
        evidence_stage = "ROUND10_BFS_FAR_WIDTH12_CONFIRMED_RECOVERY_RETAINED"
    else:
        evidence_stage = "ROUND10_BFS_FAR_WIDTH12_COMPLETE_BOUNDARY_RETAINED"
    clean_source_exports = [
        {key: value for key, value in row.items() if key != "path"} for row in source_exports
    ]
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "The exact A208 eight-block global-CSE BFS-far mechanism is composed "
            "prospectively with the complete same-challenge Width-12 partition."
        ),
        "scope": "Reduced ChaCha10 20-bit partial-key recovery over eight shared-key blocks.",
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": protocol["protocol_state"],
            "information_boundary": protocol["information_boundary"],
            "prospective_predictions": protocol["prospective_predictions"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "composition_basis": protocol["composition_basis"],
        "composition_sha256": _canonical_sha256(protocol["composition_basis"]),
        "A208_phase_anchor": protocol["A208_phase_anchor"],
        "A208_phase_anchor_sha256": _canonical_sha256(protocol["A208_phase_anchor"]),
        "solver_identities": {
            "bitwuzla": identities["bitwuzla"],
            "cadical": identities["cadical"],
        },
        "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": _A198.PUBLIC_CHALLENGE_SHA256,
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": _canonical_sha256(analysis["formula_plan"]),
        "refinement": protocol["refinement"],
        "refinement_sha256": _canonical_sha256(protocol["refinement"]),
        "source_exports": clean_source_exports,
        "source_exports_sha256": _canonical_sha256(clean_source_exports),
        "order_diagnostics": order_diagnostics,
        "order_diagnostics_sha256": _canonical_sha256(order_diagnostics),
        "transform_manifest": transform_manifest,
        "transform_manifest_sha256": _canonical_sha256(transform_manifest),
        "execution_plan": protocol["execution_plan"],
        "execution_plan_sha256": _canonical_sha256(protocol["execution_plan"]),
        "execution": execution,
        "execution_sha256": _canonical_sha256(execution),
        "confirmations": confirmations,
        "confirmation_sha256": _canonical_sha256(confirmations),
        "phase_reset_comparison": phase_reset_comparison,
        "phase_reset_comparison_sha256": _canonical_sha256(phase_reset_comparison),
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
        raise RuntimeError("A209 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "status_counts": comparisons["status_counts"],
        "confirmed_variants": comparisons["confirmed_variants"],
        "recovered_unknown_low20_assignments": comparisons["recovered_unknown_low20_assignments"],
        "complete_domain_resolution_retained": comparisons["complete_domain_resolution_retained"],
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
            "cells": analysis["protocol"]["execution_plan"]["cell_count"],
            "fixed_prefix_bits": analysis["protocol"]["refinement"]["target_fixed_prefix_bits"],
            "free_bits_per_cell": analysis["protocol"]["refinement"]["target_free_bits"],
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
