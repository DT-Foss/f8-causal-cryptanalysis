#!/usr/bin/env python3
"""Test four public affine partition geometries at the ChaCha10 A198 boundary."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
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


_A198 = _import_sibling(
    "chacha20_bitwuzla_round10_b8_partition_transfer.py",
    "chacha20_round10_geometry_a198_anchor",
)
_A199 = _import_sibling(
    "chacha20_formula_operator_atlas.py",
    "chacha20_round10_geometry_a199_anchor",
)

ATTEMPT_ID = "A200"
SCHEMA = "chacha20-round10-public-geometry-partition-v1"
PROTOCOL_SCHEMA = "chacha20-round10-public-geometry-partition-protocol-v1"
PROTOCOL_FILENAME = "chacha20_round10_public_geometry_partition_v1.json"
PROTOCOL_SHA256 = "0d220d919d5dbcd24cc2d358046622676b28500c84db0bb0d23d2d8da0677397"
A198_FILENAME = _A198.RESULT_FILENAME
A198_SHA256 = "693367464ab488c49d386c1d011e8c45e7fb094cceeb37352934dde121773373"
A198_CAUSAL_FILENAME = _A198.CAUSAL_FILENAME
A198_CAUSAL_SHA256 = "b7c4e1302594e266c7958057221fb4101fb5ef5ee284792d6ca93e43386dd514"
A199_FILENAME = _A199.RESULT_FILENAME
A199_SHA256 = "16c1025308bae64e2c45339804ec0a39d5fcb927c1cd0a1dcbf2ca8dfd3d5c48"
A199_CAUSAL_FILENAME = _A199.CAUSAL_FILENAME
A199_CAUSAL_SHA256 = "bb509b61239bf3bc4396bac2b882820204deba6683186f9f5a89f65c1968fc89"
PUBLIC_CHALLENGE_SHA256 = _A198.PUBLIC_CHALLENGE_SHA256
EXECUTION_PLAN_SHA256 = "a9cc44aece75c0f13933e980dd8876eaaeae6cf747f4292196065ffdc111245f"
VARIANT_ORDER_SHA256 = "3202edb869a43a6457b3a44ea45cce257227d217f36f66584749ca6b5814d6f9"
GEOMETRY_MASKS_SHA256 = "9b05f02259ed38e9590092b5bbdc31512f2644a14863440c426fa471cef4b457"
GEOMETRY_ORDER = (
    "gray_prefix_control",
    "fiedler_filtration",
    "laplacian_distinct_modes",
    "signed_svd_distinct_modes",
)
CELLS = tuple(f"{value:05b}" for value in range(32))
VARIANTS = tuple(f"{geometry}_cell_{cell}" for geometry in GEOMETRY_ORDER for cell in CELLS)
ROUNDS = 10
UNKNOWN_KEY_BITS = 20
KNOWN_KEY_BITS = 236
LOW_MASK = (1 << UNKNOWN_KEY_BITS) - 1
CELL_BITS = 5
FREE_BITS = 15
BLOCK_COUNT = 8
TIME_LIMIT_MS = 10_000
EXTERNAL_TIMEOUT_SLACK_SECONDS = 5
MAX_PARALLEL_WORKERS = 4
RESULT_FILENAME = "chacha20_round10_public_geometry_partition_v1.json"
CAUSAL_FILENAME = "chacha20_round10_public_geometry_partition_v1.causal"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A198._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A198._file_sha256(path)


def _mask_hex(masks: dict[str, tuple[int, ...]]) -> dict[str, list[str]]:
    return {geometry: [f"0x{mask:05x}" for mask in masks[geometry]] for geometry in GEOMETRY_ORDER}


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    if _file_sha256(path) != PROTOCOL_SHA256:
        raise RuntimeError("A200 frozen protocol hash differs")
    protocol = json.loads(path.read_bytes())
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A199_public_geometry_derivation_before_any_A200_solver_execution"
        or protocol.get("execution_plan_sha256") != EXECUTION_PLAN_SHA256
        or protocol.get("variant_order_sha256") != VARIANT_ORDER_SHA256
        or protocol.get("geometry_masks_sha256") != GEOMETRY_MASKS_SHA256
        or protocol.get("geometry_order") != list(GEOMETRY_ORDER)
        or boundary.get("A200_solver_outcomes_used_before_protocol_freeze") is not False
        or boundary.get("cell_or_geometry_order_changed_after_any_A200_outcome") is not False
        or boundary.get("early_stop_permitted") is not False
        or boundary.get("geometry_masks_selected_from_public_A199_data_only") is not True
        or boundary.get("unknown_assignment_available_to_runner_before_execution") is not False
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
    ):
        raise RuntimeError("A200 frozen protocol identity gate failed")
    return protocol


def _load_anchor_gates(results_dir: Path) -> dict[str, Any]:
    specs = (
        (
            "A198",
            A198_FILENAME,
            A198_CAUSAL_FILENAME,
            A198_SHA256,
            A198_CAUSAL_SHA256,
            _A198.SCHEMA,
            "ROUND10_B8_COMPLETE_PARTITION_BOUNDARY_RETAINED",
        ),
        (
            "A199",
            A199_FILENAME,
            A199_CAUSAL_FILENAME,
            A199_SHA256,
            A199_CAUSAL_SHA256,
            _A199.SCHEMA,
            "PUBLIC_FORMULA_OPERATOR_ATLAS_MIXED_BOUNDARY_RETAINED",
        ),
    )
    gates: dict[str, Any] = {}
    retained: dict[str, dict[str, Any]] = {}
    for label, result_name, causal_name, result_sha, causal_sha, schema, stage in specs:
        result_path = results_dir / result_name
        causal_path = results_dir / causal_name
        if _file_sha256(result_path) != result_sha or _file_sha256(causal_path) != causal_sha:
            raise RuntimeError(f"A200 {label} anchor hash gate failed")
        result = json.loads(result_path.read_bytes())
        reader = CryptoCausalReader(causal_path)
        if (
            result.get("schema") != schema
            or result.get("evidence_stage") != stage
            or reader.file_sha256 != causal_sha
            or reader.graph_sha256 != result.get("causal", {}).get("graph_sha256")
            or not reader.verify_provenance()
        ):
            raise RuntimeError(f"A200 {label} anchor content gate failed")
        retained[label] = result
        gates.update(
            {
                f"{label}_result_sha256": result_sha,
                f"{label}_causal_sha256": causal_sha,
                f"{label}_causal_graph_sha256": reader.graph_sha256,
                f"{label}_causal_provenance_verified": True,
            }
        )
    a198 = retained["A198"]
    a199 = retained["A199"]
    if (
        a198.get("execution", {}).get("returned_model_count") != 0
        or a198.get("comparisons", {}).get("primary_30000ms_prediction_retained") is not False
        or a198.get("comparisons", {}).get("secondary_10000ms_prediction_retained") is not False
        or a199.get("public_input", {}).get("hidden_assignment_present") is not False
        or a199.get("T04", {}).get("prediction_retained") is not True
        or a199.get("T05", {}).get("prediction_retained") is not True
    ):
        raise RuntimeError("A200 retained boundary/operator gate failed")
    gates["numeric_prefix_10s_and_30s_complete_covers_all_unknown"] = True
    gates["public_A199_geometry_only"] = True
    return gates


def _paired_svd_vectors(
    forward_profiles: np.ndarray, backward_profiles: np.ndarray
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    forward = _A199._row_normalize(forward_profiles.reshape(UNKNOWN_KEY_BITS, -1))
    backward = _A199._row_normalize(backward_profiles.reshape(UNKNOWN_KEY_BITS, -1))
    cross = _A199._finite_matmul(forward, backward.T, "A200-cross-copy")
    left, singular_values, right_t = np.linalg.svd(cross, full_matrices=True)
    right = right_t.T
    for mode in range(UNKNOWN_KEY_BITS):
        pivot = int(np.argmax(np.abs(left[:, mode])))
        if left[pivot, mode] < 0:
            left[:, mode] *= -1.0
            right[:, mode] *= -1.0
    return left, singular_values, right


def _top_mask(vector: np.ndarray, selected_count: int = 10) -> int:
    order = sorted(range(UNKNOWN_KEY_BITS), key=lambda index: (-vector[index], index))
    return sum(1 << bit for bit in order[:selected_count])


def _derive_geometry_masks(results_dir: Path) -> tuple[dict[str, tuple[int, ...]], dict[str, Any]]:
    a199 = json.loads((results_dir / A199_FILENAME).read_bytes())
    fiedler = tuple(int(raw, 16) for raw in a199["T04"]["chosen_mask_hex_order"])

    states = _A199._public_states(_A199.OPERATOR_SAMPLES)
    cuts = _A199._base_cuts(states)
    _, forward_profiles = _A199._key_trajectories(states)
    backward_profiles = _A199._backward_key_profiles(states, cuts)
    _, features = _A199._t05(forward_profiles, backward_profiles)
    normalized = _A199._row_normalize(features)
    distances = np.sum((normalized[:, None, :] - normalized[None, :, :]) ** 2, axis=2)
    positive = distances[np.triu_indices(UNKNOWN_KEY_BITS, 1)]
    sigma2 = float(np.median(positive[positive > 0]))
    adjacency = np.exp(-distances / (2.0 * sigma2))
    np.fill_diagonal(adjacency, 0.0)
    degrees = adjacency.sum(axis=1)
    inverse_sqrt = 1.0 / np.sqrt(degrees)
    laplacian = np.eye(UNKNOWN_KEY_BITS) - (
        inverse_sqrt[:, None] * adjacency * inverse_sqrt[None, :]
    )
    laplacian_values, laplacian_vectors = np.linalg.eigh(laplacian)
    laplacian_vectors = _A199._orient_columns(laplacian_vectors)
    laplacian_masks = tuple(_top_mask(laplacian_vectors[:, mode]) for mode in range(1, 6))

    left, singular_values, right = _paired_svd_vectors(forward_profiles, backward_profiles)
    signed_vectors = left - right
    signed_masks = tuple(_top_mask(signed_vectors[:, mode]) for mode in range(1, 6))
    masks = {
        "gray_prefix_control": (
            0x80000,
            0xC0000,
            0x60000,
            0x30000,
            0x18000,
        ),
        "fiedler_filtration": fiedler,
        "laplacian_distinct_modes": laplacian_masks,
        "signed_svd_distinct_modes": signed_masks,
    }
    expected = {
        geometry: tuple(int(raw, 16) for raw in values["mask_hex_order"])
        for geometry, values in _load_protocol_gate()["geometry_plan"].items()
    }
    if masks != expected or _canonical_sha256(_mask_hex(masks)) != GEOMETRY_MASKS_SHA256:
        raise RuntimeError("A200 public geometry derivation differs from freeze")

    partitions = {}
    for geometry, geometry_masks in masks.items():
        partition = _A199._partition_from_masks(list(geometry_masks))
        expected_sha = _load_protocol_gate()["geometry_plan"][geometry]["syndrome_map_sha256"]
        if (
            partition["binary_rank"] != CELL_BITS
            or partition["cell_histogram"] != [1 << FREE_BITS] * 32
            or partition["syndrome_map_sha256"] != expected_sha
        ):
            raise RuntimeError(f"A200 {geometry} complete partition gate failed")
        partitions[geometry] = partition
    return masks, {
        "partitions": partitions,
        "laplacian_eigenvalues_1_through_5": [
            round(float(value), 12) for value in laplacian_values[1:6]
        ],
        "cross_copy_singular_values_1_through_5": [
            round(float(value), 12) for value in singular_values[1:6]
        ],
        "public_operator_states_sha256": _sha256(states.astype("<u4").tobytes()),
    }


def _execution_plan(masks: dict[str, tuple[int, ...]]) -> dict[str, Any]:
    return {
        "complete_variant_plan_required": True,
        "early_stop_used": False,
        "execution_mode": "deterministic_geometry_major_numeric_cell_waves_external_solver",
        "external_timeout_slack_seconds_per_cell": EXTERNAL_TIMEOUT_SLACK_SECONDS,
        "formula_representation": (
            "portable_SMTLIB2_round10_split8_b8_shared_key_complete_GF2_affine_partitions"
        ),
        "geometry_order": list(GEOMETRY_ORDER),
        "geometry_masks": _mask_hex(masks),
        "known_key_bits": KNOWN_KEY_BITS,
        "max_parallel_workers": MAX_PARALLEL_WORKERS,
        "partition_cell_count_per_geometry": 32,
        "partition_cell_free_bits": FREE_BITS,
        "partition_equations_per_cell": CELL_BITS,
        "primitive": "ChaCha20_block_function",
        "rounds": ROUNDS,
        "shared_key_block_count": BLOCK_COUNT,
        "solver": "Bitwuzla_0.9.1_bitblast_CaDiCaL",
        "solver_time_limit_milliseconds": TIME_LIMIT_MS,
        "target_output_bits_per_cell": BLOCK_COUNT * 512,
        "unknown_assignment_available_to_runner_before_execution": False,
        "unknown_key_bits": UNKNOWN_KEY_BITS,
        "variant_execution_order": list(VARIANTS),
        "variants": list(VARIANTS),
        "wave_count": len(VARIANTS) // MAX_PARALLEL_WORKERS,
        "wave_size": MAX_PARALLEL_WORKERS,
    }


def _variant_spec(variant: str) -> tuple[str, str, int]:
    for geometry in GEOMETRY_ORDER:
        match = re.fullmatch(rf"{geometry}_cell_([01]{{5}})", variant)
        if match is not None:
            cell = match.group(1)
            return geometry, cell, int(cell, 2)
    raise ValueError(f"unknown A200 variant {variant}")


def _balanced_xor(bit_coordinates: list[int]) -> str:
    nodes = [f"((_ extract {bit} {bit}) k0)" for bit in sorted(bit_coordinates, reverse=True)]
    if not nodes:
        raise ValueError("A200 parity mask is empty")
    while len(nodes) > 1:
        combined = []
        for index in range(0, len(nodes), 2):
            if index + 1 == len(nodes):
                combined.append(nodes[index])
            else:
                combined.append(f"(bvxor {nodes[index]} {nodes[index + 1]})")
        nodes = combined
    return nodes[0]


def _formula(base: str, variant: str, masks: dict[str, tuple[int, ...]]) -> str:
    geometry, _, cell_value = _variant_spec(variant)
    assertions = []
    for row, mask in enumerate(masks[geometry]):
        coordinates = [bit for bit in range(UNKNOWN_KEY_BITS) if mask >> bit & 1]
        parity = (cell_value >> row) & 1
        assertions.append(f"(assert (= {_balanced_xor(coordinates)} #b{parity}))")
    return base.replace("(check-sat)", "\n".join([*assertions, "(check-sat)"]))


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    anchors = _load_anchor_gates(results_dir)
    challenge = _A198._load_public_challenge()
    masks, derivation = _derive_geometry_masks(results_dir)
    plan = _execution_plan(masks)
    if _canonical_sha256(plan) != EXECUTION_PLAN_SHA256:
        raise RuntimeError("A200 execution plan hash differs from freeze")
    if _canonical_sha256(list(VARIANTS)) != VARIANT_ORDER_SHA256:
        raise RuntimeError("A200 variant order hash differs from freeze")
    base = _A198._base_formula(challenge)
    formulas = {variant: _formula(base, variant, masks) for variant in VARIANTS}
    formula_plan = []
    for variant in VARIANTS:
        geometry, cell, cell_value = _variant_spec(variant)
        formula = formulas[variant]
        formula_plan.append(
            {
                "variant": variant,
                "geometry": geometry,
                "cell": cell,
                "cell_value": cell_value,
                "mask_hex_order": [f"0x{mask:05x}" for mask in masks[geometry]],
                "candidate_count": 1 << FREE_BITS,
                "free_bits": FREE_BITS,
                "affine_equations": CELL_BITS,
                "shared_key_block_count": BLOCK_COUNT,
                "target_output_bits": BLOCK_COUNT * 512,
                "xor_tree": "balanced_pairwise_high_coordinate_first",
                "bytes": len(formula.encode()),
                "sha256": _sha256(formula.encode()),
                "portable_smtlib2": True,
            }
        )
    for geometry in GEOMETRY_ORDER:
        rows = [row for row in formula_plan if row["geometry"] == geometry]
        if (
            len(rows) != 32
            or [row["cell"] for row in rows] != list(CELLS)
            or sum(row["candidate_count"] for row in rows) != 1 << UNKNOWN_KEY_BITS
        ):
            raise RuntimeError(f"A200 {geometry} formula cover gate failed")
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "public_challenge": challenge,
        "geometry_masks": masks,
        "geometry_derivation": derivation,
        "execution_plan": plan,
        "formulas": formulas,
        "formula_plan": formula_plan,
        "solver_execution_started": False,
    }


def _syndrome(value: int, masks: tuple[int, ...]) -> int:
    syndrome = 0
    for row, mask in enumerate(masks):
        syndrome |= ((value & mask).bit_count() & 1) << row
    return syndrome


def _run_cell(
    variant: str,
    formula: str,
    masks: dict[str, tuple[int, ...]],
    identity: dict[str, Any],
) -> dict[str, Any]:
    geometry, cell, cell_value = _variant_spec(variant)
    command = [
        identity["path"],
        "--lang",
        "smt2",
        "--time-limit",
        str(TIME_LIMIT_MS),
        "--produce-models",
        "--bv-output-format",
        "16",
        "--bv-solver",
        "bitblast",
        "--sat-solver",
        "cadical",
    ]
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            input=formula,
            text=True,
            capture_output=True,
            timeout=TIME_LIMIT_MS / 1000 + EXTERNAL_TIMEOUT_SLACK_SECONDS,
            check=False,
        )
        externally_timed_out = False
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        externally_timed_out = True
        stdout, stderr, returncode = error.stdout or "", error.stderr or "", None
    status = next(
        (line for line in stdout.splitlines() if line in {"sat", "unsat", "unknown"}),
        "invalid",
    )
    values = {
        name: int(raw, 16) for name, raw in re.findall(r"\((k0|lo8)\s+#x([0-9a-fA-F]+)\)", stdout)
    }
    model = None
    if status == "sat":
        if set(values) != {"k0", "lo8"}:
            raise RuntimeError(f"A200 {variant} SAT model parse failed")
        recovered = values["k0"] & LOW_MASK
        if _syndrome(recovered, masks[geometry]) != cell_value:
            raise RuntimeError(f"A200 {variant} model violates its affine cell")
        model = {
            "key_word0": values["k0"],
            "key_word1_low_value": values["lo8"],
            "combined_assignment": (values["lo8"] << 32) | values["k0"],
            "recovered_unknown_low20": recovered,
        }
    return {
        "variant": variant,
        "geometry": geometry,
        "cell": cell,
        "cell_value": cell_value,
        "candidate_count": 1 << FREE_BITS,
        "free_bits": FREE_BITS,
        "formula_sha256": _sha256(formula.encode()),
        "formula_bytes": len(formula.encode()),
        "command": command,
        "status": status,
        "returncode": returncode,
        "externally_timed_out": externally_timed_out,
        "volatile_seconds": time.perf_counter() - started,
        "model": model,
        "stdout_sha256": _sha256(stdout.encode()),
        "stderr_sha256": _sha256(stderr.encode()),
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_round10_public_geometry_partition",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "geometries": len(GEOMETRY_ORDER),
            "cells_per_geometry": len(CELLS),
            "solver_time_limit_milliseconds": TIME_LIMIT_MS,
        },
    )
    ids = [
        "chacha20-a200-a198-numeric-boundary",
        "chacha20-a200-a199-public-operator-atlas",
        "chacha20-a200-four-exact-affine-covers",
        "chacha20-a200-b8-affine-formula-plan",
        "chacha20-a200-complete-wave-execution",
        "chacha20-a200-independent-confirmation",
        "chacha20-a200-geometry-comparison",
    ]
    rows = [
        (
            "A198:numeric_prefix_10s_30s_complete_covers_all_unknown",
            "retain_the_exact_resource_boundary_without_reexecution",
            "A200:representation_change_required",
            "retained_numeric_partition_boundary",
            A198_CAUSAL_SHA256,
            [],
            {"anchor_gates": payload["anchor_gates"]},
        ),
        (
            "A200:representation_change_required",
            "read_public_T04_T05_operator_geometry_from_A199",
            "A200:public_geometry_candidates",
            "public_formula_operator_transfer",
            A199_CAUSAL_SHA256,
            [ids[0]],
            {"geometry_derivation": payload["geometry_derivation"]},
        ),
        (
            "A200:public_geometry_candidates",
            "prove_GF2_rank5_and_exhaustive_32_by_32768_coverage_for_each_geometry",
            "A200:four_complete_disjoint_affine_partitions",
            "complete_affine_partition_construction",
            payload["geometry_sha256"],
            [ids[1]],
            {"geometry_masks": payload["geometry_masks"]},
        ),
        (
            "A200:four_complete_disjoint_affine_partitions",
            "compile_balanced_XOR_cells_into_the_same_round10_b8_formula",
            "A200:fixed_128_cell_formula_plan",
            "balanced_affine_SMT_compilation",
            payload["formula_plan_sha256"],
            [ids[2]],
            {"formula_plan_sha256": payload["formula_plan_sha256"]},
        ),
        (
            "A200:fixed_128_cell_formula_plan",
            "execute_all_32_waves_without_early_stop",
            "A200:complete_geometry_execution",
            "complete_predeclared_solver_execution",
            payload["execution_sha256"],
            [ids[3]],
            {"execution": payload["execution"]},
        ),
        (
            "A200:complete_geometry_execution",
            "recompute_every_model_over_all_4096_target_bits_and_control",
            "A200:independently_confirmed_models",
            "independent_eight_block_confirmation",
            payload["confirmation_sha256"],
            [ids[4]],
            {"confirmations": payload["confirmations"]},
        ),
        (
            "A200:independently_confirmed_models",
            "apply_the_frozen_primary_and_comparative_geometry_rules",
            "A200:prospective_public_geometry_result",
            "prospective_public_geometry_partition_transfer",
            payload["comparison_sha256"],
            [ids[5]],
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
    rows_read = reader.triplets(include_inferred=False)
    if len(rows_read) != len(ids) or not reader.verify_provenance():
        raise RuntimeError("A200 Causal Reader provenance gate failed")
    return {
        "stats": stats,
        "explicit_triplets": len(rows_read),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def run(*, results_dir: Path, output: Path, causal_output: Path) -> dict[str, Any]:
    analysis = analyze(results_dir)
    identity = _A198._A197._A191._solver_gate(analysis["protocol"])
    observations = []
    waves = []
    for wave_index, start in enumerate(range(0, len(VARIANTS), MAX_PARALLEL_WORKERS)):
        wave = VARIANTS[start : start + MAX_PARALLEL_WORKERS]

        def execute(variant: str) -> dict[str, Any]:
            return _run_cell(
                variant,
                analysis["formulas"][variant],
                analysis["geometry_masks"],
                identity,
            )

        with ThreadPoolExecutor(max_workers=MAX_PARALLEL_WORKERS) as executor:
            rows = list(executor.map(execute, wave))
        observations.extend(rows)
        waves.append(
            {
                "wave_index": wave_index,
                "variants": list(wave),
                "statuses": [row["status"] for row in rows],
                "maximum_volatile_seconds": max(row["volatile_seconds"] for row in rows),
            }
        )
    if [row["variant"] for row in observations] != list(VARIANTS):
        raise RuntimeError("A200 did not execute the complete variant plan")

    confirmations = [
        {
            "variant": row["variant"],
            "geometry": row["geometry"],
            "cell": row["cell"],
            **_A198._confirm_model(analysis["public_challenge"], row["model"]),
        }
        for row in observations
        if row["model"] is not None
    ]
    if any(
        not row["known_key_constraints_match"]
        or not row["all_blocks_match"]
        or row["control_first_block_match"]
        or row["output_bits_checked"] != 4096
        for row in confirmations
    ):
        raise RuntimeError("A200 returned model failed independent confirmation")
    recovered = sorted({row["recovered_unknown_low20"] for row in confirmations})

    geometry_results = {}
    for geometry in GEOMETRY_ORDER:
        rows = [row for row in observations if row["geometry"] == geometry]
        confirmed = [row for row in confirmations if row["geometry"] == geometry]
        counts = {
            status: sum(row["status"] == status for row in rows)
            for status in ("sat", "unsat", "unknown", "invalid")
        }
        geometry_results[geometry] = {
            "complete_domain_candidate_count": sum(row["candidate_count"] for row in rows),
            "complete_partition_executed": len(rows) == 32,
            "status_counts": counts,
            "resolved_sat_plus_unsat_cell_count": counts["sat"] + counts["unsat"],
            "confirmed_variants": [row["variant"] for row in confirmed],
            "confirmed_model_count": len(confirmed),
            "fully_confirmed_unknown_low20_assignments": sorted(
                {row["recovered_unknown_low20"] for row in confirmed}
            ),
            "statuses": {row["variant"]: row["status"] for row in rows},
        }
    formula_geometries = GEOMETRY_ORDER[1:]
    primary = any(
        geometry_results[geometry]["confirmed_model_count"] > 0 for geometry in formula_geometries
    )
    fiedler_score = (
        geometry_results["fiedler_filtration"]["confirmed_model_count"],
        geometry_results["fiedler_filtration"]["resolved_sat_plus_unsat_cell_count"],
    )
    distinct_scores = [
        (
            geometry_results[geometry]["confirmed_model_count"],
            geometry_results[geometry]["resolved_sat_plus_unsat_cell_count"],
        )
        for geometry in ("laplacian_distinct_modes", "signed_svd_distinct_modes")
    ]
    comparative = max(distinct_scores) > fiedler_score
    comparisons = {
        "original_domain_candidate_count": 1 << UNKNOWN_KEY_BITS,
        "geometry_count": len(GEOMETRY_ORDER),
        "complete_domain_covered_once_per_geometry": True,
        "partition_complete_and_disjoint_by_construction": True,
        "same_challenge_b8_formula_and_budget": True,
        "numeric_prefix_A198_not_reexecuted": True,
        "numeric_prefix_A198_10s_and_30s_status": "all_unknown",
        "geometry_results": geometry_results,
        "fully_confirmed_unknown_low20_assignments": recovered,
        "primary_prediction_retained": primary,
        "comparative_prediction_retained": comparative,
    }
    evidence_stage = (
        "PROSPECTIVE_ROUND10_PUBLIC_GEOMETRY_RECOVERY_RETAINED"
        if primary
        else "ROUND10_PUBLIC_GEOMETRY_COMPLETE_PARTITION_BOUNDARY_RETAINED"
    )
    execution = {
        "variant_order": list(VARIANTS),
        "complete_variant_plan_executed": True,
        "early_stop_used": False,
        "observations": observations,
        "wave_observations": waves,
        "returned_model_count": len(confirmations),
        "fully_confirmed_unknown_assignment_count": len(recovered),
        "fully_confirmed_unknown_low20_assignments": recovered,
        "unknown_assignment_available_to_runner_before_execution": False,
    }
    geometry_masks_json = _mask_hex(analysis["geometry_masks"])
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "Four complete affine geometry covers test whether the public A199 operator "
            "geometry changes the reduced ChaCha10 shared-key solver boundary."
        ),
        "scope": (
            "Prospective reduced ChaCha10 width-20 partial-key partition transfer over the "
            "unchanged A198 challenge and eight-block split8 formula."
        ),
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": analysis["protocol"]["protocol_state"],
            "information_boundary": analysis["protocol"]["information_boundary"],
            "prospective_predictions": analysis["protocol"]["prospective_predictions"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256,
        "geometry_masks": geometry_masks_json,
        "geometry_sha256": _canonical_sha256(geometry_masks_json),
        "geometry_derivation": analysis["geometry_derivation"],
        "execution_plan": analysis["execution_plan"],
        "execution_plan_sha256": EXECUTION_PLAN_SHA256,
        "solver_identity": identity,
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": _canonical_sha256(analysis["formula_plan"]),
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
        raise RuntimeError("A200 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "primary_prediction_retained": primary,
        "comparative_prediction_retained": comparative,
        "fully_confirmed_unknown_low20_assignments": recovered,
        "geometry_status_counts": {
            geometry: geometry_results[geometry]["status_counts"] for geometry in GEOMETRY_ORDER
        },
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
            "execution_plan_sha256": _canonical_sha256(analysis["execution_plan"]),
            "formula_plan_sha256": _canonical_sha256(analysis["formula_plan"]),
            "geometry_masks": _mask_hex(analysis["geometry_masks"]),
            "variants": len(analysis["formula_plan"]),
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
