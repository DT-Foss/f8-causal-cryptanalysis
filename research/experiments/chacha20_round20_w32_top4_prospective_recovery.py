#!/usr/bin/env python3
"""Prospective W32 recovery using only the fixed A224 top-four trajectory cells.

The protocol is split into two processes:

* ``--freeze`` creates a fresh public W32 ChaCha20 challenge, writes no secret,
  and exits.
* ``--run`` builds the exact A223 eight-block CNF, records one complete 10-second
  Gray trajectory, applies the already-fixed A224 coherence reader, and searches
  only its top four 24-bit suffix regions with Metal.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import secrets
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


A224 = _import_sibling(
    "chacha20_round20_a223_w32_metal_label.py",
    "a227_fixed_a224_reader",
)
A223 = A224.A223
A184 = A224.A184
A119 = A224.A119

ATTEMPT_ID = "R20-A227-W32-TOP4-PROSPECTIVE-RECOVERY-V1"
PROTOCOL_SCHEMA = "chacha20-round20-w32-top4-prospective-protocol-v1"
PREFLIGHT_SCHEMA = "chacha20-round20-w32-top4-prospective-preflight-v1"
RESULT_SCHEMA = "chacha20-round20-w32-top4-prospective-result-v1"

PROTOCOL_PATH = RESEARCH / "configs" / "chacha20_round20_w32_top4_prospective_v1.json"
PREFLIGHT_PATH = RESEARCH / "results" / "v1" / "chacha20_round20_w32_top4_prospective_preflight_v1.json"
RESULT_PATH = RESEARCH / "results" / "v1" / "chacha20_round20_w32_top4_prospective_v1.json"
REPORT_PATH = RESEARCH / "reports" / "CAUSAL_CHACHA20_ROUND20_W32_TOP4_PROSPECTIVE_RECOVERY_V1.md"
ARTIFACT_DIR = RESEARCH / "artifacts" / "a227_w32_top4_prospective_v1"
CNF_PATH = ARTIFACT_DIR / "a227_w32_shared_b8_bfs_far.cnf"
HELPER_PATH = ARTIFACT_DIR / "cadical_capacity_moonshot_a227"
STDOUT_PATH = ARTIFACT_DIR / "a227_gray8_w32.stdout"
STDERR_PATH = ARTIFACT_DIR / "a227_gray8_w32.stderr"
SPOOL_PATH = ARTIFACT_DIR / "a227_gray8_w32.models"

WIDTH = 32
BLOCK_COUNT = 8
TOP_K = 4
FREE_BITS_PER_CELL = WIDTH - 8
CANDIDATES_PER_CELL = 1 << FREE_BITS_PER_CELL
LIMITED_CANDIDATES = TOP_K * CANDIDATES_PER_CELL
FULL_CANDIDATES = 1 << WIDTH
SEARCH_REDUCTION_FACTOR = FULL_CANDIDATES // LIMITED_CANDIDATES
SOLVER_SECONDS_PER_CELL = 10
ARM_NAME = "a227_gray8_w32"
SCORE_NAME = "constraint_coherence"
SCORE_DEFINITION = "ln(1+search_propagations)-ln(1+decisions)-ln(1+conflicts)"


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


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _build_challenge(
    *, key_bytes: bytes, counter_nonce_bytes: bytes, challenge_id: str
) -> dict[str, Any]:
    if len(key_bytes) != 32 or len(counter_nonce_bytes) != 16:
        raise ValueError("A227 challenge material must be 32 key bytes plus 16 public bytes")
    key_words = [int(value) for value in np.frombuffer(key_bytes, dtype="<u4")]
    public_words = [int(value) for value in np.frombuffer(counter_nonce_bytes, dtype="<u4")]
    counter_start = public_words[0]
    nonce_words = public_words[1:]
    targets = [
        A223.P1._chacha_block(
            key_words=key_words,
            counter=(counter_start + block) & 0xFFFFFFFF,
            nonce_words=nonce_words,
            rounds=20,
        )
        for block in range(BLOCK_COUNT)
    ]
    control = list(targets[0])
    control[0] ^= 1
    challenge = {
        "challenge_id": challenge_id,
        "rounds": 20,
        "block_count": BLOCK_COUNT,
        "counter_schedule": "base_plus_block_index_mod_2^32",
        "counter_start": counter_start,
        "nonce_words": nonce_words,
        "unknown_key_bits": WIDTH,
        "known_key_bits": 256 - WIDTH,
        "unknown_global_bit_interval": [0, WIDTH - 1],
        "unknown_bit_numbering": "little_endian_bit0_upward_across_key_words_k0_through_k7",
        "known_key_mask_words": [0] + [0xFFFFFFFF] * 7,
        "known_key_value_words": [0] + key_words[1:],
        "target_words": targets,
        "target_block_sha256": [
            _sha256(A223.P1._word_bytes(block)) for block in targets
        ],
        "control_target_words": control,
        "control_target_block_sha256": _sha256(A223.P1._word_bytes(control)),
        "unknown_assignment_included": False,
        "unknown_assignment_value_included": False,
        "full_key_included": False,
        "secret_used_only_for_target_construction": True,
        "secret_discarded_after_target_construction": True,
        "generation_entropy_source": "python_secrets_token_bytes_OS_CSPRNG",
    }
    A223._validate_challenge(challenge, width=WIDTH)
    return challenge


def freeze(path: Path = PROTOCOL_PATH) -> dict[str, Any]:
    if path.exists():
        raise RuntimeError(f"A227 protocol already exists: {path}")
    runner = Path(__file__)
    challenge = _build_challenge(
        key_bytes=secrets.token_bytes(32),
        counter_nonce_bytes=secrets.token_bytes(16),
        challenge_id=secrets.token_hex(16),
    )
    payload = {
        "schema": PROTOCOL_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_before_any_A227_formula_export_solver_or_Metal_candidate_execution",
        "runner_sha256": _file_sha256(runner),
        "anchors": {
            "A224_source_sha256": _file_sha256(Path(A224.__file__)),
            "A224_result_sha256": _file_sha256(A224.DEFAULT_RESULT_PATH),
            "A223_runner_sha256": _file_sha256(Path(A223.__file__)),
            "A223_helper_source_sha256": _file_sha256(A223.HELPER_SOURCE),
            "Metal_native_source_sha256": A184.NATIVE_SOURCE_SHA256,
        },
        "public_challenge": challenge,
        "public_challenge_sha256": _canonical_sha256(challenge),
        "reader_plan": {
            "trajectory": "complete_reflected_gray8_order_retained_CaDiCaL_state",
            "seconds_per_cell": SOLVER_SECONDS_PER_CELL,
            "cell_count": 256,
            "score_name": SCORE_NAME,
            "score_definition": SCORE_DEFINITION,
            "score_direction": "descending",
            "top_k": TOP_K,
            "candidate_suffix_bits_per_selected_cell": FREE_BITS_PER_CELL,
            "candidates_per_selected_cell": CANDIDATES_PER_CELL,
            "limited_candidate_count": LIMITED_CANDIDATES,
            "full_candidate_count": FULL_CANDIDATES,
            "candidate_search_reduction_factor": SEARCH_REDUCTION_FACTOR,
            "complete_top_k_regions_required": True,
            "early_stop_permitted": False,
        },
        "information_boundary": {
            "unknown_assignment_stored_in_protocol_runner_or_helper": False,
            "unknown_assignment_available_to_run_process": False,
            "target_prefix_available_to_trajectory_score_or_top_k_selection": False,
            "full_domain_Metal_label_execution_permitted_before_top_k_search": False,
            "A227_outcomes_available_when_protocol_frozen": False,
        },
    }
    _atomic_json(path, payload)
    return {
        "protocol": str(path),
        "protocol_sha256": _file_sha256(path),
        "challenge_id": challenge["challenge_id"],
    }


def _load_protocol(path: Path = PROTOCOL_PATH) -> dict[str, Any]:
    protocol = json.loads(path.read_bytes())
    challenge = protocol.get("public_challenge", {})
    A223._validate_challenge(challenge, width=WIDTH)
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("runner_sha256") != _file_sha256(Path(__file__))
        or protocol.get("public_challenge_sha256") != _canonical_sha256(challenge)
        or protocol.get("anchors", {}).get("A224_source_sha256")
        != _file_sha256(Path(A224.__file__))
        or protocol.get("anchors", {}).get("A224_result_sha256")
        != _file_sha256(A224.DEFAULT_RESULT_PATH)
        or protocol.get("anchors", {}).get("A223_runner_sha256")
        != _file_sha256(Path(A223.__file__))
        or protocol.get("anchors", {}).get("A223_helper_source_sha256")
        != _file_sha256(A223.HELPER_SOURCE)
        or protocol.get("anchors", {}).get("Metal_native_source_sha256")
        != A184.NATIVE_SOURCE_SHA256
        or protocol.get("reader_plan", {}).get("score_definition") != SCORE_DEFINITION
        or protocol.get("reader_plan", {}).get("top_k") != TOP_K
    ):
        raise RuntimeError("A227 frozen protocol gate failed")
    return protocol


def _prepare_preflight(protocol: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    if PREFLIGHT_PATH.exists():
        preflight = json.loads(PREFLIGHT_PATH.read_bytes())
        if (
            preflight.get("schema") != PREFLIGHT_SCHEMA
            or preflight.get("protocol_sha256") != _file_sha256(PROTOCOL_PATH)
            or preflight.get("runner_sha256") != _file_sha256(Path(__file__))
            or _file_sha256(CNF_PATH) != preflight["structural_CNF"]["transformed_sha256"]
            or _file_sha256(HELPER_PATH) != preflight["native_helper"]["binary_sha256"]
        ):
            raise RuntimeError("A227 retained preflight gate failed")
        return preflight

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    challenge = protocol["public_challenge"]
    with tempfile.TemporaryDirectory(prefix="a227-w32-preflight-") as raw_directory:
        directory = Path(raw_directory)
        context = A223._base_context(
            width=WIDTH,
            challenge=challenge,
            config=config,
            directory=directory,
        )
        dimensions = list(range(-1, math.ceil(math.log2(WIDTH))))

        def probe(dimension: int) -> tuple[int, int, list[int], dict[str, Any]]:
            return A223._coordinate_probe(
                context=context,
                dimension=dimension,
                config=config,
                directory=directory,
            )

        with ThreadPoolExecutor(max_workers=len(dimensions)) as executor:
            probe_rows = list(executor.map(probe, dimensions))
        source_one_literals = A223._decode_mapping(
            [(dimension, units) for _, dimension, units, _ in probe_rows],
            width=WIDTH,
        )
        structural = A223._build_structural_cnf(
            context=context,
            source_one_literals=source_one_literals,
            output=CNF_PATH,
        )
        native_helper = A223._compile_helper(
            config=config,
            output=HELPER_PATH,
            directory=directory,
        )
    preflight = {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "state": "frozen_after_formula_mapping_CNF_reindex_and_helper_compile_before_trajectory_execution",
        "protocol_sha256": _file_sha256(PROTOCOL_PATH),
        "runner_sha256": _file_sha256(Path(__file__)),
        "source_formula_sha256": context["formula_sha256"],
        "source_formula_bytes": context["formula_bytes"],
        "mapping_dimensions": dimensions,
        "mapping_probe_rows": [row for _, _, _, row in probe_rows],
        "source_one_literals_bit0_upward": source_one_literals,
        "structural_CNF": structural,
        "native_helper": native_helper,
        "arm": {
            "arm": ARM_NAME,
            "width": WIDTH,
            "order": "reflected_gray8",
            "cell_order_sha256": _canonical_sha256(A223._gray8_order()),
            "seconds_per_cell": SOLVER_SECONDS_PER_CELL,
        },
        "trajectory_execution_started": False,
        "top_k_selected": False,
        "Metal_candidate_execution_started": False,
    }
    _atomic_json(PREFLIGHT_PATH, preflight)
    return preflight


def _run_trajectory(
    *, preflight: dict[str, Any], challenge: dict[str, Any]
) -> dict[str, Any]:
    if STDOUT_PATH.exists() or STDERR_PATH.exists() or SPOOL_PATH.exists():
        raise RuntimeError("A227 trajectory output already exists without a final result")
    command = [
        str(HELPER_PATH),
        "--cnf",
        str(CNF_PATH),
        "--arm",
        ARM_NAME,
        *A223._helper_args(preflight["structural_CNF"]),
        "--cell-order",
        ",".join(A223._gray8_order()),
        "--seconds",
        str(SOLVER_SECONDS_PER_CELL),
        "--model-spool",
        str(SPOOL_PATH),
    ]
    started = time.perf_counter()
    with STDOUT_PATH.open("wb") as stdout_file, STDERR_PATH.open("wb") as stderr_file:
        process = subprocess.Popen(command, stdout=stdout_file, stderr=stderr_file)
        try:
            returncode = process.wait(timeout=3300)
            externally_timed_out = False
        except subprocess.TimeoutExpired:
            process.kill()
            returncode = process.wait(timeout=10)
            externally_timed_out = True
    stdout = STDOUT_PATH.read_text()
    stderr = STDERR_PATH.read_text()
    spool = SPOOL_PATH.read_text() if SPOOL_PATH.exists() else ""
    parsed = A223._parse_arm_after_global_barrier(
        arm_plan={"arm": ARM_NAME, "width": WIDTH, "order": "reflected_gray8"},
        stdout=stdout,
        stderr=stderr,
        spool=spool,
        returncode=returncode,
        externally_timed_out=externally_timed_out,
        preflight={"width_preflights": {str(WIDTH): {"structural_CNF": preflight["structural_CNF"]}}},
        challenge=challenge,
    )
    if parsed.get("complete_valid_arm") is not True:
        raise RuntimeError("A227 trajectory arm is not complete and valid")
    return {
        **parsed,
        "command_sha256": _canonical_sha256(command),
        "volatile_elapsed_seconds": time.perf_counter() - started,
    }


def _score_rows(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for observation in observations:
        delta = observation["metrics_delta"]
        score = (
            math.log1p(float(delta["search_propagations"]))
            - math.log1p(float(delta["decisions"]))
            - math.log1p(float(delta["conflicts"]))
        )
        rows.append(
            {
                "prefix8": observation["prefix8"],
                "cell_index": observation["cell_index"],
                "constraint_coherence": score,
                "conflicts": int(delta["conflicts"]),
                "decisions": int(delta["decisions"]),
                "search_propagations": int(delta["search_propagations"]),
            }
        )
    return sorted(rows, key=lambda row: (-row["constraint_coherence"], row["prefix8"]))


def _initial(challenge: dict[str, Any]) -> np.ndarray:
    initial = np.zeros(16, dtype=np.uint32)
    initial[:4] = A119.CONSTANTS
    initial[4:12] = np.array(challenge["known_key_value_words"], dtype=np.uint32)
    initial[12] = np.uint32(challenge["counter_start"])
    initial[13:16] = np.array(challenge["nonce_words"], dtype=np.uint32)
    return initial


def _confirm_candidate(challenge: dict[str, Any], word0: int) -> dict[str, Any]:
    key_words = list(challenge["known_key_value_words"])
    key_words[0] = word0
    blocks = [
        A223.P1._chacha_block(
            key_words=key_words,
            counter=(challenge["counter_start"] + block) & 0xFFFFFFFF,
            nonce_words=challenge["nonce_words"],
            rounds=20,
        )
        for block in range(BLOCK_COUNT)
    ]
    matches = [
        candidate == target
        for candidate, target in zip(blocks, challenge["target_words"], strict=True)
    ]
    hashes = [_sha256(A223.P1._word_bytes(block)) for block in blocks]
    return {
        "key_word0": word0,
        "key_word0_hex": f"0x{word0:08x}",
        "prefix8": f"{word0 >> 24:08b}",
        "block_matches": matches,
        "all_blocks_match": all(matches),
        "candidate_block_sha256": hashes,
        "output_bits_checked": BLOCK_COUNT * 512,
        "flipped_control_rejected": hashes[0] != challenge["control_target_block_sha256"],
    }


def _limited_metal_search(
    *, challenge: dict[str, Any], selected: list[dict[str, Any]]
) -> dict[str, Any]:
    executable, native_build = A184._A181._compile_native(
        ARTIFACT_DIR / "metal_build", "swiftc"
    )
    target = np.array(challenge["target_words"][0], dtype=np.uint32)
    control = np.array(challenge["control_target_words"], dtype=np.uint32)
    initial = _initial(challenge)
    host = A184.SliceMetalHost(executable, initial, target, control)
    try:
        observed = host.blocks(0x12345600, 8)
        scalar = np.repeat(initial.reshape(1, 16), 8, axis=0)
        scalar[:, 4] = np.arange(0x12345600, 0x12345608, dtype=np.uint32)
        expected = (A119._core(scalar.copy(), 20) + scalar).astype(np.uint32)
        if not np.array_equal(observed, expected):
            raise RuntimeError("A227 Metal mapping gate differs from NumPy")
        factual: list[int] = []
        control_matches: list[int] = []
        regions = []
        for rank, row in enumerate(selected, start=1):
            prefix = int(row["prefix8"], 2)
            first = prefix << FREE_BITS_PER_CELL
            response = host.filter(first, CANDIDATES_PER_CELL)
            factual.extend(int(value) for value in response["factual"])
            control_matches.extend(int(value) for value in response["control"])
            regions.append(
                {
                    "reader_rank": rank,
                    "prefix8": row["prefix8"],
                    "first_candidate": first,
                    "candidate_count": CANDIDATES_PER_CELL,
                    "factual_filter_matches": [int(value) for value in response["factual"]],
                    "control_filter_matches": [int(value) for value in response["control"]],
                }
            )
        host_identity = host.identity
    finally:
        host.close()
    confirmations = [_confirm_candidate(challenge, value) for value in factual]
    exact = [row for row in confirmations if row["all_blocks_match"] and row["flipped_control_rejected"]]
    return {
        "native_build": native_build,
        "host_identity": host_identity,
        "mapping_gate_exact_numpy_identity": True,
        "selected_region_count": len(selected),
        "candidates_per_region": CANDIDATES_PER_CELL,
        "logical_candidate_count": LIMITED_CANDIDATES,
        "full_domain_candidate_count": FULL_CANDIDATES,
        "candidate_search_reduction_factor": SEARCH_REDUCTION_FACTOR,
        "complete_selected_regions_executed": len(regions) == TOP_K,
        "early_stop_used": False,
        "regions": regions,
        "factual_filter_matches": factual,
        "control_filter_matches": control_matches,
        "confirmations": confirmations,
        "exact_confirmed_matches": exact,
        "prospective_recovery_success": len(exact) == 1 and not control_matches,
    }


def _write_report(payload: dict[str, Any]) -> None:
    metal = payload["limited_Metal_search"]
    lines = [
        "# A227 — Prospective W32 top-four recovery",
        "",
        "## Outcome",
        "",
        f"- Prospective recovery success: **{metal['prospective_recovery_success']}**",
        f"- Candidate evaluations: `{metal['logical_candidate_count']}` instead of `{metal['full_domain_candidate_count']}`",
        f"- Candidate-search reduction: **{metal['candidate_search_reduction_factor']}x**",
        f"- Selected prefixes: `{', '.join(row['prefix8'] for row in payload['reader']['selected_top4'])}`",
        "",
    ]
    if metal["exact_confirmed_matches"]:
        match = metal["exact_confirmed_matches"][0]
        lines.extend(
            [
                f"Recovered key word 0: `{match['key_word0_hex']}`; reader rank: "
                f"`{next(index + 1 for index, row in enumerate(payload['reader']['ranked_cells']) if row['prefix8'] == match['prefix8'])}`.",
                "",
            ]
        )
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = REPORT_PATH.with_name(f".{REPORT_PATH.name}.tmp")
    temporary.write_text("\n".join(lines))
    temporary.replace(REPORT_PATH)


def run() -> dict[str, Any]:
    if RESULT_PATH.exists():
        raise RuntimeError(f"A227 result already exists: {RESULT_PATH}")
    protocol = _load_protocol()
    challenge = protocol["public_challenge"]
    config = A223._load_config()
    preflight = _prepare_preflight(protocol, config)
    trajectory = _run_trajectory(preflight=preflight, challenge=challenge)
    ranked = _score_rows(trajectory["observations"])
    selected = ranked[:TOP_K]
    limited_search = _limited_metal_search(challenge=challenge, selected=selected)
    exact = limited_search["exact_confirmed_matches"]
    recovered_rank = None
    if len(exact) == 1:
        recovered_prefix = exact[0]["prefix8"]
        recovered_rank = next(
            index + 1 for index, row in enumerate(ranked) if row["prefix8"] == recovered_prefix
        )
    payload = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PROSPECTIVE_FULLROUND_W32_TOP4_REGION_RECOVERY",
        "result": (
            "A fresh secret-free R20 W32 challenge is read by the fixed A224 "
            "trajectory score and searched only inside its four highest-ranked regions."
        ),
        "anchors": {
            "protocol_sha256": _file_sha256(PROTOCOL_PATH),
            "preflight_sha256": _file_sha256(PREFLIGHT_PATH),
            "runner_sha256": _file_sha256(Path(__file__)),
            "A224_source_sha256": _file_sha256(Path(A224.__file__)),
            "A224_result_sha256": _file_sha256(A224.DEFAULT_RESULT_PATH),
        },
        "information_boundary": protocol["information_boundary"],
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "trajectory": trajectory,
        "reader": {
            "score_name": SCORE_NAME,
            "score_definition": SCORE_DEFINITION,
            "score_direction": "descending",
            "ranked_cells": ranked,
            "selected_top4": selected,
            "target_label_available_at_selection": False,
            "recovered_prefix_rank_after_limited_search": recovered_rank,
        },
        "limited_Metal_search": limited_search,
    }
    _atomic_json(RESULT_PATH, payload)
    _write_report(payload)
    return payload


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--freeze", action="store_true")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args(argv)
    if args.freeze == args.run:
        parser.error("select exactly one of --freeze or --run")
    if args.freeze:
        value = freeze()
    else:
        payload = run()
        value = {
            "attempt_id": payload["attempt_id"],
            "prospective_recovery_success": payload["limited_Metal_search"]["prospective_recovery_success"],
            "candidate_search_reduction_factor": payload["limited_Metal_search"]["candidate_search_reduction_factor"],
            "selected_top4": [row["prefix8"] for row in payload["reader"]["selected_top4"]],
            "recovered_prefix_rank": payload["reader"]["recovered_prefix_rank_after_limited_search"],
            "result": str(RESULT_PATH),
            "report": str(REPORT_PATH),
        }
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
