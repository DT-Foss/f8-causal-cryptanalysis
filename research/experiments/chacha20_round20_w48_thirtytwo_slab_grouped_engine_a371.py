#!/usr/bin/env python3
"""A371: target-free W48 thirty-two-slab adapter over the qualified Metal grid."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w48_thirtytwo_slab_grouped_engine_a371_design_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_w48_thirtytwo_slab_grouped_engine_a371_v1.json"
QUALIFICATION = (
    RESULTS / "chacha20_round20_w48_thirtytwo_slab_grouped_engine_a371_qualification_v1.json"
)
A346_RUNNER = RESEARCH / "experiments/chacha20_round20_w47_sixteen_slab_grouped_engine_a346.py"
A346_DESIGN = CONFIGS / "chacha20_round20_w47_sixteen_slab_grouped_engine_a346_design_v1.json"
A346_PROTOCOL = CONFIGS / "chacha20_round20_w47_sixteen_slab_grouped_engine_a346_v1.json"
A346_QUALIFICATION = (
    RESULTS / "chacha20_round20_w47_sixteen_slab_grouped_engine_a346_qualification_v1.json"
)
TEST = ROOT / "tests/test_chacha20_round20_w48_thirtytwo_slab_grouped_engine_a371.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w48_thirtytwo_slab_grouped_engine_a371.sh"

ATTEMPT_ID = "A371"
DESIGN_SHA256 = "3069c3106b02899bfc77c0c1252f47dda2db192f0bccfdf7dadd45ec944ff368"
A346_DESIGN_SHA256 = "d9da59b50820a033973b54c845d10e568aeeb65e2f3d0c1254e5306371fea0ba"
A346_PROTOCOL_SHA256 = "4cb6c1c7e0a9719cf4ac04e870d9f5190772664b786d541a0fc4c7c7ea86e3ca"
A346_QUALIFICATION_SHA256 = (
    "58b0fbb2d5ca1f63a990b23fc46608f9f06f7e5bf479bc2b3affd75c3284d502"
)
A346_RUNNER_SHA256 = "b022a3c19de0e5c0ab09cee68fa738e2fb3586823f5155d087441361588156d2"
GROUPED_EXECUTABLE_SHA256 = "d1c41a049db90997ada5eba880d1ba2d0787b1d74be499f0a254183f1b577acf"

WIDTH = 48
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
SLAB_BITS = 5
OUTER_LOW_BITS = 11
CELLS = 1 << PREFIX_BITS
WORD0_PER_GROUP = 1 << WORD0_SUFFIX_BITS
OUTER_SLICES = 1 << OUTER_LOW_BITS
SLABS = tuple(range(1 << SLAB_BITS))
SLAB_SIZE = WORD0_PER_GROUP * OUTER_SLICES
GROUP_SIZE = len(SLABS) * SLAB_SIZE
DOMAIN_SIZE = 1 << WIDTH
HOST_REFRESH_GROUPS = 16


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A371 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A346 = load_module(A346_RUNNER, "a371_a346")
W43 = A346.W43
file_sha256 = A346.file_sha256
canonical_sha256 = A346.canonical_sha256
atomic_json = A346.atomic_json
relative = A346.relative
path_from_ref = A346.path_from_ref
anchor = A346.anchor


def boundary_outer16_values() -> list[int]:
    values = {0, 1}
    for slab in SLABS:
        values.add(slab << OUTER_LOW_BITS)
        values.add((slab << OUTER_LOW_BITS) | (OUTER_SLICES - 1))
    result = sorted(values)
    if len(result) != 65 or result[0] != 0 or result[-1] != 0xFFFF:
        raise RuntimeError("A371 boundary construction differs")
    return result


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A371 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    engine = value.get("engine_contract", {})
    qualification = value.get("qualification_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w48-thirtytwo-slab-grouped-engine-a371-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "target_free_W48_engine_adapter_frozen_after_A346_qualification_before_any_W48_production_challenge_candidate_prefix_or_filter_outcome"
        or engine.get("unknown_key_bits") != WIDTH
        or engine.get("slabs") != len(SLABS)
        or engine.get("candidate_group_size") != GROUP_SIZE
        or engine.get("filter_dispatches_per_W48_prefix_group") != len(SLABS)
        or engine.get("complete_group_before_success_evaluation") is not True
        or engine.get("early_stop_inside_group") is not False
        or engine.get("full_domain_assignments") != DOMAIN_SIZE
        or engine.get("host_refresh_interval_W48_prefix_groups") != HOST_REFRESH_GROUPS
        or engine.get("full_rounds") != 20
        or engine.get("feedforward_included") is not True
        or qualification.get("scalar_boundary_count") != len(boundary_outer16_values())
        or qualification.get("complete_W48_group_gate") is not True
        or qualification.get("complete_W48_group_candidates") != GROUP_SIZE
        or boundary.get("A346_qualification_complete_before_A371_design") is not True
        or boundary.get("W48_production_challenge_available_at_freeze") is not False
        or boundary.get("W48_target_assignment_available_at_freeze") is not False
        or boundary.get("W48_candidate_available_at_freeze") is not False
        or boundary.get("A371_qualification_uses_only_synthetic_targets") is not True
    ):
        raise RuntimeError("A371 frozen design semantics differ")
    sources = value["source_anchors"]
    for path_key, sha_key in (
        ("A346_design_path", "A346_design_sha256"),
        ("A346_protocol_path", "A346_protocol_sha256"),
        ("A346_qualification_path", "A346_qualification_sha256"),
        ("A346_runner_path", "A346_runner_sha256"),
        ("grouped_executable_path", "grouped_executable_sha256"),
    ):
        anchor(path_from_ref(sources[path_key]), sources[sha_key])
    return value


def load_a346_source() -> tuple[dict[str, Any], dict[str, Any]]:
    protocol = A346.load_protocol(A346_PROTOCOL_SHA256)
    if file_sha256(A346_QUALIFICATION) != A346_QUALIFICATION_SHA256:
        raise RuntimeError("A371 A346 qualification hash differs")
    qualification = json.loads(A346_QUALIFICATION.read_bytes())
    group = qualification.get("complete_group_gate", {})
    if (
        qualification.get("evidence_stage")
        != "TARGET_FREE_COMPLETE_W47_GROUP_ENGINE_EXACTLY_QUALIFIED"
        or qualification.get("protocol_sha256") != A346_PROTOCOL_SHA256
        or qualification.get("production_W47_challenge_used") is not False
        or qualification.get("production_W47_candidate_used") is not False
        or qualification.get("synthetic_filter_exact") is not True
        or qualification.get("matched_control_empty") is not True
        or group.get("logical_candidates") != 1 << 35
        or group.get("complete_W47_group_before_outcome_evaluation") is not True
        or len(group.get("factual_candidates", [])) != 1
        or group.get("control_candidates") != []
    ):
        raise RuntimeError("A371 A346 source semantics differ")
    return protocol, qualification


def _base_initial(challenge: Mapping[str, Any]) -> np.ndarray:
    initial = W43._initial(  # noqa: SLF001
        challenge["known_zeroed_key_words"],
        int(challenge["counter_start"]),
        challenge["nonce_words"],
        0,
    ).copy()
    initial[5] = np.uint32(int(initial[5]) & 0xFFFF0000)
    return initial


def initial_for_slab(challenge: Mapping[str, Any], slab: int) -> np.ndarray:
    if slab not in SLABS:
        raise ValueError("A371 slab must be in zero through thirty-one")
    initial = _base_initial(challenge)
    initial[5] = np.uint32(int(initial[5]) | (slab << OUTER_LOW_BITS))
    return initial


def initial_for_outer16(challenge: Mapping[str, Any], outer16: int) -> np.ndarray:
    if not 0 <= outer16 < 1 << 16:
        raise ValueError("A371 word1 low16 exceeds W48")
    initial = _base_initial(challenge)
    initial[5] = np.uint32(int(initial[5]) | outer16)
    return initial


def encode_assignment(*, word0: int, slab: int, outer_low11: int) -> int:
    if not 0 <= word0 <= 0xFFFFFFFF:
        raise ValueError("A371 word0 exceeds uint32")
    if slab not in SLABS or not 0 <= outer_low11 < OUTER_SLICES:
        raise ValueError("A371 slab/outer pair differs")
    return (((slab << OUTER_LOW_BITS) | outer_low11) << 32) | word0


def decode_assignment(assignment: int) -> dict[str, int]:
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A371 assignment exceeds W48")
    outer16 = assignment >> 32
    return {
        "word0": assignment & 0xFFFFFFFF,
        "word1_low16": outer16,
        "slab": outer16 >> OUTER_LOW_BITS,
        "outer_low11": outer16 & (OUTER_SLICES - 1),
    }


def scalar_blocks_w48(
    *, challenge: Mapping[str, Any], outer16: int, first_word0: int, count: int
) -> np.ndarray:
    if count <= 0 or first_word0 < 0 or first_word0 + count > 1 << 32:
        raise ValueError("A371 scalar word0 interval differs")
    initial = initial_for_outer16(challenge, outer16)
    scalar = np.repeat(initial.reshape(1, 16), count, axis=0)
    scalar[:, 4] = np.arange(first_word0, first_word0 + count, dtype=np.uint32)
    return (W43.ANCHOR.A119._core(scalar.copy(), 20) + scalar).astype(  # noqa: SLF001
        np.uint32
    )


def filter_complete_prefix(
    *,
    host: Any,
    challenge: Mapping[str, Any],
    prefix: int,
    target: np.ndarray,
    control: np.ndarray,
) -> dict[str, Any]:
    if not 0 <= prefix < CELLS:
        raise ValueError("A371 prefix is outside the exact 4,096-cell cover")
    first_word0 = prefix << WORD0_SUFFIX_BITS
    slab_rows: list[dict[str, Any]] = []
    started = time.perf_counter()
    for slab in SLABS:
        host.configure(initial_for_slab(challenge, slab), target, control)
        observed = host.filter_group(
            first_word0=first_word0,
            word0_count=WORD0_PER_GROUP,
            outer_first=0,
            outer_count=OUTER_SLICES,
        )
        slab_rows.append({"slab": slab, "observed": observed})
    factual: list[int] = []
    controls: list[int] = []
    gpu_seconds = 0.0
    for row in slab_rows:
        slab = int(row["slab"])
        observed = row["observed"]
        factual.extend(
            encode_assignment(word0=int(word0), slab=slab, outer_low11=int(outer))
            for word0, outer in observed["factual"]
        )
        controls.extend(
            encode_assignment(word0=int(word0), slab=slab, outer_low11=int(outer))
            for word0, outer in observed["control"]
        )
        gpu_seconds += float(observed["gpu_seconds"])
    return {
        "prefix": prefix,
        "first_word0": first_word0,
        "factual_candidates": sorted(factual),
        "control_candidates": sorted(controls),
        "slabs_executed": list(SLABS),
        "filter_dispatches": len(SLABS),
        "logical_candidates": GROUP_SIZE,
        "complete_W48_group_before_outcome_evaluation": True,
        "early_stop_inside_group": False,
        "gpu_seconds": gpu_seconds,
        "volatile_wall_seconds": time.perf_counter() - started,
    }


def freeze() -> dict[str, Any]:
    if PROTOCOL.exists() or QUALIFICATION.exists():
        raise FileExistsError("A371 protocol or qualification already exists")
    design = load_design()
    a346_protocol, a346_qualification = load_a346_source()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A371 test and reproducer must precede protocol freeze")
    payload = {
        "schema": "chacha20-round20-w48-thirtytwo-slab-grouped-engine-a371-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "target_free_adapter_frozen_before_any_W48_production_challenge",
        "design_sha256": DESIGN_SHA256,
        "engine_contract": design["engine_contract"],
        "qualification_contract": design["qualification_contract"],
        "information_boundary": design["information_boundary"],
        "source_engine": {
            "attempt_id": "A346",
            "protocol_sha256": A346_PROTOCOL_SHA256,
            "qualification_artifact_sha256": A346_QUALIFICATION_SHA256,
            "qualification_sha256": a346_qualification["qualification_sha256"],
            "executable_sha256": a346_protocol["source_engine"]["executable_sha256"],
        },
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "A346_design": {"path": relative(A346_DESIGN), "sha256": A346_DESIGN_SHA256},
            "A346_protocol": {
                "path": relative(A346_PROTOCOL),
                "sha256": A346_PROTOCOL_SHA256,
            },
            "A346_qualification": {
                "path": relative(A346_QUALIFICATION),
                "sha256": A346_QUALIFICATION_SHA256,
            },
            "A346_runner": {"path": relative(A346_RUNNER), "sha256": A346_RUNNER_SHA256},
            "grouped_executable": {
                "path": a346_protocol["anchors"]["grouped_executable"]["path"],
                "sha256": GROUPED_EXECUTABLE_SHA256,
            },
            "A371_runner": {"path": relative(Path(__file__)), "sha256": file_sha256(Path(__file__))},
            "A371_test": {"path": relative(TEST), "sha256": file_sha256(TEST)},
            "A371_reproducer": {"path": relative(REPRO), "sha256": file_sha256(REPRO)},
        },
        "production_W48_challenge_available": False,
        "production_W48_candidate_available": False,
        "production_W48_execution_started": False,
    }
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_protocol_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_protocol_sha256:
        raise RuntimeError("A371 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w48-thirtytwo-slab-grouped-engine-a371-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_state")
        != "target_free_adapter_frozen_before_any_W48_production_challenge"
        or value.get("production_W48_challenge_available") is not False
        or value.get("production_W48_candidate_available") is not False
        or value.get("production_W48_execution_started") is not False
        or value.get("engine_contract", {}).get("candidate_group_size") != GROUP_SIZE
        or value.get("source_engine", {}).get("executable_sha256")
        != GROUPED_EXECUTABLE_SHA256
    ):
        raise RuntimeError("A371 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    return value


def qualify(*, expected_protocol_sha256: str) -> dict[str, Any]:
    if QUALIFICATION.exists():
        raise FileExistsError("A371 qualification already exists")
    protocol = load_protocol(expected_protocol_sha256)
    _a346_protocol, a346_qualification = load_a346_source()
    challenge = json.loads(A346.A324.A311.A307.A304.A302.PROTOCOL.read_bytes())[
        "public_challenge"
    ]
    executable = path_from_ref(protocol["anchors"]["grouped_executable"]["path"])
    anchor(executable, GROUPED_EXECUTABLE_SHA256)
    placeholder = np.asarray([0, 0], dtype=np.uint32)
    host = A346.A324.A311.A307.A304.GroupedMetalHost(
        executable,
        initial_for_slab(challenge, 0),
        placeholder,
        placeholder,
    )
    boundary_rows: list[dict[str, Any]] = []
    first_word0 = 0x45678000
    count = 17
    try:
        for outer16 in boundary_outer16_values():
            slab = outer16 >> OUTER_LOW_BITS
            outer_low11 = outer16 & (OUTER_SLICES - 1)
            host.configure(initial_for_slab(challenge, slab), placeholder, placeholder)
            observed = host.blocks_group(
                first_word0=first_word0,
                word0_count=count,
                outer_first=outer_low11,
                outer_count=1,
            )[0]
            expected = scalar_blocks_w48(
                challenge=challenge,
                outer16=outer16,
                first_word0=first_word0,
                count=count,
            )
            if not np.array_equal(observed, expected):
                raise RuntimeError("A371 W48 boundary scalar identity gate failed")
            boundary_rows.append(
                {
                    "outer16": outer16,
                    "slab": slab,
                    "outer_low11": outer_low11,
                    "word0_count": count,
                    "complete_output_bits_checked": count * 512,
                    "output_sha256": hashlib.sha256(expected.astype("<u4").tobytes()).hexdigest(),
                    "grouped_equals_scalar": True,
                }
            )

        target_prefix = 0xA37
        target_word0 = (target_prefix << WORD0_SUFFIX_BITS) | 0x13579
        target_outer16 = 0xE437
        target_block = scalar_blocks_w48(
            challenge=challenge,
            outer16=target_outer16,
            first_word0=target_word0,
            count=1,
        )[0]
        control = target_block.copy()
        control[0] ^= np.uint32(1)
        complete = filter_complete_prefix(
            host=host,
            challenge=challenge,
            prefix=target_prefix,
            target=target_block,
            control=control,
        )
        expected_assignment = (target_outer16 << 32) | target_word0
        if complete["factual_candidates"] != [expected_assignment]:
            raise RuntimeError("A371 complete W48 group factual gate failed")
        if complete["control_candidates"] != []:
            raise RuntimeError("A371 complete W48 group control gate failed")
        identity = host.identity
    finally:
        host.close()

    payload = {
        "schema": "chacha20-round20-w48-thirtytwo-slab-grouped-engine-a371-qualification-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "TARGET_FREE_COMPLETE_W48_GROUP_ENGINE_EXACTLY_QUALIFIED",
        "protocol_sha256": expected_protocol_sha256,
        "production_W48_challenge_used": False,
        "production_W48_candidate_used": False,
        "source_engine_qualification_sha256": a346_qualification["qualification_sha256"],
        "source_executable_sha256": GROUPED_EXECUTABLE_SHA256,
        "metal_identity": identity,
        "boundary_full_block_rows": boundary_rows,
        "total_boundary_output_bits_checked": sum(
            row["complete_output_bits_checked"] for row in boundary_rows
        ),
        "complete_group_gate": {
            key: item for key, item in complete.items() if not key.startswith("volatile_")
        },
        "expected_synthetic_assignment": expected_assignment,
        "expected_synthetic_assignment_hex": f"{expected_assignment:012x}",
        "synthetic_filter_exact": True,
        "matched_control_empty": True,
        "information_boundary": protocol["information_boundary"],
    }
    payload["qualification_sha256"] = canonical_sha256(
        {
            "boundary_full_block_rows": boundary_rows,
            "complete_group_gate": payload["complete_group_gate"],
            "expected_synthetic_assignment": expected_assignment,
            "source_executable_sha256": GROUPED_EXECUTABLE_SHA256,
            "production_W48_challenge_used": False,
        }
    )
    atomic_json(QUALIFICATION, payload)
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "protocol_frozen": PROTOCOL.exists(),
        "qualification_complete": QUALIFICATION.exists(),
        "candidate_group_size": GROUP_SIZE,
        "full_domain_size": DOMAIN_SIZE,
        "slabs_per_prefix_group": len(SLABS),
        "production_target_used": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze", action="store_true")
    action.add_argument("--qualify", action="store_true")
    parser.add_argument("--expected-protocol-sha256")
    args = parser.parse_args()
    if args.analyze:
        payload = analyze()
    elif args.freeze:
        payload = freeze()
    else:
        if not args.expected_protocol_sha256:
            parser.error("--qualify requires --expected-protocol-sha256")
        payload = qualify(expected_protocol_sha256=args.expected_protocol_sha256)
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
