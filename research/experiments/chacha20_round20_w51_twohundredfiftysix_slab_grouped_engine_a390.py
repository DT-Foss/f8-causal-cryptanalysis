#!/usr/bin/env python3
"""A390: target-free W51 two-hundred-fifty-six-slab adapter over the qualified Metal grid."""

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

DESIGN = CONFIGS / "chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_design_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_v1.json"
QUALIFICATION = (
    RESULTS / "chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_qualification_v1.json"
)
A384_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_onehundredtwentyeight_slab_grouped_engine_a384.py"
A384_DESIGN = CONFIGS / "chacha20_round20_w50_onehundredtwentyeight_slab_grouped_engine_a384_design_v1.json"
A384_PROTOCOL = CONFIGS / "chacha20_round20_w50_onehundredtwentyeight_slab_grouped_engine_a384_v1.json"
A384_QUALIFICATION = (
    RESULTS / "chacha20_round20_w50_onehundredtwentyeight_slab_grouped_engine_a384_qualification_v1.json"
)
TEST = ROOT / "tests/test_chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390.sh"

ATTEMPT_ID = "A390"
DESIGN_SHA256 = "feffc7944535d9785392489de843247d15dab660f6ba2df9f9cfeec9f2595870"
A384_DESIGN_SHA256 = "9ca2dacdff315b4f117113bea1046a1c11764213f66464fc8f65f07223e8cd2c"
A384_PROTOCOL_SHA256 = "1bd9a1e572906ff98aab30b52b547f48f4b1d61785ccc0ca8082ae4c6bd13fcb"
A384_QUALIFICATION_SHA256 = (
    "0e31d4d7b0e0bb0e45cd815d975e2898c60eeea16e04498d720f0a58dd41dc30"
)
A384_RUNNER_SHA256 = "60352d5f0d09fad8272e87f5a202d6f62274911d7bdd154738a47bac04b6264f"
GROUPED_EXECUTABLE_SHA256 = "d1c41a049db90997ada5eba880d1ba2d0787b1d74be499f0a254183f1b577acf"

WIDTH = 51
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
SLAB_BITS = 8
OUTER_LOW_BITS = 11
CELLS = 1 << PREFIX_BITS
WORD0_PER_GROUP = 1 << WORD0_SUFFIX_BITS
OUTER_SLICES = 1 << OUTER_LOW_BITS
SLABS = tuple(range(1 << SLAB_BITS))
SLAB_SIZE = WORD0_PER_GROUP * OUTER_SLICES
GROUP_SIZE = len(SLABS) * SLAB_SIZE
DOMAIN_SIZE = 1 << WIDTH
HOST_REFRESH_GROUPS = 2


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A390 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A384 = load_module(A384_RUNNER, "a390_a384")
W43 = A384.W43
file_sha256 = A384.file_sha256
canonical_sha256 = A384.canonical_sha256
atomic_json = A384.atomic_json
relative = A384.relative
path_from_ref = A384.path_from_ref
anchor = A384.anchor


def boundary_outer19_values() -> list[int]:
    values = {0, 1}
    for slab in SLABS:
        values.add(slab << OUTER_LOW_BITS)
        values.add((slab << OUTER_LOW_BITS) | (OUTER_SLICES - 1))
    result = sorted(values)
    if len(result) != 513 or result[0] != 0 or result[-1] != 0x7FFFF:
        raise RuntimeError("A390 boundary construction differs")
    return result


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A390 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    engine = value.get("engine_contract", {})
    qualification = value.get("qualification_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w51-twohundredfiftysix-slab-grouped-engine-a390-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "target_free_W51_engine_adapter_frozen_after_A384_exact_qualification_before_any_W51_production_challenge_candidate_prefix_or_filter_outcome"
        or engine.get("unknown_key_bits") != WIDTH
        or engine.get("slabs") != len(SLABS)
        or engine.get("candidate_group_size") != GROUP_SIZE
        or engine.get("filter_dispatches_per_W51_prefix_group") != len(SLABS)
        or engine.get("complete_group_before_success_evaluation") is not True
        or engine.get("early_stop_inside_group") is not False
        or engine.get("full_domain_assignments") != DOMAIN_SIZE
        or engine.get("host_refresh_interval_W51_prefix_groups") != HOST_REFRESH_GROUPS
        or engine.get("full_rounds") != 20
        or engine.get("feedforward_included") is not True
        or qualification.get("scalar_boundary_count") != len(boundary_outer19_values())
        or qualification.get("complete_W51_group_gate") is not True
        or qualification.get("complete_W51_group_candidates") != GROUP_SIZE
        or boundary.get("A384_exact_qualification_complete_before_A390_design") is not True
        or boundary.get("W51_production_challenge_available_at_freeze") is not False
        or boundary.get("W51_target_assignment_available_at_freeze") is not False
        or boundary.get("W51_candidate_available_at_freeze") is not False
        or boundary.get("A390_qualification_uses_only_synthetic_targets") is not True
    ):
        raise RuntimeError("A390 frozen design semantics differ")
    sources = value["source_anchors"]
    for path_key, sha_key in (
        ("A384_design_path", "A384_design_sha256"),
        ("A384_protocol_path", "A384_protocol_sha256"),
        ("A384_qualification_path", "A384_qualification_sha256"),
        ("A384_runner_path", "A384_runner_sha256"),
        ("grouped_executable_path", "grouped_executable_sha256"),
    ):
        anchor(path_from_ref(sources[path_key]), sources[sha_key])
    return value


def load_a384_source() -> tuple[dict[str, Any], dict[str, Any]]:
    protocol = A384.load_protocol(A384_PROTOCOL_SHA256)
    if file_sha256(A384_QUALIFICATION) != A384_QUALIFICATION_SHA256:
        raise RuntimeError("A390 A384 qualification hash differs")
    qualification = json.loads(A384_QUALIFICATION.read_bytes())
    group = qualification.get("complete_group_gate", {})
    if (
        qualification.get("evidence_stage")
        != "TARGET_FREE_COMPLETE_W50_GROUP_ENGINE_EXACTLY_QUALIFIED"
        or qualification.get("protocol_sha256") != A384_PROTOCOL_SHA256
        or qualification.get("production_W50_challenge_used") is not False
        or qualification.get("production_W50_candidate_used") is not False
        or qualification.get("synthetic_filter_exact") is not True
        or qualification.get("matched_control_empty") is not True
        or group.get("logical_candidates") != 1 << 38
        or group.get("complete_W50_group_before_outcome_evaluation") is not True
        or len(group.get("factual_candidates", [])) != 1
        or group.get("control_candidates") != []
    ):
        raise RuntimeError("A390 A384 source semantics differ")
    return protocol, qualification


def source_challenge() -> dict[str, Any]:
    return A384.source_challenge()


def _base_initial(challenge: Mapping[str, Any]) -> np.ndarray:
    initial = W43._initial(  # noqa: SLF001
        challenge["known_zeroed_key_words"],
        int(challenge["counter_start"]),
        challenge["nonce_words"],
        0,
    ).copy()
    initial[5] = np.uint32(int(initial[5]) & 0xFFF80000)
    return initial


def initial_for_slab(challenge: Mapping[str, Any], slab: int) -> np.ndarray:
    if slab not in SLABS:
        raise ValueError("A390 slab must be in zero through two hundred fifty-five")
    initial = _base_initial(challenge)
    initial[5] = np.uint32(int(initial[5]) | (slab << OUTER_LOW_BITS))
    return initial


def initial_for_outer19(challenge: Mapping[str, Any], outer19: int) -> np.ndarray:
    if not 0 <= outer19 < 1 << 19:
        raise ValueError("A390 word1 low19 exceeds W51")
    initial = _base_initial(challenge)
    initial[5] = np.uint32(int(initial[5]) | outer19)
    return initial


def encode_assignment(*, word0: int, slab: int, outer_low11: int) -> int:
    if not 0 <= word0 <= 0xFFFFFFFF:
        raise ValueError("A390 word0 exceeds uint32")
    if slab not in SLABS or not 0 <= outer_low11 < OUTER_SLICES:
        raise ValueError("A390 slab/outer pair differs")
    return (((slab << OUTER_LOW_BITS) | outer_low11) << 32) | word0


def decode_assignment(assignment: int) -> dict[str, int]:
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A390 assignment exceeds W51")
    outer19 = assignment >> 32
    return {
        "word0": assignment & 0xFFFFFFFF,
        "word1_low19": outer19,
        "slab": outer19 >> OUTER_LOW_BITS,
        "outer_low11": outer19 & (OUTER_SLICES - 1),
    }


def scalar_blocks_w51(
    *, challenge: Mapping[str, Any], outer19: int, first_word0: int, count: int
) -> np.ndarray:
    if count <= 0 or first_word0 < 0 or first_word0 + count > 1 << 32:
        raise ValueError("A390 scalar word0 interval differs")
    initial = initial_for_outer19(challenge, outer19)
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
        raise ValueError("A390 prefix is outside the exact 4,096-cell cover")
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
        "complete_W51_group_before_outcome_evaluation": True,
        "early_stop_inside_group": False,
        "gpu_seconds": gpu_seconds,
        "volatile_wall_seconds": time.perf_counter() - started,
    }


def freeze() -> dict[str, Any]:
    if PROTOCOL.exists() or QUALIFICATION.exists():
        raise FileExistsError("A390 protocol or qualification already exists")
    design = load_design()
    a384_protocol, a384_qualification = load_a384_source()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A390 test and reproducer must precede protocol freeze")
    payload = {
        "schema": "chacha20-round20-w51-twohundredfiftysix-slab-grouped-engine-a390-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "target_free_adapter_frozen_before_any_W51_production_challenge",
        "design_sha256": DESIGN_SHA256,
        "engine_contract": design["engine_contract"],
        "qualification_contract": design["qualification_contract"],
        "information_boundary": design["information_boundary"],
        "source_engine": {
            "attempt_id": "A384",
            "protocol_sha256": A384_PROTOCOL_SHA256,
            "qualification_artifact_sha256": A384_QUALIFICATION_SHA256,
            "qualification_sha256": a384_qualification["qualification_sha256"],
            "executable_sha256": a384_protocol["source_engine"]["executable_sha256"],
        },
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "A384_design": {"path": relative(A384_DESIGN), "sha256": A384_DESIGN_SHA256},
            "A384_protocol": {
                "path": relative(A384_PROTOCOL),
                "sha256": A384_PROTOCOL_SHA256,
            },
            "A384_qualification": {
                "path": relative(A384_QUALIFICATION),
                "sha256": A384_QUALIFICATION_SHA256,
            },
            "A384_runner": {"path": relative(A384_RUNNER), "sha256": A384_RUNNER_SHA256},
            "grouped_executable": {
                "path": a384_protocol["anchors"]["grouped_executable"]["path"],
                "sha256": GROUPED_EXECUTABLE_SHA256,
            },
            "A390_runner": {"path": relative(Path(__file__)), "sha256": file_sha256(Path(__file__))},
            "A390_test": {"path": relative(TEST), "sha256": file_sha256(TEST)},
            "A390_reproducer": {"path": relative(REPRO), "sha256": file_sha256(REPRO)},
        },
        "production_W51_challenge_available": False,
        "production_W51_candidate_available": False,
        "production_W51_execution_started": False,
    }
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_protocol_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_protocol_sha256:
        raise RuntimeError("A390 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w51-twohundredfiftysix-slab-grouped-engine-a390-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_state")
        != "target_free_adapter_frozen_before_any_W51_production_challenge"
        or value.get("production_W51_challenge_available") is not False
        or value.get("production_W51_candidate_available") is not False
        or value.get("production_W51_execution_started") is not False
        or value.get("engine_contract", {}).get("candidate_group_size") != GROUP_SIZE
        or value.get("source_engine", {}).get("executable_sha256")
        != GROUPED_EXECUTABLE_SHA256
    ):
        raise RuntimeError("A390 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    return value


def qualify(*, expected_protocol_sha256: str) -> dict[str, Any]:
    if QUALIFICATION.exists():
        raise FileExistsError("A390 qualification already exists")
    protocol = load_protocol(expected_protocol_sha256)
    _a384_protocol, a384_qualification = load_a384_source()
    challenge = source_challenge()
    executable = path_from_ref(protocol["anchors"]["grouped_executable"]["path"])
    anchor(executable, GROUPED_EXECUTABLE_SHA256)
    placeholder = np.asarray([0, 0], dtype=np.uint32)
    host = A384.A378.A371.A346.A324.A311.A307.A304.GroupedMetalHost(
        executable,
        initial_for_slab(challenge, 0),
        placeholder,
        placeholder,
    )
    boundary_rows: list[dict[str, Any]] = []
    first_word0 = 0x56789000
    count = 17
    try:
        for outer19 in boundary_outer19_values():
            slab = outer19 >> OUTER_LOW_BITS
            outer_low11 = outer19 & (OUTER_SLICES - 1)
            host.configure(initial_for_slab(challenge, slab), placeholder, placeholder)
            observed = host.blocks_group(
                first_word0=first_word0,
                word0_count=count,
                outer_first=outer_low11,
                outer_count=1,
            )[0]
            expected = scalar_blocks_w51(
                challenge=challenge,
                outer19=outer19,
                first_word0=first_word0,
                count=count,
            )
            if not np.array_equal(observed, expected):
                raise RuntimeError("A390 W51 boundary scalar identity gate failed")
            boundary_rows.append(
                {
                    "outer19": outer19,
                    "slab": slab,
                    "outer_low11": outer_low11,
                    "word0_count": count,
                    "complete_output_bits_checked": count * 512,
                    "output_sha256": hashlib.sha256(expected.astype("<u4").tobytes()).hexdigest(),
                    "grouped_equals_scalar": True,
                }
            )

        target_prefix = 0xA38
        target_word0 = (target_prefix << WORD0_SUFFIX_BITS) | 0x2468A
        target_outer19 = 0x6E437
        target_block = scalar_blocks_w51(
            challenge=challenge,
            outer19=target_outer19,
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
        expected_assignment = (target_outer19 << 32) | target_word0
        if complete["factual_candidates"] != [expected_assignment]:
            raise RuntimeError("A390 complete W51 group factual gate failed")
        if complete["control_candidates"] != []:
            raise RuntimeError("A390 complete W51 group control gate failed")
        identity = host.identity
    finally:
        host.close()

    payload = {
        "schema": "chacha20-round20-w51-twohundredfiftysix-slab-grouped-engine-a390-qualification-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "TARGET_FREE_COMPLETE_W51_GROUP_ENGINE_EXACTLY_QUALIFIED",
        "protocol_sha256": expected_protocol_sha256,
        "production_W51_challenge_used": False,
        "production_W51_candidate_used": False,
        "source_engine_qualification_sha256": a384_qualification["qualification_sha256"],
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
        "expected_synthetic_assignment_hex": f"{expected_assignment:013x}",
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
            "production_W51_challenge_used": False,
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
