#!/usr/bin/env python3
"""A346: target-free W47 sixteen-slab adapter over the qualified Metal grid."""

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

DESIGN = CONFIGS / "chacha20_round20_w47_sixteen_slab_grouped_engine_a346_design_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_w47_sixteen_slab_grouped_engine_a346_v1.json"
QUALIFICATION = RESULTS / "chacha20_round20_w47_sixteen_slab_grouped_engine_a346_qualification_v1.json"
A324_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_eight_slab_grouped_engine_a324.py"
TEST = ROOT / "tests/test_chacha20_round20_w47_sixteen_slab_grouped_engine_a346.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w47_sixteen_slab_grouped_engine_a346.sh"

ATTEMPT_ID = "A346"
DESIGN_SHA256 = "d9da59b50820a033973b54c845d10e568aeeb65e2f3d0c1254e5306371fea0ba"
A324_PROTOCOL_SHA256 = "a787285d547e4eaaeffd808c35fcaa3f44df2ce2bd01dece67cd6f4ceb550694"
A324_QUALIFICATION_SHA256 = "996dcddfc5f9b9e91f7c77c01aa10747af8f291795dfa04d3e7eaf890047296a"
A324_RUNNER_SHA256 = "d286102bfcdf5ec4902c7e7240aa6b4ba6c9edd486933b58cbc895355b0c0f4b"
GROUPED_EXECUTABLE_SHA256 = "d1c41a049db90997ada5eba880d1ba2d0787b1d74be499f0a254183f1b577acf"

WIDTH = 47
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
SLAB_BITS = 4
OUTER_LOW_BITS = 11
CELLS = 1 << PREFIX_BITS
WORD0_PER_GROUP = 1 << WORD0_SUFFIX_BITS
OUTER_SLICES = 1 << OUTER_LOW_BITS
SLABS = tuple(range(1 << SLAB_BITS))
SLAB_SIZE = WORD0_PER_GROUP * OUTER_SLICES
GROUP_SIZE = len(SLABS) * SLAB_SIZE
DOMAIN_SIZE = 1 << WIDTH
HOST_REFRESH_GROUPS = 32


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A346 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A324 = load_module(A324_RUNNER, "a346_a324_common")
W43 = A324.W43
file_sha256 = A324.file_sha256
canonical_sha256 = A324.canonical_sha256
atomic_json = A324.atomic_json
relative = A324.relative
path_from_ref = A324.path_from_ref
anchor = A324.anchor


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A346 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    engine = value.get("engine_contract", {})
    boundary = value.get("information_boundary", {})
    qualification = value.get("qualification_contract", {})
    if (
        value.get("schema")
        != "chacha20-round20-w47-sixteen-slab-grouped-engine-a346-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "target_free_W47_engine_adapter_frozen_before_any_W47_production_challenge_candidate_prefix_or_filter_outcome"
        or engine.get("unknown_key_bits") != WIDTH
        or engine.get("candidate_group_size") != GROUP_SIZE
        or engine.get("slabs") != list(SLABS)
        or engine.get("filter_dispatches_per_W47_prefix_group") != len(SLABS)
        or engine.get("complete_group_before_success_evaluation") is not True
        or engine.get("early_stop_inside_group") is not False
        or engine.get("host_refresh_interval_W47_prefix_groups")
        != HOST_REFRESH_GROUPS
        or engine.get("full_rounds") != 20
        or engine.get("feedforward_included") is not True
        or qualification.get("complete_W47_group_gate") is not True
        or qualification.get("complete_W47_group_candidates") != GROUP_SIZE
        or boundary.get("W47_production_challenge_available_at_freeze") is not False
        or boundary.get("W47_target_assignment_available_at_freeze") is not False
        or boundary.get("W47_filter_outcome_available_at_freeze") is not False
        or boundary.get("A346_qualification_uses_only_synthetic_targets") is not True
    ):
        raise RuntimeError("A346 frozen design semantics differ")
    sources = value["source_anchors"]
    for path_key, sha_key in (
        ("A324_protocol_path", "A324_protocol_sha256"),
        ("A324_qualification_path", "A324_qualification_sha256"),
        ("A324_runner_path", "A324_runner_sha256"),
        ("grouped_executable_path", "grouped_executable_sha256"),
    ):
        anchor(path_from_ref(sources[path_key]), sources[sha_key])
    return value


def load_a324_source() -> tuple[dict[str, Any], dict[str, Any]]:
    protocol = A324.load_protocol(A324_PROTOCOL_SHA256)
    if file_sha256(A324.QUALIFICATION) != A324_QUALIFICATION_SHA256:
        raise RuntimeError("A346 A324 qualification hash differs")
    qualification = json.loads(A324.QUALIFICATION.read_bytes())
    group = qualification.get("complete_group_gate", {})
    if (
        qualification.get("schema")
        != "chacha20-round20-w46-eight-slab-grouped-engine-a324-qualification-v1"
        or qualification.get("protocol_sha256") != A324_PROTOCOL_SHA256
        or qualification.get("production_W46_challenge_used") is not False
        or qualification.get("production_W46_candidate_used") is not False
        or qualification.get("synthetic_filter_exact") is not True
        or qualification.get("matched_control_empty") is not True
        or group.get("logical_candidates") != 1 << 34
        or group.get("complete_W46_group_before_outcome_evaluation") is not True
        or len(group.get("factual_candidates", [])) != 1
        or group.get("control_candidates") != []
    ):
        raise RuntimeError("A346 A324 source qualification semantics differ")
    return protocol, qualification


def _base_initial(challenge: Mapping[str, Any]) -> np.ndarray:
    initial = W43._initial(  # noqa: SLF001
        challenge["known_zeroed_key_words"],
        int(challenge["counter_start"]),
        challenge["nonce_words"],
        0,
    ).copy()
    initial[5] = np.uint32(int(initial[5]) & 0xFFFF8000)
    return initial


def initial_for_slab(challenge: Mapping[str, Any], slab: int) -> np.ndarray:
    if slab not in SLABS:
        raise ValueError("A346 slab must be in zero through fifteen")
    initial = _base_initial(challenge)
    initial[5] = np.uint32(int(initial[5]) | (slab << OUTER_LOW_BITS))
    return initial


def initial_for_outer15(challenge: Mapping[str, Any], outer15: int) -> np.ndarray:
    if not 0 <= outer15 < (1 << (SLAB_BITS + OUTER_LOW_BITS)):
        raise ValueError("A346 word1 low15 value is outside the W47 domain")
    initial = _base_initial(challenge)
    initial[5] = np.uint32(int(initial[5]) | outer15)
    return initial


def encode_assignment(*, word0: int, slab: int, outer_low11: int) -> int:
    if not 0 <= word0 <= 0xFFFFFFFF:
        raise ValueError("A346 word0 exceeds uint32")
    if slab not in SLABS or not 0 <= outer_low11 < OUTER_SLICES:
        raise ValueError("A346 slab/outer pair differs")
    return (((slab << OUTER_LOW_BITS) | outer_low11) << 32) | word0


def decode_assignment(assignment: int) -> dict[str, int]:
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A346 assignment exceeds W47")
    outer15 = assignment >> 32
    return {
        "word0": assignment & 0xFFFFFFFF,
        "word1_low15": outer15,
        "slab": outer15 >> OUTER_LOW_BITS,
        "outer_low11": outer15 & (OUTER_SLICES - 1),
    }


def scalar_blocks_w47(
    *, challenge: Mapping[str, Any], outer15: int, first_word0: int, count: int
) -> np.ndarray:
    if count <= 0 or first_word0 < 0 or first_word0 + count > 1 << 32:
        raise ValueError("A346 scalar word0 interval differs")
    initial = initial_for_outer15(challenge, outer15)
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
    """Execute all sixteen complete 2^31 slabs before inspecting any outcome."""
    if not 0 <= prefix < CELLS:
        raise ValueError("A346 prefix is outside the exact 4096-cell cover")
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
        "complete_W47_group_before_outcome_evaluation": True,
        "early_stop_inside_group": False,
        "gpu_seconds": gpu_seconds,
        "volatile_wall_seconds": time.perf_counter() - started,
    }


def freeze() -> dict[str, Any]:
    if PROTOCOL.exists() or QUALIFICATION.exists():
        raise FileExistsError("A346 protocol or qualification already exists")
    design = load_design()
    a324_protocol, a324_qualification = load_a324_source()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A346 test and reproducer must precede protocol freeze")
    payload = {
        "schema": "chacha20-round20-w47-sixteen-slab-grouped-engine-a346-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "target_free_adapter_frozen_before_any_W47_production_challenge",
        "design_sha256": DESIGN_SHA256,
        "engine_contract": design["engine_contract"],
        "qualification_contract": design["qualification_contract"],
        "information_boundary": design["information_boundary"],
        "source_engine": {
            "attempt_id": "A324",
            "protocol_sha256": A324_PROTOCOL_SHA256,
            "qualification_artifact_sha256": A324_QUALIFICATION_SHA256,
            "qualification_sha256": a324_qualification["qualification_sha256"],
            "executable_sha256": a324_protocol["source_engine"]["executable_sha256"],
        },
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "A324_protocol": {
                "path": relative(A324.PROTOCOL),
                "sha256": A324_PROTOCOL_SHA256,
            },
            "A324_qualification": {
                "path": relative(A324.QUALIFICATION),
                "sha256": A324_QUALIFICATION_SHA256,
            },
            "A324_runner": {
                "path": relative(A324_RUNNER),
                "sha256": A324_RUNNER_SHA256,
            },
            "grouped_executable": {
                "path": a324_protocol["anchors"]["grouped_executable"]["path"],
                "sha256": GROUPED_EXECUTABLE_SHA256,
            },
            "A346_runner": {
                "path": relative(Path(__file__)),
                "sha256": file_sha256(Path(__file__)),
            },
            "A346_test": {"path": relative(TEST), "sha256": file_sha256(TEST)},
            "A346_reproducer": {
                "path": relative(REPRO),
                "sha256": file_sha256(REPRO),
            },
        },
        "production_W47_challenge_available": False,
        "production_W47_candidate_available": False,
        "production_W47_execution_started": False,
    }
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_protocol_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_protocol_sha256:
        raise RuntimeError("A346 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w47-sixteen-slab-grouped-engine-a346-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_state")
        != "target_free_adapter_frozen_before_any_W47_production_challenge"
        or value.get("production_W47_challenge_available") is not False
        or value.get("production_W47_candidate_available") is not False
        or value.get("production_W47_execution_started") is not False
        or value.get("engine_contract", {}).get("candidate_group_size") != GROUP_SIZE
        or value.get("source_engine", {}).get("executable_sha256")
        != GROUPED_EXECUTABLE_SHA256
    ):
        raise RuntimeError("A346 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    return value


def qualify(*, expected_protocol_sha256: str) -> dict[str, Any]:
    if QUALIFICATION.exists():
        raise FileExistsError("A346 qualification already exists")
    protocol = load_protocol(expected_protocol_sha256)
    _a324_protocol, a324_qualification = load_a324_source()
    challenge = json.loads(A324.A311.A307.A304.A302.PROTOCOL.read_bytes())[
        "public_challenge"
    ]
    executable = path_from_ref(protocol["anchors"]["grouped_executable"]["path"])
    anchor(executable, GROUPED_EXECUTABLE_SHA256)
    placeholder = np.asarray([0, 0], dtype=np.uint32)
    host = A324.A311.A307.A304.GroupedMetalHost(
        executable,
        initial_for_slab(challenge, 0),
        placeholder,
        placeholder,
    )
    boundary_rows: list[dict[str, Any]] = []
    first_word0 = 0x34567000
    count = 17
    boundaries = protocol["qualification_contract"]["full_block_outer15_boundaries"]
    try:
        for outer15 in boundaries:
            slab = int(outer15) >> OUTER_LOW_BITS
            outer_low11 = int(outer15) & (OUTER_SLICES - 1)
            host.configure(initial_for_slab(challenge, slab), placeholder, placeholder)
            observed = host.blocks_group(
                first_word0=first_word0,
                word0_count=count,
                outer_first=outer_low11,
                outer_count=1,
            )[0]
            expected = scalar_blocks_w47(
                challenge=challenge,
                outer15=int(outer15),
                first_word0=first_word0,
                count=count,
            )
            if not np.array_equal(observed, expected):
                raise RuntimeError("A346 W47 boundary scalar identity gate failed")
            boundary_rows.append(
                {
                    "outer15": int(outer15),
                    "slab": slab,
                    "outer_low11": outer_low11,
                    "word0_count": count,
                    "complete_output_bits_checked": count * 512,
                    "output_sha256": hashlib.sha256(
                        expected.astype("<u4").tobytes()
                    ).hexdigest(),
                    "grouped_equals_scalar": True,
                }
            )

        target_prefix = 0x6B4
        target_word0 = (target_prefix << WORD0_SUFFIX_BITS) | 0x2468A
        target_outer15 = 0x7437
        target_block = scalar_blocks_w47(
            challenge=challenge,
            outer15=target_outer15,
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
        expected_assignment = (target_outer15 << 32) | target_word0
        if complete["factual_candidates"] != [expected_assignment]:
            raise RuntimeError("A346 complete W47 group factual gate failed")
        if complete["control_candidates"] != []:
            raise RuntimeError("A346 complete W47 group control gate failed")
        identity = host.identity
    finally:
        host.close()

    payload = {
        "schema": "chacha20-round20-w47-sixteen-slab-grouped-engine-a346-qualification-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "TARGET_FREE_COMPLETE_W47_GROUP_ENGINE_EXACTLY_QUALIFIED",
        "protocol_sha256": expected_protocol_sha256,
        "production_W47_challenge_used": False,
        "production_W47_candidate_used": False,
        "source_engine_qualification_sha256": a324_qualification[
            "qualification_sha256"
        ],
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
            "production_W47_challenge_used": False,
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
