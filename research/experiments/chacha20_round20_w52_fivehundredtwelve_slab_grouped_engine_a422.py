#!/usr/bin/env python3
"""A422: target-free W52 five-hundred-twelve-slab adapter over the qualified Metal grid."""

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

DESIGN = CONFIGS / "chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422_design_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422_v1.json"
QUALIFICATION = RESULTS / "chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422_qualification_v1.json"
A390_RUNNER = RESEARCH / "experiments/chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390.py"
A390_DESIGN = CONFIGS / "chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_design_v1.json"
A390_PROTOCOL = CONFIGS / "chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_v1.json"
A390_QUALIFICATION = RESULTS / "chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_qualification_v1.json"
A421_RESULT = RESULTS / "chacha20_round20_w51_external_reader_shared_stop_recovery_a421_v1.json"
TEST = ROOT / "tests/test_chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422.sh"

ATTEMPT_ID = "A422"
DESIGN_SHA256 = "eec874d7b680e65c34322e0a1b7a4cabccde3082b6c911944486ec968633cc68"
A390_DESIGN_SHA256 = "feffc7944535d9785392489de843247d15dab660f6ba2df9f9cfeec9f2595870"
A390_PROTOCOL_SHA256 = "d13d5c0b34de900bdc2d3abe26706b508091685e6a1c7a640168ab5496e479d0"
A390_RUNNER_SHA256 = "1864f7ecd5fb448219784b1a9e514cfddfb3f77f16e46f0d6104f8a778338330"
GROUPED_EXECUTABLE_SHA256 = "d1c41a049db90997ada5eba880d1ba2d0787b1d74be499f0a254183f1b577acf"

WIDTH = 52
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
SLAB_BITS = 9
OUTER_LOW_BITS = 11
CELLS = 1 << PREFIX_BITS
WORD0_PER_GROUP = 1 << WORD0_SUFFIX_BITS
OUTER_SLICES = 1 << OUTER_LOW_BITS
SLABS = tuple(range(1 << SLAB_BITS))
SLAB_SIZE = WORD0_PER_GROUP * OUTER_SLICES
GROUP_SIZE = len(SLABS) * SLAB_SIZE
DOMAIN_SIZE = 1 << WIDTH
HOST_REFRESH_GROUPS = 1


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A422 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A390 = load_module(A390_RUNNER, "a422_a390")
W43 = A390.W43
file_sha256 = A390.file_sha256
canonical_sha256 = A390.canonical_sha256
atomic_json = A390.atomic_json
relative = A390.relative
path_from_ref = A390.path_from_ref
anchor = A390.anchor


def boundary_outer20_values() -> list[int]:
    values = {0, 1}
    for slab in SLABS:
        values.add(slab << OUTER_LOW_BITS)
        values.add((slab << OUTER_LOW_BITS) | (OUTER_SLICES - 1))
    result = sorted(values)
    if len(result) != 1025 or result[0] != 0 or result[-1] != 0xFFFFF:
        raise RuntimeError("A422 boundary construction differs")
    return result


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A422 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    engine = value.get("engine_contract", {})
    qualification = value.get("qualification_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-fivehundredtwelve-slab-grouped-engine-a422-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "target_free_W52_engine_adapter_frozen_after_A390_protocol_before_A390_qualification_A421_result_or_any_W52_production_challenge_assignment_candidate_prefix_or_filter_outcome"
        or engine.get("unknown_key_bits") != WIDTH
        or engine.get("slabs") != len(SLABS)
        or engine.get("candidate_group_size") != GROUP_SIZE
        or engine.get("filter_dispatches_per_W52_prefix_group") != len(SLABS)
        or engine.get("complete_group_before_success_evaluation") is not True
        or engine.get("early_stop_inside_group") is not False
        or engine.get("full_domain_assignments") != DOMAIN_SIZE
        or engine.get("host_refresh_interval_W52_prefix_groups") != HOST_REFRESH_GROUPS
        or qualification.get("scalar_boundary_count") != len(boundary_outer20_values())
        or qualification.get("complete_W52_group_gate") is not True
        or qualification.get("complete_W52_group_candidates") != GROUP_SIZE
        or qualification.get("A390_exact_W51_qualification_required") is not True
        or boundary.get("A390_qualification_available_at_A422_design_freeze") is not False
        or boundary.get("A421_result_available_at_A422_design_freeze") is not False
        or boundary.get("W52_production_challenge_available_at_freeze") is not False
        or boundary.get("W52_target_assignment_available_at_freeze") is not False
        or boundary.get("A422_qualification_uses_only_synthetic_targets") is not True
    ):
        raise RuntimeError("A422 frozen design semantics differ")
    sources = value["source_anchors"]
    for path_key, sha_key in (
        ("A390_design_path", "A390_design_sha256"),
        ("A390_protocol_path", "A390_protocol_sha256"),
        ("A390_runner_path", "A390_runner_sha256"),
        ("grouped_executable_path", "grouped_executable_sha256"),
    ):
        anchor(ROOT / sources[path_key], sources[sha_key])
    return value


def load_a390_source_qualification(expected_sha256: str) -> dict[str, Any]:
    A390.load_protocol(A390_PROTOCOL_SHA256)
    if file_sha256(A390_QUALIFICATION) != expected_sha256:
        raise RuntimeError("A422 A390 qualification file hash differs")
    value = json.loads(A390_QUALIFICATION.read_bytes())
    group = value.get("complete_group_gate", {})
    unsigned = {
        "boundary_full_block_rows": value.get("boundary_full_block_rows"),
        "complete_group_gate": group,
        "expected_synthetic_assignment": value.get("expected_synthetic_assignment"),
        "source_executable_sha256": value.get("source_executable_sha256"),
        "production_W51_challenge_used": False,
    }
    if (
        value.get("schema")
        != "chacha20-round20-w51-twohundredfiftysix-slab-grouped-engine-a390-qualification-v1"
        or value.get("evidence_stage") != "TARGET_FREE_COMPLETE_W51_GROUP_ENGINE_EXACTLY_QUALIFIED"
        or value.get("protocol_sha256") != A390_PROTOCOL_SHA256
        or value.get("production_W51_challenge_used") is not False
        or value.get("production_W51_candidate_used") is not False
        or value.get("synthetic_filter_exact") is not True
        or value.get("matched_control_empty") is not True
        or group.get("logical_candidates") != 1 << 39
        or group.get("complete_W51_group_before_outcome_evaluation") is not True
        or group.get("slabs_executed") != list(range(256))
        or len(group.get("factual_candidates", [])) != 1
        or group.get("control_candidates") != []
        or value.get("qualification_sha256") != canonical_sha256(unsigned)
    ):
        raise RuntimeError("A422 A390 source qualification semantics differ")
    return value


def source_challenge() -> dict[str, Any]:
    return A390.source_challenge()


def _base_initial(challenge: Mapping[str, Any]) -> np.ndarray:
    initial = W43._initial(  # noqa: SLF001
        challenge["known_zeroed_key_words"],
        int(challenge["counter_start"]),
        challenge["nonce_words"],
        0,
    ).copy()
    initial[5] = np.uint32(int(initial[5]) & 0xFFF00000)
    return initial


def initial_for_slab(challenge: Mapping[str, Any], slab: int) -> np.ndarray:
    if slab not in SLABS:
        raise ValueError("A422 slab must be in zero through five hundred eleven")
    initial = _base_initial(challenge)
    initial[5] = np.uint32(int(initial[5]) | (slab << OUTER_LOW_BITS))
    return initial


def initial_for_outer20(challenge: Mapping[str, Any], outer20: int) -> np.ndarray:
    if not 0 <= outer20 < 1 << 20:
        raise ValueError("A422 word1 low20 exceeds W52")
    initial = _base_initial(challenge)
    initial[5] = np.uint32(int(initial[5]) | outer20)
    return initial


def encode_assignment(*, word0: int, slab: int, outer_low11: int) -> int:
    if not 0 <= word0 <= 0xFFFFFFFF:
        raise ValueError("A422 word0 exceeds uint32")
    if slab not in SLABS or not 0 <= outer_low11 < OUTER_SLICES:
        raise ValueError("A422 slab/outer pair differs")
    return (((slab << OUTER_LOW_BITS) | outer_low11) << 32) | word0


def decode_assignment(assignment: int) -> dict[str, int]:
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A422 assignment exceeds W52")
    outer20 = assignment >> 32
    return {
        "word0": assignment & 0xFFFFFFFF,
        "word1_low20": outer20,
        "slab": outer20 >> OUTER_LOW_BITS,
        "outer_low11": outer20 & (OUTER_SLICES - 1),
    }


def scalar_blocks_w52(
    *, challenge: Mapping[str, Any], outer20: int, first_word0: int, count: int
) -> np.ndarray:
    if count <= 0 or first_word0 < 0 or first_word0 + count > 1 << 32:
        raise ValueError("A422 scalar word0 interval differs")
    initial = initial_for_outer20(challenge, outer20)
    scalar = np.repeat(initial.reshape(1, 16), count, axis=0)
    scalar[:, 4] = np.arange(first_word0, first_word0 + count, dtype=np.uint32)
    return (W43.ANCHOR.A119._core(scalar.copy(), 20) + scalar).astype(np.uint32)  # noqa: SLF001


def filter_complete_prefix(
    *, host: Any, challenge: Mapping[str, Any], prefix: int, target: np.ndarray, control: np.ndarray
) -> dict[str, Any]:
    if not 0 <= prefix < CELLS:
        raise ValueError("A422 prefix is outside the exact 4,096-cell cover")
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
        "complete_W52_group_before_outcome_evaluation": True,
        "early_stop_inside_group": False,
        "gpu_seconds": gpu_seconds,
        "volatile_wall_seconds": time.perf_counter() - started,
    }


def freeze() -> dict[str, Any]:
    if PROTOCOL.exists() or QUALIFICATION.exists():
        raise FileExistsError("A422 protocol or qualification already exists")
    if A390_QUALIFICATION.exists() or A421_RESULT.exists():
        raise RuntimeError("A422 target-free protocol freeze must precede A390 qualification and A421 result")
    design = load_design()
    source_protocol = A390.load_protocol(A390_PROTOCOL_SHA256)
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A422 test and reproducer must precede protocol freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-fivehundredtwelve-slab-grouped-engine-a422-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "target_free_W52_adapter_frozen_before_A390_qualification_A421_result_or_any_W52_production_challenge",
        "design_sha256": DESIGN_SHA256,
        "engine_contract": design["engine_contract"],
        "qualification_contract": design["qualification_contract"],
        "information_boundary": design["information_boundary"],
        "source_engine": {
            "attempt_id": "A390",
            "protocol_sha256": A390_PROTOCOL_SHA256,
            "executable_sha256": source_protocol["source_engine"]["executable_sha256"],
            "A390_qualification_available_at_protocol_freeze": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A390_design": anchor(A390_DESIGN, A390_DESIGN_SHA256),
            "A390_protocol": anchor(A390_PROTOCOL, A390_PROTOCOL_SHA256),
            "A390_runner": anchor(A390_RUNNER, A390_RUNNER_SHA256),
            "grouped_executable": {
                "path": source_protocol["anchors"]["grouped_executable"]["path"],
                "sha256": GROUPED_EXECUTABLE_SHA256,
            },
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
        "production_W52_challenge_available": False,
        "production_W52_candidate_available": False,
        "production_W52_execution_started": False,
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A422 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-fivehundredtwelve-slab-grouped-engine-a422-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_state")
        != "target_free_W52_adapter_frozen_before_A390_qualification_A421_result_or_any_W52_production_challenge"
        or value.get("production_W52_challenge_available") is not False
        or value.get("production_W52_candidate_available") is not False
        or value.get("production_W52_execution_started") is not False
        or value.get("engine_contract", {}).get("candidate_group_size") != GROUP_SIZE
        or value.get("source_engine", {}).get("executable_sha256") != GROUPED_EXECUTABLE_SHA256
        or value.get("source_engine", {}).get("A390_qualification_available_at_protocol_freeze") is not False
    ):
        raise RuntimeError("A422 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {key: item for key, item in value.items() if key != "protocol_commitment_sha256"}
    if value.get("protocol_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A422 protocol commitment differs")
    return value


def qualify(*, expected_protocol_sha256: str, expected_a390_qualification_sha256: str) -> dict[str, Any]:
    if QUALIFICATION.exists():
        raise FileExistsError("A422 qualification already exists")
    protocol = load_protocol(expected_protocol_sha256)
    source_qualification = load_a390_source_qualification(expected_a390_qualification_sha256)
    challenge = source_challenge()
    executable = path_from_ref(protocol["anchors"]["grouped_executable"]["path"])
    anchor(executable, GROUPED_EXECUTABLE_SHA256)
    placeholder = np.asarray([0, 0], dtype=np.uint32)
    host = A390.A384.A378.A371.A346.A324.A311.A307.A304.GroupedMetalHost(
        executable, initial_for_slab(challenge, 0), placeholder, placeholder
    )
    boundary_rows: list[dict[str, Any]] = []
    first_word0 = 0x34567000
    count = 17
    try:
        for outer20 in boundary_outer20_values():
            slab = outer20 >> OUTER_LOW_BITS
            outer_low11 = outer20 & (OUTER_SLICES - 1)
            host.configure(initial_for_slab(challenge, slab), placeholder, placeholder)
            observed = host.blocks_group(
                first_word0=first_word0,
                word0_count=count,
                outer_first=outer_low11,
                outer_count=1,
            )[0]
            expected = scalar_blocks_w52(
                challenge=challenge, outer20=outer20, first_word0=first_word0, count=count
            )
            if not np.array_equal(observed, expected):
                raise RuntimeError("A422 W52 boundary scalar identity gate failed")
            boundary_rows.append(
                {
                    "outer20": outer20,
                    "slab": slab,
                    "outer_low11": outer_low11,
                    "word0_count": count,
                    "complete_output_bits_checked": count * 512,
                    "output_sha256": hashlib.sha256(expected.astype("<u4").tobytes()).hexdigest(),
                    "grouped_equals_scalar": True,
                }
            )

        target_prefix = 0xB29
        target_word0 = (target_prefix << WORD0_SUFFIX_BITS) | 0x13579
        target_outer20 = 0xD6437
        target_block = scalar_blocks_w52(
            challenge=challenge, outer20=target_outer20, first_word0=target_word0, count=1
        )[0]
        control = target_block.copy()
        control[0] ^= np.uint32(1)
        complete = filter_complete_prefix(
            host=host, challenge=challenge, prefix=target_prefix, target=target_block, control=control
        )
        expected_assignment = (target_outer20 << 32) | target_word0
        if complete["factual_candidates"] != [expected_assignment]:
            raise RuntimeError("A422 complete W52 group factual gate failed")
        if complete["control_candidates"] != []:
            raise RuntimeError("A422 complete W52 group control gate failed")
        identity = host.identity
    finally:
        host.close()

    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-fivehundredtwelve-slab-grouped-engine-a422-qualification-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "TARGET_FREE_COMPLETE_W52_GROUP_ENGINE_EXACTLY_QUALIFIED",
        "protocol_sha256": expected_protocol_sha256,
        "A390_qualification_file_sha256": expected_a390_qualification_sha256,
        "A390_semantic_qualification_sha256": source_qualification["qualification_sha256"],
        "production_W52_challenge_used": False,
        "production_W52_candidate_used": False,
        "source_executable_sha256": GROUPED_EXECUTABLE_SHA256,
        "metal_identity": identity,
        "boundary_full_block_rows": boundary_rows,
        "total_boundary_output_bits_checked": sum(row["complete_output_bits_checked"] for row in boundary_rows),
        "complete_group_gate": {key: item for key, item in complete.items() if not key.startswith("volatile_")},
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
            "A390_qualification_file_sha256": expected_a390_qualification_sha256,
            "production_W52_challenge_used": False,
        }
    )
    atomic_json(QUALIFICATION, payload)
    return payload


def analyze() -> dict[str, Any]:
    payload = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "protocol_frozen": PROTOCOL.exists(),
        "A390_qualification_complete": A390_QUALIFICATION.exists(),
        "qualification_complete": QUALIFICATION.exists(),
        "candidate_group_size": GROUP_SIZE,
        "full_domain_size": DOMAIN_SIZE,
        "slabs_per_prefix_group": len(SLABS),
        "production_target_used": False,
    }
    if PROTOCOL.exists():
        payload["protocol_sha256"] = file_sha256(PROTOCOL)
        load_protocol(payload["protocol_sha256"])
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze", action="store_true")
    action.add_argument("--qualify", action="store_true")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-a390-qualification-sha256")
    args = parser.parse_args()
    if args.analyze:
        payload = analyze()
    elif args.freeze:
        payload = freeze()
    else:
        if not args.expected_protocol_sha256 or not args.expected_a390_qualification_sha256:
            parser.error("--qualify requires protocol and A390 qualification hashes")
        payload = qualify(
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_a390_qualification_sha256=args.expected_a390_qualification_sha256,
        )
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
