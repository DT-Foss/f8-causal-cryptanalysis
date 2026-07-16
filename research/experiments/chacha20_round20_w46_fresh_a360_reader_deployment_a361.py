#!/usr/bin/env python3
"""A361: deploy A360's holdout-gated Reader on a fresh full-round W46 target."""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import inspect
import json
import math
import os
import secrets
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np
import zstandard

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
ARTIFACTS = RESEARCH / "artifacts/a361_chacha20_r20_w46_fresh_a360_reader"
MEASUREMENTS = RESULTS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_v1"

DESIGN = CONFIGS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_implementation_v1.json"
)
PROTOCOL = CONFIGS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_protocol_v1.json"
PREFLIGHT = RESULTS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_preflight_v1.json"
MEASUREMENT = RESULTS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_measurement_v1.json"
ORDER = RESULTS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_order_v1.json"
PROGRESS = RESULTS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_progress_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
BASE_CNF = ARTIFACTS / "base.cnf"
TEST = ROOT / "tests/test_chacha20_round20_w46_fresh_a360_reader_deployment_a361.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_fresh_a360_reader_deployment_a361.sh"

A360_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_within_slice_reader_selection_a360.py"
A349_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w46_direct12_prospective_a345_validation_a349.py"
)
A345_RUNNER = RESEARCH / "experiments/chacha20_round20_fresh_w46_factor2_replication_a345.py"

ATTEMPT_ID = "A361"
DESIGN_SHA256 = "2397beb94273e3a4f25a6c1257662ae273beff7f4c1213259969bbde0c8a99f0"
A360_SELECTION_SHA256 = "e6425afbf257cfdcbe3099ee16e77a90cc3cd1d48db3649ac7af7cdb975c849b"
A360_PRIMARY_NAME = "single_signed::212::redundant_clauses_delta__second_difference_2_4_8__raw_z"
A360_PRIMARY_WEIGHTS_SHA256 = "1e26d6b62694cfefad50bed902eaf4c71e762583230125497267f0de9e7031fa"
A324_QUALIFICATION_SHA256 = "996dcddfc5f9b9e91f7c77c01aa10747af8f291795dfa04d3e7eaf890047296a"
WIDTH = 46
DOMAIN_SIZE = 1 << WIDTH
SLICES = tuple(range(16))
COARSE_CELLS = 256
CELLS = 4096
HORIZONS = [1, 2, 4, 8]
WATCHDOG_SECONDS = 2
WORKERS = 4
ZSTD_LEVEL = 9
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A361 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A360 = load_module(A360_RUNNER, "a361_a360")
A349 = load_module(A349_RUNNER, "a361_a349")
A345 = load_module(A345_RUNNER, "a361_a345")
A355 = A360.A359.A355
A275 = A360.A275
A340 = A349.A340
A325 = A345.A325
A324 = A345.A324
WRAPPER = A349.WRAPPER

file_sha256 = A360.file_sha256
canonical_sha256 = A360.canonical_sha256
canonical_bytes = A360.canonical_bytes
atomic_json = A360.atomic_json
atomic_bytes = A360.atomic_bytes
relative = A360.relative
path_from_ref = A360.path_from_ref
anchor = A360.anchor
sha256 = A360.sha256


def order_sha256(values: Sequence[int]) -> str:
    order = exact_group_order(values)
    return sha256(b"".join(value.to_bytes(2, "big") for value in order))


def exact_group_order(values: Sequence[int]) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError("A361 group order is not an exact 4,096-cell permutation")
    return order


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A361 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    reader = value.get("reader_contract", {})
    measurement = value.get("measurement_contract", {})
    order = value.get("order_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w46-fresh-a360-reader-deployment-a361-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A360_selection_before_A360_holdout_result_or_A361_fresh_challenge"
        or reader.get("A360_selection_sha256") != A360_SELECTION_SHA256
        or reader.get("A360_primary_definition") != A360_PRIMARY_NAME
        or reader.get("A360_primary_weights_sha256") != A360_PRIMARY_WEIGHTS_SHA256
        or reader.get("reader_refits") != 0
        or measurement.get("complete_direct12_cells") != CELLS
        or measurement.get("conflict_horizons") != HORIZONS
        or measurement.get("reader_unavailable_during_measurement") is not True
        or order.get("holdout_gate_required_before_scoring") is not True
        or boundary.get("A360_holdout_result_available_at_design_freeze") is not False
        or boundary.get("A361_fresh_challenge_available_at_design_freeze") is not False
        or boundary.get("A361_reader_scores_or_order_available_at_design_freeze") is not False
    ):
        raise RuntimeError("A361 frozen design semantics differ")
    sources = value["source_anchors"]
    for name, path_value in sources.items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, sources[f"{stem}_sha256"])
    return value


def load_reader_selection() -> dict[str, Any]:
    value = A360.load_selection(A360_SELECTION_SHA256)
    primary = value.get("reader_selection", {}).get("primary", {})
    if (
        value.get("holdout_measurement_files_opened") != 0
        or value.get("holdout_scores_or_ranks_available") is not False
        or primary.get("definition", {}).get("name") != A360_PRIMARY_NAME
        or primary.get("weights_sha256") != A360_PRIMARY_WEIGHTS_SHA256
        or len(primary.get("weights", [])) != A360.FEATURES
    ):
        raise RuntimeError("A361 frozen A360 primary Reader differs")
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A361 implementation already exists")
    if any(
        path.exists()
        for path in (
            PROTOCOL,
            PREFLIGHT,
            MEASUREMENT,
            ORDER,
            PROGRESS,
            RESULT,
            CAUSAL,
            REPORT,
            ARTIFACTS,
            MEASUREMENTS,
        )
    ):
        raise RuntimeError("A361 implementation must precede every target artifact")
    load_design()
    selection = load_reader_selection()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A361 test and reproducer must exist before freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-fresh-a360-reader-deployment-a361-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": (
            "frozen_before_A361_fresh_challenge_preflight_measurement_order_candidate_or_prefix"
        ),
        "design_sha256": DESIGN_SHA256,
        "A360_selection_sha256": A360_SELECTION_SHA256,
        "A360_selection_commitment_sha256": selection["selection_commitment_sha256"],
        "A360_primary_definition": A360_PRIMARY_NAME,
        "A360_primary_weights_sha256": A360_PRIMARY_WEIGHTS_SHA256,
        "A360_holdout_result_available_at_implementation_freeze": A360.RESULT.exists(),
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A360_selection": anchor(A360.SELECTION, A360_SELECTION_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A361 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-fresh-a360-reader-deployment-a361-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_before_A361_fresh_challenge_preflight_measurement_order_candidate_or_prefix"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A360_selection_sha256") != A360_SELECTION_SHA256
        or value.get("A360_primary_weights_sha256") != A360_PRIMARY_WEIGHTS_SHA256
    ):
        raise RuntimeError("A361 implementation semantics differ")
    expected = {
        "design": DESIGN,
        "A360_selection": A360.SELECTION,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }
    for name, path in expected.items():
        row = value.get("anchors", {}).get(name, {})
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A361 implementation anchor differs: {name}")
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A361 implementation commitment differs")
    return value


def challenge_from_assignment(*, label: str, assignment: int) -> dict[str, Any]:
    challenge = A325.challenge_from_assignment(label=label, assignment=assignment)
    challenge["challenge_id"] = "chacha20-r20-w46-a361-fresh-reader-deployment-v1"
    return challenge


def validate_challenge(challenge: Mapping[str, Any]) -> None:
    if challenge.get("challenge_id") != "chacha20-r20-w46-a361-fresh-reader-deployment-v1":
        raise RuntimeError("A361 public challenge id differs")
    translated = dict(challenge)
    translated["challenge_id"] = "chacha20-r20-w46-a325-fresh-v1"
    A325.validate_challenge(translated)


def fresh_challenge() -> dict[str, Any]:
    label = f"A361|fresh-W46-A360-reader|{secrets.token_hex(32)}"
    assignment = secrets.randbits(WIDTH)
    challenge = challenge_from_assignment(label=label, assignment=assignment)
    del assignment
    validate_challenge(challenge)
    return challenge


def materialize_target(
    *, expected_implementation_sha256: str, expected_a324_qualification_sha256: str
) -> dict[str, Any]:
    if any(
        path.exists()
        for path in (
            PROTOCOL,
            PREFLIGHT,
            MEASUREMENT,
            ORDER,
            PROGRESS,
            RESULT,
            CAUSAL,
            REPORT,
            ARTIFACTS,
            MEASUREMENTS,
        )
    ):
        raise FileExistsError("A361 target or execution artifact already exists")
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    load_reader_selection()
    qualification = A325.load_a324_qualification(expected_a324_qualification_sha256)
    if expected_a324_qualification_sha256 != A324_QUALIFICATION_SHA256:
        raise RuntimeError("A361 A324 qualification hash differs")
    challenge = fresh_challenge()
    public_sha = canonical_sha256(challenge)
    boundary = {
        **design["information_boundary"],
        "implementation_frozen_before_A361_challenge": True,
        "A361_assignment_absent_from_protocol": True,
        "A361_candidate_or_prefix_available_at_protocol_freeze": False,
        "A361_reader_scores_or_order_available_at_protocol_freeze": False,
        "A360_holdout_result_available_at_protocol_freeze": A360.RESULT.exists(),
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-fresh-a360-reader-deployment-a361-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": (
            "fresh_W46_target_frozen_after_reader_and_implementation_before_measurement_"
            "order_candidate_or_prefix"
        ),
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A360_selection_sha256": A360_SELECTION_SHA256,
        "A360_primary_definition": A360_PRIMARY_NAME,
        "A360_primary_weights_sha256": A360_PRIMARY_WEIGHTS_SHA256,
        "A324_qualification_sha256": expected_a324_qualification_sha256,
        "A324_semantic_qualification_sha256": qualification["qualification_sha256"],
        "public_challenge": challenge,
        "public_challenge_sha256": public_sha,
        "execution_contract": design["execution_contract"],
        "information_boundary": boundary,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A360_selection": anchor(A360.SELECTION, A360_SELECTION_SHA256),
            "A324_qualification": anchor(
                A345.A324_QUALIFICATION, expected_a324_qualification_sha256
            ),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "implementation_commitment_sha256": payload["implementation_commitment_sha256"],
            "A360_selection_sha256": A360_SELECTION_SHA256,
            "A360_primary_weights_sha256": A360_PRIMARY_WEIGHTS_SHA256,
            "A324_qualification_sha256": expected_a324_qualification_sha256,
            "public_challenge_sha256": public_sha,
            "execution_contract": payload["execution_contract"],
            "information_boundary": boundary,
        }
    )
    atomic_json(PROTOCOL, payload)
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol": relative(PROTOCOL),
        "protocol_sha256": file_sha256(PROTOCOL),
        "protocol_commitment_sha256": payload["protocol_commitment_sha256"],
        "public_challenge_sha256": public_sha,
        "unknown_assignment_included": False,
    }


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A361 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    challenge = value.get("public_challenge", {})
    if (
        value.get("schema") != "chacha20-round20-w46-fresh-a360-reader-deployment-a361-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_state")
        != (
            "fresh_W46_target_frozen_after_reader_and_implementation_before_measurement_"
            "order_candidate_or_prefix"
        )
        or value.get("A360_selection_sha256") != A360_SELECTION_SHA256
        or value.get("A360_primary_weights_sha256") != A360_PRIMARY_WEIGHTS_SHA256
        or value.get("A324_qualification_sha256") != A324_QUALIFICATION_SHA256
        or canonical_sha256(challenge) != value.get("public_challenge_sha256")
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("unknown_key_bits") != WIDTH
        or {"assignment", "candidate", "prefix12", "prefix12_hex"}.intersection(challenge)
        or value.get("information_boundary", {}).get("A361_assignment_absent_from_protocol")
        is not True
    ):
        raise RuntimeError("A361 frozen protocol semantics differ")
    validate_challenge(challenge)
    for artifact in value["anchors"].values():
        anchor(path_from_ref(artifact["path"]), artifact["sha256"])
    unsigned = {key: item for key, item in value.items() if key != "protocol_commitment_sha256"}
    expected_commitment = canonical_sha256(
        {
            "design_sha256": value["design_sha256"],
            "implementation_commitment_sha256": value["implementation_commitment_sha256"],
            "A360_selection_sha256": value["A360_selection_sha256"],
            "A360_primary_weights_sha256": value["A360_primary_weights_sha256"],
            "A324_qualification_sha256": value["A324_qualification_sha256"],
            "public_challenge_sha256": value["public_challenge_sha256"],
            "execution_contract": value["execution_contract"],
            "information_boundary": value["information_boundary"],
        }
    )
    if value.get("protocol_commitment_sha256") != expected_commitment or not unsigned:
        raise RuntimeError("A361 protocol commitment differs")
    return value


def preflight(
    *, expected_implementation_sha256: str, expected_protocol_sha256: str
) -> dict[str, Any]:
    if PREFLIGHT.exists() or ARTIFACTS.exists() or MEASUREMENTS.exists():
        raise FileExistsError("A361 preflight or measurement artifact already exists")
    load_design()
    load_implementation(expected_implementation_sha256)
    protocol = load_protocol(expected_protocol_sha256)
    bridge = A340.bridge_challenge({"public_challenge": protocol["public_challenge"]})
    bridge["challenge_id"] = "A361-bridge-" + str(protocol["public_challenge"]["challenge_id"])
    a223 = A340.load_module(A340.A223_SOURCE, "a361_a223_preflight")
    config = json.loads(A340.A223_CONFIG.read_bytes())
    a223._toolchain_gates(config)  # noqa: SLF001
    a223._validate_challenge(bridge, width=WIDTH)  # noqa: SLF001
    original_block_count = int(a223.BLOCK_COUNT)
    formula = A340.w46_source_formula(a223, bridge)
    if a223.BLOCK_COUNT != original_block_count:
        raise RuntimeError("A361 A223 block-count restoration gate failed")
    ARTIFACTS.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="a361_preflight_", dir=ARTIFACTS.parent) as temporary:
        stage = Path(temporary) / ARTIFACTS.name
        stage.mkdir(parents=False, exist_ok=False)
        base = stage / "base.cnf"
        export = a223._export_cnf(  # noqa: SLF001
            formula=formula,
            output=base,
            config=config,
            label="A361_FRESH_W46_B1_CORRECTED_DIRECT12",
        )
        raw = base.read_bytes()
        lines = raw.splitlines(keepends=True)
        header = lines[0].split() if lines else []
        if len(header) != 4 or header[:2] != [b"p", b"cnf"]:
            raise RuntimeError("A361 base CNF header differs")
        context = {
            "width": WIDTH,
            "formula": formula,
            "formula_bytes": len(formula.encode()),
            "formula_sha256": sha256(formula.encode()),
            "base_path": base,
            "base_raw": raw,
            "base_body": b"".join(lines[1:]),
            "base_body_sha256": sha256(b"".join(lines[1:])),
            "variable_count": int(header[2]),
            "clause_count": int(header[3]),
            "base_export": export,
        }
        probe_dir = stage / "mapping_probes"
        probe_dir.mkdir(parents=False, exist_ok=False)
        probes = [
            a223._coordinate_probe(  # noqa: SLF001
                context=context,
                dimension=dimension,
                config=config,
                directory=probe_dir,
            )
            for dimension in range(-1, math.ceil(math.log2(WIDTH)))
        ]
        source_mapping = a223._decode_mapping(  # noqa: SLF001
            [(dimension, units) for _, dimension, units, _ in probes],
            width=WIDTH,
        )
        probe_dir.rmdir()
        corrected_mapping = A355.corrected_synthetic_mapping(source_mapping)
        if (
            len(source_mapping) != WIDTH
            or len({abs(value) for value in source_mapping}) != WIDTH
            or len(corrected_mapping) != 20
            or corrected_mapping
            != [source_mapping[index] for index in A355.SYNTHETIC_SOURCE_INDICES]
        ):
            raise RuntimeError("A361 corrected target-specific mapping differs")
        slices = []
        for low4 in SLICES:
            slice_path = stage / f"slice_{low4:02x}.cnf"
            slice_raw = A355.render_slice_cnf(raw, low4=low4, source_mapping=source_mapping)
            atomic_bytes(slice_path, slice_raw)
            slices.append(
                {
                    "low4": low4,
                    "path": relative(ARTIFACTS / slice_path.name),
                    "sha256": sha256(slice_raw),
                    "bytes": len(slice_raw),
                }
            )
        os.replace(stage, ARTIFACTS)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-fresh-a360-reader-deployment-a361-preflight-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": ("FRESH_TARGET_PUBLIC_OUTPUT_CNF_AND_CORRECTED_DIRECT12_MAPPING_FROZEN"),
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "protocol_sha256": expected_protocol_sha256,
        "protocol_commitment_sha256": protocol["protocol_commitment_sha256"],
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "bridge_challenge_sha256": canonical_sha256(bridge),
        "formula_sha256": sha256(formula.encode()),
        "formula_bytes": len(formula.encode()),
        "base_CNF": anchor(BASE_CNF, export["sha256"]),
        "base_CNF_header": export["header"],
        "source_one_literals_bit0_upward": source_mapping,
        "source_mapping_sha256": canonical_sha256(source_mapping),
        "corrected_synthetic_reader_mapping": corrected_mapping,
        "corrected_synthetic_reader_mapping_sha256": canonical_sha256(corrected_mapping),
        "coordinate_probe_rows": [probe[3] for probe in probes],
        "slice_CNF_ledger": slices,
        "reader_available_during_preflight": False,
        "reader_scores_or_order_available_during_preflight": False,
        "target_labels_used": 0,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "protocol": anchor(PROTOCOL, expected_protocol_sha256),
            "A360_selection": anchor(A360.SELECTION, A360_SELECTION_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["preflight_commitment_sha256"] = canonical_sha256(
        {
            "protocol_commitment_sha256": payload["protocol_commitment_sha256"],
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "formula_sha256": payload["formula_sha256"],
            "base_CNF_sha256": payload["base_CNF"]["sha256"],
            "source_mapping_sha256": payload["source_mapping_sha256"],
            "corrected_synthetic_reader_mapping_sha256": payload[
                "corrected_synthetic_reader_mapping_sha256"
            ],
            "coordinate_probe_rows": payload["coordinate_probe_rows"],
            "slice_CNF_ledger": slices,
            "reader_available_during_preflight": False,
            "target_labels_used": 0,
        }
    )
    atomic_json(PREFLIGHT, payload)
    return {
        "attempt_id": ATTEMPT_ID,
        "preflight": relative(PREFLIGHT),
        "preflight_sha256": file_sha256(PREFLIGHT),
        "preflight_commitment_sha256": payload["preflight_commitment_sha256"],
        "source_mapping_sha256": payload["source_mapping_sha256"],
        "corrected_mapping_sha256": payload["corrected_synthetic_reader_mapping_sha256"],
        "slice_CNF_count": len(slices),
    }


def load_preflight(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PREFLIGHT) != expected_sha256:
        raise RuntimeError("A361 preflight hash differs")
    value = json.loads(PREFLIGHT.read_bytes())
    source_mapping = [int(item) for item in value.get("source_one_literals_bit0_upward", [])]
    corrected_mapping = [int(item) for item in value.get("corrected_synthetic_reader_mapping", [])]
    if (
        value.get("schema") != "chacha20-round20-w46-fresh-a360-reader-deployment-a361-preflight-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("reader_available_during_preflight") is not False
        or value.get("reader_scores_or_order_available_during_preflight") is not False
        or value.get("target_labels_used") != 0
        or len(value.get("slice_CNF_ledger", [])) != len(SLICES)
        or len(value.get("coordinate_probe_rows", [])) != 1 + math.ceil(math.log2(WIDTH))
        or value.get("source_mapping_sha256") != canonical_sha256(source_mapping)
        or corrected_mapping != A355.corrected_synthetic_mapping(source_mapping)
        or value.get("corrected_synthetic_reader_mapping_sha256")
        != canonical_sha256(corrected_mapping)
    ):
        raise RuntimeError("A361 frozen preflight semantics differ")
    anchor(BASE_CNF, value["base_CNF"]["sha256"])
    for row in value["slice_CNF_ledger"]:
        anchor(path_from_ref(row["path"]), row["sha256"])
    for artifact in value["anchors"].values():
        anchor(path_from_ref(artifact["path"]), artifact["sha256"])
    return value


def _slice_paths(low4: int) -> tuple[Path, Path]:
    return (
        ARTIFACTS / f"slice_{low4:02x}.cnf",
        MEASUREMENTS / f"slice_{low4:02x}.json.zst",
    )


def _write_measurement(path: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    raw = canonical_bytes(value)
    compressed = zstandard.ZstdCompressor(
        level=ZSTD_LEVEL,
        threads=0,
        write_checksum=True,
        write_content_size=True,
        write_dict_id=False,
    ).compress(raw)
    atomic_bytes(path, compressed)
    return {
        "path": relative(path),
        "raw_bytes": len(raw),
        "raw_sha256": sha256(raw),
        "compressed_bytes": len(compressed),
        "compressed_sha256": sha256(compressed),
    }


def _read_measurement(
    path: Path,
    *,
    expected_protocol_sha256: str,
    expected_preflight_sha256: str,
    ledger: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    compressed = path.read_bytes()
    if ledger is not None and sha256(compressed) != ledger["compressed_sha256"]:
        raise RuntimeError("A361 compressed slice hash differs")
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    if ledger is not None and sha256(raw) != ledger["raw_sha256"]:
        raise RuntimeError("A361 raw slice hash differs")
    value = json.loads(raw)
    run = value.get("run", {})
    cells = run.get("cells", [])
    if (
        value.get("schema") != "chacha20-round20-w46-fresh-a360-reader-deployment-a361-slice-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("preflight_sha256") != expected_preflight_sha256
        or value.get("reader_available_during_measurement") is not False
        or value.get("target_label_available_during_measurement") is not False
        or value.get("complete_candidate_cover") is not True
        or value.get("candidate_order") != "numeric_0_through_255"
        or value.get("reader_refits") != 0
        or len(cells) != COARSE_CELLS
        or [int(cell.get("cell_index", -1)) for cell in cells] != list(range(COARSE_CELLS))
        or not 1 <= len(run.get("stages", [])) <= COARSE_CELLS * len(HORIZONS)
        or run.get("all_watchdogs_clear") is not True
        or canonical_bytes(value) != raw
    ):
        raise RuntimeError(f"A361 measurement shard gate failed: {path.name}")
    return value


def _run_slice(
    row: Mapping[str, Any],
    *,
    helper: Path,
    key_mapping: Sequence[int],
    protocol_sha256: str,
    preflight_sha256: str,
) -> dict[str, Any]:
    low4 = int(row["low4"])
    cnf_path, measurement_path = _slice_paths(low4)
    if measurement_path.exists():
        value = _read_measurement(
            measurement_path,
            expected_protocol_sha256=protocol_sha256,
            expected_preflight_sha256=preflight_sha256,
        )
        if value["low4"] != low4:
            raise RuntimeError(f"A361 resumed low4 differs: {low4}")
        return {
            "low4": low4,
            "resumed": True,
            "ledger": _write_measurement(measurement_path, value),
        }
    started = time.perf_counter()
    raw_run = WRAPPER.run_fresh_clause_identity(
        helper=helper,
        cnf=cnf_path,
        mode=f"A361_FRESH_W46_CORRECTED_DIRECT12_LOW4_{low4:02x}",
        order=[f"{value:08b}" for value in range(COARSE_CELLS)],
        key_one_literals_bit0_through_bit19=key_mapping,
        conflict_horizons=HORIZONS,
        watchdog_seconds=WATCHDOG_SECONDS,
        external_timeout_seconds=3600.0,
    )
    stable = {
        key: item
        for key, item in raw_run.items()
        if key not in {"command", "process_elapsed_seconds"}
    }
    value = {
        "schema": "chacha20-round20-w46-fresh-a360-reader-deployment-a361-slice-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": protocol_sha256,
        "preflight_sha256": preflight_sha256,
        "low4": low4,
        "fixed_unit_literals": A355.low4_unit_literals(
            low4, row["source_one_literals_bit0_upward"]
        ),
        "slice_CNF_sha256": row["slice_CNF_sha256"],
        "run": stable,
        "volatile_process_elapsed_seconds": time.perf_counter() - started,
        "reader_available_during_measurement": False,
        "target_label_available_during_measurement": False,
        "label_used_for_feature_construction_or_scoring": False,
        "candidate_order": "numeric_0_through_255",
        "reader_refits": 0,
        "complete_candidate_cover": len(stable.get("cells", [])) == COARSE_CELLS,
    }
    _readback = _write_measurement(measurement_path, value)
    checked = _read_measurement(
        measurement_path,
        expected_protocol_sha256=protocol_sha256,
        expected_preflight_sha256=preflight_sha256,
        ledger=_readback,
    )
    if checked != value:
        raise RuntimeError(f"A361 slice readback differs: {low4}")
    return {"low4": low4, "resumed": False, "ledger": _readback}


def measure(
    *,
    expected_implementation_sha256: str,
    expected_protocol_sha256: str,
    expected_preflight_sha256: str,
) -> dict[str, Any]:
    if MEASUREMENT.exists() or ORDER.exists() or PROGRESS.exists() or RESULT.exists():
        raise FileExistsError("A361 measurement or execution artifact already exists")
    implementation = load_implementation(expected_implementation_sha256)
    protocol = load_protocol(expected_protocol_sha256)
    preflight_value = load_preflight(expected_preflight_sha256)
    source_mapping = [int(value) for value in preflight_value["source_one_literals_bit0_upward"]]
    corrected_mapping = [
        int(value) for value in preflight_value["corrected_synthetic_reader_mapping"]
    ]
    slice_by_low4 = {int(row["low4"]): row for row in preflight_value["slice_CNF_ledger"]}
    if set(slice_by_low4) != set(SLICES):
        raise RuntimeError("A361 preflight slice cover differs")
    _a275, _model, _a291, _indices, helper = A340.A296._reader_stack()  # noqa: SLF001
    WRAPPER._load_base_wrapper()  # noqa: SLF001
    MEASUREMENTS.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    completed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = []
        for low4 in SLICES:
            row = {
                "low4": low4,
                "slice_CNF_sha256": slice_by_low4[low4]["sha256"],
                "source_one_literals_bit0_upward": source_mapping,
            }
            futures.append(
                executor.submit(
                    _run_slice,
                    row,
                    helper=helper,
                    key_mapping=corrected_mapping,
                    protocol_sha256=expected_protocol_sha256,
                    preflight_sha256=expected_preflight_sha256,
                )
            )
        for future in concurrent.futures.as_completed(futures):
            completed.append(future.result())
    completed.sort(key=lambda row: row["low4"])
    if [row["low4"] for row in completed] != list(SLICES):
        raise RuntimeError("A361 complete measurement slice cover differs")
    status_counts = {status: 0 for status in ("sat", "unknown", "unsat")}
    stage_count = 0
    ledgers = []
    for row in completed:
        value = _read_measurement(
            path_from_ref(row["ledger"]["path"]),
            expected_protocol_sha256=expected_protocol_sha256,
            expected_preflight_sha256=expected_preflight_sha256,
            ledger=row["ledger"],
        )
        stage_count += len(value["run"]["stages"])
        for cell in value["run"]["cells"]:
            status = str(cell["final_status"])
            if status not in status_counts:
                raise RuntimeError(f"A361 unknown cell status {status}")
            status_counts[status] += 1
        ledgers.append({**row["ledger"], "low4": row["low4"], "resumed": row["resumed"]})
    if sum(status_counts.values()) != CELLS:
        raise RuntimeError("A361 measurement status cover differs")
    summary = {
        "complete_direct12_cells": CELLS,
        "low4_slices": len(SLICES),
        "high8_cells_per_slice": COARSE_CELLS,
        "solver_stages": stage_count,
        "status_counts": status_counts,
        "measured_assignment_bit_interval": [20, 31],
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "A360_primary_reader_read_during_measurement": False,
        "reader_scoring_eligible": status_counts
        == {
            "sat": 0,
            "unknown": CELLS,
            "unsat": 0,
        },
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-fresh-a360-reader-deployment-a361-measurement-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FRESH_TARGET_COMPLETE_UNLABELED_CORRECTED_DIRECT12_MEASUREMENT",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "protocol_sha256": expected_protocol_sha256,
        "protocol_commitment_sha256": protocol["protocol_commitment_sha256"],
        "preflight_sha256": expected_preflight_sha256,
        "preflight_commitment_sha256": preflight_value["preflight_commitment_sha256"],
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "measurement_summary": summary,
        "measurement_ledger": ledgers,
        "measurement_ledger_sha256": canonical_sha256(ledgers),
        "volatile_wall_seconds": time.perf_counter() - started,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "protocol": anchor(PROTOCOL, expected_protocol_sha256),
            "preflight": anchor(PREFLIGHT, expected_preflight_sha256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["measurement_commitment_sha256"] = canonical_sha256(
        {
            "protocol_commitment_sha256": payload["protocol_commitment_sha256"],
            "preflight_commitment_sha256": payload["preflight_commitment_sha256"],
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "measurement_summary": summary,
            "measurement_ledger": ledgers,
        }
    )
    atomic_json(MEASUREMENT, payload)
    return {
        "attempt_id": ATTEMPT_ID,
        "measurement": relative(MEASUREMENT),
        "measurement_sha256": file_sha256(MEASUREMENT),
        "measurement_commitment_sha256": payload["measurement_commitment_sha256"],
        "measurement_summary": summary,
    }


def load_measurement(expected_sha256: str, *, expected_protocol_sha256: str) -> dict[str, Any]:
    if file_sha256(MEASUREMENT) != expected_sha256:
        raise RuntimeError("A361 measurement hash differs")
    value = json.loads(MEASUREMENT.read_bytes())
    summary = value.get("measurement_summary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w46-fresh-a360-reader-deployment-a361-measurement-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_sha256") != expected_protocol_sha256
        or summary.get("complete_direct12_cells") != CELLS
        or summary.get("target_labels_used") != 0
        or summary.get("reader_refits") != 0
        or summary.get("A360_primary_reader_read_during_measurement") is not False
        or len(value.get("measurement_ledger", [])) != len(SLICES)
    ):
        raise RuntimeError("A361 measurement semantics differ")
    for row in value["measurement_ledger"]:
        _read_measurement(
            path_from_ref(row["path"]),
            expected_protocol_sha256=expected_protocol_sha256,
            expected_preflight_sha256=value["preflight_sha256"],
            ledger=row,
        )
    for artifact in value["anchors"].values():
        anchor(path_from_ref(artifact["path"]), artifact["sha256"])
    return value


def load_a360_holdout(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(A360.RESULT) != expected_sha256:
        raise RuntimeError("A361 A360 holdout result hash differs")
    value = json.loads(A360.RESULT.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w46-within-slice-reader-selection-a360-v1"
        or value.get("selection_sha256") != A360_SELECTION_SHA256
        or value.get("retention_gate", {}).get("passed") is not True
        or value.get("reader_refits_after_selection_freeze") != 0
        or value.get("holdout_target_indices") != list(range(16, 32))
        or value.get("selection_summary", {}).get("primary") != A360_PRIMARY_NAME
    ):
        raise RuntimeError("A361 A360 disjoint holdout deployment gate failed")
    for artifact in value["anchors"].values():
        anchor(path_from_ref(artifact["path"]), artifact["sha256"])
    return value


def _measurement_map(
    value: Mapping[str, Any], *, protocol_sha256: str
) -> dict[int, dict[str, Any]]:
    result = {}
    for row in value["measurement_ledger"]:
        low4 = int(row["low4"])
        result[low4] = _read_measurement(
            path_from_ref(row["path"]),
            expected_protocol_sha256=protocol_sha256,
            expected_preflight_sha256=value["preflight_sha256"],
            ledger=row,
        )
    if set(result) != set(SLICES):
        raise RuntimeError("A361 measurement-map slice cover differs")
    return result


def _validate_within_order(order: Sequence[int]) -> list[int]:
    values = [int(item) for item in order]
    if len(values) != COARSE_CELLS or set(values) != set(range(COARSE_CELLS)):
        raise ValueError("A361 within-slice order differs")
    return values


def compose_round_robin(within_slice_orders: Mapping[int, Sequence[int]]) -> list[int]:
    checked = {
        int(low4): _validate_within_order(order) for low4, order in within_slice_orders.items()
    }
    if set(checked) != set(SLICES):
        raise ValueError("A361 within-slice order cover differs")
    return exact_group_order(
        [(checked[low4][rank] << 4) | low4 for rank in range(COARSE_CELLS) for low4 in SLICES]
    )


def freeze_order(
    *,
    expected_protocol_sha256: str,
    expected_measurement_sha256: str,
    expected_a360_result_sha256: str,
) -> dict[str, Any]:
    if ORDER.exists() or PROGRESS.exists() or RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A361 order or execution artifact already exists")
    load_design()
    protocol = load_protocol(expected_protocol_sha256)
    measurement = load_measurement(
        expected_measurement_sha256,
        expected_protocol_sha256=expected_protocol_sha256,
    )
    holdout = load_a360_holdout(expected_a360_result_sha256)
    if measurement["measurement_summary"].get("reader_scoring_eligible") is not True:
        raise RuntimeError(
            "A361 measurement contains a terminal solver status; Reader scoring stops"
        )
    selection = load_reader_selection()
    primary = selection["reader_selection"]["primary"]
    weights = np.asarray(primary["weights"], dtype=np.float64)
    if (
        weights.shape != (A360.FEATURES,)
        or not np.isfinite(weights).all()
        or canonical_sha256(weights.tolist()) != A360_PRIMARY_WEIGHTS_SHA256
    ):
        raise RuntimeError("A361 frozen primary weights differ")
    measurements = _measurement_map(measurement, protocol_sha256=expected_protocol_sha256)
    score_fields: dict[int, list[float]] = {}
    within_orders: dict[int, list[int]] = {}
    for low4 in SLICES:
        matrix = A360.target_normalize(A275._target_feature_matrix(measurements[low4]))  # noqa: SLF001
        scores = np.einsum("cf,f->c", matrix, weights, optimize=False)
        if scores.shape != (COARSE_CELLS,) or not np.isfinite(scores).all():
            raise RuntimeError(f"A361 score field differs: low4={low4}")
        score_fields[low4] = scores.tolist()
        within_orders[low4] = A360.exact_order(scores)
    selected_order = compose_round_robin(within_orders)
    selected_order_hash = order_sha256(selected_order)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-fresh-a360-reader-deployment-a361-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": ("DISJOINT_HOLDOUT_GATED_ZERO_REFIT_FRESH_TARGET_READER_ORDER_FROZEN"),
        "design_sha256": DESIGN_SHA256,
        "protocol_sha256": expected_protocol_sha256,
        "protocol_commitment_sha256": protocol["protocol_commitment_sha256"],
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "measurement_sha256": expected_measurement_sha256,
        "measurement_commitment_sha256": measurement["measurement_commitment_sha256"],
        "A360_selection_sha256": A360_SELECTION_SHA256,
        "A360_result_sha256": expected_a360_result_sha256,
        "A360_result_commitment_sha256": holdout["result_sha256"],
        "A360_retention_gate": holdout["retention_gate"],
        "selected_reader": {
            "definition": primary["definition"],
            "weights_sha256": primary["weights_sha256"],
        },
        "score_kernel": "numpy_einsum_cf_f_to_c_optimize_false",
        "within_slice_score_fields": [
            {"low4": low4, "scores": score_fields[low4]} for low4 in SLICES
        ],
        "within_slice_score_field_sha256": canonical_sha256(score_fields),
        "within_slice_orders": [{"low4": low4, "order": within_orders[low4]} for low4 in SLICES],
        "within_slice_orders_sha256": canonical_sha256(within_orders),
        "selected_order": selected_order,
        "selected_order_uint16be_sha256": selected_order_hash,
        "global_group_rank_formula": "16*(within_slice_rank-1)+true_low4+1",
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "candidate_or_prefix_available_at_order_freeze": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "protocol": anchor(PROTOCOL, expected_protocol_sha256),
            "measurement": anchor(MEASUREMENT, expected_measurement_sha256),
            "A360_selection": anchor(A360.SELECTION, A360_SELECTION_SHA256),
            "A360_result": anchor(A360.RESULT, expected_a360_result_sha256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["order_commitment_sha256"] = canonical_sha256(
        {
            "protocol_commitment_sha256": payload["protocol_commitment_sha256"],
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "measurement_commitment_sha256": payload["measurement_commitment_sha256"],
            "A360_result_commitment_sha256": payload["A360_result_commitment_sha256"],
            "selected_reader": payload["selected_reader"],
            "within_slice_score_field_sha256": payload["within_slice_score_field_sha256"],
            "within_slice_orders_sha256": payload["within_slice_orders_sha256"],
            "selected_order_uint16be_sha256": selected_order_hash,
            "target_labels_used": 0,
            "reader_refits": 0,
        }
    )
    atomic_json(ORDER, payload)
    return {
        "attempt_id": ATTEMPT_ID,
        "order": relative(ORDER),
        "order_sha256": file_sha256(ORDER),
        "order_commitment_sha256": payload["order_commitment_sha256"],
        "selected_order_uint16be_sha256": selected_order_hash,
        "target_labels_used": 0,
        "reader_refits": 0,
    }


def load_order(expected_sha256: str, *, expected_protocol_sha256: str) -> dict[str, Any]:
    if file_sha256(ORDER) != expected_sha256:
        raise RuntimeError("A361 order hash differs")
    value = json.loads(ORDER.read_bytes())
    selected = exact_group_order(value.get("selected_order", []))
    if (
        value.get("schema") != "chacha20-round20-w46-fresh-a360-reader-deployment-a361-order-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("A360_selection_sha256") != A360_SELECTION_SHA256
        or value.get("A360_retention_gate", {}).get("passed") is not True
        or value.get("selected_reader", {}).get("definition", {}).get("name") != A360_PRIMARY_NAME
        or value.get("selected_reader", {}).get("weights_sha256") != A360_PRIMARY_WEIGHTS_SHA256
        or value.get("selected_order_uint16be_sha256") != order_sha256(selected)
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_or_prefix_available_at_order_freeze") is not False
    ):
        raise RuntimeError("A361 frozen order semantics differ")
    for artifact in value["anchors"].values():
        anchor(path_from_ref(artifact["path"]), artifact["sha256"])
    return value


def _load_resume(
    *, protocol_sha256: str, order_hash: str, qualification_sha256: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    if not PROGRESS.exists():
        return 0, 0.0, 0, None
    value = json.loads(PROGRESS.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w46-fresh-a360-reader-deployment-a361-progress-v1"
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("selected_order_uint16be_sha256") != order_hash
        or value.get("A324_qualification_sha256") != qualification_sha256
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A361 progress fingerprint differs")
    if value.get("status") == "candidate_found":
        excluded = {
            "schema",
            "attempt_id",
            "protocol_sha256",
            "selected_operator",
            "selected_order_uint16be_sha256",
            "A324_qualification_sha256",
            "status",
        }
        return 0, 0.0, 0, {key: item for key, item in value.items() if key not in excluded}
    completed = int(value.get("executed_prefix_groups", -1))
    if not 0 <= completed < CELLS or value.get("factual_filter_candidates") != 0:
        raise RuntimeError("A361 resumable progress state differs")
    return (
        completed,
        float(value.get("gpu_seconds", 0.0)),
        int(value.get("host_instances", 0)),
        None,
    )


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    selected = "A360:selection_only_primary_reader"
    gated = "A360:disjoint_holdout_retention_gate"
    ordered = "A361:fresh_target_zero_refit_group_order"
    model = "A361:sole_factual_W46_model"
    terminal = "A361:confirmed_fresh_fullround_W46_recovery"
    writer = CausalWriter(api_id="a361dep")
    writer._rules = []
    writer.add_rule(
        name="selection_reader_to_disjoint_holdout_gate",
        description="The selection-only primary Reader advances only through A360's frozen disjoint holdout retention gate.",
        pattern=[selected],
        conclusion=gated,
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="holdout_gate_to_fresh_target_order",
        description="The unchanged Reader scores every cell of a fresh complete corrected-coordinate target grid and emits the exact round-robin group order.",
        pattern=[gated],
        conclusion=ordered,
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="fresh_order_to_factual_model",
        description="The A324 engine executes complete groups in frozen order and the matched control remains empty.",
        pattern=[ordered],
        conclusion=model,
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="factual_model_to_full_confirmation",
        description="Two independent implementations reproduce all eight full-round output blocks.",
        pattern=[model],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger=selected,
        mechanism="prospective_disjoint_holdout_retention_without_refit",
        outcome=gated,
        confidence=1.0,
        source=payload["A360_result_sha256"],
        quantification=json.dumps(payload["A360_retention_gate"], sort_keys=True),
        evidence="sixteen disjoint holdout targets",
        domain="Known-key Reader validation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=gated,
        mechanism="complete_fresh_target_corrected_grid_scoring_and_round_robin_composition",
        outcome=ordered,
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=json.dumps(payload["rank_analysis"], sort_keys=True),
        evidence="zero target labels and zero Reader refits",
        domain="Fresh ChaCha20 R20 W46 deployment",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=ordered,
        mechanism="ordered_complete_eight_slab_group_search_with_matched_control",
        outcome=model,
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence="every entered prefix group completed before outcome inspection",
        domain="Full-round residual-key recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=model,
        mechanism="dual_independent_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="Confirmed full-round ChaCha20 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=selected,
        mechanism="materialized_selection_holdout_fresh_order_recovery_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A361_fresh_reader_deployment_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A361 fresh Reader deployment and full-round recovery",
        entities=[selected, gated, ordered, model, terminal],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_W47_reader_transfer_or_second_fresh_W46_replication",
        confidence=1.0,
        suggested_queries=[
            "Does the unchanged A360 Reader and round-robin construction retain strict-subset recovery on W47?"
        ],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a361dep"
        or len(explicit) != 4
        or len(all_rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 4
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A361 authentic Causal reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(CAUSAL),
        "sha256": file_sha256(CAUSAL),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "reader_source": anchor(Path(inspect.getsourcefile(CausalReader) or "")),
        "writer_stats": stats,
        "personal_semantic_readback": {
            "first_relation": explicit[0],
            "terminal_relation": explicit[-1],
            "materialized_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def recover(
    *,
    expected_protocol_sha256: str,
    expected_order_sha256: str,
    expected_a324_qualification_sha256: str,
) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A361 result artifact already exists")
    protocol = load_protocol(expected_protocol_sha256)
    order_value = load_order(
        expected_order_sha256, expected_protocol_sha256=expected_protocol_sha256
    )
    qualification = A325.load_a324_qualification(expected_a324_qualification_sha256)
    if expected_a324_qualification_sha256 != A324_QUALIFICATION_SHA256:
        raise RuntimeError("A361 qualification hash differs")
    challenge = protocol["public_challenge"]
    a324_protocol = A324.load_protocol(A325.A324_PROTOCOL_SHA256)
    executable_row = a324_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A324.A311.A307.A304.GroupedMetalHost(
            executable,
            A324.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            PROGRESS,
            {
                "schema": ("chacha20-round20-w46-fresh-a360-reader-deployment-a361-progress-v1"),
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": expected_protocol_sha256,
                "selected_operator": "A360_holdout_gated_primary_round_robin",
                "selected_order_uint16be_sha256": order_value["selected_order_uint16be_sha256"],
                "A324_qualification_sha256": expected_a324_qualification_sha256,
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed_discovery = _load_resume(
        protocol_sha256=expected_protocol_sha256,
        order_hash=order_value["selected_order_uint16be_sha256"],
        qualification_sha256=expected_a324_qualification_sha256,
    )
    discovery = completed_discovery or A325.ordered_discovery(
        host_factory=host_factory,
        challenge=challenge,
        order=order_value["selected_order"],
        start_group=start,
        prior_gpu_seconds=prior_gpu,
        prior_host_instances=prior_hosts,
        progress_callback=write_progress,
    )
    if discovery["matched_control_candidates"] != 0:
        raise RuntimeError("A361 matched control produced a candidate")
    candidate = int(discovery["candidate"])
    confirmation = A325.confirm(challenge, candidate)
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("A361 dual independent confirmation failed")
    prefix = int(discovery["prefix12"])
    rank = order_value["selected_order"].index(prefix) + 1
    if rank != discovery["executed_prefix_groups"]:
        raise RuntimeError("A361 discovery rank differs from frozen order")
    within_rank = next(
        index + 1
        for index, high8 in enumerate(order_value["within_slice_orders"][prefix & 0xF]["order"])
        if high8 == prefix >> 4
    )
    exact_global_rank = 16 * (within_rank - 1) + (prefix & 0xF) + 1
    if exact_global_rank != rank:
        raise RuntimeError("A361 round-robin rank identity differs")
    strict_subset = rank < CELLS
    rank_analysis = {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "true_low4": prefix & 0xF,
        "true_high8": prefix >> 4,
        "within_slice_rank_one_based": within_rank,
        "global_group_rank_one_based": rank,
        "global_group_rank_formula": "16*(within_slice_rank-1)+true_low4+1",
        "gain_bits_vs_complete_domain": math.log2(CELLS / rank),
        "domain_reduction_factor": CELLS / rank,
        "ranks_computed_only_after_independent_confirmation": True,
    }
    evidence_stage = (
        "FULLROUND_R20_FRESH_HOLDOUT_GATED_READER_W46_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_FRESH_HOLDOUT_GATED_READER_W46_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    stable_discovery = {
        key: item for key, item in discovery.items() if not key.startswith("volatile_")
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-fresh-a360-reader-deployment-a361-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "design_sha256": DESIGN_SHA256,
        "protocol_sha256": expected_protocol_sha256,
        "protocol_commitment_sha256": protocol["protocol_commitment_sha256"],
        "order_sha256": expected_order_sha256,
        "order_commitment_sha256": order_value["order_commitment_sha256"],
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "A360_selection_sha256": A360_SELECTION_SHA256,
        "A360_result_sha256": order_value["A360_result_sha256"],
        "A360_retention_gate": order_value["A360_retention_gate"],
        "A324_qualification_sha256": expected_a324_qualification_sha256,
        "selected_operator": "A360_holdout_gated_primary_round_robin",
        "selected_reader": order_value["selected_reader"],
        "selected_order_uint16be_sha256": order_value["selected_order_uint16be_sha256"],
        "discovery": discovery,
        "rank_analysis": rank_analysis,
        "confirmation": confirmation,
        "strict_subset_of_complete_domain": strict_subset,
        "reader_refits": 0,
        "target_labels_used": 0,
        "qualification_gate": {
            "evidence_stage": qualification["evidence_stage"],
            "qualification_sha256": qualification["qualification_sha256"],
            "complete_W46_group_candidates": qualification["complete_group_gate"][
                "logical_candidates"
            ],
            "synthetic_filter_exact": qualification["synthetic_filter_exact"],
            "production_target_used": False,
        },
        "information_boundary": protocol["information_boundary"],
        "anchors": {
            **protocol["anchors"],
            "order": anchor(ORDER, expected_order_sha256),
            "A360_result": anchor(A360.RESULT, order_value["A360_result_sha256"]),
        },
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "selected_operator": payload["selected_operator"],
            "selected_order_uint16be_sha256": payload["selected_order_uint16be_sha256"],
            "discovery": stable_discovery,
            "A324_qualification_sha256": expected_a324_qualification_sha256,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "discovery": stable_discovery,
            "rank_analysis": rank_analysis,
            "confirmation": confirmation,
            "qualification_gate": payload["qualification_gate"],
            "A360_retention_gate": payload["A360_retention_gate"],
            "reader_refits": 0,
            "target_labels_used": 0,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A361 — fresh holdout-gated Reader deployment and W46 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Frozen Reader: **{A360_PRIMARY_NAME}**\n"
            "- Known-key selection / disjoint holdout: **16 / 16 targets**\n"
            f"- Fresh W46 execution rank: **{rank} / 4,096 groups**\n"
            f"- Domain reduction: **{rank_analysis['domain_reduction_factor']:.9f}x**\n"
            f"- Search-gain bits: **{rank_analysis['gain_bits_vs_complete_domain']:.9f}**\n"
            f"- Complete candidate evaluations: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W46 assignment: **0x{candidate:012x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Matched one-bit control: **zero candidates**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Reader refits / target labels: **0 / 0**\n"
            "- Authentic AI-native Causal readback: **4 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    response: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "preflight_complete": PREFLIGHT.exists(),
        "measurement_complete": MEASUREMENT.exists(),
        "A360_holdout_result_available": A360.RESULT.exists(),
        "order_frozen": ORDER.exists(),
        "progress_exists": PROGRESS.exists(),
        "result_complete": RESULT.exists(),
        "measurement_shards_available": (
            len(list(MEASUREMENTS.glob("slice_*.json.zst"))) if MEASUREMENTS.exists() else 0
        ),
    }
    for name, path in {
        "implementation": IMPLEMENTATION,
        "protocol": PROTOCOL,
        "preflight": PREFLIGHT,
        "measurement": MEASUREMENT,
        "A360_result": A360.RESULT,
        "order": ORDER,
        "progress": PROGRESS,
        "result": RESULT,
    }.items():
        if path.exists():
            response[f"{name}_sha256"] = file_sha256(path)
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--materialize-target", action="store_true")
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--measure", action="store_true")
    action.add_argument("--freeze-order", action="store_true")
    action.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-preflight-sha256")
    parser.add_argument("--expected-measurement-sha256")
    parser.add_argument("--expected-a360-result-sha256")
    parser.add_argument("--expected-order-sha256")
    parser.add_argument("--expected-a324-qualification-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.materialize_target:
        if not args.expected_implementation_sha256 or not args.expected_a324_qualification_sha256:
            parser.error(
                "--materialize-target requires --expected-implementation-sha256 "
                "and --expected-a324-qualification-sha256"
            )
        payload = materialize_target(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a324_qualification_sha256=args.expected_a324_qualification_sha256,
        )
    elif args.preflight:
        if not args.expected_implementation_sha256 or not args.expected_protocol_sha256:
            parser.error(
                "--preflight requires --expected-implementation-sha256 and "
                "--expected-protocol-sha256"
            )
        payload = preflight(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_protocol_sha256=args.expected_protocol_sha256,
        )
    elif args.measure:
        if (
            not args.expected_implementation_sha256
            or not args.expected_protocol_sha256
            or not args.expected_preflight_sha256
        ):
            parser.error(
                "--measure requires --expected-implementation-sha256, "
                "--expected-protocol-sha256 and --expected-preflight-sha256"
            )
        payload = measure(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_preflight_sha256=args.expected_preflight_sha256,
        )
    elif args.freeze_order:
        if (
            not args.expected_protocol_sha256
            or not args.expected_measurement_sha256
            or not args.expected_a360_result_sha256
        ):
            parser.error(
                "--freeze-order requires --expected-protocol-sha256, "
                "--expected-measurement-sha256 and --expected-a360-result-sha256"
            )
        payload = freeze_order(
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_measurement_sha256=args.expected_measurement_sha256,
            expected_a360_result_sha256=args.expected_a360_result_sha256,
        )
    elif args.recover:
        if (
            not args.expected_protocol_sha256
            or not args.expected_order_sha256
            or not args.expected_a324_qualification_sha256
        ):
            parser.error(
                "--recover requires --expected-protocol-sha256, "
                "--expected-order-sha256 and --expected-a324-qualification-sha256"
            )
        payload = recover(
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_order_sha256=args.expected_order_sha256,
            expected_a324_qualification_sha256=args.expected_a324_qualification_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
