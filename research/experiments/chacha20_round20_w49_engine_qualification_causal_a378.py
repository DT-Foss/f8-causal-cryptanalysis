#!/usr/bin/env python3
"""Build and natively reopen the AI-native Causal graph for A378 qualification."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
RESULTS = RESEARCH / "results/v1"
RUNNER = RESEARCH / "experiments/chacha20_round20_w49_sixtyfour_slab_grouped_engine_a378.py"
QUALIFICATION = (
    RESULTS / "chacha20_round20_w49_sixtyfour_slab_grouped_engine_a378_qualification_v1.json"
)
CAUSAL = QUALIFICATION.with_suffix(".causal")
READBACK = RESULTS / "chacha20_round20_w49_sixtyfour_slab_grouped_engine_a378_causal_readback_v1.json"
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")

ATTEMPT_ID = "A378"
PROTOCOL_SHA256 = "c926f6474c7cb54909e0204182941d7d1c63889fd892e92f0fbc4c5c48305af3"
RUNNER_SHA256 = "16e2832e49925a4c8d73580f2656788b22da3cb9e5a6e33281ffc5dbe4194c27"
GROUP_SIZE = 1 << 37


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A378 Causal dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A378 = load_module(RUNNER, "a378_causal_source")
file_sha256 = A378.file_sha256
canonical_sha256 = A378.canonical_sha256
atomic_json = A378.atomic_json
relative = A378.relative
anchor = A378.anchor


def load_qualification(expected_file_sha256: str) -> dict[str, Any]:
    if file_sha256(RUNNER) != RUNNER_SHA256:
        raise RuntimeError("A378 Causal source runner hash differs")
    A378.load_protocol(PROTOCOL_SHA256)
    if file_sha256(QUALIFICATION) != expected_file_sha256:
        raise RuntimeError("A378 qualification file hash differs")
    value = json.loads(QUALIFICATION.read_bytes())
    group = value.get("complete_group_gate", {})
    if (
        value.get("schema")
        != "chacha20-round20-w49-sixtyfour-slab-grouped-engine-a378-qualification-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("evidence_stage")
        != "TARGET_FREE_COMPLETE_W49_GROUP_ENGINE_EXACTLY_QUALIFIED"
        or value.get("protocol_sha256") != PROTOCOL_SHA256
        or value.get("production_W49_challenge_used") is not False
        or value.get("production_W49_candidate_used") is not False
        or value.get("synthetic_filter_exact") is not True
        or value.get("matched_control_empty") is not True
        or len(value.get("boundary_full_block_rows", [])) != 129
        or group.get("logical_candidates") != GROUP_SIZE
        or group.get("slabs_executed") != list(range(64))
        or len(group.get("factual_candidates", [])) != 1
        or group.get("control_candidates") != []
    ):
        raise RuntimeError("A378 qualification semantics differ")
    return value


def build(*, expected_qualification_sha256: str) -> dict[str, Any]:
    if CAUSAL.exists() or READBACK.exists():
        raise FileExistsError("A378 Causal or readback artifact already exists")
    qualification = load_qualification(expected_qualification_sha256)
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    group = qualification["complete_group_gate"]
    writer = CausalWriter(api_id="a378w49")
    writer._rules = []
    writer.add_rule(
        name="qualified_W48_grid_to_complete_W49_group",
        description="A378 composes sixty-four unchanged 2^31-candidate Metal slabs and evaluates success only after their exact 2^37 union.",
        pattern=["A371_exact_W48_engine", "A378_sixty_four_slab_composition"],
        conclusion="A378_exact_W49_complete_group_engine",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="target_free_W49_qualification_to_pretarget_protocol_gate",
        description="Exact scalar boundaries, the planted factual assignment, and the empty matched control unlock W49 challenge materialization only after qualification.",
        pattern=["A378_exact_W49_complete_group_engine", "A379_frozen_pretarget_design"],
        conclusion="A379_W49_pretarget_materialization_ready",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A371:exact_W48_complete_group_engine",
        mechanism="candidate_preserving_sixty_four_slab_composition",
        outcome="A378:exact_W49_complete_group_engine",
        confidence=1.0,
        source=qualification["qualification_sha256"],
        quantification=json.dumps(
            {
                "slabs": 64,
                "candidates_per_slab": 1 << 31,
                "complete_group_candidates": GROUP_SIZE,
                "filter_dispatches": group["filter_dispatches"],
            },
            sort_keys=True,
        ),
        evidence="unchanged grouped executable and complete-group outcome boundary",
        domain="target-free standard ChaCha20 R20 plus feed-forward W49 execution",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A378:exact_W49_complete_group_engine",
        mechanism="scalar_boundary_identity_plus_synthetic_factual_control_gate",
        outcome="A379:W49_pretarget_materialization_ready",
        confidence=1.0,
        source=qualification["qualification_sha256"],
        quantification=json.dumps(
            {
                "boundary_points": len(qualification["boundary_full_block_rows"]),
                "boundary_output_bits": qualification[
                    "total_boundary_output_bits_checked"
                ],
                "factual_candidates": len(group["factual_candidates"]),
                "control_candidates": len(group["control_candidates"]),
            },
            sort_keys=True,
        ),
        evidence="qualification contains no W49 production challenge or candidate",
        domain="prospective W49 information boundary",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A371:exact_W48_complete_group_engine",
        mechanism="materialized_target_free_W49_engine_and_pretarget_gate_closure",
        outcome="A379:W49_pretarget_materialization_ready",
        confidence=1.0,
        source="materialized:A378_W49_engine_chain",
        quantification="exact retained closure",
        evidence="A378 qualification precedes every W49 production challenge",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A378 exact target-free W49 engine lift",
        entities=[
            "A371:exact_W48_complete_group_engine",
            "A378:exact_W49_complete_group_engine",
            "A379:W49_pretarget_materialization_ready",
        ],
    )
    writer.add_gap(
        subject="A379:W49_pretarget_materialization_ready",
        predicate="next_required_object",
        expected_object_type="fresh_W49_public_challenge_and_zero_refit_reader_order",
        confidence=1.0,
        suggested_queries=[
            "Freeze the byte-identical A373 transfer order, then create the fresh W49 challenge and its target-conditioned Reader order."
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
        reader.api_id != "a378w49"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A378 authentic Causal reopen gate failed")
    payload = {
        "schema": "chacha20-round20-w49-engine-qualification-causal-readback-a378-v1",
        "attempt_id": ATTEMPT_ID,
        "qualification_file_sha256": expected_qualification_sha256,
        "qualification_sha256": qualification["qualification_sha256"],
        "causal": {
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
                "terminal_chain": all_rows[-1],
                "next_gap": reader._gaps[0],
            },
        },
        "anchors": {
            "qualification": anchor(QUALIFICATION, expected_qualification_sha256),
            "A378_runner": anchor(RUNNER, RUNNER_SHA256),
            "causal_builder": anchor(Path(__file__)),
        },
    }
    payload["readback_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(READBACK, payload)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true", required=True)
    parser.add_argument("--expected-qualification-sha256", required=True)
    args = parser.parse_args()
    payload = build(expected_qualification_sha256=args.expected_qualification_sha256)
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
