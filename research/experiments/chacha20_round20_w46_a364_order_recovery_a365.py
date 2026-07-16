#!/usr/bin/env python3
"""A365: execute A364's sealed-target W46 order and confirm the factual model."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w46_a364_order_recovery_a365_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w46_a364_order_recovery_a365_implementation_v1.json"
PROGRESS = RESULTS / "chacha20_round20_w46_a364_order_recovery_a365_progress_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_a364_order_recovery_a365_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w46_a364_order_recovery_a365.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_a364_order_recovery_a365.sh"

A361_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_fresh_a360_reader_deployment_a361.py"
A364_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_a362_reader_sealed_a361_order_a364.py"
A361_PROTOCOL = CONFIGS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_protocol_v1.json"
A324_QUALIFICATION = (
    RESULTS / "chacha20_round20_w46_eight_slab_grouped_engine_a324_qualification_v1.json"
)

ATTEMPT_ID = "A365"
DESIGN_SHA256 = "7778d4c93510d3375607f0a6918b208d554f24a37300ac13c2e074ec6fa20222"
A361_PROTOCOL_SHA256 = "3396559ab6fde25ef12f5fdcae68e33585234926885b88b136c1f4af47c13228"
A324_QUALIFICATION_SHA256 = "996dcddfc5f9b9e91f7c77c01aa10747af8f291795dfa04d3e7eaf890047296a"
GROUPS = 4096
DOMAIN_SIZE = 1 << 46
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A365 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A361 = load_module(A361_RUNNER, "a365_a361")
A364 = load_module(A364_RUNNER, "a365_a364")
A325 = A361.A325
A324 = A361.A324

file_sha256 = A361.file_sha256
canonical_sha256 = A361.canonical_sha256
atomic_json = A361.atomic_json
atomic_bytes = A361.atomic_bytes
relative = A361.relative
path_from_ref = A361.path_from_ref
anchor = A361.anchor


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A365 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    chain = value.get("conditional_chain", {})
    execution = value.get("execution_contract", {})
    confirmation = value.get("confirmation_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w46-a364-order-recovery-a365-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_before_A363_result_A364_order_candidate_prefix_or_recovery_execution"
        or chain.get("A363_retention_gate_required") is not True
        or chain.get("A364_order_required") is not True
        or chain.get("A363_result_available_at_design_freeze") is not False
        or chain.get("A364_order_available_at_design_freeze") is not False
        or execution.get("rounds") != 20
        or execution.get("feed_forward") is not True
        or execution.get("public_output_blocks") != 8
        or execution.get("unknown_key_bits") != 46
        or execution.get("complete_group_suffix_bits") != 34
        or execution.get("group_count") != GROUPS
        or execution.get("maximum_complete_domain_assignments") != DOMAIN_SIZE
        or confirmation.get("all_eight_output_blocks_required") is not True
        or confirmation.get("matched_control_candidates_required") != 0
        or boundary.get("A361_secret_or_true_prefix_available_at_design_freeze") is not False
        or boundary.get("A363_result_available_at_design_freeze") is not False
        or boundary.get("A364_order_available_at_design_freeze") is not False
        or boundary.get("candidate_or_prefix_available_at_design_freeze") is not False
        or boundary.get("candidate_assignments_executed_at_design_freeze") != 0
    ):
        raise RuntimeError("A365 frozen design semantics differ")
    for name, path_value in value["source_anchors"].items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, value["source_anchors"][f"{stem}_sha256"])
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A365 implementation already exists")
    if any(path.exists() for path in (PROGRESS, RESULT, CAUSAL, REPORT)):
        raise RuntimeError("A365 implementation must precede every recovery artifact")
    if A364.A363.RESULT.exists() or A364.ORDER.exists():
        raise RuntimeError("A365 implementation must freeze before A363 result and A364 order")
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A365 test and reproducer must exist before freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-a364-order-recovery-a365-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A363_result_A364_order_candidate_prefix_or_execution",
        "design_sha256": DESIGN_SHA256,
        "A363_result_available_at_implementation_freeze": False,
        "A364_order_available_at_implementation_freeze": False,
        "candidate_or_prefix_available_at_implementation_freeze": False,
        "candidate_assignments_executed_at_implementation_freeze": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A361_protocol": anchor(A361_PROTOCOL, A361_PROTOCOL_SHA256),
            "A324_qualification": anchor(A324_QUALIFICATION, A324_QUALIFICATION_SHA256),
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
        raise RuntimeError("A365 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w46-a364-order-recovery-a365-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_before_A363_result_A364_order_candidate_prefix_or_execution"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A363_result_available_at_implementation_freeze") is not False
        or value.get("A364_order_available_at_implementation_freeze") is not False
        or value.get("candidate_or_prefix_available_at_implementation_freeze") is not False
        or value.get("candidate_assignments_executed_at_implementation_freeze") != 0
    ):
        raise RuntimeError("A365 frozen implementation semantics differ")
    for name, path in {
        "design": DESIGN,
        "A361_protocol": A361_PROTOCOL,
        "A324_qualification": A324_QUALIFICATION,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }.items():
        row = value["anchors"][name]
        if row["path"] != relative(path) or row["sha256"] != file_sha256(path):
            raise RuntimeError(f"A365 implementation anchor differs: {name}")
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value["implementation_commitment_sha256"] != canonical_sha256(unsigned):
        raise RuntimeError("A365 implementation commitment differs")
    return value


def _load_resume(
    *, protocol_sha256: str, order_hash: str, qualification_sha256: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    if not PROGRESS.exists():
        return 0, 0.0, 0, None
    value = json.loads(PROGRESS.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w46-a364-order-recovery-a365-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("selected_order_uint16be_sha256") != order_hash
        or value.get("A324_qualification_sha256") != qualification_sha256
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A365 progress fingerprint differs")
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
    if not 0 <= completed < GROUPS or value.get("factual_filter_candidates") != 0:
        raise RuntimeError("A365 resumable progress state differs")
    return (
        completed,
        float(value.get("gpu_seconds", 0.0)),
        int(value.get("host_instances", 0)),
        None,
    )


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    validated = "A363:prospective_reader_gate_passed"
    ordered = "A364:sealed_target_exact_group_order"
    searched = "A365:complete_group_execution_with_matched_control"
    model = "A365:factual_W46_model"
    confirmed = "A365:independent_full_output_confirmation"
    writer = CausalWriter(api_id="a365rec")
    writer._rules = []
    rules = [
        (
            "validation_to_order",
            "A363's retained gate permits A364 to materialize the sealed-target order.",
            [validated],
            ordered,
        ),
        (
            "order_to_group_search",
            "The qualified A324 engine executes complete suffix domains in the immutable A364 order.",
            [ordered],
            searched,
        ),
        (
            "group_search_to_model",
            "A sole factual filter candidate with an empty matched control determines the W46 model.",
            [searched],
            model,
        ),
        (
            "model_to_confirmation",
            "Independent ChaCha20 transcriptions reproduce all eight public output blocks.",
            [model],
            confirmed,
        ),
    ]
    for name, description, pattern, conclusion in rules:
        writer.add_rule(
            name=name,
            description=description,
            pattern=pattern,
            conclusion=conclusion,
            confidence_modifier=1.0,
        )
    writer.add_triplet(
        trigger=validated,
        mechanism="prospective_gate_conditioned_sealed_target_order_freeze",
        outcome=ordered,
        confidence=1.0,
        source=payload["A364_order_commitment_sha256"],
        quantification=json.dumps(payload["A363_retention_gate"], sort_keys=True),
        evidence="A364 order frozen with no candidate or prefix",
        domain="ChaCha20 R20 W46 prospective recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=ordered,
        mechanism="ordered_complete_eight_slab_group_search_with_one_bit_control",
        outcome=searched,
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence="all visited groups complete; matched control empty",
        domain="Qualified commodity-hardware execution",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=searched,
        mechanism="sole_factual_filter_candidate_and_zero_control_candidates",
        outcome=model,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["rank_analysis"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="Residual-key model discovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=model,
        mechanism="dual_independent_eight_block_RFC8439_confirmation",
        outcome=confirmed,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence="complete public relation reproduced",
        domain="Independent confirmation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=validated,
        mechanism="materialized_validation_order_search_model_confirmation_chain",
        outcome=confirmed,
        confidence=1.0,
        source="materialized:A365_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A365 sealed-target recovery",
        entities=[validated, ordered, searched, model, confirmed],
    )
    writer.add_gap(
        subject=confirmed,
        predicate="next_required_object",
        expected_object_type="fresh_W46_replication_or_W47_transfer",
        confidence=1.0,
        suggested_queries=[
            "Replicate the invariant Reader and confirmed recovery on a second sealed W46 target or transfer the mechanism to a W47 grouped engine."
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
        reader.api_id != "a365rec"
        or len(explicit) != 4
        or len(all_rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 4
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A365 authentic Causal reopen gate failed")
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
    expected_implementation_sha256: str,
    expected_order_sha256: str,
    expected_a324_qualification_sha256: str,
) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A365 result already exists")
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    protocol = A361.load_protocol(A361_PROTOCOL_SHA256)
    order_value = A364.load_order(expected_order_sha256)
    qualification = A325.load_a324_qualification(expected_a324_qualification_sha256)
    if expected_a324_qualification_sha256 != A324_QUALIFICATION_SHA256:
        raise RuntimeError("A365 qualification hash differs")
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
                "schema": "chacha20-round20-w46-a364-order-recovery-a365-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": A361_PROTOCOL_SHA256,
                "selected_operator": "A362_polarity_invariant_linf_round_robin",
                "selected_order_uint16be_sha256": order_value["selected_order_uint16be_sha256"],
                "A324_qualification_sha256": expected_a324_qualification_sha256,
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed_discovery = _load_resume(
        protocol_sha256=A361_PROTOCOL_SHA256,
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
        raise RuntimeError("A365 matched control produced a candidate")
    candidate = int(discovery["candidate"])
    confirmation = A325.confirm(challenge, candidate)
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("A365 independent confirmation failed")
    prefix = int(discovery["prefix12"])
    rank = order_value["selected_order"].index(prefix) + 1
    if rank != discovery["executed_prefix_groups"]:
        raise RuntimeError("A365 discovery rank differs from frozen order")
    order_by_low4 = {
        int(row["low4"]): [int(value) for value in row["order"]]
        for row in order_value["within_slice_orders"]
    }
    within_rank = order_by_low4[prefix & 0xF].index(prefix >> 4) + 1
    exact_global_rank = 16 * (within_rank - 1) + (prefix & 0xF) + 1
    if exact_global_rank != rank:
        raise RuntimeError("A365 round-robin rank identity differs")
    strict_subset = rank < GROUPS
    rank_analysis = {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "true_low4": prefix & 0xF,
        "true_high8": prefix >> 4,
        "within_slice_rank_one_based": within_rank,
        "global_group_rank_one_based": rank,
        "global_group_rank_formula": "16*(within_slice_rank-1)+true_low4+1",
        "gain_bits_vs_complete_domain": math.log2(GROUPS / rank),
        "domain_reduction_factor": GROUPS / rank,
        "ranks_computed_only_after_independent_confirmation": True,
    }
    evidence_stage = (
        "FULLROUND_R20_FRESH_POLARITY_INVARIANT_READER_W46_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_FRESH_POLARITY_INVARIANT_READER_W46_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    stable_discovery = {
        key: item for key, item in discovery.items() if not key.startswith("volatile_")
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-a364-order-recovery-a365-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "protocol_sha256": A361_PROTOCOL_SHA256,
        "protocol_commitment_sha256": protocol["protocol_commitment_sha256"],
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "A364_order_sha256": expected_order_sha256,
        "A364_order_commitment_sha256": order_value["order_commitment_sha256"],
        "A363_result_sha256": order_value["A363_result_sha256"],
        "A363_retention_gate": order_value["A363_retention_gate"],
        "A324_qualification_sha256": expected_a324_qualification_sha256,
        "selected_operator": "A362_polarity_invariant_linf_round_robin",
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
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "protocol": anchor(A361_PROTOCOL, A361_PROTOCOL_SHA256),
            "order": anchor(A364.ORDER, expected_order_sha256),
            "A324_qualification": anchor(A324_QUALIFICATION, expected_a324_qualification_sha256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
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
            "A363_retention_gate": payload["A363_retention_gate"],
            "reader_refits": 0,
            "target_labels_used": 0,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A365 — fresh polarity-invariant Reader W46 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Frozen Reader: **{order_value['selected_reader']['name']}**\n"
            f"- Fresh W46 execution rank: **{rank} / {GROUPS:,} groups**\n"
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
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "implementation_sha256": file_sha256(IMPLEMENTATION) if IMPLEMENTATION.exists() else None,
        "A363_result_available": A364.A363.RESULT.exists(),
        "A364_order_available": A364.ORDER.exists(),
        "progress_available": PROGRESS.exists(),
        "result_complete": RESULT.exists(),
        "result_sha256": file_sha256(RESULT) if RESULT.exists() else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-order-sha256")
    parser.add_argument("--expected-a324-qualification-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.recover:
        if (
            not args.expected_implementation_sha256
            or not args.expected_order_sha256
            or not args.expected_a324_qualification_sha256
        ):
            parser.error(
                "--recover requires --expected-implementation-sha256, --expected-order-sha256 and --expected-a324-qualification-sha256"
            )
        payload = recover(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_order_sha256=args.expected_order_sha256,
            expected_a324_qualification_sha256=args.expected_a324_qualification_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
