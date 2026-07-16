#!/usr/bin/env python3
"""A364: conditionally freeze A362's order on the sealed A361 W46 target."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w46_a362_reader_sealed_a361_order_a364_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w46_a362_reader_sealed_a361_order_a364_implementation_v1.json"
)
ORDER = RESULTS / "chacha20_round20_w46_a362_reader_sealed_a361_order_a364_v1.json"
CAUSAL = ORDER.with_suffix(".causal")
REPORT = ORDER.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w46_a362_reader_sealed_a361_order_a364.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_a362_reader_sealed_a361_order_a364.sh"

A361_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_fresh_a360_reader_deployment_a361.py"
A362_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_polarity_invariant_reader_a362.py"
A363_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_polarity_invariant_validation_a363.py"
A361_PROTOCOL = CONFIGS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_protocol_v1.json"
A361_PREFLIGHT = (
    RESULTS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_preflight_v1.json"
)
A361_MEASUREMENT = (
    RESULTS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_measurement_v1.json"
)
A362_RESULT = RESULTS / "chacha20_round20_w46_polarity_invariant_reader_a362_v1.json"

ATTEMPT_ID = "A364"
DESIGN_SHA256 = "a197962c366e6806a79c8eeb0c88f1a87574de4f390f9a0b1494c267eadad124"
A361_PROTOCOL_SHA256 = "3396559ab6fde25ef12f5fdcae68e33585234926885b88b136c1f4af47c13228"
A361_PREFLIGHT_SHA256 = "9158edea44ff3884d60308517a7ede1df6b0c0faff2732d520ab61efa88d3d0a"
A361_MEASUREMENT_SHA256 = "a074afc4da9ab4476acf1f09dd752fdc9937486f4a458d8594ef7815046c89dc"
A361_MEASUREMENT_COMMITMENT_SHA256 = (
    "9fc46a4e78b849f3e0d64b5dc591431e531682563907f78d0b80caa12e500b55"
)
A362_RESULT_SHA256 = "6c7ffb32effc2c0141e9f7ce02776a75e4e4772f18126a87bc84c61c6d45705e"
A362_SELECTION_COMMITMENT_SHA256 = (
    "4791833558d170ec540c7045b273e10e78a9f954c91c5a1d6f14bbc891a24032"
)
PRIMARY_NAME = "ensemble::linf_intersection::073-355-380-479"
PRIMARY_FEATURE_INDICES = (73, 355, 380, 479)
SLICES = tuple(range(16))
WITHIN_CELLS = 256
GROUPS = 4096
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A364 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A361 = load_module(A361_RUNNER, "a364_a361")
A362 = load_module(A362_RUNNER, "a364_a362")
A363 = load_module(A363_RUNNER, "a364_a363")
A360 = A362.A360
A275 = A362.A275

file_sha256 = A362.file_sha256
canonical_sha256 = A362.canonical_sha256
atomic_json = A362.atomic_json
atomic_bytes = A362.atomic_bytes
relative = A362.relative
path_from_ref = A362.path_from_ref
anchor = A362.anchor


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A364 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    gate = value.get("gate_contract", {})
    reader = value.get("reader_contract", {})
    measurement = value.get("sealed_measurement_contract", {})
    order = value.get("order_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w46-a362-reader-sealed-a361-order-a364-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A361_complete_measurement_and_A362_reader_before_A363_result_or_A361_shard_content_read"
        or gate.get("required_attempt") != "A363"
        or gate.get("retention_gate_passed_required") is not True
        or gate.get("A363_result_available_at_A364_design_freeze") is not False
        or reader.get("A362_result_sha256") != A362_RESULT_SHA256
        or reader.get("A362_selection_commitment_sha256") != A362_SELECTION_COMMITMENT_SHA256
        or reader.get("primary_definition") != PRIMARY_NAME
        or reader.get("primary_member_feature_indices") != list(PRIMARY_FEATURE_INDICES)
        or reader.get("reader_refits") != 0
        or measurement.get("A361_measurement_sha256") != A361_MEASUREMENT_SHA256
        or measurement.get("A361_measurement_commitment_sha256")
        != A361_MEASUREMENT_COMMITMENT_SHA256
        or measurement.get("complete_low4_slices") != len(SLICES)
        or measurement.get("complete_direct12_cells") != GROUPS
        or measurement.get("compressed_shard_semantics_read_before_A363_gate") is not False
        or order.get("group_count") != GROUPS
        or order.get("candidate_or_prefix_available_at_order_freeze") is not False
        or boundary.get("A361_secret_or_true_prefix_available") is not False
        or boundary.get("A361_compressed_measurement_shard_content_opened_before_A363_gate")
        is not False
        or boundary.get("A363_result_available_at_design_freeze") is not False
        or boundary.get("order_available_at_design_freeze") is not False
    ):
        raise RuntimeError("A364 frozen design semantics differ")
    for name, path_value in value["source_anchors"].items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, value["source_anchors"][f"{stem}_sha256"])
    return value


def _load_primary_definition() -> dict[str, Any]:
    result = A362.load_result(A362_RESULT_SHA256)
    primary = result["reader_selection"]["primary"]["definition"]
    if (
        result["selection_commitment_sha256"] != A362_SELECTION_COMMITMENT_SHA256
        or primary["name"] != PRIMARY_NAME
        or primary["member_feature_indices"] != list(PRIMARY_FEATURE_INDICES)
    ):
        raise RuntimeError("A364 frozen A362 primary differs")
    return primary


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A364 implementation already exists")
    if any(path.exists() for path in (ORDER, CAUSAL, REPORT)):
        raise RuntimeError("A364 implementation must precede its order")
    if A363.RESULT.exists():
        raise RuntimeError("A364 implementation must freeze before the A363 result")
    load_design()
    primary = _load_primary_definition()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A364 test and reproducer must exist before freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-a362-reader-sealed-a361-order-a364-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A363_result_A361_shard_read_order_candidate_or_prefix",
        "design_sha256": DESIGN_SHA256,
        "A362_result_sha256": A362_RESULT_SHA256,
        "A362_selection_commitment_sha256": A362_SELECTION_COMMITMENT_SHA256,
        "A361_measurement_sha256": A361_MEASUREMENT_SHA256,
        "A361_measurement_commitment_sha256": A361_MEASUREMENT_COMMITMENT_SHA256,
        "primary_definition": primary,
        "A363_result_available_at_implementation_freeze": False,
        "A361_compressed_measurement_shard_content_opened_before_implementation_freeze": False,
        "candidate_or_prefix_available_at_implementation_freeze": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A361_protocol": anchor(A361_PROTOCOL, A361_PROTOCOL_SHA256),
            "A361_preflight": anchor(A361_PREFLIGHT, A361_PREFLIGHT_SHA256),
            "A361_measurement": anchor(A361_MEASUREMENT, A361_MEASUREMENT_SHA256),
            "A362_result": anchor(A362_RESULT, A362_RESULT_SHA256),
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
        raise RuntimeError("A364 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-a362-reader-sealed-a361-order-a364-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_before_A363_result_A361_shard_read_order_candidate_or_prefix"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A362_result_sha256") != A362_RESULT_SHA256
        or value.get("A362_selection_commitment_sha256") != A362_SELECTION_COMMITMENT_SHA256
        or value.get("A361_measurement_sha256") != A361_MEASUREMENT_SHA256
        or value.get("A363_result_available_at_implementation_freeze") is not False
        or value.get(
            "A361_compressed_measurement_shard_content_opened_before_implementation_freeze"
        )
        is not False
        or value.get("candidate_or_prefix_available_at_implementation_freeze") is not False
    ):
        raise RuntimeError("A364 frozen implementation semantics differ")
    for name, path in {
        "design": DESIGN,
        "A361_protocol": A361_PROTOCOL,
        "A361_preflight": A361_PREFLIGHT,
        "A361_measurement": A361_MEASUREMENT,
        "A362_result": A362_RESULT,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }.items():
        row = value["anchors"][name]
        if row["path"] != relative(path) or row["sha256"] != file_sha256(path):
            raise RuntimeError(f"A364 implementation anchor differs: {name}")
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value["implementation_commitment_sha256"] != canonical_sha256(unsigned):
        raise RuntimeError("A364 implementation commitment differs")
    return value


def _validate_A363_gate(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(A363.RESULT) != expected_sha256:
        raise RuntimeError("A364 A363 result hash differs")
    value = json.loads(A363.RESULT.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w46-polarity-invariant-validation-a363-v1"
        or value.get("attempt_id") != "A363"
        or value.get("evidence_stage")
        != "PROSPECTIVE_NEW_CORPUS_POLARITY_INVARIANT_READER_RETAINED"
        or value.get("A362_result_sha256") != A362_RESULT_SHA256
        or value.get("A362_selection_commitment_sha256") != A362_SELECTION_COMMITMENT_SHA256
        or value.get("retention_gate", {}).get("passed") is not True
        or value.get("reader_refits_after_A362_selection_freeze") != 0
    ):
        raise RuntimeError("A364 A363 retention gate did not pass")
    for artifact in value["anchors"].values():
        anchor(path_from_ref(artifact["path"]), artifact["sha256"])
    anchor(path_from_ref(value["causal"]["path"]), value["causal"]["sha256"])
    return value


def _order_from_ranks(ranks: Sequence[int]) -> list[int]:
    values = [int(value) for value in ranks]
    if len(values) != WITHIN_CELLS or set(values) != set(range(1, WITHIN_CELLS + 1)):
        raise ValueError("A364 within-slice rank field differs")
    return sorted(range(WITHIN_CELLS), key=lambda cell: (values[cell], cell))


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    gated = "A363:prospective_reader_gate_passed"
    sealed = "A361:complete_sealed_unlabeled_direct12_field"
    scored = "A364:A362_primary_zero_refit_slice_ranks"
    ordered = "A364:exact_4096_group_order"
    writer = CausalWriter(api_id="a364ord")
    writer._rules = []
    rules = [
        (
            "gate_to_shard_read",
            "Only a passing A363 result unlocks semantic reads of the already committed A361 shards.",
            [gated],
            sealed,
        ),
        (
            "sealed_field_to_frozen_ranks",
            "The unchanged A362 primary maps every sealed slice to an exact within-slice rank field.",
            [sealed],
            scored,
        ),
        (
            "slice_ranks_to_round_robin_order",
            "Within-slice ranks compose into one exact 4,096-group Metal-prefix permutation.",
            [scored],
            ordered,
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
        trigger=gated,
        mechanism="conditional_unlock_after_prospective_new_corpus_retention_gate",
        outcome=sealed,
        confidence=1.0,
        source=payload["A363_result_sha256"],
        quantification=json.dumps(payload["A363_retention_gate"], sort_keys=True),
        evidence="A363 passed before A361 compressed shard semantic read",
        domain="ChaCha20 R20 W46 sealed-target deployment",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=sealed,
        mechanism="frozen_absolute_primitive_ranks_and_linf_intersection_without_refit",
        outcome=scored,
        confidence=1.0,
        source=payload["within_slice_rank_fields_sha256"],
        quantification=json.dumps(payload["selected_reader"], sort_keys=True),
        evidence="all sixteen complete A361 slices",
        domain="Sealed public-output Reader scoring",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=scored,
        mechanism="exact_rank_major_low4_round_robin_composition",
        outcome=ordered,
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=json.dumps(payload["order_summary"], sort_keys=True),
        evidence="complete 4,096-group permutation with zero candidate executions",
        domain="Metal group-order freeze",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=gated,
        mechanism="materialized_gate_sealed_field_reader_order_chain",
        outcome=ordered,
        confidence=1.0,
        source="materialized:A364_order_chain",
        quantification="exact retained closure",
        evidence="A364 frozen conditional deployment",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(name="A364 sealed A361 order", entities=[gated, sealed, scored, ordered])
    writer.add_gap(
        subject=ordered,
        predicate="next_required_object",
        expected_object_type="A365_complete_group_recovery_with_matched_control",
        confidence=1.0,
        suggested_queries=[
            "Execute the exact A364 order from rank one with the qualified A324 eight-slab engine and independently confirm any sole factual model."
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
        reader.api_id != "a364ord"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A364 authentic Causal reopen gate failed")
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


def freeze_order(
    *, expected_implementation_sha256: str, expected_A363_result_sha256: str
) -> dict[str, Any]:
    if any(path.exists() for path in (ORDER, CAUSAL, REPORT)):
        raise FileExistsError("A364 order already exists")
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    a363 = _validate_A363_gate(expected_A363_result_sha256)
    measurement = A361.load_measurement(
        A361_MEASUREMENT_SHA256, expected_protocol_sha256=A361_PROTOCOL_SHA256
    )
    if (
        measurement["measurement_commitment_sha256"] != A361_MEASUREMENT_COMMITMENT_SHA256
        or measurement["measurement_summary"]["reader_scoring_eligible"] is not True
    ):
        raise RuntimeError("A364 sealed A361 measurement differs")
    measurements = A361._measurement_map(  # noqa: SLF001
        measurement, protocol_sha256=A361_PROTOCOL_SHA256
    )
    primary = _load_primary_definition()
    rank_fields: dict[int, list[int]] = {}
    within_orders: dict[int, list[int]] = {}
    for low4 in SLICES:
        matrix = A360.target_normalize(A275._target_feature_matrix(measurements[low4]))  # noqa: SLF001
        primitives = A362.primitive_rank_fields(matrix)
        ranks = A362.candidate_rank_field(primitives, primary)
        rank_fields[low4] = [int(value) for value in ranks]
        within_orders[low4] = _order_from_ranks(ranks)
    selected_order = A361.compose_round_robin(within_orders)
    selected_order_hash = A361.order_sha256(selected_order)
    order_summary = {
        "groups": len(selected_order),
        "first_32_groups": selected_order[:32],
        "last_32_groups": selected_order[-32:],
        "selected_order_uint16be_sha256": selected_order_hash,
        "within_slice_orders_sha256": canonical_sha256(within_orders),
        "within_slice_rank_fields_sha256": canonical_sha256(rank_fields),
        "candidate_assignments_executed": 0,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-a362-reader-sealed-a361-order-a364-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "A363_GATED_SEALED_A361_POLARITY_INVARIANT_ORDER_FROZEN",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A363_result_sha256": expected_A363_result_sha256,
        "A363_result_commitment_sha256": a363["result_sha256"],
        "A363_retention_gate": a363["retention_gate"],
        "A361_protocol_sha256": A361_PROTOCOL_SHA256,
        "A361_measurement_sha256": A361_MEASUREMENT_SHA256,
        "A361_measurement_commitment_sha256": A361_MEASUREMENT_COMMITMENT_SHA256,
        "A362_result_sha256": A362_RESULT_SHA256,
        "A362_selection_commitment_sha256": A362_SELECTION_COMMITMENT_SHA256,
        "selected_reader": primary,
        "reader_refits": 0,
        "within_slice_rank_fields": [{"low4": low4, "ranks": rank_fields[low4]} for low4 in SLICES],
        "within_slice_rank_fields_sha256": canonical_sha256(rank_fields),
        "within_slice_orders": [{"low4": low4, "order": within_orders[low4]} for low4 in SLICES],
        "within_slice_orders_sha256": canonical_sha256(within_orders),
        "selected_order": selected_order,
        "selected_order_uint16be_sha256": selected_order_hash,
        "order_summary": order_summary,
        "A361_shard_content_read_only_after_A363_gate": True,
        "candidate_or_prefix_available_at_order_freeze": False,
        "candidate_assignments_executed": 0,
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A361_protocol": anchor(A361_PROTOCOL, A361_PROTOCOL_SHA256),
            "A361_preflight": anchor(A361_PREFLIGHT, A361_PREFLIGHT_SHA256),
            "A361_measurement": anchor(A361_MEASUREMENT, A361_MEASUREMENT_SHA256),
            "A362_result": anchor(A362_RESULT, A362_RESULT_SHA256),
            "A363_result": anchor(A363.RESULT, expected_A363_result_sha256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["order_commitment_sha256"] = canonical_sha256(
        {
            "implementation_commitment_sha256": payload["implementation_commitment_sha256"],
            "A363_result_commitment_sha256": payload["A363_result_commitment_sha256"],
            "A361_measurement_commitment_sha256": A361_MEASUREMENT_COMMITMENT_SHA256,
            "A362_selection_commitment_sha256": A362_SELECTION_COMMITMENT_SHA256,
            "selected_reader": primary,
            "within_slice_rank_fields_sha256": payload["within_slice_rank_fields_sha256"],
            "within_slice_orders_sha256": payload["within_slice_orders_sha256"],
            "selected_order_uint16be_sha256": selected_order_hash,
            "candidate_or_prefix_available_at_order_freeze": False,
            "candidate_assignments_executed": 0,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(ORDER, payload)
    atomic_bytes(
        REPORT,
        (
            "# A364 — sealed A361 polarity-invariant group order\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Reader: **{PRIMARY_NAME}**\n"
            f"- A363 gate: **{a363['retention_gate']['passed']}**\n"
            f"- Exact groups: **{GROUPS:,}**\n"
            f"- Order SHA-256: **{selected_order_hash}**\n"
            f"- First 32 groups: **{selected_order[:32]}**\n"
            "- Reader refits / candidate executions: **0 / 0**\n"
            "- Candidate or prefix available at freeze: **False**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def load_order(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(ORDER) != expected_sha256:
        raise RuntimeError("A364 order hash differs")
    value = json.loads(ORDER.read_bytes())
    selected = A361.exact_group_order(value.get("selected_order", []))
    if (
        value.get("schema") != "chacha20-round20-w46-a362-reader-sealed-a361-order-a364-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("evidence_stage") != "A363_GATED_SEALED_A361_POLARITY_INVARIANT_ORDER_FROZEN"
        or value.get("A363_retention_gate", {}).get("passed") is not True
        or value.get("selected_reader", {}).get("name") != PRIMARY_NAME
        or value.get("reader_refits") != 0
        or value.get("selected_order_uint16be_sha256") != A361.order_sha256(selected)
        or value.get("A361_shard_content_read_only_after_A363_gate") is not True
        or value.get("candidate_or_prefix_available_at_order_freeze") is not False
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A364 frozen order semantics differ")
    for artifact in value["anchors"].values():
        anchor(path_from_ref(artifact["path"]), artifact["sha256"])
    anchor(path_from_ref(value["causal"]["path"]), value["causal"]["sha256"])
    return value


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "implementation_sha256": file_sha256(IMPLEMENTATION) if IMPLEMENTATION.exists() else None,
        "A363_result_available": A363.RESULT.exists(),
        "order_frozen": ORDER.exists(),
        "order_sha256": file_sha256(ORDER) if ORDER.exists() else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-order", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-a363-result-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_order:
        if not args.expected_implementation_sha256 or not args.expected_a363_result_sha256:
            parser.error(
                "--freeze-order requires --expected-implementation-sha256 and --expected-a363-result-sha256"
            )
        payload = freeze_order(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_A363_result_sha256=args.expected_a363_result_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
