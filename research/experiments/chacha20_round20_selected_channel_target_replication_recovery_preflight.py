#!/usr/bin/env python3
"""Freeze A276 recovery only after A275's complete unlabeled target order exists."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

ATTEMPT_ID = "A276"
A275_PROTOCOL = (
    ROOT / "research/configs/chacha20_round20_selected_channel_target_replication_v1.json"
)
A275_RESULT = (
    ROOT / "research/results/v1/chacha20_round20_selected_channel_target_replication_order_v1.json"
)
A275_CAUSAL = A275_RESULT.with_suffix(".causal")
A275_RUNNER = Path(__file__).with_name(
    "chacha20_round20_selected_channel_target_replication_measure.py"
)
PUBLIC_CORE = Path(__file__).with_name("chacha20_round20_public_core.py")
TEMPLATE_PROTOCOL = ROOT / "research/configs/chacha20_round20_knownkey_propagation_atlas_v3.json"
TEMPLATE = Path(__file__).with_name("chacha20_round20_symbolic_template.py")
RANKED_WRAPPER = Path(__file__).with_name("chacha20_ranked_until_sat.py")
RANKED_SOURCE = ROOT / "research/native/cadical_ranked_until_sat.cpp"
INDEPENDENT_REFERENCE = ROOT / "src/arx_carry_leak/chacha20_rfc8439_reference.py"
RUNNER = Path(__file__).with_name(
    "chacha20_round20_selected_channel_target_replication_recovery.py"
)
OUTPUT = (
    ROOT / "research/configs/chacha20_round20_selected_channel_target_replication_recovery_v1.json"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)

A275_PROTOCOL_SHA256 = "d6e753defe3eba1e9989e8e6f792a6e731d8371487788917db0d7cff518c75f9"
A275_RUNNER_SHA256 = "218815280ce978aba16ba857db80828424e390cc1d141a1be3d33fb330c4e56b"
PUBLIC_CORE_SHA256 = "953e4478d369b2eb39657d4b6f718fa97a46cac1855b0364cce1bc4e4753f77f"
TEMPLATE_PROTOCOL_SHA256 = "aa5b7af87c74cbffe7f6d3e50332cc65c07f084435edb4314b32e4904b625698"
TEMPLATE_SHA256 = "34f4c5542f7fa12e7b0ff06ab7e042605c2414f23001f11894fa6dbdfc0b4721"
RANKED_WRAPPER_SHA256 = "692b98ae740f17b672226a5158c44f1b3b8a962189a591a3e2a188a9494920af"
RANKED_SOURCE_SHA256 = "8ff6e2621a5307f8bf04820debaa021ca60d33a1621406876e58531121e83f45"
INDEPENDENT_REFERENCE_SHA256 = "df67f3329ad71b8dc4db7103ce9e42700cebf185bc77395fa8a3c982c6d824f5"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _canonical_sha256(value: Any) -> str:
    return _sha256(_canonical_bytes(value))


def _atomic_json(path: Path, value: Any) -> None:
    raw = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False).encode(
            "ascii"
        )
        + b"\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A276 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_dotcausal() -> Any:
    try:
        return importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not DEFAULT_DOTCAUSAL_SRC.is_dir():
            raise FileNotFoundError("dotcausal source is unavailable") from None
        sys.path.insert(0, str(DEFAULT_DOTCAUSAL_SRC))
        return importlib.import_module("dotcausal.io")


def _validate_a275() -> tuple[dict[str, Any], dict[str, Any], list[int], Path]:
    if not A275_RESULT.is_file() or not A275_CAUSAL.is_file():
        raise FileNotFoundError("A275 result and authentic Causal artifact must exist first")
    if (
        _file_sha256(A275_PROTOCOL) != A275_PROTOCOL_SHA256
        or _file_sha256(A275_RUNNER) != A275_RUNNER_SHA256
    ):
        raise RuntimeError("A276 A275 protocol or runner anchor differs")
    protocol = json.loads(A275_PROTOCOL.read_bytes())
    result = json.loads(A275_RESULT.read_bytes())
    measurement_path = ROOT / result.get("measurement", {}).get("path", "")
    if (
        protocol.get("schema") != "chacha20-round20-selected-channel-target-replication-protocol-v1"
        or result.get("schema")
        != "chacha20-round20-selected-channel-target-replication-order-result-v1"
        or result.get("evidence_stage")
        != "FULLROUND_R20_TARGET_BLIND_SELECTED_CHANNEL_REPLICATION_ORDER_FROZEN"
        or result.get("protocol_sha256") != A275_PROTOCOL_SHA256
        or result.get("runner_sha256") != A275_RUNNER_SHA256
        or result.get("public_challenge_sha256")
        != protocol.get("target", {}).get("public_challenge_sha256")
        or result.get("measurement", {}).get("complete_candidate_cover") is not True
        or not measurement_path.is_file()
        or _file_sha256(measurement_path) != result.get("measurement", {}).get("compressed_sha256")
    ):
        raise RuntimeError("A276 A275 result identity gate failed")

    runner = _import_path(A275_RUNNER, "a276_a275_measurement_validator")
    (
        loaded_protocol,
        _,
        _,
        _,
        _,
        _,
        model,
        indices,
    ) = runner._load_protocol(A275_PROTOCOL, A275_PROTOCOL_SHA256)
    if loaded_protocol != protocol:
        raise RuntimeError("A276 A275 runner protocol readback differs")
    measurement, measurement_ledger = runner._read_measurement(
        measurement_path,
        expected_protocol_sha256=A275_PROTOCOL_SHA256,
        expected_target_sha256=protocol["target"]["public_challenge_sha256"],
    )
    recorded_measurement = result.get("measurement", {})
    ledger_fields = (
        "path",
        "raw_bytes",
        "raw_sha256",
        "compressed_bytes",
        "compressed_sha256",
    )
    if (
        any(recorded_measurement.get(field) != measurement_ledger[field] for field in ledger_fields)
        or measurement.get("order_name") != "numeric"
        or measurement.get("public_target_block_sha256")
        != protocol["target"]["target_block_sha256"]
        or measurement.get("target_label_available_to_measurement") is not False
        or measurement.get("label_used_for_feature_construction_or_scoring") is not False
        or recorded_measurement.get("complete_candidate_cover") is not True
        or recorded_measurement.get("accepted_learned_clauses")
        != measurement["run"]["summary"]["learned_clause_accepted_total"]
        or recorded_measurement.get("rejected_over_64_literal_clauses")
        != measurement["run"]["summary"]["learned_clause_rejected_large_total"]
    ):
        raise RuntimeError("A276 A275 semantic measurement ledger differs")

    matrix = runner._target_feature_matrix(measurement)
    contributions = runner.standardized_contributions(
        matrix,
        means=model.means,
        scales=model.scales,
        coefficients=model.coefficients,
    )
    scores = contributions[:, indices].sum(axis=1)
    order = runner._candidate_order(scores)
    top128 = order[:128]
    expected_analysis = {
        "score_field": scores.tolist(),
        "score_field_sha256": runner._canonical_sha256(scores.tolist()),
        "complete_cell_order": order,
        "complete_cell_order_uint8_sha256": _sha256(bytes(order)),
        "top128_cell_order": top128,
        "top128_cell_order_uint8_sha256": _sha256(bytes(top128)),
        "order_tiebreak": "descending_score_then_ascending_candidate",
        "selected_feature_indices": list(indices),
        "model_refits": 0,
        "target_labels_used": 0,
    }
    expected_headline = {
        "complete_candidate_cells": 256,
        "complete_order_uint8_sha256": expected_analysis["complete_cell_order_uint8_sha256"],
        "top128_order_uint8_sha256": expected_analysis["top128_cell_order_uint8_sha256"],
        "top128_assignment_bits": 19,
        "target_label_available": False,
    }
    if (
        result.get("analysis") != expected_analysis
        or result.get("analysis_sha256") != runner._canonical_sha256(expected_analysis)
        or result.get("headline") != expected_headline
        or result.get("protocol_state") != protocol["protocol_state"]
        or result.get("selected_hypothesis") != protocol["selected_hypothesis"]
        or result.get("A272_result_sha256") != protocol["anchors"]["A272_result_sha256"]
        or result.get("A274_result_sha256") != protocol["anchors"]["A274_result_sha256"]
        or result.get("information_boundary") != protocol["information_boundary"]
    ):
        raise RuntimeError("A276 recomputed A275 score or order differs")
    runner._assert_secret_free(result)

    causal = result.get("causal", {})
    if (
        _file_sha256(A275_CAUSAL) != causal.get("file_sha256")
        or causal.get("format") != "authentic_dotcausal_v1_AI_native"
        or causal.get("integrity_verified_by_authoritative_reader") is not True
        or causal.get("api_id") != "a275"
        or causal.get("explicit_triplets") != 2
        or causal.get("materialized_inferred_triplets") != 1
        or causal.get("embedded_rules") != 2
        or causal.get("clusters") != 1
        or causal.get("gaps") != 1
    ):
        raise RuntimeError("A276 A275 authentic Causal gate failed")
    reader = _load_dotcausal().CausalReader(str(A275_CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    terminal = all_rows[-1] if all_rows else {}
    gap = reader._gaps[0] if len(reader._gaps) == 1 else {}
    readback = causal.get("personal_semantic_readback", {})
    if (
        reader.version != 1
        or reader.api_id != "a275"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or explicit[0].get("source") != protocol["anchors"]["A274_result_sha256"]
        or explicit[0].get("outcome") != "A275:target_blind_reader_contract"
        or explicit[1].get("source") != result["analysis_sha256"]
        or explicit[1].get("outcome") != "A275:hash_frozen_target_candidate_order"
        or json.loads(explicit[1].get("evidence", "null")) != expected_headline
        or terminal.get("source")
        != "materialized:A274_confirmation_plus_A275_complete_target_cover"
        or terminal.get("outcome") != "A275:hash_frozen_target_candidate_order"
        or terminal.get("is_inferred") is not True
        or gap.get("expected_object_type")
        != "hash_frozen_top128_retained_state_replication_recovery"
        or readback.get("terminal_chain") != terminal
        or readback.get("next_gap") != gap
    ):
        raise RuntimeError("A276 personal A275 Causal readback differs")
    return protocol, result, order, measurement_path


def build_protocol() -> dict[str, Any]:
    if OUTPUT.exists():
        raise FileExistsError(f"A276 protocol already exists: {OUTPUT}")
    fixed = {
        A275_PROTOCOL: A275_PROTOCOL_SHA256,
        A275_RUNNER: A275_RUNNER_SHA256,
        PUBLIC_CORE: PUBLIC_CORE_SHA256,
        TEMPLATE_PROTOCOL: TEMPLATE_PROTOCOL_SHA256,
        TEMPLATE: TEMPLATE_SHA256,
        RANKED_WRAPPER: RANKED_WRAPPER_SHA256,
        RANKED_SOURCE: RANKED_SOURCE_SHA256,
        INDEPENDENT_REFERENCE: INDEPENDENT_REFERENCE_SHA256,
    }
    for path, expected in fixed.items():
        if _file_sha256(path) != expected:
            raise RuntimeError(f"A276 anchored dependency differs: {path.name}")
    if not RUNNER.is_file():
        raise FileNotFoundError("A276 recovery runner must exist before protocol freeze")
    a275_protocol, a275_result, order, measurement_path = _validate_a275()
    ranked = _import_path(RANKED_WRAPPER, "a276_ranked_preflight")
    build = ranked.compile_helper()
    if build["source_sha256"] != RANKED_SOURCE_SHA256 or not isinstance(
        build.get("binary_sha256"), str
    ):
        raise RuntimeError("A276 ranked helper preflight differs")
    binary = Path(build["command"][-1])
    anchors = {
        "A275_protocol_path": str(A275_PROTOCOL.relative_to(ROOT)),
        "A275_protocol_sha256": A275_PROTOCOL_SHA256,
        "A275_result_path": str(A275_RESULT.relative_to(ROOT)),
        "A275_result_sha256": _file_sha256(A275_RESULT),
        "A275_causal_path": str(A275_CAUSAL.relative_to(ROOT)),
        "A275_causal_sha256": _file_sha256(A275_CAUSAL),
        "A275_measurement_path": str(measurement_path.relative_to(ROOT)),
        "A275_measurement_sha256": _file_sha256(measurement_path),
        "A275_runner_path": str(A275_RUNNER.relative_to(ROOT)),
        "A275_runner_sha256": A275_RUNNER_SHA256,
        "public_core_path": str(PUBLIC_CORE.relative_to(ROOT)),
        "public_core_sha256": PUBLIC_CORE_SHA256,
        "symbolic_template_protocol_path": str(TEMPLATE_PROTOCOL.relative_to(ROOT)),
        "symbolic_template_protocol_sha256": TEMPLATE_PROTOCOL_SHA256,
        "symbolic_template_path": str(TEMPLATE.relative_to(ROOT)),
        "symbolic_template_sha256": TEMPLATE_SHA256,
        "ranked_helper_wrapper_path": str(RANKED_WRAPPER.relative_to(ROOT)),
        "ranked_helper_wrapper_sha256": RANKED_WRAPPER_SHA256,
        "ranked_helper_source_path": str(RANKED_SOURCE.relative_to(ROOT)),
        "ranked_helper_source_sha256": RANKED_SOURCE_SHA256,
        "ranked_helper_binary_path": str(binary.relative_to(ROOT)),
        "ranked_helper_binary_sha256": build["binary_sha256"],
        "independent_reference_path": str(INDEPENDENT_REFERENCE.relative_to(ROOT)),
        "independent_reference_sha256": INDEPENDENT_REFERENCE_SHA256,
        "runner_path": str(RUNNER.relative_to(ROOT)),
        "runner_sha256": _file_sha256(RUNNER),
    }
    return {
        "schema": "chacha20-round20-selected-channel-target-replication-recovery-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_after_complete_A275_unlabeled_target_order_and_before_any_A276_ranked_solver_execution_model_or_confirmation",
        "research_question": "Does A272's unchanged prospectively retained channel reproduce the A274 search advantage on a second distinct full-round ChaCha20-R20 target while executing at most the top half of the 20-bit residual domain?",
        "anchors": anchors,
        "target": {
            "public_challenge_sha256": a275_result["public_challenge_sha256"],
            "target_block_sha256": a275_protocol["target"]["target_block_sha256"],
            "generation_label_available": False,
            "replication_index": 2,
        },
        "frozen_reader_order": {
            "source_attempt": "A275",
            "complete_cell_order": order,
            "complete_cell_order_uint8_sha256": _sha256(bytes(order)),
            "top128_cell_order": order[:128],
            "top128_cell_order_uint8_sha256": _sha256(bytes(order[:128])),
            "order_change_permitted": False,
            "correct_prefix_or_rank_known": False,
        },
        "solver_protocol": {
            "formula": "target_independent_symbolic_R20_base_plus_512_public_output_units",
            "state_retention": "one_CaDiCaL_instance_across_ordered_prefix_cells",
            "seconds_per_cell": 30.0,
            "maximum_cells": 128,
            "maximum_logical_assignments": 2**19,
            "full_residual_domain_assignments": 2**20,
            "stop_condition": "first_SAT_only",
            "unknown_semantics": "per_cell_time_horizon_exhausted_not_UNSAT",
            "external_timeout_seconds": 4200.0,
        },
        "claim_gate": {
            "SAT_model_required": True,
            "all_eight_standard_R20_blocks_must_match": True,
            "independent_RFC8439_implementation_must_match": True,
            "flipped_first_block_control_must_reject": True,
            "output_bits_confirmed": 4096,
            "strictly_fewer_than_full_2pow20_prefix_suffix_assignments_required": True,
        },
        "information_boundary": {
            "target_generation_label_available_before_or_during_execution": False,
            "correct_prefix_or_A275_target_rank_known_before_execution": False,
            "A275_order_may_not_change_after_freeze": True,
            "A275_measurement_was_complete_model_free_and_unlabeled": True,
            "recovery_stops_only_on_first_SAT": True,
            "confirmation_occurs_only_after_solver_model": True,
        },
    }


def verify_frozen_protocol(protocol_path: Path, expected_protocol_sha256: str) -> dict[str, Any]:
    """Authenticate an existing A276 freeze without compiling or executing it."""

    actual_sha256 = _file_sha256(protocol_path)
    if actual_sha256 != expected_protocol_sha256:
        raise RuntimeError("A276 frozen recovery protocol hash differs")
    a275_protocol, a275_result, order, measurement_path = _validate_a275()
    protocol = json.loads(protocol_path.read_bytes())
    anchors = protocol.get("anchors", {})
    frozen = protocol.get("frozen_reader_order", {})
    solver = protocol.get("solver_protocol", {})
    claim = protocol.get("claim_gate", {})
    boundary = protocol.get("information_boundary", {})
    expected_a275_anchors = {
        "A275_protocol_path": str(A275_PROTOCOL.relative_to(ROOT)),
        "A275_protocol_sha256": A275_PROTOCOL_SHA256,
        "A275_result_path": str(A275_RESULT.relative_to(ROOT)),
        "A275_result_sha256": _file_sha256(A275_RESULT),
        "A275_causal_path": str(A275_CAUSAL.relative_to(ROOT)),
        "A275_causal_sha256": _file_sha256(A275_CAUSAL),
        "A275_measurement_path": str(measurement_path.relative_to(ROOT)),
        "A275_measurement_sha256": _file_sha256(measurement_path),
        "A275_runner_path": str(A275_RUNNER.relative_to(ROOT)),
        "A275_runner_sha256": A275_RUNNER_SHA256,
    }
    expected_dependency_anchors = {
        "public_core_path": str(PUBLIC_CORE.relative_to(ROOT)),
        "public_core_sha256": PUBLIC_CORE_SHA256,
        "symbolic_template_protocol_path": str(TEMPLATE_PROTOCOL.relative_to(ROOT)),
        "symbolic_template_protocol_sha256": TEMPLATE_PROTOCOL_SHA256,
        "symbolic_template_path": str(TEMPLATE.relative_to(ROOT)),
        "symbolic_template_sha256": TEMPLATE_SHA256,
        "ranked_helper_wrapper_path": str(RANKED_WRAPPER.relative_to(ROOT)),
        "ranked_helper_wrapper_sha256": RANKED_WRAPPER_SHA256,
        "ranked_helper_source_path": str(RANKED_SOURCE.relative_to(ROOT)),
        "ranked_helper_source_sha256": RANKED_SOURCE_SHA256,
        "independent_reference_path": str(INDEPENDENT_REFERENCE.relative_to(ROOT)),
        "independent_reference_sha256": INDEPENDENT_REFERENCE_SHA256,
        "runner_path": str(RUNNER.relative_to(ROOT)),
        "runner_sha256": _file_sha256(RUNNER),
    }
    expected_anchor_keys = {
        *expected_a275_anchors,
        *expected_dependency_anchors,
        "ranked_helper_binary_path",
        "ranked_helper_binary_sha256",
    }
    if (
        set(anchors) != expected_anchor_keys
        or any(anchors.get(key) != value for key, value in expected_a275_anchors.items())
        or any(anchors.get(key) != value for key, value in expected_dependency_anchors.items())
    ):
        raise RuntimeError("A276 frozen A275 anchor set differs")
    for path_key, path_value in anchors.items():
        if not path_key.endswith("_path"):
            continue
        hash_key = f"{path_key.removesuffix('_path')}_sha256"
        if _file_sha256(ROOT / path_value) != anchors.get(hash_key):
            raise RuntimeError(f"A276 frozen dependency hash differs: {path_key}")
    top128 = order[:128]
    if (
        protocol.get("schema")
        != "chacha20-round20-selected-channel-target-replication-recovery-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_complete_A275_unlabeled_target_order_and_before_any_A276_ranked_solver_execution_model_or_confirmation"
        or protocol.get("target", {}).get("public_challenge_sha256")
        != a275_result["public_challenge_sha256"]
        or protocol.get("target", {}).get("target_block_sha256")
        != a275_protocol["target"]["target_block_sha256"]
        or protocol.get("target", {}).get("generation_label_available") is not False
        or protocol.get("target", {}).get("replication_index") != 2
        or frozen.get("source_attempt") != "A275"
        or frozen.get("complete_cell_order") != order
        or frozen.get("complete_cell_order_uint8_sha256") != _sha256(bytes(order))
        or frozen.get("top128_cell_order") != top128
        or frozen.get("top128_cell_order_uint8_sha256") != _sha256(bytes(top128))
        or frozen.get("order_change_permitted") is not False
        or frozen.get("correct_prefix_or_rank_known") is not False
        or solver
        != {
            "formula": "target_independent_symbolic_R20_base_plus_512_public_output_units",
            "state_retention": "one_CaDiCaL_instance_across_ordered_prefix_cells",
            "seconds_per_cell": 30.0,
            "maximum_cells": 128,
            "maximum_logical_assignments": 2**19,
            "full_residual_domain_assignments": 2**20,
            "stop_condition": "first_SAT_only",
            "unknown_semantics": "per_cell_time_horizon_exhausted_not_UNSAT",
            "external_timeout_seconds": 4200.0,
        }
        or claim
        != {
            "SAT_model_required": True,
            "all_eight_standard_R20_blocks_must_match": True,
            "independent_RFC8439_implementation_must_match": True,
            "flipped_first_block_control_must_reject": True,
            "output_bits_confirmed": 4096,
            "strictly_fewer_than_full_2pow20_prefix_suffix_assignments_required": True,
        }
        or boundary
        != {
            "target_generation_label_available_before_or_during_execution": False,
            "correct_prefix_or_A275_target_rank_known_before_execution": False,
            "A275_order_may_not_change_after_freeze": True,
            "A275_measurement_was_complete_model_free_and_unlabeled": True,
            "recovery_stops_only_on_first_SAT": True,
            "confirmation_occurs_only_after_solver_model": True,
        }
    ):
        raise RuntimeError("A276 frozen protocol semantic authentication failed")
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol": str(protocol_path),
        "protocol_sha256": actual_sha256,
        "A275_result_sha256": _file_sha256(A275_RESULT),
        "A275_measurement_sha256": _file_sha256(measurement_path),
        "complete_order_sha256": _sha256(bytes(order)),
        "top128_order_sha256": _sha256(bytes(top128)),
        "maximum_cells": 128,
        "target_generation_label_available": False,
        "authenticated_without_solver_execution": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", action="store_true")
    parser.add_argument("--verify-frozen", type=Path)
    parser.add_argument("--expected-protocol-sha256")
    args = parser.parse_args()
    if args.freeze and args.verify_frozen is not None:
        parser.error("--freeze and --verify-frozen are mutually exclusive")
    if args.verify_frozen is not None:
        if not args.expected_protocol_sha256:
            parser.error("--verify-frozen requires --expected-protocol-sha256")
        print(
            json.dumps(
                verify_frozen_protocol(
                    args.verify_frozen,
                    args.expected_protocol_sha256,
                ),
                indent=2,
                sort_keys=True,
            )
        )
        return
    if not args.freeze:
        print(json.dumps({"attempt_id": ATTEMPT_ID, "output": str(OUTPUT)}, indent=2))
        return
    protocol = build_protocol()
    _atomic_json(OUTPUT, protocol)
    print(
        json.dumps(
            {
                "output": str(OUTPUT),
                "protocol_sha256": _file_sha256(OUTPUT),
                "A275_result_sha256": protocol["anchors"]["A275_result_sha256"],
                "top128_order_sha256": protocol["frozen_reader_order"][
                    "top128_cell_order_uint8_sha256"
                ],
                "maximum_logical_assignments": 2**19,
                "target_generation_label_available": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
