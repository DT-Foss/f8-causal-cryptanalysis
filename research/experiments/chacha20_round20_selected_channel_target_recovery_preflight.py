#!/usr/bin/env python3
"""Freeze A274 recovery only after A273's complete unlabeled target order exists."""

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

ATTEMPT_ID = "A274"
A273_PROTOCOL = ROOT / "research/configs/chacha20_round20_selected_channel_target_v1.json"
A273_RESULT = (
    ROOT / "research/results/v1/chacha20_round20_selected_channel_target_order_v1.json"
)
A273_CAUSAL = A273_RESULT.with_suffix(".causal")
A273_RUNNER = Path(__file__).with_name("chacha20_round20_selected_channel_target_measure.py")
PUBLIC_CORE = Path(__file__).with_name("chacha20_round20_public_core.py")
TEMPLATE_PROTOCOL = (
    ROOT / "research/configs/chacha20_round20_knownkey_propagation_atlas_v3.json"
)
TEMPLATE = Path(__file__).with_name("chacha20_round20_symbolic_template.py")
RANKED_WRAPPER = Path(__file__).with_name("chacha20_ranked_until_sat.py")
RANKED_SOURCE = ROOT / "research/native/cadical_ranked_until_sat.cpp"
INDEPENDENT_REFERENCE = ROOT / "src/arx_carry_leak/chacha20_rfc8439_reference.py"
RUNNER = Path(__file__).with_name("chacha20_round20_selected_channel_target_recovery.py")
OUTPUT = (
    ROOT / "research/configs/chacha20_round20_selected_channel_target_recovery_v1.json"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)

A273_PROTOCOL_SHA256 = "28ab0b12e7f58b8e4096fd278d4f88991e7af3797f104202d84d3a70f7b85600"
A273_RUNNER_SHA256 = "4ab909384ee49206c4ecede6c3bb41d91ee583986e6224fefd1f92e5b7733bb2"
PUBLIC_CORE_SHA256 = "953e4478d369b2eb39657d4b6f718fa97a46cac1855b0364cce1bc4e4753f77f"
TEMPLATE_PROTOCOL_SHA256 = "aa5b7af87c74cbffe7f6d3e50332cc65c07f084435edb4314b32e4904b625698"
TEMPLATE_SHA256 = "34f4c5542f7fa12e7b0ff06ab7e042605c2414f23001f11894fa6dbdfc0b4721"
RANKED_WRAPPER_SHA256 = "692b98ae740f17b672226a5158c44f1b3b8a962189a591a3e2a188a9494920af"
RANKED_SOURCE_SHA256 = "8ff6e2621a5307f8bf04820debaa021ca60d33a1621406876e58531121e83f45"
INDEPENDENT_REFERENCE_SHA256 = (
    "df67f3329ad71b8dc4db7103ce9e42700cebf185bc77395fa8a3c982c6d824f5"
)


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
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
        .encode("ascii")
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
        raise RuntimeError(f"cannot import A274 dependency {path}")
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


def _validate_a273() -> tuple[dict[str, Any], dict[str, Any], list[int], Path]:
    if not A273_RESULT.is_file() or not A273_CAUSAL.is_file():
        raise FileNotFoundError("A273 result and authentic Causal artifact must exist first")
    protocol = json.loads(A273_PROTOCOL.read_bytes())
    result = json.loads(A273_RESULT.read_bytes())
    analysis = result.get("analysis", {})
    order = analysis.get("complete_cell_order", [])
    measurement_path = ROOT / result.get("measurement", {}).get("path", "")
    if (
        protocol.get("schema") != "chacha20-round20-selected-channel-target-protocol-v1"
        or result.get("schema")
        != "chacha20-round20-selected-channel-target-order-result-v1"
        or result.get("evidence_stage")
        != "FULLROUND_R20_TARGET_BLIND_SELECTED_CHANNEL_ORDER_FROZEN"
        or result.get("protocol_sha256") != A273_PROTOCOL_SHA256
        or result.get("runner_sha256") != A273_RUNNER_SHA256
        or result.get("public_challenge_sha256")
        != protocol.get("target", {}).get("public_challenge_sha256")
        or result.get("measurement", {}).get("complete_candidate_cover") is not True
        or not measurement_path.is_file()
        or _file_sha256(measurement_path)
        != result.get("measurement", {}).get("compressed_sha256")
        or len(order) != 256
        or set(order) != set(range(256))
        or _sha256(bytes(order)) != analysis.get("complete_cell_order_uint8_sha256")
        or analysis.get("top128_cell_order") != order[:128]
        or _sha256(bytes(order[:128])) != analysis.get("top128_cell_order_uint8_sha256")
        or analysis.get("model_refits") != 0
        or analysis.get("target_labels_used") != 0
        or result.get("headline", {}).get("target_label_available") is not False
        or result.get("information_boundary", {}).get(
            "target_generation_label_stored_in_protocol_result_Causal_or_report"
        )
        is not False
    ):
        raise RuntimeError("A274 A273 result/order gate failed")
    causal = result.get("causal", {})
    if (
        _file_sha256(A273_CAUSAL) != causal.get("file_sha256")
        or causal.get("format") != "authentic_dotcausal_v1_AI_native"
        or causal.get("integrity_verified_by_authoritative_reader") is not True
        or causal.get("personal_semantic_readback", {})
        .get("next_gap", {})
        .get("expected_object_type")
        != "hash_frozen_top128_retained_state_target_recovery"
    ):
        raise RuntimeError("A274 A273 authentic Causal gate failed")
    reader = _load_dotcausal().CausalReader(str(A273_CAUSAL), verify_integrity=True)
    if (
        reader.version != 1
        or reader.api_id != "a273"
        or len(reader._gaps) != 1
        or reader._gaps[0].get("expected_object_type")
        != "hash_frozen_top128_retained_state_target_recovery"
    ):
        raise RuntimeError("A274 personal A273 Causal readback differs")
    return protocol, result, [int(value) for value in order], measurement_path


def build_protocol() -> dict[str, Any]:
    if OUTPUT.exists():
        raise FileExistsError(f"A274 protocol already exists: {OUTPUT}")
    fixed = {
        A273_PROTOCOL: A273_PROTOCOL_SHA256,
        A273_RUNNER: A273_RUNNER_SHA256,
        PUBLIC_CORE: PUBLIC_CORE_SHA256,
        TEMPLATE_PROTOCOL: TEMPLATE_PROTOCOL_SHA256,
        TEMPLATE: TEMPLATE_SHA256,
        RANKED_WRAPPER: RANKED_WRAPPER_SHA256,
        RANKED_SOURCE: RANKED_SOURCE_SHA256,
        INDEPENDENT_REFERENCE: INDEPENDENT_REFERENCE_SHA256,
    }
    for path, expected in fixed.items():
        if _file_sha256(path) != expected:
            raise RuntimeError(f"A274 anchored dependency differs: {path.name}")
    if not RUNNER.is_file():
        raise FileNotFoundError("A274 recovery runner must exist before protocol freeze")
    a273_protocol, a273_result, order, measurement_path = _validate_a273()
    ranked = _import_path(RANKED_WRAPPER, "a274_ranked_preflight")
    build = ranked.compile_helper()
    if (
        build["source_sha256"] != RANKED_SOURCE_SHA256
        or not isinstance(build.get("binary_sha256"), str)
    ):
        raise RuntimeError("A274 ranked helper preflight differs")
    binary = Path(build["command"][-1])
    anchors = {
        "A273_protocol_path": str(A273_PROTOCOL.relative_to(ROOT)),
        "A273_protocol_sha256": A273_PROTOCOL_SHA256,
        "A273_result_path": str(A273_RESULT.relative_to(ROOT)),
        "A273_result_sha256": _file_sha256(A273_RESULT),
        "A273_causal_path": str(A273_CAUSAL.relative_to(ROOT)),
        "A273_causal_sha256": _file_sha256(A273_CAUSAL),
        "A273_measurement_path": str(measurement_path.relative_to(ROOT)),
        "A273_measurement_sha256": _file_sha256(measurement_path),
        "A273_runner_path": str(A273_RUNNER.relative_to(ROOT)),
        "A273_runner_sha256": A273_RUNNER_SHA256,
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
        "schema": "chacha20-round20-selected-channel-target-recovery-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_after_complete_A273_unlabeled_target_order_and_before_any_A274_ranked_solver_execution_model_or_confirmation",
        "research_question": "Does A272's prospectively retained channel recover a separately generated full-round ChaCha20-R20 target while executing at most the top half of the 20-bit residual domain?",
        "anchors": anchors,
        "target": {
            "public_challenge_sha256": a273_result["public_challenge_sha256"],
            "target_block_sha256": a273_protocol["target"]["target_block_sha256"],
            "generation_label_available": False,
        },
        "frozen_reader_order": {
            "source_attempt": "A273",
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
            "correct_prefix_or_A273_target_rank_known_before_execution": False,
            "A273_order_may_not_change_after_freeze": True,
            "A273_measurement_was_complete_model_free_and_unlabeled": True,
            "recovery_stops_only_on_first_SAT": True,
            "confirmation_occurs_only_after_solver_model": True,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", action="store_true")
    args = parser.parse_args()
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
                "A273_result_sha256": protocol["anchors"]["A273_result_sha256"],
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
