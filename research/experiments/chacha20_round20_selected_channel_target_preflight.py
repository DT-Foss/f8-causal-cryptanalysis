#!/usr/bin/env python3
"""Freeze A273's fresh secret-free R20 target before any target measurement."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import secrets
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

ATTEMPT_ID = "A273"
A220_PROTOCOL = ROOT / "research/configs/chacha20_round20_factorial_trajectory_transfer_v1.json"
A220_DESIGN = ROOT / "research/experiments/chacha20_round20_factorial_key_design.py"
A268_PREFLIGHT = (
    ROOT
    / "research/provenance/chacha20_round20_a268_prospective_trajectory_shape_preflight_v1.json"
)
A268_PREFLIGHT_RUNNER = Path(__file__).with_name(
    "chacha20_round20_prospective_trajectory_shape_preflight.py"
)
A272_PROTOCOL = (
    ROOT
    / "research/configs/chacha20_round20_selected_channel_prospective_validation_v1.json"
)
A272_RESULT = (
    ROOT
    / "research/results/v1/chacha20_round20_selected_channel_prospective_validation_v1.json"
)
A272_CAUSAL = A272_RESULT.with_suffix(".causal")
A272_RUNNER = Path(__file__).with_name(
    "chacha20_round20_selected_channel_prospective_validation.py"
)
PUBLIC_CORE = Path(__file__).with_name("chacha20_round20_public_core.py")
SHAPE_SOURCE = ROOT / "src/arx_carry_leak/solver_trajectory_shape.py"
CONTRIBUTION_SOURCE = ROOT / "src/arx_carry_leak/trajectory_contribution.py"
RUNNER = Path(__file__).with_name("chacha20_round20_selected_channel_target_measure.py")
OUTPUT = ROOT / "research/configs/chacha20_round20_selected_channel_target_v1.json"

A220_PROTOCOL_SHA256 = "70df07cb4f4f22115e3aa63765de0fca0dd610607cc87356946a188f53fe5645"
A220_DESIGN_SHA256 = "ad34f5ee660e164ea6af63b1e6d0acd10108038afdb98266be2a80b954d4eeea"
A268_PREFLIGHT_SHA256 = "d8fdbb88254b40ea90812c29563baf8f82b693d5fa9980f28a116089abfa9a17"
A272_PROTOCOL_SHA256 = "67c568baf4ac5a4d7191cca2ac7bbe4e07e62a81475b51ba838be3f011d6220f"
A272_RESULT_SHA256 = "41460e75bed006f5df23057151d22d594d30e88b55f6320f28462e24945f18da"
A272_CAUSAL_SHA256 = "18b1d58b74af5e7d6b66622f9607ce751a7911da802c1d058715bcd892d9de3f"
A272_RUNNER_SHA256 = "a973d10d6f4a8835ff58d0254ae3c220170a018e75ec5494639dbcad1e0a70c1"
PUBLIC_CORE_SHA256 = "953e4478d369b2eb39657d4b6f718fa97a46cac1855b0364cce1bc4e4753f77f"
SHAPE_SOURCE_SHA256 = "44056b27937c1b4f1ab9af2dfaf904ad3b5f239deda05519c2e9a16f9f1e8160"
CONTRIBUTION_SOURCE_SHA256 = "edcee636acf826a7c7cc737bd72193731b2272986857156543762baa6054aba3"
SELECTED_FEATURE_INDICES = [502, 504, 505, 508, 509, 510, 511, 514]
FORBIDDEN_SERIALIZED_KEYS = {
    "known_low20",
    "low20",
    "low20_hex",
    "recovered_unknown_low20",
    "recovered_unknown_low20_hex",
    "salt",
    "salt_hex",
    "secret_low20",
    "target_prefix8",
    "true_prefix",
    "unknown_assignment",
    "unknown_key_word0_low_value",
}


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
        raise RuntimeError(f"cannot import A273 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def assert_secret_free(value: Any) -> None:
    """Reject serialization of the discarded target label at any depth."""

    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).lower() in FORBIDDEN_SERIALIZED_KEYS:
                raise RuntimeError(f"A273 secret-bearing field is forbidden: {key}")
            assert_secret_free(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            assert_secret_free(child)


def _prior_geometry() -> dict[str, Any]:
    design = _import_path(A220_DESIGN, "a273_factorial_design")
    old = _import_path(A268_PREFLIGHT_RUNNER, "a273_a268_preflight")
    a220 = json.loads(A220_PROTOCOL.read_bytes())
    a268 = json.loads(A268_PREFLIGHT.read_bytes())
    a272 = json.loads(A272_PROTOCOL.read_bytes())
    low20 = {int(row["low20"]) for row in design.factorial_ledger()}
    low20.update(
        int(value)
        for value in a220["factorial_design"]["prior_key_exclusion"]["sorted_low20"]
    )
    low20.update(int(row["low20"]) for row in a268["prospective_design"]["rows"])
    low20.update(int(row["low20"]) for row in a272["prospective_design"]["rows"])
    prefixes = {value >> 12 for value in low20}
    suffixes = {value & 0xFFF for value in low20}
    prefixes.update(int(value) for value in old.OLD_PREFIXES)
    suffixes.update(int(value) for value in old.OLD_SUFFIXES)
    ledger = {
        "low20": sorted(low20),
        "prefix8": sorted(prefixes),
        "suffix12": sorted(suffixes),
    }
    return {
        "low20": low20,
        "prefix8": prefixes,
        "suffix12": suffixes,
        "ledger_sha256": _canonical_sha256(ledger),
        "low20_count": len(low20),
        "prefix8_count": len(prefixes),
        "suffix12_count": len(suffixes),
    }


def _fresh_challenge(
    *,
    public: Any,
    public_template: Mapping[str, Any],
    prior: Mapping[str, Any],
    low20_source: Callable[[], int],
) -> dict[str, Any]:
    for _ in range(4096):
        candidate = low20_source()
        if not isinstance(candidate, int) or isinstance(candidate, bool) or not 0 <= candidate < 2**20:
            raise ValueError("A273 target source returned a value outside the twenty-bit domain")
        if (
            candidate in prior["low20"]
            or candidate >> 12 in prior["prefix8"]
            or candidate & 0xFFF in prior["suffix12"]
        ):
            continue
        challenge = public.build_known_challenge(public_template, low20=candidate)
        assert_secret_free(challenge)
        return challenge
    raise RuntimeError("A273 could not draw a prefix-, suffix-, and key-disjoint target")


def build_protocol(
    *, low20_source: Callable[[], int] = lambda: secrets.randbits(20)
) -> dict[str, Any]:
    if OUTPUT.exists():
        raise FileExistsError(f"A273 protocol already exists: {OUTPUT}")
    fixed = {
        A220_PROTOCOL: A220_PROTOCOL_SHA256,
        A220_DESIGN: A220_DESIGN_SHA256,
        A268_PREFLIGHT: A268_PREFLIGHT_SHA256,
        A272_PROTOCOL: A272_PROTOCOL_SHA256,
        A272_RESULT: A272_RESULT_SHA256,
        A272_CAUSAL: A272_CAUSAL_SHA256,
        A272_RUNNER: A272_RUNNER_SHA256,
        PUBLIC_CORE: PUBLIC_CORE_SHA256,
        SHAPE_SOURCE: SHAPE_SOURCE_SHA256,
        CONTRIBUTION_SOURCE: CONTRIBUTION_SOURCE_SHA256,
    }
    for path, expected in fixed.items():
        if _file_sha256(path) != expected:
            raise RuntimeError(f"A273 anchored predecessor differs: {path.name}")
    if not RUNNER.is_file():
        raise FileNotFoundError("A273 measurement runner must exist before protocol freeze")
    a272_result = json.loads(A272_RESULT.read_bytes())
    a272_protocol = json.loads(A272_PROTOCOL.read_bytes())
    if (
        a272_result.get("evidence_stage")
        != "FULLROUND_R20_PROSPECTIVE_SELECTED_CHANNEL_SIGNAL"
        or a272_result.get("retention_gate", {}).get("passed") is not True
        or a272_result.get("headline", {}).get("exact_shared_xor_p") != 1 / 256
        or a272_result.get("headline", {}).get("bit_gain") != 1.6187517100916802
        or a272_protocol.get("selected_hypothesis", {}).get("feature_indices")
        != SELECTED_FEATURE_INDICES
    ):
        raise RuntimeError("A273 A272 retention gate differs")
    a220 = json.loads(A220_PROTOCOL.read_bytes())
    public = _import_path(PUBLIC_CORE, "a273_public_core")
    public_template = public.validate_public_template(a220["public_only_R20_material"])
    if _canonical_sha256(public_template) != a220["public_only_R20_material_sha256"]:
        raise RuntimeError("A273 public-only material hash differs")
    prior = _prior_geometry()
    challenge = _fresh_challenge(
        public=public,
        public_template=public_template,
        prior=prior,
        low20_source=low20_source,
    )
    challenge_sha256 = _canonical_sha256(challenge)
    anchors = {
        "A220_protocol_path": str(A220_PROTOCOL.relative_to(ROOT)),
        "A220_protocol_sha256": A220_PROTOCOL_SHA256,
        "A220_factorial_design_path": str(A220_DESIGN.relative_to(ROOT)),
        "A220_factorial_design_sha256": A220_DESIGN_SHA256,
        "A268_preflight_path": str(A268_PREFLIGHT.relative_to(ROOT)),
        "A268_preflight_sha256": A268_PREFLIGHT_SHA256,
        "A268_preflight_runner_path": str(A268_PREFLIGHT_RUNNER.relative_to(ROOT)),
        "A268_preflight_runner_sha256": _file_sha256(A268_PREFLIGHT_RUNNER),
        "A272_protocol_path": str(A272_PROTOCOL.relative_to(ROOT)),
        "A272_protocol_sha256": A272_PROTOCOL_SHA256,
        "A272_result_path": str(A272_RESULT.relative_to(ROOT)),
        "A272_result_sha256": A272_RESULT_SHA256,
        "A272_causal_path": str(A272_CAUSAL.relative_to(ROOT)),
        "A272_causal_sha256": A272_CAUSAL_SHA256,
        "A272_runner_path": str(A272_RUNNER.relative_to(ROOT)),
        "A272_runner_sha256": A272_RUNNER_SHA256,
        "public_core_path": str(PUBLIC_CORE.relative_to(ROOT)),
        "public_core_sha256": PUBLIC_CORE_SHA256,
        "shape_source_path": str(SHAPE_SOURCE.relative_to(ROOT)),
        "shape_source_sha256": SHAPE_SOURCE_SHA256,
        "contribution_source_path": str(CONTRIBUTION_SOURCE.relative_to(ROOT)),
        "contribution_source_sha256": CONTRIBUTION_SOURCE_SHA256,
        "runner_path": str(RUNNER.relative_to(ROOT)),
        "runner_sha256": _file_sha256(RUNNER),
    }
    protocol = {
        "schema": "chacha20-round20-selected-channel-target-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_after_A272_retention_and_fresh_target_generation_with_ephemeral_label_discarded_before_any_target_CNF_measurement_score_order_or_recovery",
        "anchors": anchors,
        "selected_hypothesis": a272_protocol["selected_hypothesis"],
        "target": {
            "public_template": public_template,
            "public_template_sha256": _canonical_sha256(public_template),
            "public_challenge": challenge,
            "public_challenge_sha256": challenge_sha256,
            "target_block_sha256": challenge["target_block_sha256"],
            "generation": "secrets.randbits_20_with_rejection_of_all_prior_key_prefix_and_suffix_levels",
            "prior_geometry_ledger_sha256": prior["ledger_sha256"],
            "prior_low20_count": prior["low20_count"],
            "prior_prefix8_count": prior["prefix8_count"],
            "prior_suffix12_count": prior["suffix12_count"],
            "ephemeral_generation_label_returned_or_serialized": False,
        },
        "measurement": {
            "fresh_solver_instance_per_candidate": True,
            "identical_unsolved_base_snapshot": True,
            "candidate_order": "numeric_0_through_255",
            "conflict_horizons": [1, 2, 4, 8],
            "watchdog_seconds_per_stage": 2.0,
            "maximum_captured_learned_clause_size": 64,
            "complete_256_candidate_cover_required_before_scoring": True,
            "terminal_SAT_UNSAT_or_model_bits_permitted": False,
            "bounded_variable_addition_enabled": False,
            "early_stop_permitted": False,
        },
        "readout": {
            "view_count": 1,
            "feature_indices": SELECTED_FEATURE_INDICES,
            "score": "sum_of_frozen_standardized_additive_contributions",
            "order": "descending_score_then_ascending_candidate_tiebreak",
            "model_refit_or_coefficient_update_permitted": False,
            "target_label_available_to_readout": False,
        },
        "next_execution": {
            "recovery_order_prefix": 128,
            "logical_domain_covered_if_exhausted": 2**19,
            "full_residual_domain": 2**20,
            "retained_solver_state_across_ordered_prefix_cells": True,
            "recovery_protocol_must_freeze_after_complete_A273_order": True,
        },
        "information_boundary": {
            "A272_hypothesis_retained_before_target_generation": True,
            "target_generated_from_cryptographic_rng_after_A272_retention": True,
            "target_generation_label_discarded_before_protocol_serialization": True,
            "target_generation_label_stored_in_protocol_result_Causal_or_report": False,
            "any_target_CNF_or_solver_measurement_started_before_freeze": False,
            "any_target_channel_score_or_candidate_order_known_before_freeze": False,
            "any_target_recovery_started_before_freeze": False,
            "target_label_used_for_feature_construction_scoring_order_or_stop": False,
            "all_256_cells_required_before_scoring": True,
            "all_1024_shallow_stages_must_remain_unknown_and_model_free": True,
        },
    }
    assert_secret_free(protocol)
    return protocol


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
                "public_challenge_sha256": protocol["target"]["public_challenge_sha256"],
                "runner_sha256": protocol["anchors"]["runner_sha256"],
                "target_generation_label_returned_or_serialized": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
