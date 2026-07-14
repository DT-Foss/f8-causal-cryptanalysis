#!/usr/bin/env python3
"""Freeze A278's complete cross-material R20 recovery schedule before target generation."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import inspect
import json
import os
import secrets
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
ATTEMPT_ID = "A278"
DEFAULT_OUTPUT = (
    ROOT
    / "research/configs/chacha20_round20_cross_material_composite_master_v1.json"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)

A275_PROTOCOL = (
    ROOT / "research/configs/chacha20_round20_selected_channel_target_replication_v1.json"
)
A275_RESULT = (
    ROOT
    / "research/results/v1/chacha20_round20_selected_channel_target_replication_order_v1.json"
)
A275_CAUSAL = A275_RESULT.with_suffix(".causal")
A275_MEASUREMENT = (
    ROOT
    / "research/results/v1/chacha20_round20_selected_channel_target_replication_order_v1/target.numeric.measurement.json.zst"
)
A275_RUNNER = Path(__file__).with_name(
    "chacha20_round20_selected_channel_target_replication_measure.py"
)
A276_PROTOCOL = (
    ROOT
    / "research/configs/chacha20_round20_selected_channel_target_replication_recovery_v1.json"
)
A276_RUNNER = Path(__file__).with_name(
    "chacha20_round20_selected_channel_target_replication_recovery.py"
)
A277_PROTOCOL = (
    ROOT / "research/configs/chacha20_round20_replication_residual_two_pass_v1.json"
)
A277_RESULT = (
    ROOT / "research/results/v1/chacha20_round20_replication_residual_two_pass_v1.json"
)
A277_CAUSAL = A277_RESULT.with_suffix(".causal")
A277_RUNNER = Path(__file__).with_name(
    "chacha20_round20_replication_residual_two_pass.py"
)
PUBLIC_CORE = Path(__file__).with_name("chacha20_round20_public_core.py")
SYMBOLIC_TEMPLATE = Path(__file__).with_name("chacha20_round20_symbolic_template.py")
RESIDUAL_WRAPPER = Path(__file__).with_name("chacha20_residual_two_pass.py")
RESIDUAL_NATIVE = ROOT / "research/native/cadical_residual_two_pass.cpp"

EXPECTED = {
    A275_PROTOCOL: "d6e753defe3eba1e9989e8e6f792a6e731d8371487788917db0d7cff518c75f9",
    A275_RESULT: "2c9236c2aff721ba18f1c4009fdd1dd1724b0ba0d5799268ac49c0ac2d4a672a",
    A275_CAUSAL: "fadae6b3dece94cb207f3eba4572d9fc1bfd6796e4256a5bd7b3de5e11e03f3b",
    A275_MEASUREMENT: "0452f3c418bb29b1904170f7dd7a2a8278b4de68d056b8537ead6985ae97ddde",
    A275_RUNNER: "218815280ce978aba16ba857db80828424e390cc1d141a1be3d33fb330c4e56b",
    A276_PROTOCOL: "b40a8d6da6a5ce3af80e6f34f0eae28f87f1eb22448985ee95e5382ae455b9e5",
    A276_RUNNER: "e82f3e8d8d98c38b13f7674ed31657737276b021025dc652af790e608b53a931",
    A277_PROTOCOL: "1f7aa99d6b869287cb78bc9a3a321cf5d559c44137d554dc19b9435bb1f78b69",
    A277_RESULT: "dd47a7dfdc5740defef134f0b588d58f8dae9dd6dee22068aa1f67c25b37c5d7",
    A277_CAUSAL: "3da37f9177102c14626b425e8c58f8fe7dddbc35dab99f1fadf6599a8f54d196",
    A277_RUNNER: "7710e978fd7a1ba33155bf12919d49b243806342c78fc0517bdeee02c2bf6e60",
    PUBLIC_CORE: "953e4478d369b2eb39657d4b6f718fa97a46cac1855b0364cce1bc4e4753f77f",
    SYMBOLIC_TEMPLATE: "34f4c5542f7fa12e7b0ff06ab7e042605c2414f23001f11894fa6dbdfc0b4721",
    RESIDUAL_WRAPPER: "023c23008f62c062fcb9a4b1485e22417707c649d7354ec0357e73b082dc59e6",
    RESIDUAL_NATIVE: "b0fcd4a8a08579055bed98003c01fcbadfd8782731745ad87f007dbd7db679dd",
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
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _load_reader(dotcausal_src: Path) -> tuple[Any, dict[str, Any]]:
    try:
        module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError("dotcausal source is unavailable") from None
        sys.path.insert(0, str(dotcausal_src))
        module = importlib.import_module("dotcausal.io")
    source = Path(inspect.getsourcefile(module.CausalReader) or "")
    return module.CausalReader, {
        "module": "dotcausal.io",
        "io_path": str(source),
        "io_sha256": _file_sha256(source),
    }


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A278 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _public_template(seed: bytes) -> dict[str, Any]:
    if len(seed) != 32:
        raise ValueError("A278 public seed must contain 32 bytes")
    seed_hex = seed.hex()
    label = (
        "f8-causal:cross-material:chacha20:r20-width20:known-material:"
        f"{seed_hex}"
    )
    derived = hashlib.shake_256(label.encode("ascii")).digest(48)
    words = [
        int.from_bytes(derived[offset : offset + 4], "little")
        for offset in range(0, 48, 4)
    ]
    return {
        "block_count": 8,
        "counter_schedule": "base_plus_block_index_mod_2^32",
        "counter_start": words[8],
        "known_key_bits": 236,
        "known_key_word0_upper12": words[0] & ~((1 << 20) - 1),
        "known_key_words_1_through_7": words[1:8],
        "known_material_derivation_label": label,
        "known_material_derivation_sha256": _sha256(derived),
        "nonce_words": words[9:12],
        "public_seed_hex": seed_hex,
        "rounds": 20,
        "unknown_assignment_bits": 20,
        "unknown_assignment_included": False,
        "unknown_key_word0_low_bits": 20,
        "unknown_key_word0_low_value_included": False,
        "unknown_secret_low20_included": False,
    }


def build_protocol(
    *,
    root_review_acknowledged: bool,
    dotcausal_src: Path,
    public_seed_source: Callable[[], bytes] = lambda: secrets.token_bytes(32),
) -> dict[str, Any]:
    if root_review_acknowledged is not True:
        raise RuntimeError("A278 freeze requires explicit root review acknowledgement")
    for path, digest in EXPECTED.items():
        if _file_sha256(path) != digest:
            raise RuntimeError(f"A278 retained anchor differs: {path.name}")
    a275_protocol = json.loads(A275_PROTOCOL.read_bytes())
    a275_result = json.loads(A275_RESULT.read_bytes())
    a276_protocol = json.loads(A276_PROTOCOL.read_bytes())
    a277_protocol = json.loads(A277_PROTOCOL.read_bytes())
    a277 = json.loads(A277_RESULT.read_bytes())
    if (
        a277.get("evidence_stage")
        != "FULLROUND_R20_TARGET_BLIND_RESIDUAL_GLOBAL_RECOVERY_CONFIRMED"
        or a277.get("execution_summary", {}).get("global_status") != "sat"
        or a277.get("execution_summary", {}).get(
            "complete_remaining_half_enumeration_used"
        )
        is not False
        or a277.get("execution_summary", {}).get("attempted_solver_calls") != 1
        or a277.get("confirmation", {}).get("all_blocks_match") is not True
        or a277.get("confirmation", {}).get("output_bits_checked") != 4096
        or a277.get("confirmation", {}).get("control_first_block_match") is not False
        or a275_protocol.get("readout", {}).get("feature_indices")
        != [502, 504, 505, 508, 509, 510, 511, 514]
        or a275_result.get("headline", {}).get("complete_candidate_cells") != 256
        or a276_protocol.get("solver_protocol", {}).get("seconds_per_cell") != 30.0
        or a277_protocol.get("solver_protocol", {}).get("global_seconds") != 300.0
    ):
        raise RuntimeError("A278 predecessor or frozen schedule gate differs")

    CausalReader, reader_source = _load_reader(dotcausal_src)
    reader = CausalReader(str(A277_CAUSAL), verify_integrity=True)
    gaps = list(reader._gaps)
    if (
        reader.version != 1
        or reader.api_id != "a277"
        or len(gaps) != 1
        or gaps[0].get("expected_object_type")
        != "cross_public_material_replication_with_frozen_residual_schedule"
    ):
        raise RuntimeError("A278 authentic A277 Causal gap differs")

    seed = public_seed_source()
    if not isinstance(seed, bytes):
        raise TypeError("A278 public seed source must return bytes")
    public_template = _public_template(seed)
    old_template = a275_protocol["target"]["public_template"]
    public = _import_path(PUBLIC_CORE, "a278_public_core")
    if (
        public.validate_public_template(public_template) != public_template
        or public_template["public_seed_hex"] == old_template["public_seed_hex"]
        or _canonical_sha256(public_template) == _canonical_sha256(old_template)
    ):
        raise RuntimeError("A278 public material did not change")

    anchor_paths = {
        "A275_protocol": A275_PROTOCOL,
        "A275_result": A275_RESULT,
        "A275_causal": A275_CAUSAL,
        "A275_measurement": A275_MEASUREMENT,
        "A275_runner": A275_RUNNER,
        "A276_protocol": A276_PROTOCOL,
        "A276_runner": A276_RUNNER,
        "A277_protocol": A277_PROTOCOL,
        "A277_result": A277_RESULT,
        "A277_causal": A277_CAUSAL,
        "A277_runner": A277_RUNNER,
        "public_core": PUBLIC_CORE,
        "symbolic_template": SYMBOLIC_TEMPLATE,
        "residual_wrapper": RESIDUAL_WRAPPER,
        "residual_native": RESIDUAL_NATIVE,
    }
    anchors = {
        key: {
            "path": str(path.relative_to(ROOT)),
            "sha256": EXPECTED[path],
        }
        for key, path in anchor_paths.items()
    }
    schedule = {
        "measurement": {
            "reader": "unchanged_A272_eight_feature_selected_channel_reader",
            "feature_indices": [502, 504, 505, 508, 509, 510, 511, 514],
            "candidate_order": "numeric_0_through_255",
            "conflict_horizons": [1, 2, 4, 8],
            "watchdog_seconds_per_stage": 2.0,
            "complete_256_candidate_cover_before_scoring": True,
            "all_stages_must_remain_model_free_UNKNOWN": True,
            "score": "sum_of_frozen_standardized_additive_contributions",
            "rank_order": "descending_score_then_ascending_candidate",
        },
        "top_half": {
            "prefix_cells": 128,
            "seconds_per_cell": 30.0,
            "single_retained_CaDiCaL_state": True,
            "stop_condition": "first_SAT_only",
            "UNKNOWN_is_not_elimination": True,
        },
        "residual": {
            "entry_condition": (
                "no_top_half_SAT_and_all_128_top_half_cells_exact_UNSAT"
            ),
            "materialization": "one_negated_8_assumption_clause_per_exact_prefix",
            "global_seconds": 300.0,
            "discovery_seconds_per_cell": 10.0,
            "fallback_seconds_per_discovery_UNKNOWN_cell": 30.0,
            "single_retained_state_within_global_discovery_fallback": True,
            "discovery_UNKNOWN_is_not_elimination": True,
            "fallback_UNKNOWN_is_not_elimination": True,
            "stop_condition": "first_SAT_only",
        },
        "confirmation": {
            "implementations": 2,
            "standard_output_blocks": 8,
            "output_bits": 4096,
            "flipped_control_required": True,
        },
    }
    protocol: dict[str, Any] = {
        "schema": "chacha20-round20-cross-material-composite-master-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": (
            "frozen_before_cross_material_target_generation_measurement_order_or_solve"
        ),
        "research_question": (
            "Does the complete A275-A277 target-blind schedule recover a fresh "
            "ChaCha20-R20 target under entirely new public known-key, counter, and "
            "nonce material without complete residual-domain enumeration?"
        ),
        "anchors": anchors,
        "cross_material_public_template": public_template,
        "cross_material_public_template_sha256": _canonical_sha256(public_template),
        "frozen_schedule": schedule,
        "target_generation_contract": {
            "process": "separate_post_master_freeze_process",
            "source": "secrets.randbits_20",
            "reject_prior_low20_prefix8_and_suffix12": True,
            "reject_all_prior_public_challenge_hashes": True,
            "generation_label_returned_or_serialized": False,
        },
        "information_boundary": {
            "new_public_material_frozen_before_target_generation": True,
            "reader_and_all_solver_budgets_frozen_before_target_generation": True,
            "target_generation_label_available": False,
            "target_measurement_or_solver_execution_started": False,
            "target_rank_or_correct_prefix_known": False,
            "confirmation_permitted_only_after_solver_model": True,
        },
        "authentic_causal_readback": {
            "A277_gap": gaps[0],
            "reader_source": reader_source,
            "read_personally_by_main_before_freeze": True,
        },
    }
    protocol["scientific_design_sha256"] = _canonical_sha256(
        {
            "cross_material_public_template": public_template,
            "frozen_schedule": schedule,
            "target_generation_contract": protocol["target_generation_contract"],
            "information_boundary": protocol["information_boundary"],
        }
    )
    return protocol


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--root-review-acknowledged", action="store_true")
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args(argv)
    if args.output.exists():
        raise FileExistsError(f"A278 master protocol already exists: {args.output}")
    protocol = build_protocol(
        root_review_acknowledged=args.root_review_acknowledged,
        dotcausal_src=args.dotcausal_src,
    )
    _atomic_json(args.output, protocol)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "protocol_sha256": _file_sha256(args.output),
                "scientific_design_sha256": protocol["scientific_design_sha256"],
                "public_template_sha256": protocol[
                    "cross_material_public_template_sha256"
                ],
                "target_generated": False,
                "solver_execution_started": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
