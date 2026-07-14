#!/usr/bin/env python3
"""Generate A279's label-free target only after the complete A278 schedule freeze."""

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
ATTEMPT_ID = "A279"
MASTER = (
    ROOT
    / "research/configs/chacha20_round20_cross_material_composite_master_v1.json"
)
MASTER_SHA256 = "256504ef394fbc4d5e1da2881f3de0c8a32af5908f454e58cf9711da733551b6"
DEFAULT_OUTPUT = (
    ROOT / "research/configs/chacha20_round20_cross_material_target_v1.json"
)
A275_PREFLIGHT = Path(__file__).with_name(
    "chacha20_round20_selected_channel_target_replication_preflight.py"
)
A275_PREFLIGHT_SHA256 = "290de9f7f5b8f11bd70f31cf462635895d9b5a2c713724daf9ae1cb8c883a562"
A277_RESULT = (
    ROOT / "research/results/v1/chacha20_round20_replication_residual_two_pass_v1.json"
)
A277_RESULT_SHA256 = "dd47a7dfdc5740defef134f0b588d58f8dae9dd6dee22068aa1f67c25b37c5d7"
PUBLIC_CORE = Path(__file__).with_name("chacha20_round20_public_core.py")
PUBLIC_CORE_SHA256 = "953e4478d369b2eb39657d4b6f718fa97a46cac1855b0364cce1bc4e4753f77f"
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


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A279 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _assert_label_free(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).lower() in FORBIDDEN_SERIALIZED_KEYS:
                raise RuntimeError(f"A279 label-bearing field is forbidden: {key}")
            _assert_label_free(child)
    elif isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        for child in value:
            _assert_label_free(child)


def _prior_challenge_hashes() -> list[str]:
    hashes: set[str] = set()
    for path in sorted((ROOT / "research/results/v1").glob("chacha20*.json")):
        try:
            value = json.loads(path.read_bytes())
        except (json.JSONDecodeError, OSError):
            continue
        digest = value.get("public_challenge_sha256")
        if isinstance(digest, str) and len(digest) == 64:
            hashes.add(digest)
    return sorted(hashes)


def build_protocol(
    *,
    low20_source: Callable[[], int] = lambda: secrets.randbits(20),
) -> dict[str, Any]:
    if _file_sha256(MASTER) != MASTER_SHA256:
        raise RuntimeError("A279 master protocol hash differs")
    fixed = {
        A275_PREFLIGHT: A275_PREFLIGHT_SHA256,
        A277_RESULT: A277_RESULT_SHA256,
        PUBLIC_CORE: PUBLIC_CORE_SHA256,
    }
    for path, digest in fixed.items():
        if _file_sha256(path) != digest:
            raise RuntimeError(f"A279 anchor differs: {path.name}")
    master = json.loads(MASTER.read_bytes())
    a277 = json.loads(A277_RESULT.read_bytes())
    if (
        master.get("attempt_id") != "A278"
        or master.get("protocol_state")
        != "frozen_before_cross_material_target_generation_measurement_order_or_solve"
        or master.get("information_boundary", {}).get(
            "new_public_material_frozen_before_target_generation"
        )
        is not True
        or master.get("information_boundary", {}).get(
            "reader_and_all_solver_budgets_frozen_before_target_generation"
        )
        is not True
        or a277.get("confirmation", {}).get("all_blocks_match") is not True
    ):
        raise RuntimeError("A279 master semantic gate differs")
    public = _import_path(PUBLIC_CORE, "a279_public_core")
    public_template = public.validate_public_template(
        master["cross_material_public_template"]
    )
    if (
        _canonical_sha256(public_template)
        != master["cross_material_public_template_sha256"]
    ):
        raise RuntimeError("A279 frozen cross-material template differs")

    a275_preflight = _import_path(A275_PREFLIGHT, "a279_a275_preflight")
    prior = a275_preflight._prior_geometry()
    recovered = a277.get("confirmation", {}).get("recovered_unknown_low20")
    if not isinstance(recovered, int) or not 0 <= recovered < 2**20:
        raise RuntimeError("A279 A277 recovered label is unavailable for exclusion")
    prior_low20 = set(prior["low20"])
    prior_prefix8 = set(prior["prefix8"])
    prior_suffix12 = set(prior["suffix12"])
    prior_low20.add(recovered)
    prior_prefix8.add(recovered >> 12)
    prior_suffix12.add(recovered & 0xFFF)
    prior_hashes = _prior_challenge_hashes()
    if a277["public_challenge_sha256"] not in prior_hashes:
        raise RuntimeError("A279 prior public-challenge ledger omitted A277")

    challenge = None
    for _ in range(4096):
        candidate = low20_source()
        if (
            not isinstance(candidate, int)
            or isinstance(candidate, bool)
            or not 0 <= candidate < 2**20
        ):
            raise ValueError("A279 target source returned an invalid value")
        if (
            candidate in prior_low20
            or candidate >> 12 in prior_prefix8
            or candidate & 0xFFF in prior_suffix12
        ):
            continue
        proposed = public.build_known_challenge(public_template, low20=candidate)
        if _canonical_sha256(proposed) in prior_hashes:
            continue
        challenge = proposed
        break
    if challenge is None:
        raise RuntimeError("A279 could not draw a geometry-disjoint target")
    _assert_label_free(challenge)
    challenge_sha256 = _canonical_sha256(challenge)
    prior_ledger = {
        "low20": sorted(prior_low20),
        "prefix8": sorted(prior_prefix8),
        "suffix12": sorted(prior_suffix12),
        "public_challenge_sha256": prior_hashes,
    }
    protocol: dict[str, Any] = {
        "schema": "chacha20-round20-cross-material-target-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": (
            "frozen_after_A278_master_and_label_discard_before_any_target_measurement_or_solve"
        ),
        "master_protocol": {
            "path": str(MASTER.relative_to(ROOT)),
            "sha256": MASTER_SHA256,
            "scientific_design_sha256": master["scientific_design_sha256"],
        },
        "runner_sha256": _file_sha256(Path(__file__)),
        "anchors": {
            "A275_preflight": {
                "path": str(A275_PREFLIGHT.relative_to(ROOT)),
                "sha256": A275_PREFLIGHT_SHA256,
            },
            "A277_result": {
                "path": str(A277_RESULT.relative_to(ROOT)),
                "sha256": A277_RESULT_SHA256,
            },
            "public_core": {
                "path": str(PUBLIC_CORE.relative_to(ROOT)),
                "sha256": PUBLIC_CORE_SHA256,
            },
        },
        "public_template": public_template,
        "public_template_sha256": master[
            "cross_material_public_template_sha256"
        ],
        "public_challenge": challenge,
        "public_challenge_sha256": challenge_sha256,
        "target_block_sha256": challenge["target_block_sha256"],
        "generation": {
            "source": "secrets.randbits_20",
            "rejection": "all_prior_low20_prefix8_suffix12_and_challenge_hashes",
            "prior_ledger_sha256": _canonical_sha256(prior_ledger),
            "prior_low20_count": len(prior_low20),
            "prior_prefix8_count": len(prior_prefix8),
            "prior_suffix12_count": len(prior_suffix12),
            "prior_public_challenge_count": len(prior_hashes),
            "generation_label_returned_or_serialized": False,
        },
        "information_boundary": {
            "master_schedule_frozen_before_target_generation": True,
            "target_generation_label_discarded_before_protocol_serialization": True,
            "target_generation_label_available": False,
            "target_measurement_started": False,
            "target_candidate_order_known": False,
            "target_solver_execution_started": False,
        },
    }
    _assert_label_free(protocol)
    return protocol


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--freeze", action="store_true")
    args = parser.parse_args(argv)
    if not args.freeze:
        print(
            json.dumps(
                {"attempt_id": ATTEMPT_ID, "output": str(args.output)},
                indent=2,
                sort_keys=True,
            )
        )
        return
    if args.output.exists():
        raise FileExistsError(f"A279 target protocol already exists: {args.output}")
    protocol = build_protocol()
    _atomic_json(args.output, protocol)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "protocol_sha256": _file_sha256(args.output),
                "public_challenge_sha256": protocol["public_challenge_sha256"],
                "public_template_sha256": protocol["public_template_sha256"],
                "target_generation_label_returned_or_serialized": False,
                "measurement_or_solver_started": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
