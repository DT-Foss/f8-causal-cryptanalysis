#!/usr/bin/env python3
"""Commit a fresh A218 R20 target without exposing its low20 label."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import secrets
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
PROTOCOL = RESEARCH / "configs/chacha20_round20_knownkey_trajectory_atlas_v1.json"
PROTOCOL_SHA256 = "037b415e25e0956a2d8b13cd0bd62a838c50dce6b831ddc8734bd03ed2ec44c7"
DEFAULT_PUBLIC = RESEARCH / "challenges/chacha20_round20_knownkey_trajectory_atlas_v1_public.json"
DEFAULT_SECRET = ROOT / ".research_sealed/chacha20_round20_knownkey_trajectory_atlas_v1_secret.json"
COMMITMENT_DOMAIN = b"f8-causal:A218:target-commitment:v1\0"


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
    ).encode()


def _canonical_sha256(value: Any) -> str:
    return _sha256(_canonical_bytes(value))


def _atomic_json(path: Path, value: Any, *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    )
    if private:
        temporary.chmod(0o600)
    temporary.replace(path)
    if private:
        path.chmod(0o600)


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def target_commitment(*, low20: int, salt: bytes) -> str:
    if low20 < 0 or low20 >= 1 << 20 or len(salt) != 32:
        raise ValueError("invalid A218 target commitment material")
    return _sha256(COMMITMENT_DOMAIN + salt + low20.to_bytes(4, "little"))


def _verify_existing(public_path: Path, secret_path: Path) -> dict[str, Any]:
    public = json.loads(public_path.read_bytes())
    secret = json.loads(secret_path.read_bytes())
    salt = bytes.fromhex(secret["salt_hex"])
    low20 = int(secret["low20"])
    commitment = target_commitment(low20=low20, salt=salt)
    if (
        public.get("schema") != "chacha20-round20-trajectory-target-public-v1"
        or secret.get("schema") != "chacha20-round20-trajectory-target-secret-v1"
        or public.get("protocol_sha256") != PROTOCOL_SHA256
        or secret.get("protocol_sha256") != PROTOCOL_SHA256
        or public.get("commitment_sha256") != commitment
        or secret.get("commitment_sha256") != commitment
        or public.get("challenge_sha256") != _canonical_sha256(public.get("public_challenge"))
        or secret.get("public_challenge_sha256") != public.get("challenge_sha256")
    ):
        raise RuntimeError("existing A218 target commitment fails identity gates")
    return public


def create_target(*, public_path: Path, secret_path: Path) -> dict[str, Any]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A218 frozen protocol hash differs")
    if public_path.exists() or secret_path.exists():
        if public_path.exists() and secret_path.exists():
            return _verify_existing(public_path, secret_path)
        raise RuntimeError("partial A218 target commitment exists; refusing overwrite")

    protocol = json.loads(PROTOCOL.read_bytes())
    anchors = protocol["anchors"]
    r20_path = ROOT / anchors["R20_runner_path"]
    helper_path = ROOT / anchors["A214_knownkey_helper_path"]
    if (
        _file_sha256(r20_path) != anchors["R20_runner_sha256"]
        or _file_sha256(helper_path) != anchors["A214_knownkey_helper_sha256"]
    ):
        raise RuntimeError("A218 target generator anchor drift")
    r20 = _import_path(r20_path, "a218_target_r20")
    helper = _import_path(helper_path, "a218_target_knownkey_helper")
    ledger = helper.atlas_ledger()
    if helper.atlas_ledger_sha256(ledger) != anchors["A214_knownkey_ledger_sha256"]:
        raise RuntimeError("A218 target generator ledger drift")
    known = {int(row["low20"]) for row in ledger}
    low20 = secrets.randbelow(1 << 20)
    while low20 in known:
        low20 = secrets.randbelow(1 << 20)
    salt = secrets.token_bytes(32)
    commitment = target_commitment(low20=low20, salt=salt)

    analysis = r20.analyze()
    challenge = helper.training_challenge(
        analysis["public_challenge"],
        low20=low20,
        chacha_block=r20.P1._chacha_block,
    )
    challenge_sha256 = _canonical_sha256(challenge)
    public = {
        "schema": "chacha20-round20-trajectory-target-public-v1",
        "attempt_id": "A218",
        "protocol_path": str(PROTOCOL.relative_to(ROOT)),
        "protocol_sha256": PROTOCOL_SHA256,
        "generation_boundary": "generated_after_protocol_freeze_and_before_any_A218_trajectory_or_model_measurement",
        "secret_source": "OS_CSPRNG",
        "commitment_scheme": "SHA256(domain_separator||random_256bit_salt||low20_le32)",
        "commitment_sha256": commitment,
        "public_challenge": challenge,
        "challenge_sha256": challenge_sha256,
        "atlas_key_count_excluded": len(known),
        "low20_or_salt_present": False,
    }
    secret = {
        "schema": "chacha20-round20-trajectory-target-secret-v1",
        "attempt_id": "A218",
        "protocol_sha256": PROTOCOL_SHA256,
        "commitment_sha256": commitment,
        "public_challenge_sha256": challenge_sha256,
        "low20": low20,
        "low20_hex": f"{low20:05x}",
        "salt_hex": salt.hex(),
        "atlas_collision": low20 in known,
    }
    _atomic_json(secret_path, secret, private=True)
    _atomic_json(public_path, public)
    return _verify_existing(public_path, secret_path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-output", type=Path, default=DEFAULT_PUBLIC)
    parser.add_argument("--secret-output", type=Path, default=DEFAULT_SECRET)
    arguments = parser.parse_args()
    public = create_target(
        public_path=arguments.public_output,
        secret_path=arguments.secret_output,
    )
    print(
        json.dumps(
            {
                "public_output": str(arguments.public_output),
                "public_output_sha256": _file_sha256(arguments.public_output),
                "public_challenge_sha256": public["challenge_sha256"],
                "commitment_sha256": public["commitment_sha256"],
                "secret_material_printed": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
