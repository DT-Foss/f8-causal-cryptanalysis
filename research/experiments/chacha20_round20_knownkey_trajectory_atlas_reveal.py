#!/usr/bin/env python3
"""Reveal and independently confirm the frozen A218 target order."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

from arx_carry_leak.crypto_causal import (
    CryptoCausalBuilder,
    CryptoCausalReader,
    ExactRule,
)

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
PROTOCOL = RESEARCH / "configs/chacha20_round20_knownkey_trajectory_atlas_v1.json"
PROTOCOL_SHA256 = "037b415e25e0956a2d8b13cd0bd62a838c50dce6b831ddc8734bd03ed2ec44c7"
PUBLIC_TARGET = RESEARCH / "challenges/chacha20_round20_knownkey_trajectory_atlas_v1_public.json"
PREREVEAL = RESEARCH / "results/v1/chacha20_round20_knownkey_trajectory_atlas_v1_prereveal.json"
DEFAULT_SECRET = ROOT / ".research_sealed/chacha20_round20_knownkey_trajectory_atlas_v1_secret.json"
DEFAULT_OUTPUT = RESEARCH / "results/v1/chacha20_round20_knownkey_trajectory_atlas_v1.json"
DEFAULT_CAUSAL = RESEARCH / "results/v1/chacha20_round20_knownkey_trajectory_atlas_v1.causal"
DEFAULT_REPORT = RESEARCH / "reports/CAUSAL_CHACHA20_ROUND20_KNOWNKEY_TRAJECTORY_ATLAS_V1.md"
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


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_write(
        path,
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n",
    )


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
        raise ValueError("invalid A218 reveal material")
    return _sha256(COMMITMENT_DOMAIN + salt + low20.to_bytes(4, "little"))


def evidence_stage(*, validation_p: float, target_rank: int) -> str:
    validation = validation_p <= 0.05
    if validation and target_rank == 1:
        return "FULLROUND_R20_KNOWNKEY_TRAJECTORY_RANK1_TRANSFER_CONFIRMED"
    if validation and target_rank <= 16:
        return "FULLROUND_R20_KNOWNKEY_TRAJECTORY_TOP16_TRANSFER_CONFIRMED"
    if validation and target_rank <= 64:
        return "FULLROUND_R20_KNOWNKEY_TRAJECTORY_TOP64_TRANSFER_CONFIRMED"
    if validation and target_rank < 256:
        return "FULLROUND_R20_KNOWNKEY_TRAJECTORY_DOMAIN_REDUCTION_RETAINED"
    if target_rank == 1:
        return "FULLROUND_R20_TARGET_RANK1_WITH_VALIDATION_NULL_BOUNDARY"
    if validation:
        return "FULLROUND_R20_VALIDATION_ASSOCIATION_WITH_TARGET_TRANSFER_BOUNDARY"
    return "FULLROUND_R20_TRAJECTORY_REPRESENTATION_BOUNDARY_RETAINED"


def _confirmation(r20: Any, challenge: dict[str, Any], low20: int) -> dict[str, Any]:
    key_word0 = int(challenge["known_key_word0_upper12"]) | low20
    key_words = [key_word0, *challenge["known_key_words_1_through_7"]]
    blocks = [
        r20.P1._chacha_block(
            key_words=key_words,
            counter=(int(challenge["counter_start"]) + index) & 0xFFFFFFFF,
            nonce_words=challenge["nonce_words"],
            rounds=20,
        )
        for index in range(int(challenge["block_count"]))
    ]
    hashes = [_sha256(r20.P1._word_bytes(block)) for block in blocks]
    block_matches = [
        block == target for block, target in zip(blocks, challenge["target_words"], strict=True)
    ]
    return {
        "implementation": "independent_pure_Python_standard_ChaCha20_block",
        "rounds": 20,
        "key_word0": key_word0,
        "recovered_unknown_low20": low20,
        "block_count_checked": len(blocks),
        "output_bits_checked": 512 * len(blocks),
        "candidate_block_sha256": hashes,
        "block_matches": block_matches,
        "all_blocks_match": all(block_matches),
        "control_first_block_match": hashes[0] == challenge["control_target_block_sha256"],
    }


def _causal(payload: dict[str, Any], output: Path) -> dict[str, Any]:
    source = f"measurement:sha256:{payload['measurement_sha256']}"
    builder = CryptoCausalBuilder(
        experiment="chacha20_round20_knownkey_trajectory_atlas",
        parameters={
            "attempt_id": "A218",
            "protocol_sha256": PROTOCOL_SHA256,
            "prereveal_sha256": payload["prereveal_sha256"],
            "target_secret_unavailable_until_after_prereveal": True,
        },
    )
    builder.add_rule(
        ExactRule(
            name="trajectory_atlas_transfer",
            first="fits_selection_matched_key_disjoint_trajectory_readout",
            second="applies_frozen_readout_to_committed_target",
            conclusion="transfers_solver_trajectory_map_to_unseen_R20_target",
        )
    )
    builder.add_triplet(
        edge_id="a218-budget-calibration",
        trigger="A218P:revealed_anchor_conflict_budget_calibration",
        mechanism="selects_repeatable_conflict32_trajectory_horizon",
        outcome="A218:fixed_budgeted_numeric_gray_measurement",
        confidence=1.0,
        evidence_kind="repeatable_measurement_hash",
        source=source,
        attrs={"A218P_measurement_sha256": payload["anchors"]["A218P_measurement_sha256"]},
    )
    builder.add_triplet(
        edge_id="a218-key-disjoint-fit",
        trigger="A218:fixed_budgeted_numeric_gray_measurement",
        mechanism="fits_selection_matched_key_disjoint_trajectory_readout",
        outcome="A218:selected_readout_and_validation",
        confidence=1.0,
        evidence_kind="16_train_8_validation_complete_key_units",
        source=source,
        attrs={
            "validation_metrics": payload["selected_validation"],
            "selection_matched_null_p": payload["selection_matched_null_p"],
        },
    )
    builder.add_triplet(
        edge_id="a218-prereveal-order",
        trigger="A218:selected_readout_and_validation",
        mechanism="applies_frozen_readout_to_committed_target",
        outcome="A218:frozen_target_cell_order",
        confidence=1.0,
        evidence_kind="atomic_prereveal_order_hash",
        source=source,
        attrs={
            "prereveal_sha256": payload["prereveal_sha256"],
            "cell_order_sha256": payload["target_cell_order_sha256"],
        },
    )
    builder.add_triplet(
        edge_id="a218-independent-reveal",
        trigger="A218:frozen_target_cell_order",
        mechanism="independent_commitment_reveal_and_4096bit_confirmation",
        outcome=f"A218:{payload['evidence_stage']}",
        confidence=1.0,
        evidence_kind="post_prereveal_salted_commitment_open_and_full_output_confirmation",
        source=source,
        attrs={
            "target_prefix_rank": payload["target_prefix_rank"],
            "all_blocks_match": payload["confirmation"]["all_blocks_match"],
            "control_rejected": not payload["confirmation"]["control_first_block_match"],
        },
    )
    builder.infer_exact_closure(max_hops=4)
    stats = builder.save(output)
    reader = CryptoCausalReader(output)
    if not reader.verify_provenance() or reader.graph_sha256 != stats["graph_sha256"]:
        raise RuntimeError("A218 causal reader gate failed")
    return {**stats, "reader_verified": True}


def _report(payload: dict[str, Any], output: Path) -> None:
    selected = payload["selected_model_identity"]
    validation = payload["selected_validation"]
    lines = [
        "# ChaCha20 R20 Known-Key Solver-Trajectory Atlas (A218)",
        "",
        f"**Evidence stage:** `{payload['evidence_stage']}`",
        "",
        "A218 measures two retained CaDiCaL operators at a fixed 32-conflict horizon "
        "on 16 known full-round keys, selects every model choice on eight disjoint "
        "keys, repeats the complete selection under 64 whole-key null assignments, "
        "and freezes a 256-cell order for a newly committed target before opening its "
        "salted secret.",
        "",
        "## Prospective target result",
        "",
        f"- True prefix rank: **{payload['target_prefix_rank']} / 256**",
        f"- True prefix: `{payload['target_prefix8']}`",
        f"- Complete cell-order SHA-256: `{payload['target_cell_order_sha256']}`",
        f"- All eight R20 blocks match: `{payload['confirmation']['all_blocks_match']}`",
        f"- Output bits independently checked: `{payload['confirmation']['output_bits_checked']}`",
        f"- Flipped control rejected: `{not payload['confirmation']['control_first_block_match']}`",
        "",
        "## Selected transparent readout",
        "",
        f"- Feature family: `{selected['feature_family']}`",
        f"- Reader: `{selected['readout']}`",
        f"- Ridge lambda: `{selected['ridge_lambda']}`",
        f"- Validation ranks: `{validation['ranks']}`",
        f"- Validation mean log2 rank: `{validation['mean_log2_rank']:.9f}`",
        f"- Selection-matched whole-key null p: `{payload['selection_matched_null_p']:.9f}`",
        "",
        "## Information boundary",
        "",
        f"- Target commitment: `{payload['target_commitment_sha256']}`",
        f"- Prereveal SHA-256: `{payload['prereveal_sha256']}`",
        "- The prereveal runner never opened the secret file or target label.",
        "- The target order, selected model, complete validation grid, and all 64 "
        "  selection-matched null grids were atomically written before reveal.",
        "",
        "## Reproduction",
        "",
        "```bash",
        "PYTHONPATH=src .venv/bin/python research/experiments/chacha20_round20_trajectory_corpus.py",
        "PYTHONPATH=src .venv/bin/python research/experiments/chacha20_round20_knownkey_trajectory_atlas.py",
        "PYTHONPATH=src .venv/bin/python research/experiments/chacha20_round20_knownkey_trajectory_atlas_reveal.py",
        "```",
        "",
        f"- Protocol SHA-256: `{PROTOCOL_SHA256}`",
        f"- Measurement SHA-256: `{payload['measurement_sha256']}`",
        f"- Causal graph SHA-256: `{payload['causal_artifact']['graph_sha256']}`",
    ]
    _atomic_write(output, ("\n".join(lines) + "\n").encode())


def reveal(
    *, secret_path: Path, output: Path, causal_output: Path, report_output: Path
) -> dict[str, Any]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A218 frozen protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    prereveal = json.loads(PREREVEAL.read_bytes())
    public = json.loads(PUBLIC_TARGET.read_bytes())
    secret = json.loads(secret_path.read_bytes())
    measurement = {key: prereveal[key] for key in prereveal["measurement_hash_scope"]}
    if (
        prereveal.get("schema") != "chacha20-round20-knownkey-trajectory-atlas-prereveal-v1"
        or prereveal.get("protocol_sha256") != PROTOCOL_SHA256
        or prereveal.get("secret_file_or_target_label_read") is not False
        or prereveal.get("target_rank_known_at_prereveal") is not False
        or prereveal.get("measurement_sha256") != _canonical_sha256(measurement)
        or public.get("protocol_sha256") != PROTOCOL_SHA256
        or secret.get("protocol_sha256") != PROTOCOL_SHA256
    ):
        raise RuntimeError("A218 prereveal or reveal identity gate failed")
    low20 = int(secret["low20"])
    salt = bytes.fromhex(secret["salt_hex"])
    commitment = target_commitment(low20=low20, salt=salt)
    if (
        commitment != public["commitment_sha256"]
        or commitment != secret["commitment_sha256"]
        or public["challenge_sha256"] != secret["public_challenge_sha256"]
        or public["challenge_sha256"] != _canonical_sha256(public["public_challenge"])
        or secret.get("atlas_collision") is not False
    ):
        raise RuntimeError("A218 salted target commitment does not open")
    order = [int(value) for value in prereveal["target_readout"]["complete_cell_order"]]
    if len(order) != 256 or set(order) != set(range(256)):
        raise RuntimeError("A218 prereveal target order is malformed")
    prefix = low20 >> 12
    rank = order.index(prefix) + 1

    anchors = protocol["anchors"]
    r20_path = ROOT / anchors["R20_runner_path"]
    if _file_sha256(r20_path) != anchors["R20_runner_sha256"]:
        raise RuntimeError("A218 reveal R20 runner anchor drift")
    r20 = _import_path(r20_path, "a218_reveal_r20")
    confirmation = _confirmation(r20, public["public_challenge"], low20)
    if (
        confirmation["all_blocks_match"] is not True
        or confirmation["control_first_block_match"] is not False
        or confirmation["output_bits_checked"] != 4096
    ):
        raise RuntimeError("A218 target reveal failed independent confirmation")

    validation_p = float(prereveal["selection_matched_null"]["lower_tail_plus_one_p"])
    stage = evidence_stage(validation_p=validation_p, target_rank=rank)
    selected = prereveal["selected"]
    payload = {
        "schema": "chacha20-round20-knownkey-trajectory-atlas-result-v1",
        "attempt_id": "A218",
        "evidence_stage": stage,
        "protocol_sha256": PROTOCOL_SHA256,
        "prereveal_path": str(PREREVEAL.relative_to(ROOT)),
        "prereveal_sha256": _file_sha256(PREREVEAL),
        "prereveal_measurement_sha256": prereveal["measurement_sha256"],
        "target_commitment_sha256": commitment,
        "commitment_opened_after_prereveal": True,
        "revealed_low20": low20,
        "revealed_low20_hex": f"{low20:05x}",
        "revealed_salt_hex": salt.hex(),
        "target_prefix8": f"{prefix:08b}",
        "target_prefix_rank": rank,
        "target_cell_order_sha256": prereveal["target_readout"]["complete_cell_order_uint8_sha256"],
        "selected_model_identity": {
            "feature_family": selected["feature_family"],
            "readout": selected["readout"],
            "ridge_lambda": selected["ridge_lambda"],
        },
        "selected_validation": selected["validation"],
        "selection_matched_null_p": validation_p,
        "confirmation": confirmation,
        "anchors": {
            "A218P_measurement_sha256": anchors["A218P_measurement_sha256"],
            "A217_evidence_stage": anchors["A217_evidence_stage"],
        },
    }
    payload["measurement_hash_scope"] = [
        "evidence_stage",
        "target_commitment_sha256",
        "revealed_low20",
        "revealed_salt_hex",
        "target_prefix_rank",
        "target_cell_order_sha256",
        "selected_model_identity",
        "selected_validation",
        "selection_matched_null_p",
        "confirmation",
    ]
    payload["measurement_sha256"] = _canonical_sha256(
        {key: payload[key] for key in payload["measurement_hash_scope"]}
    )
    payload["causal_artifact"] = _causal(payload, causal_output)
    _atomic_json(output, payload)
    _report(payload, report_output)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--secret", type=Path, default=DEFAULT_SECRET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--causal-output", type=Path, default=DEFAULT_CAUSAL)
    parser.add_argument("--report-output", type=Path, default=DEFAULT_REPORT)
    arguments = parser.parse_args()
    payload = reveal(
        secret_path=arguments.secret,
        output=arguments.output,
        causal_output=arguments.causal_output,
        report_output=arguments.report_output,
    )
    print(
        json.dumps(
            {
                "output": str(arguments.output),
                "output_sha256": _file_sha256(arguments.output),
                "measurement_sha256": payload["measurement_sha256"],
                "evidence_stage": payload["evidence_stage"],
                "target_prefix_rank": payload["target_prefix_rank"],
                "all_blocks_match": payload["confirmation"]["all_blocks_match"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
