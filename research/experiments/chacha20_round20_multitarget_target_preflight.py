#!/usr/bin/env python3
"""Generate A283's four label-free targets after the complete A282 freeze."""

from __future__ import annotations

import argparse
import json
import secrets
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from chacha20_round20_multitarget_common import (
    ROOT,
    anchor,
    assert_label_free,
    atomic_json,
    canonical_sha256,
    file_sha256,
    import_path,
    path_from_ref,
    path_ref,
    prior_challenge_hashes,
    prior_recovered_low20,
    verify_anchors,
)

ATTEMPT_ID = "A283"
DEFAULT_MASTER = (
    ROOT / "research/configs/chacha20_round20_multitarget_panel_master_v1.json"
)
DEFAULT_OUTPUT = (
    ROOT / "research/configs/chacha20_round20_multitarget_targets_v1.json"
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


def _target_path(index: int) -> Path:
    return (
        ROOT
        / f"research/configs/chacha20_round20_multitarget_t{index:02d}_target_v1.json"
    )


def _load_panel(master_path: Path, expected_master_sha256: str) -> dict[str, Any]:
    if file_sha256(master_path) != expected_master_sha256:
        raise RuntimeError("A283 panel-master hash differs")
    panel = json.loads(master_path.read_bytes())
    if (
        panel.get("schema") != "chacha20-round20-multitarget-panel-master-v1"
        or panel.get("attempt_id") != "A282"
        or panel.get("protocol_state")
        != "four_public_materials_and_symbolic_mappings_frozen_before_any_target_generation"
        or panel.get("panel_size") != 4
        or len(panel.get("panel_rows", [])) != 4
        or panel.get("information_boundary", {}).get("any_panel_target_generated")
        is not False
        or panel.get("target_generation_contract", {}).get(
            "generation_labels_returned_or_serialized"
        )
        is not False
    ):
        raise RuntimeError("A283 panel-master semantic gate failed")
    verify_anchors(panel["source_anchors"], context="A283 panel sources")
    for row in panel["panel_rows"]:
        for key in ("master_protocol", "symbolic_protocol"):
            value = row[key]
            path = path_from_ref(value["path"])
            if file_sha256(path) != value["sha256"]:
                raise RuntimeError(f"A283 panel row anchor differs: {row['target_id']}/{key}")
    return panel


def build_targets(
    *, master_path: Path, expected_master_sha256: str
) -> tuple[dict[str, Any], list[tuple[Path, dict[str, Any]]]]:
    panel = _load_panel(master_path, expected_master_sha256)
    fixed = {
        A275_PREFLIGHT: A275_PREFLIGHT_SHA256,
        A277_RESULT: A277_RESULT_SHA256,
        PUBLIC_CORE: PUBLIC_CORE_SHA256,
        Path(__file__): panel["source_anchors"]["A283_target_preflight"]["sha256"],
    }
    for path, digest in fixed.items():
        if file_sha256(path) != digest:
            raise RuntimeError(f"A283 frozen source differs: {path.name}")

    a275 = import_path(A275_PREFLIGHT, "a283_a275_preflight")
    public = import_path(PUBLIC_CORE, "a283_public_core")
    prior = a275._prior_geometry()
    prior_low20 = set(int(value) for value in prior["low20"])
    prior_low20.update(prior_recovered_low20())
    prior_prefix8 = set(int(value) for value in prior["prefix8"])
    prior_suffix12 = set(int(value) for value in prior["suffix12"])
    prior_prefix8.update(value >> 12 for value in prior_low20)
    prior_suffix12.update(value & 0xFFF for value in prior_low20)
    prior_hashes = prior_challenge_hashes()
    base_prior_ledger = {
        "low20": sorted(prior_low20),
        "prefix8": sorted(prior_prefix8),
        "suffix12": sorted(prior_suffix12),
        "public_challenge_sha256": sorted(prior_hashes),
    }

    selected_labels: list[int] = []
    selected_prefixes: set[int] = set()
    selected_suffixes: set[int] = set()
    selected_hashes: set[str] = set()
    generated: list[tuple[Path, dict[str, Any]]] = []
    ledger_rows: list[dict[str, Any]] = []
    for row in panel["panel_rows"]:
        index = int(row["panel_index"])
        target_id = str(row["target_id"])
        submaster_path = path_from_ref(row["master_protocol"]["path"])
        submaster = json.loads(submaster_path.read_bytes())
        public_template = public.validate_public_template(
            submaster["cross_material_public_template"]
        )
        challenge = None
        candidate = None
        for _ in range(16384):
            proposed = secrets.randbits(20)
            proposed_prefix = proposed >> 12
            proposed_suffix = proposed & 0xFFF
            if (
                proposed in prior_low20
                or proposed in selected_labels
                or proposed_prefix in prior_prefix8
                or proposed_prefix in selected_prefixes
                or proposed_suffix in prior_suffix12
                or proposed_suffix in selected_suffixes
            ):
                continue
            proposed_challenge = public.build_known_challenge(
                public_template, low20=proposed
            )
            proposed_hash = canonical_sha256(proposed_challenge)
            if proposed_hash in prior_hashes or proposed_hash in selected_hashes:
                continue
            candidate = proposed
            challenge = proposed_challenge
            break
        if challenge is None or candidate is None:
            raise RuntimeError(f"A283 could not draw a disjoint target: {target_id}")
        assert_label_free(challenge)
        challenge_sha256 = canonical_sha256(challenge)
        selected_labels.append(candidate)
        selected_prefixes.add(candidate >> 12)
        selected_suffixes.add(candidate & 0xFFF)
        selected_hashes.add(challenge_sha256)
        target_path = _target_path(index)
        protocol: dict[str, Any] = {
            "schema": "chacha20-round20-cross-material-target-v1",
            "attempt_id": "A279",
            "protocol_state": (
                "frozen_after_A278_master_and_label_discard_before_any_target_measurement_or_solve"
            ),
            "panel_context": {
                "panel_attempt_id": ATTEMPT_ID,
                "target_id": target_id,
                "panel_index": index,
                "panel_master": anchor(master_path, expected_master_sha256),
            },
            "master_protocol": {
                **anchor(submaster_path, row["master_protocol"]["sha256"]),
                "scientific_design_sha256": row[
                    "master_scientific_design_sha256"
                ],
            },
            "runner_sha256": file_sha256(Path(__file__)),
            "anchors": {
                "A275_preflight": anchor(A275_PREFLIGHT, A275_PREFLIGHT_SHA256),
                "A277_result": anchor(A277_RESULT, A277_RESULT_SHA256),
                "public_core": anchor(PUBLIC_CORE, PUBLIC_CORE_SHA256),
                "A282_panel_master": anchor(master_path, expected_master_sha256),
                "A283_target_preflight": anchor(Path(__file__)),
            },
            "public_template": public_template,
            "public_template_sha256": row["public_template_sha256"],
            "public_challenge": challenge,
            "public_challenge_sha256": challenge_sha256,
            "target_block_sha256": challenge["target_block_sha256"],
            "generation": {
                "source": "secrets.randbits_20",
                "rejection": (
                    "all_prior_and_intra_panel_low20_prefix8_suffix12_and_challenge_hashes"
                ),
                "prior_ledger_sha256": canonical_sha256(base_prior_ledger),
                "prior_low20_count": len(prior_low20),
                "prior_prefix8_count": len(prior_prefix8),
                "prior_suffix12_count": len(prior_suffix12),
                "prior_public_challenge_count": len(prior_hashes),
                "intra_panel_targets_preceding": index - 1,
                "generation_label_returned_or_serialized": False,
            },
            "information_boundary": {
                "master_schedule_frozen_before_target_generation": True,
                "all_panel_public_material_and_symbolic_mappings_frozen_before_target_generation": True,
                "target_generation_label_discarded_before_protocol_serialization": True,
                "target_generation_label_available": False,
                "target_measurement_started": False,
                "target_candidate_order_known": False,
                "target_solver_execution_started": False,
            },
        }
        assert_label_free(protocol)
        generated.append((target_path, protocol))
        ledger_rows.append(
            {
                "target_id": target_id,
                "panel_index": index,
                "master_protocol": row["master_protocol"],
                "symbolic_protocol": row["symbolic_protocol"],
                "target_protocol_path": path_ref(target_path),
                "public_template_sha256": row["public_template_sha256"],
                "public_challenge_sha256": challenge_sha256,
            }
        )

    if (
        len(selected_labels) != 4
        or len(set(selected_labels)) != 4
        or len(selected_prefixes) != 4
        or len(selected_suffixes) != 4
        or len(selected_hashes) != 4
    ):
        raise RuntimeError("A283 intra-panel target-disjointness gate failed")
    selected_labels.clear()
    ledger: dict[str, Any] = {
        "schema": "chacha20-round20-multitarget-target-ledger-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "all_four_targets_frozen_and_labels_discarded_before_any_measurement",
        "panel_master": anchor(master_path, expected_master_sha256),
        "target_count": len(ledger_rows),
        "targets": ledger_rows,
        "generation_summary": {
            "all_targets_generated_in_one_process": True,
            "all_low20_values_distinct": True,
            "all_prefix8_values_distinct": True,
            "all_suffix12_values_distinct": True,
            "all_public_challenge_hashes_distinct": True,
            "generation_labels_returned_or_serialized": False,
            "prior_ledger_sha256": canonical_sha256(base_prior_ledger),
        },
        "information_boundary": {
            "all_four_target_protocols_complete_before_any_measurement": True,
            "any_target_generation_label_available": False,
            "any_measurement_started": False,
            "any_recovery_started": False,
        },
    }
    assert_label_free(ledger)
    return ledger, generated


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--master", type=Path, default=DEFAULT_MASTER)
    parser.add_argument("--expected-master-sha256", required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--freeze", action="store_true")
    args = parser.parse_args(argv)
    if not args.freeze:
        print(json.dumps({"attempt_id": ATTEMPT_ID, "output": path_ref(args.output)}))
        return
    target_paths = [_target_path(index) for index in range(1, 5)]
    existing = [path for path in [args.output, *target_paths] if path.exists()]
    if existing:
        raise FileExistsError(f"A283 target artifact already exists: {existing[0]}")
    ledger, generated = build_targets(
        master_path=args.master,
        expected_master_sha256=args.expected_master_sha256,
    )
    for path, protocol in generated:
        atomic_json(path, protocol)
    for row, (path, _) in zip(ledger["targets"], generated, strict=True):
        row["target_protocol"] = anchor(path)
        row.pop("target_protocol_path")
    atomic_json(args.output, ledger)
    print(
        json.dumps(
            {
                "attempt_id": ATTEMPT_ID,
                "output": path_ref(args.output),
                "ledger_sha256": file_sha256(args.output),
                "target_count": ledger["target_count"],
                "public_challenge_sha256": [
                    row["public_challenge_sha256"] for row in ledger["targets"]
                ],
                "target_labels_returned_or_serialized": False,
                "measurement_or_recovery_started": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
