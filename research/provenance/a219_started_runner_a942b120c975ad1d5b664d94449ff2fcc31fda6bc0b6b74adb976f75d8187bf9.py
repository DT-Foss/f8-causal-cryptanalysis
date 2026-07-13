#!/usr/bin/env python3
"""Execute the frozen A218 order against the committed R20 target without reveal."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
PROTOCOL = RESEARCH / "configs/chacha20_round20_ranked_target_recovery_v1.json"
PROTOCOL_SHA256 = "e2b457120536a5e7a3950b288bf8ed65fd4ff2e9740535b946416127a441d80b"
DEFAULT_OUTPUT = RESEARCH / "results/v1/chacha20_round20_ranked_target_recovery_v1.json"
DEFAULT_CAUSAL = RESEARCH / "results/v1/chacha20_round20_ranked_target_recovery_v1.causal"
DEFAULT_REPORT = RESEARCH / "reports/CAUSAL_CHACHA20_ROUND20_RANKED_TARGET_RECOVERY_V1.md"


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


def _decode_model(model_bits: list[int]) -> int:
    if len(model_bits) != 20 or set(model_bits) - {0, 1}:
        raise RuntimeError("A219 SAT model is not twenty Boolean key bits")
    return sum(int(value) << bit for bit, value in enumerate(model_bits))


def _confirm(r20: Any, challenge: dict[str, Any], low20: int) -> dict[str, Any]:
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
    matches = [
        block == target for block, target in zip(blocks, challenge["target_words"], strict=True)
    ]
    return {
        "implementation": "independent_pure_Python_standard_ChaCha20_block",
        "recovered_unknown_low20": low20,
        "recovered_unknown_low20_hex": f"{low20:05x}",
        "key_word0": key_word0,
        "block_count_checked": len(blocks),
        "output_bits_checked": 512 * len(blocks),
        "candidate_block_sha256": hashes,
        "block_matches": matches,
        "all_blocks_match": all(matches),
        "control_first_block_match": hashes[0] == challenge["control_target_block_sha256"],
    }


def _scientific_execution(execution: Mapping[str, Any]) -> dict[str, Any]:
    rows = []
    for row in execution["rows"]:
        rows.append({key: value for key, value in row.items() if key != "elapsed_seconds"})
    return {
        "mode": execution["mode"],
        "order": execution["order"],
        "seconds_budget_per_cell": execution["seconds_budget_per_cell"],
        "max_cells": execution["max_cells"],
        "rows": rows,
        "summary": execution["summary"],
        "sat_found": execution["sat_found"],
        "retained_state_continuity_verified": execution["retained_state_continuity_verified"],
    }


def _evidence_stage(*, confirmation: dict[str, Any] | None, attempted: int) -> str:
    if confirmation is None:
        return "FULLROUND_R20_TARGET_BLIND_COMPLETE_ORDER_SOLVER_BOUNDARY_RETAINED"
    if attempted <= 16:
        band = "TOP16"
    elif attempted <= 64:
        band = "TOP64"
    else:
        band = "COMPLETE_ORDER"
    return f"FULLROUND_R20_TARGET_BLIND_{band}_RECOVERY_CONFIRMED_WITH_READER_BOUNDARY"


def _causal(payload: dict[str, Any], output: Path) -> dict[str, Any]:
    source = f"measurement:sha256:{payload['measurement_sha256']}"
    builder = CryptoCausalBuilder(
        experiment="chacha20_round20_ranked_target_recovery",
        parameters={
            "attempt_id": "A219",
            "protocol_sha256": PROTOCOL_SHA256,
            "target_secret_unread": True,
        },
    )
    builder.add_triplet(
        edge_id="a219-reader-boundary",
        trigger="A218:key_disjoint_linear_trajectory_reader",
        mechanism="complete_selection_matched_null",
        outcome="A218:linear_across_key_reader_boundary_retained",
        confidence=1.0,
        evidence_kind="64_complete_key_null_worlds",
        source=source,
        attrs={
            "p_value": payload["A218_selection_matched_null_p"],
            "boundary_retained": True,
        },
    )
    builder.add_triplet(
        edge_id="a219-frozen-order-execution",
        trigger="A218:atomic_target_order_prereveal",
        mechanism="executes_one_retained_CaDiCaL_state_until_first_SAT",
        outcome="A219:ranked_target_execution",
        confidence=1.0,
        evidence_kind="target_blind_hash_frozen_operator_execution",
        source=source,
        attrs={
            "order_sha256": payload["target_cell_order_sha256"],
            "attempted_cells": payload["execution"]["summary"]["attempted_cells"],
            "secret_read": False,
        },
    )
    builder.add_triplet(
        edge_id="a219-outcome",
        trigger="A219:ranked_target_execution",
        mechanism="independent_eight_block_standard_ChaCha20_confirmation",
        outcome=f"A219:{payload['evidence_stage']}",
        confidence=1.0,
        evidence_kind=(
            "4096bit_model_confirmation"
            if payload["confirmation"] is not None
            else "complete_budgeted_order_boundary"
        ),
        source=source,
        attrs={
            "sat_found": payload["execution"]["sat_found"],
            "all_blocks_match": (
                payload["confirmation"]["all_blocks_match"]
                if payload["confirmation"] is not None
                else None
            ),
        },
    )
    stats = builder.save(output)
    reader = CryptoCausalReader(output)
    if not reader.verify_provenance() or reader.graph_sha256 != stats["graph_sha256"]:
        raise RuntimeError("A219 causal reader gate failed")
    return {**stats, "reader_verified": True}


def _report(payload: dict[str, Any], output: Path) -> None:
    summary = payload["execution"]["summary"]
    lines = [
        "# ChaCha20 R20 Target-Blind Ranked Recovery (A219)",
        "",
        f"**Evidence stage:** `{payload['evidence_stage']}`",
        "",
        "A219 executes the complete target order frozen by A218 before the target "
        "secret or correct prefix is opened. One CaDiCaL state is retained across "
        "cells and execution stops only on the first SAT model or after all 256 cells.",
        "",
        "## Execution",
        "",
        f"- Attempted cells: `{summary['attempted_cells']}`",
        f"- SAT / UNSAT / UNKNOWN: `{summary['sat']}` / `{summary['unsat']}` / `{summary['unknown']}`",
        f"- Seconds per cell: `{summary['seconds_budget']}`",
        f"- SAT found: `{payload['execution']['sat_found']}`",
        f"- Target secret read: `{payload['target_secret_or_salt_read']}`",
        "",
        "## A218 reader boundary",
        "",
        f"- Selection-matched whole-key null p: `{payload['A218_selection_matched_null_p']}`",
        "- The A218 linear across-key reader boundary remains in force regardless of "
        "  the A219 solver outcome.",
    ]
    if payload["confirmation"] is not None:
        confirmation = payload["confirmation"]
        lines.extend(
            [
                "",
                "## Independent model confirmation",
                "",
                f"- Recovered low20: `{confirmation['recovered_unknown_low20_hex']}`",
                f"- Matching output bits: `{confirmation['output_bits_checked']}`",
                f"- All eight R20 blocks match: `{confirmation['all_blocks_match']}`",
                f"- Flipped control rejected: `{not confirmation['control_first_block_match']}`",
                f"- Numeric prefix position: `{payload['post_model_controls']['numeric_position']}`",
                f"- Gray8 prefix position: `{payload['post_model_controls']['gray8_position']}`",
            ]
        )
    lines.extend(
        [
            "",
            "## Reproduction",
            "",
            "```bash",
            "PYTHONPATH=src .venv/bin/python research/experiments/chacha20_round20_ranked_target_recovery.py",
            "```",
            "",
            f"- Protocol SHA-256: `{PROTOCOL_SHA256}`",
            f"- Measurement SHA-256: `{payload['measurement_sha256']}`",
            f"- Causal graph SHA-256: `{payload['causal_artifact']['graph_sha256']}`",
        ]
    )
    _atomic_write(output, ("\n".join(lines) + "\n").encode())


def run(*, output: Path, causal_output: Path, report_output: Path) -> dict[str, Any]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A219 frozen protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    anchors = protocol["anchors"]
    paths = {
        name: ROOT / anchors[key]
        for name, key in (
            ("A218_protocol", "A218_protocol_path"),
            ("prereveal", "A218_prereveal_path"),
            ("public_target", "public_target_path"),
            ("target_trajectory", "target_trajectory_path"),
            ("r20", "R20_runner_path"),
            ("template_protocol", "A214_template_protocol_path"),
            ("template", "A214_symbolic_template_path"),
            ("ranked_source", "ranked_helper_source_path"),
            ("ranked_wrapper", "ranked_helper_wrapper_path"),
        )
    }
    expected = {
        "A218_protocol": anchors["A218_protocol_sha256"],
        "prereveal": anchors["A218_prereveal_sha256"],
        "public_target": anchors["public_target_sha256"],
        "target_trajectory": anchors["target_trajectory_sha256"],
        "r20": anchors["R20_runner_sha256"],
        "template_protocol": anchors["A214_template_protocol_sha256"],
        "template": anchors["A214_symbolic_template_sha256"],
        "ranked_source": anchors["ranked_helper_source_sha256"],
        "ranked_wrapper": anchors["ranked_helper_wrapper_sha256"],
    }
    drift = {
        name: _file_sha256(paths[name])
        for name in paths
        if _file_sha256(paths[name]) != expected[name]
    }
    if drift:
        raise RuntimeError(f"A219 anchor drift: {drift}")
    prereveal = json.loads(paths["prereveal"].read_bytes())
    public = json.loads(paths["public_target"].read_bytes())
    order_values = prereveal["target_readout"]["complete_cell_order"]
    if (
        prereveal["measurement_sha256"] != anchors["A218_prereveal_measurement_sha256"]
        or prereveal["selection_matched_null"]["lower_tail_plus_one_p"]
        != anchors["A218_selection_matched_null_p"]
        or prereveal["target_readout"]["complete_cell_order_uint8_sha256"]
        != anchors["A218_target_cell_order_uint8_sha256"]
        or len(order_values) != 256
        or set(order_values) != set(range(256))
        or public["challenge_sha256"] != anchors["public_target_challenge_sha256"]
        or public["commitment_sha256"] != anchors["target_commitment_sha256"]
    ):
        raise RuntimeError("A219 frozen target-order gate failed")

    r20 = _import_path(paths["r20"], "a219_r20")
    template = _import_path(paths["template"], "a219_template")
    ranked = _import_path(paths["ranked_wrapper"], "a219_ranked")
    template_protocol = json.loads(paths["template_protocol"].read_bytes())
    helper_build = ranked.compile_helper()
    analysis = r20.analyze()
    with tempfile.TemporaryDirectory(prefix="a219-ranked-target-") as raw_directory:
        directory = Path(raw_directory)
        base_raw, key_mapping, output_mapping, template_manifest = template.compile_template(
            r20=r20,
            public_challenge=analysis["public_challenge"],
            protocol=template_protocol,
            directory=directory,
        )
        target_raw, _, target_instantiation = template.instantiate_output(
            base_raw,
            output_mapping,
            public["public_challenge"]["target_words"][0],
        )
        cnf = directory / "a219_committed_target.cnf"
        cnf.write_bytes(target_raw)
        order = [f"{int(value):08b}" for value in order_values]
        solver = protocol["solver_protocol"]
        execution = ranked.run_ranked(
            helper=ranked.BINARY,
            cnf=cnf,
            mode="A219_A218_frozen_order",
            order=order,
            key_one_literals_bit0_through_bit19=key_mapping,
            seconds=float(solver["seconds_per_cell"]),
            max_cells=int(solver["maximum_cells"]),
            external_timeout_seconds=float(solver["external_timeout_seconds"]),
        )

    confirmation = None
    controls = None
    if execution["sat_found"]:
        sat_row = execution["sat_row"]
        low20 = _decode_model(sat_row["model_bits_bit0_through_bit19"])
        prefix = low20 >> 12
        if sat_row["prefix8"] != f"{prefix:08b}":
            raise RuntimeError("A219 SAT model prefix differs from assumed cell")
        confirmation = _confirm(r20, public["public_challenge"], low20)
        if (
            confirmation["all_blocks_match"] is not True
            or confirmation["control_first_block_match"] is not False
            or confirmation["output_bits_checked"] != 4096
        ):
            raise RuntimeError("A219 SAT model failed independent confirmation")
        gray = [value ^ (value >> 1) for value in range(256)]
        controls = {
            "recovered_prefix8": f"{prefix:08b}",
            "frozen_order_position": int(sat_row["cell_index"]) + 1,
            "numeric_position": prefix + 1,
            "gray8_position": gray.index(prefix) + 1,
            "computed_only_after_confirmed_model": True,
        }
    attempted = int(execution["summary"]["attempted_cells"])
    stage = _evidence_stage(confirmation=confirmation, attempted=attempted)
    payload = {
        "schema": "chacha20-round20-ranked-target-recovery-result-v1",
        "attempt_id": "A219",
        "evidence_stage": stage,
        "protocol_sha256": PROTOCOL_SHA256,
        "anchor_hashes": expected,
        "A218_selection_matched_null_p": anchors["A218_selection_matched_null_p"],
        "A218_reader_boundary_retained": True,
        "target_commitment_sha256": anchors["target_commitment_sha256"],
        "target_cell_order_sha256": anchors["A218_target_cell_order_uint8_sha256"],
        "target_secret_or_salt_read": False,
        "native_helper_build": helper_build,
        "symbolic_template_manifest": template_manifest,
        "target_instantiation": target_instantiation,
        "execution": execution,
        "confirmation": confirmation,
        "post_model_controls": controls,
    }
    payload["measurement_hash_scope"] = [
        "A218_selection_matched_null_p",
        "A218_reader_boundary_retained",
        "target_commitment_sha256",
        "target_cell_order_sha256",
        "target_secret_or_salt_read",
        "symbolic_template_manifest",
        "target_instantiation",
        "scientific_execution",
        "confirmation",
        "post_model_controls",
        "evidence_stage",
    ]
    payload["scientific_execution"] = _scientific_execution(execution)
    payload["measurement_sha256"] = _canonical_sha256(
        {key: payload[key] for key in payload["measurement_hash_scope"]}
    )
    payload["causal_artifact"] = _causal(payload, causal_output)
    _atomic_json(output, payload)
    _report(payload, report_output)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--causal-output", type=Path, default=DEFAULT_CAUSAL)
    parser.add_argument("--report-output", type=Path, default=DEFAULT_REPORT)
    arguments = parser.parse_args()
    payload = run(
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
                "sat_found": payload["execution"]["sat_found"],
                "attempted_cells": payload["execution"]["summary"]["attempted_cells"],
                "all_blocks_match": (
                    payload["confirmation"]["all_blocks_match"]
                    if payload["confirmation"] is not None
                    else None
                ),
                "target_secret_or_salt_read": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
