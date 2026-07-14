#!/usr/bin/env python3
"""Execute A274's frozen top-128 retained-state ChaCha20-R20 recovery."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import inspect
import json
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.chacha20_rfc8439_reference import (  # noqa: E402
    chacha20_block as independent_rfc8439_block,
)
from arx_carry_leak.chacha20_rfc8439_reference import (  # noqa: E402
    rfc8439_section_2_3_2_kat,
)

ATTEMPT_ID = "A274"
DEFAULT_PROTOCOL = (
    ROOT / "research/configs/chacha20_round20_selected_channel_target_recovery_v1.json"
)
DEFAULT_RESULT = (
    ROOT / "research/results/v1/chacha20_round20_selected_channel_target_recovery_v1.json"
)
DEFAULT_CAUSAL = DEFAULT_RESULT.with_suffix(".causal")
DEFAULT_REPORT = (
    ROOT
    / "research/reports/CAUSAL_CHACHA20_ROUND20_SELECTED_CHANNEL_TARGET_RECOVERY_V1.md"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
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


def _atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_bytes(
        path,
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False).encode(
            "ascii"
        )
        + b"\n",
    )


def _anchor_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A274 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _decode_model(model_bits: Sequence[int]) -> int:
    bits = [int(value) for value in model_bits]
    if len(bits) != 20 or set(bits) - {0, 1}:
        raise RuntimeError("A274 SAT model is not twenty Boolean key bits")
    return sum(value << bit for bit, value in enumerate(bits))


def _confirm(public: Any, challenge: Mapping[str, Any], low20: int) -> dict[str, Any]:
    key_word0 = int(challenge["known_key_word0_upper12"]) | low20
    key_words = [key_word0, *[int(value) for value in challenge["known_key_words_1_through_7"]]]
    key_bytes = b"".join(int(word).to_bytes(4, "little") for word in key_words)
    nonce_bytes = b"".join(int(word).to_bytes(4, "little") for word in challenge["nonce_words"])
    primary_blocks = [
        public.P1._chacha_block(
            key_words=key_words,
            counter=(int(challenge["counter_start"]) + index) & 0xFFFFFFFF,
            nonce_words=challenge["nonce_words"],
            rounds=20,
        )
        for index in range(int(challenge["block_count"]))
    ]
    primary_bytes = [public.P1._word_bytes(block) for block in primary_blocks]
    independent_bytes = [
        independent_rfc8439_block(
            key=key_bytes,
            counter=(int(challenge["counter_start"]) + index) & 0xFFFFFFFF,
            nonce=nonce_bytes,
        )
        for index in range(int(challenge["block_count"]))
    ]
    target_bytes = [
        b"".join(int(word).to_bytes(4, "little") for word in block)
        for block in challenge["target_words"]
    ]
    primary_hashes = [_sha256(block) for block in primary_bytes]
    independent_hashes = [_sha256(block) for block in independent_bytes]
    primary_matches = [
        candidate == target
        for candidate, target in zip(primary_bytes, target_bytes, strict=True)
    ]
    independent_matches = [
        candidate == target
        for candidate, target in zip(independent_bytes, target_bytes, strict=True)
    ]
    cross_matches = [
        left == right
        for left, right in zip(primary_bytes, independent_bytes, strict=True)
    ]
    kat = rfc8439_section_2_3_2_kat()
    return {
        "implementation": "dual_independent_standard_ChaCha20_R20_blocks",
        "primary_implementation": "frozen_public_core_pure_Python",
        "claim_gate_implementation": "standalone_byte_oriented_RFC8439_reference",
        "claim_gate_source_sha256": _file_sha256(
            ROOT / "src/arx_carry_leak/chacha20_rfc8439_reference.py"
        ),
        "claim_gate_rfc8439_section_2_3_2_kat": kat,
        "recovered_unknown_low20": low20,
        "recovered_unknown_low20_hex": f"{low20:05x}",
        "key_word0": key_word0,
        "block_count_checked": len(primary_blocks),
        "output_bits_checked": 512 * len(primary_blocks),
        "candidate_block_sha256": primary_hashes,
        "claim_gate_candidate_block_sha256": independent_hashes,
        "block_matches": primary_matches,
        "claim_gate_block_matches": independent_matches,
        "cross_implementation_block_matches": cross_matches,
        "all_cross_implementation_blocks_match": all(cross_matches),
        "all_blocks_match": (
            kat
            and all(primary_matches)
            and all(independent_matches)
            and all(cross_matches)
        ),
        "control_first_block_match": (
            primary_hashes[0] == challenge["control_target_block_sha256"]
            or independent_hashes[0] == challenge["control_target_block_sha256"]
        ),
    }


def _scientific_execution(execution: Mapping[str, Any]) -> dict[str, Any]:
    rows = [
        {key: value for key, value in row.items() if key != "elapsed_seconds"}
        for row in execution["rows"]
    ]
    return {
        "mode": execution["mode"],
        "order": execution["order"],
        "seconds_budget_per_cell": execution["seconds_budget_per_cell"],
        "max_cells": execution["max_cells"],
        "rows": rows,
        "summary": execution["summary"],
        "sat_found": execution["sat_found"],
        "retained_state_continuity_verified": execution[
            "retained_state_continuity_verified"
        ],
    }


def _evidence_stage(*, confirmation: Mapping[str, Any] | None, attempted: int) -> str:
    if confirmation is None:
        return "FULLROUND_R20_TARGET_BLIND_TOP128_SELECTED_CHANNEL_RECOVERY_BOUNDARY"
    if attempted <= 16:
        band = "TOP16"
    elif attempted <= 64:
        band = "TOP64"
    else:
        band = "TOP128"
    return f"FULLROUND_R20_TARGET_BLIND_{band}_SELECTED_CHANNEL_RECOVERY_CONFIRMED"


def _load_protocol(
    protocol_path: Path, expected_protocol_sha256: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], Any, Any, Any, Any]:
    if _file_sha256(protocol_path) != expected_protocol_sha256:
        raise RuntimeError("A274 frozen protocol hash differs")
    protocol = json.loads(protocol_path.read_bytes())
    solver = protocol.get("solver_protocol", {})
    boundary = protocol.get("information_boundary", {})
    order = protocol.get("frozen_reader_order", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-selected-channel-target-recovery-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_complete_A273_unlabeled_target_order_and_before_any_A274_ranked_solver_execution_model_or_confirmation"
        or solver.get("seconds_per_cell") != 30.0
        or solver.get("maximum_cells") != 128
        or solver.get("maximum_logical_assignments") != 2**19
        or solver.get("full_residual_domain_assignments") != 2**20
        or solver.get("stop_condition") != "first_SAT_only"
        or len(order.get("complete_cell_order", [])) != 256
        or set(order["complete_cell_order"]) != set(range(256))
        or order.get("top128_cell_order") != order["complete_cell_order"][:128]
        or _sha256(bytes(order["complete_cell_order"]))
        != order.get("complete_cell_order_uint8_sha256")
        or _sha256(bytes(order["top128_cell_order"]))
        != order.get("top128_cell_order_uint8_sha256")
        or order.get("order_change_permitted") is not False
        or order.get("correct_prefix_or_rank_known") is not False
        or boundary.get("target_generation_label_available_before_or_during_execution")
        is not False
        or boundary.get("correct_prefix_or_A273_target_rank_known_before_execution")
        is not False
        or boundary.get("confirmation_occurs_only_after_solver_model") is not True
    ):
        raise RuntimeError("A274 frozen protocol semantic gate failed")
    anchors = protocol["anchors"]
    for path_key, path_value in anchors.items():
        if not path_key.endswith("_path"):
            continue
        hash_key = f"{path_key.removesuffix('_path')}_sha256"
        if _file_sha256(_anchor_path(path_value)) != anchors.get(hash_key):
            raise RuntimeError(f"A274 anchored dependency hash differs: {path_key}")
    a273_protocol = json.loads(_anchor_path(anchors["A273_protocol_path"]).read_bytes())
    a273_result = json.loads(_anchor_path(anchors["A273_result_path"]).read_bytes())
    if (
        a273_result.get("analysis", {}).get("complete_cell_order")
        != order["complete_cell_order"]
        or a273_result.get("public_challenge_sha256")
        != protocol["target"]["public_challenge_sha256"]
        or a273_protocol.get("target", {}).get("public_challenge_sha256")
        != protocol["target"]["public_challenge_sha256"]
        or protocol["target"].get("generation_label_available") is not False
    ):
        raise RuntimeError("A274 A273 target/order identity differs")
    public = _import_path(_anchor_path(anchors["public_core_path"]), "a274_public")
    challenge = a273_protocol["target"]["public_challenge"]
    public.P1._validate_challenge(challenge)
    template = _import_path(_anchor_path(anchors["symbolic_template_path"]), "a274_template")
    ranked = _import_path(_anchor_path(anchors["ranked_helper_wrapper_path"]), "a274_ranked")
    template_protocol = json.loads(
        _anchor_path(anchors["symbolic_template_protocol_path"]).read_bytes()
    )
    return protocol, a273_protocol, a273_result, public, template, ranked, template_protocol


def _load_dotcausal(dotcausal_src: Path) -> tuple[Any, Any, dict[str, Any]]:
    try:
        io_module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError("dotcausal source is unavailable") from None
        sys.path.insert(0, str(dotcausal_src))
        io_module = importlib.import_module("dotcausal.io")
    source = Path(inspect.getsourcefile(io_module.CausalReader) or "")
    return io_module.CausalWriter, io_module.CausalReader, {
        "module": "dotcausal.io",
        "io_path": str(source),
        "io_sha256": _file_sha256(source),
    }


def _build_causal(
    path: Path, payload: Mapping[str, Any], dotcausal_src: Path
) -> dict[str, Any]:
    CausalWriter, CausalReader, source = _load_dotcausal(dotcausal_src)
    confirmed = payload["confirmation"] is not None
    terminal = (
        "A274:confirmed_fullround_R20_top128_recovery"
        if confirmed
        else "A274:top128_retained_solver_boundary"
    )
    writer = CausalWriter(api_id="a274")
    writer._rules = []
    writer.add_rule(
        name="frozen_target_order_precedes_recovery",
        description="A273 completes and hashes the unlabeled target order before A274 freezes the top-128 retained-state execution.",
        pattern=["A273_hash_frozen_target_order", "A274_top128_execution_contract"],
        conclusion="A274_target_blind_recovery_evidence",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="solver_model_requires_dual_full_output_confirmation",
        description="A SAT model becomes recovery evidence only after two independent standard ChaCha20 implementations match all eight blocks and the flipped control rejects.",
        pattern=["A274_solver_model", "A274_dual_4096_bit_confirmation"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A273:hash_frozen_target_candidate_order",
        mechanism="execute_only_first_128_cells_in_one_retained_CaDiCaL_state",
        outcome="A274:top128_ranked_execution",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["execution_summary"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="full-round ChaCha20-R20 residual-key recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A274:top128_ranked_execution",
        mechanism=(
            "dual_independent_all_eight_block_confirmation"
            if confirmed
            else "complete_top128_budget_without_SAT_model"
        ),
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=(
            "4096 output bits plus flipped control"
            if confirmed
            else "128 prefix cells; 2^19 logical assignments"
        ),
        evidence=json.dumps(payload["confirmation"], sort_keys=True),
        domain="independently confirmed recovery or measured solver boundary",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A273:hash_frozen_target_candidate_order",
        mechanism="materialized_frozen_order_plus_retained_execution_plus_confirmation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A273_order_plus_A274_execution",
        quantification="prospective two-stage chain retained in-file",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A274 selected-channel target recovery",
        entities=[
            "A273:hash_frozen_target_candidate_order",
            "A274:top128_ranked_execution",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "independent_fresh_target_replication_or_wider_residual_domain"
            if confirmed
            else "ordered_clause_timing_or_budget_reallocation_after_top128_boundary"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Repeat the fully frozen pipeline on another fresh target.",
                "Transfer the retained reader to a wider residual-key domain.",
            ]
            if confirmed
            else [
                "Which top-128 cells showed the strongest retained progress trajectory?",
                "Can ordered clause timing re-rank the unresolved cells prospectively?",
            ]
        ),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, path)
    reader = CausalReader(str(path), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.version != 1
        or reader.api_id != "a274"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or all_rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A274 authentic Causal Reader reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "file_sha256": _file_sha256(path),
        "file_bytes": path.stat().st_size,
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "integrity_verified_by_authoritative_reader": True,
        "reader_source": source,
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def _report(payload: Mapping[str, Any]) -> str:
    execution = payload["execution_summary"]
    confirmation = payload["confirmation"]
    rows = [
        "# A274 — ChaCha20-R20 selected-channel target recovery",
        "",
        f"Evidence stage: **{payload['evidence_stage']}**",
        "",
        f"- Attempted frozen cells: **{execution['attempted_cells']}/128**",
        f"- Logical assignments inside attempted cells: **{execution['logical_assignments']}**",
        f"- SAT model found: **{execution['sat_found']}**",
    ]
    if confirmation is not None:
        rows.extend(
            [
                f"- Recovered low20: **`0x{confirmation['recovered_unknown_low20_hex']}`**",
                f"- Independent output bits confirmed: **{confirmation['output_bits_checked']}**",
                f"- Flipped control matched: **{confirmation['control_first_block_match']}**",
            ]
        )
    rows.extend(
        [
            "",
            "## Authentic AI-native Causal readback",
            "",
            f"- Next gap: **{payload['causal']['personal_semantic_readback']['next_gap']['expected_object_type']}**",
            "",
        ]
    )
    return "\n".join(rows)


def execute(
    *,
    protocol_path: Path,
    expected_protocol_sha256: str,
    output: Path,
    causal_output: Path,
    report_output: Path,
    dotcausal_src: Path,
) -> dict[str, Any]:
    (
        protocol,
        a273_protocol,
        _,
        public,
        template,
        ranked,
        template_protocol,
    ) = _load_protocol(protocol_path, expected_protocol_sha256)
    anchors = protocol["anchors"]
    build = ranked.compile_helper(output=_anchor_path(anchors["ranked_helper_binary_path"]))
    if (
        build["source_sha256"] != anchors["ranked_helper_source_sha256"]
        or build["binary_sha256"] != anchors["ranked_helper_binary_sha256"]
    ):
        raise RuntimeError("A274 ranked helper rebuild differs from freeze")
    challenge = a273_protocol["target"]["public_challenge"]
    with tempfile.TemporaryDirectory(prefix="a274_selected_channel_recovery_") as temporary:
        directory = Path(temporary)
        base_raw, key_mapping, output_mapping, template_manifest = template.compile_template(
            r20=public,
            public_challenge=challenge,
            protocol=template_protocol,
            directory=directory,
        )
        target_raw, _, target_instantiation = template.instantiate_output(
            base_raw,
            output_mapping,
            challenge["target_words"][0],
        )
        cnf = directory / "a274_unlabeled_target.cnf"
        _atomic_bytes(cnf, target_raw)
        if _file_sha256(cnf) != target_instantiation["sha256"]:
            raise RuntimeError("A274 target CNF readback differs")
        order_values = protocol["frozen_reader_order"]["complete_cell_order"]
        order = [f"{int(value):08b}" for value in order_values]
        solver = protocol["solver_protocol"]
        execution = ranked.run_ranked(
            helper=_anchor_path(anchors["ranked_helper_binary_path"]),
            cnf=cnf,
            mode="A274_A273_frozen_selected_channel_top128",
            order=order,
            key_one_literals_bit0_through_bit19=key_mapping,
            seconds=float(solver["seconds_per_cell"]),
            max_cells=int(solver["maximum_cells"]),
            external_timeout_seconds=float(solver["external_timeout_seconds"]),
        )
    confirmation = None
    post_model = None
    if execution["sat_found"]:
        sat_row = execution["sat_row"]
        low20 = _decode_model(sat_row["model_bits_bit0_through_bit19"])
        prefix = low20 >> 12
        if sat_row["prefix8"] != f"{prefix:08b}":
            raise RuntimeError("A274 SAT model prefix differs from assumed cell")
        confirmation = _confirm(public, challenge, low20)
        if (
            confirmation["all_blocks_match"] is not True
            or confirmation["all_cross_implementation_blocks_match"] is not True
            or confirmation["claim_gate_rfc8439_section_2_3_2_kat"] is not True
            or confirmation["control_first_block_match"] is not False
            or confirmation["output_bits_checked"] != 4096
        ):
            raise RuntimeError("A274 SAT model failed dual-independent confirmation")
        post_model = {
            "recovered_prefix8": prefix,
            "frozen_order_position": int(sat_row["cell_index"]) + 1,
            "numeric_position": prefix + 1,
            "computed_only_after_confirmed_model": True,
        }
    attempted = int(execution["summary"]["attempted_cells"])
    stage = _evidence_stage(confirmation=confirmation, attempted=attempted)
    scientific = _scientific_execution(execution)
    execution_summary = {
        "attempted_cells": attempted,
        "logical_assignments": attempted * 2**12,
        "full_residual_domain_assignments": 2**20,
        "strict_subset_of_full_domain": attempted < 256,
        "sat_found": execution["sat_found"],
        "sat": execution["summary"]["sat"],
        "unsat": execution["summary"]["unsat"],
        "unknown": execution["summary"]["unknown"],
        "retained_state_continuity_verified": execution[
            "retained_state_continuity_verified"
        ],
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-selected-channel-target-recovery-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": stage,
        "protocol_sha256": expected_protocol_sha256,
        "runner_sha256": _file_sha256(Path(__file__)),
        "A273_result_sha256": anchors["A273_result_sha256"],
        "public_challenge_sha256": protocol["target"]["public_challenge_sha256"],
        "target_generation_label_available": False,
        "target_cell_order_sha256": protocol["frozen_reader_order"][
            "complete_cell_order_uint8_sha256"
        ],
        "top128_cell_order_sha256": protocol["frozen_reader_order"][
            "top128_cell_order_uint8_sha256"
        ],
        "native_helper_build": build,
        "symbolic_template_manifest": template_manifest,
        "target_instantiation": target_instantiation,
        "execution": execution,
        "scientific_execution": scientific,
        "execution_summary": execution_summary,
        "confirmation": confirmation,
        "post_model_controls": post_model,
        "information_boundary": protocol["information_boundary"],
    }
    payload["measurement_sha256"] = _canonical_sha256(
        {
            key: payload[key]
            for key in (
                "evidence_stage",
                "A273_result_sha256",
                "public_challenge_sha256",
                "target_generation_label_available",
                "target_cell_order_sha256",
                "top128_cell_order_sha256",
                "symbolic_template_manifest",
                "target_instantiation",
                "scientific_execution",
                "execution_summary",
                "confirmation",
                "post_model_controls",
            )
        }
    )
    payload["causal"] = _build_causal(causal_output, payload, dotcausal_src)
    _atomic_json(output, payload)
    _atomic_bytes(report_output, _report(payload).encode("utf-8"))
    return payload


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=DEFAULT_PROTOCOL)
    parser.add_argument("--expected-protocol-sha256", required=True)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--output", type=Path, default=DEFAULT_RESULT)
    parser.add_argument("--causal-output", type=Path, default=DEFAULT_CAUSAL)
    parser.add_argument("--report-output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args(argv)
    if not args.run:
        print(
            json.dumps(
                {
                    "attempt_id": ATTEMPT_ID,
                    "protocol": str(args.protocol),
                    "expected_protocol_sha256": args.expected_protocol_sha256,
                    "execution_started": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    payload = execute(
        protocol_path=args.protocol,
        expected_protocol_sha256=args.expected_protocol_sha256,
        output=args.output,
        causal_output=args.causal_output,
        report_output=args.report_output,
        dotcausal_src=args.dotcausal_src,
    )
    print(
        json.dumps(
            {
                "evidence_stage": payload["evidence_stage"],
                **payload["execution_summary"],
                "result": str(args.output),
                "result_sha256": _file_sha256(args.output),
                "causal": str(args.causal_output),
                "causal_sha256": _file_sha256(args.causal_output),
            },
            indent=2,
            sort_keys=True,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
