#!/usr/bin/env python3
"""Post-barrier full W32 label and rank diagnosis for the completed A227 miss."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


A227 = _import_sibling(
    "chacha20_round20_w32_top4_prospective_recovery.py",
    "a228_completed_a227_anchor",
)
A224 = A227.A224
A184 = A227.A184

ATTEMPT_ID = "R20-A228-A227-POSTBARRIER-LABEL-V1"
SCHEMA = "chacha20-round20-a227-postbarrier-label-v1"
OUTPUT = RESEARCH / "results" / "v1" / "chacha20_round20_a227_postbarrier_label_v1.json"
REPORT = RESEARCH / "reports" / "CAUSAL_CHACHA20_ROUND20_A227_POSTBARRIER_LABEL_V1.md"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def main() -> None:
    if OUTPUT.exists():
        raise RuntimeError(f"A228 output already exists: {OUTPUT}")
    protocol = json.loads(A227.PROTOCOL_PATH.read_bytes())
    a227 = json.loads(A227.RESULT_PATH.read_bytes())
    if (
        a227.get("schema") != A227.RESULT_SCHEMA
        or a227.get("limited_Metal_search", {}).get("prospective_recovery_success") is not False
        or a227.get("limited_Metal_search", {}).get("complete_selected_regions_executed") is not True
        or a227.get("limited_Metal_search", {}).get("logical_candidate_count") != 1 << 26
    ):
        raise RuntimeError("A228 requires the completed unsuccessful A227 top-four barrier")
    challenge = protocol["public_challenge"]
    target = np.array(challenge["target_words"][0], dtype=np.uint32)
    control = np.array(challenge["control_target_words"], dtype=np.uint32)
    executable, native_build = A184._A181._compile_native(
        A227.ARTIFACT_DIR / "a228_metal_build", "swiftc"
    )
    host = A184.SliceMetalHost(executable, A227._initial(challenge), target, control)
    try:
        execution = A224._enumerate_word0(host)
        host_identity = host.identity
    finally:
        host.close()
    word0 = execution["factual_filter_matches"][0]
    confirmation = A227._confirm_candidate(challenge, word0)
    if not confirmation["all_blocks_match"] or not confirmation["flipped_control_rejected"]:
        raise RuntimeError("A228 recovered label failed independent confirmation")
    true_prefix = confirmation["prefix8"]
    readout = A224._trajectory_readout(
        a227["trajectory"]["observations"], true_prefix8=true_prefix
    )
    fixed_rank = next(
        index + 1
        for index, row in enumerate(a227["reader"]["ranked_cells"])
        if row["prefix8"] == true_prefix
    )
    selected = {row["prefix8"] for row in a227["reader"]["selected_top4"]}
    payload = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "POST_A227_BARRIER_FULL_W32_LABEL_AND_RANK_DIAGNOSIS",
        "anchors": {
            "A227_protocol_sha256": _file_sha256(A227.PROTOCOL_PATH),
            "A227_result_sha256": _file_sha256(A227.RESULT_PATH),
            "A227_top4_completed_before_A228": True,
        },
        "information_boundary": {
            "A228_started_only_after_A227_top4_result_was_final": True,
            "A228_label_could_not_change_A227_selected_regions": True,
        },
        "native_build": native_build,
        "host_identity": host_identity,
        "full_domain_execution": execution,
        "confirmation": confirmation,
        "A227_fixed_coherence_rank": fixed_rank,
        "A227_selected_top4_contained_true_prefix": true_prefix in selected,
        "all_fixed_A224_view_ranks": readout["true_cell_ranks"],
        "true_cell_features": readout["true_cell_features"],
    }
    _atomic_json(OUTPUT, payload)
    ranks = payload["all_fixed_A224_view_ranks"]
    lines = [
        "# A228 — A227 post-barrier label",
        "",
        f"- Recovered word 0: `{confirmation['key_word0_hex']}`",
        f"- True prefix: `{true_prefix}`",
        f"- A227 fixed coherence rank: **{fixed_rank} / 256**",
        f"- Conflicts rank: {ranks['conflicts']['rank']} / 256",
        f"- Decisions rank: {ranks['decisions']['rank']} / 256",
        f"- Local coherence residual rank: {ranks['coherence_local_residual']['rank']} / 256",
        "",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    temporary = REPORT.with_name(f".{REPORT.name}.tmp")
    temporary.write_text("\n".join(lines))
    temporary.replace(REPORT)
    print(
        json.dumps(
            {
                "recovered_word0": confirmation["key_word0_hex"],
                "true_prefix8": true_prefix,
                "fixed_coherence_rank": fixed_rank,
                "view_ranks": {name: row["rank"] for name, row in ranks.items()},
                "output": str(OUTPUT),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
