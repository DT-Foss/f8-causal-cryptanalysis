#!/usr/bin/env python3
"""Freeze A281's full cross-material top-half plus residual recovery protocol."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
ATTEMPT_ID = "A281"
DEFAULT_OUTPUT = (
    ROOT / "research/configs/chacha20_round20_cross_material_composite_recovery_v1.json"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
MASTER = ROOT / "research/configs/chacha20_round20_cross_material_composite_master_v1.json"
TARGET = ROOT / "research/configs/chacha20_round20_cross_material_target_v1.json"
SYMBOLIC = ROOT / "research/configs/chacha20_round20_cross_material_symbolic_template_v1.json"
ORDER_RESULT = ROOT / "research/results/v1/chacha20_round20_cross_material_order_v1.json"
ORDER_CAUSAL = ORDER_RESULT.with_suffix(".causal")
ORDER_MEASUREMENT = (
    ROOT
    / "research/results/v1/chacha20_round20_cross_material_order_v1"
    / "target.numeric.measurement.json.zst"
)
ORDER_RUNNER = Path(__file__).with_name("chacha20_round20_cross_material_measure.py")
RECOVERY_RUNNER = Path(__file__).with_name(
    "chacha20_round20_cross_material_composite_recovery.py"
)
PREFLIGHT = Path(__file__)
MASTER_SHA256 = "256504ef394fbc4d5e1da2881f3de0c8a32af5908f454e58cf9711da733551b6"
TARGET_SHA256 = "a2685c03c3fb486c25362e5e7ae99a001ae14b36a7d96595b0f66628c52b0b16"
SYMBOLIC_SHA256 = "5443d4ef635d1b31001a99295be34fa0e4878f0496c570b58fed59efb60e1f75"
FORBIDDEN_SERIALIZED_KEYS = {
    "known_low20",
    "low20",
    "low20_hex",
    "recovered_unknown_low20",
    "recovered_unknown_low20_hex",
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


def _path(value: str) -> Path:
    candidate = Path(value)
    return candidate if candidate.is_absolute() else ROOT / candidate


def _assert_secret_free(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).lower() in FORBIDDEN_SERIALIZED_KEYS:
                raise RuntimeError(f"A281 secret-bearing field is forbidden: {key}")
            _assert_secret_free(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            _assert_secret_free(child)


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


def _anchor(path: Path, digest: str | None = None) -> dict[str, str]:
    return {
        "path": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),
        "sha256": digest or _file_sha256(path),
    }


def build_protocol(
    *,
    order_result_sha256: str,
    order_causal_sha256: str,
    order_measurement_sha256: str,
    root_review_acknowledged: bool,
    dotcausal_src: Path,
) -> dict[str, Any]:
    if root_review_acknowledged is not True:
        raise RuntimeError("A281 freeze requires explicit root review acknowledgement")
    fixed = {
        MASTER: MASTER_SHA256,
        TARGET: TARGET_SHA256,
        SYMBOLIC: SYMBOLIC_SHA256,
        ORDER_RESULT: order_result_sha256,
        ORDER_CAUSAL: order_causal_sha256,
        ORDER_MEASUREMENT: order_measurement_sha256,
    }
    for path, digest in fixed.items():
        if _file_sha256(path) != digest:
            raise RuntimeError(f"A281 frozen input hash differs: {path.name}")
    if not RECOVERY_RUNNER.is_file():
        raise RuntimeError("A281 recovery runner must exist before protocol freeze")
    master = json.loads(MASTER.read_bytes())
    target = json.loads(TARGET.read_bytes())
    order_result = json.loads(ORDER_RESULT.read_bytes())
    order = order_result.get("analysis", {}).get("complete_cell_order", [])
    top128 = order[:128]
    residual = order[128:]
    if (
        master.get("schema")
        != "chacha20-round20-cross-material-composite-master-v1"
        or master.get("attempt_id") != "A278"
        or target.get("schema") != "chacha20-round20-cross-material-target-v1"
        or target.get("attempt_id") != "A279"
        or order_result.get("schema")
        != "chacha20-round20-cross-material-order-result-v1"
        or order_result.get("attempt_id") != "A280"
        or order_result.get("evidence_stage")
        != "FULLROUND_R20_CROSS_MATERIAL_TARGET_BLIND_ORDER_FROZEN"
        or order_result.get("target_protocol_sha256") != TARGET_SHA256
        or order_result.get("master_protocol_sha256") != MASTER_SHA256
        or order_result.get("symbolic_protocol_sha256") != SYMBOLIC_SHA256
        or order_result.get("measurement", {}).get("complete_candidate_cover") is not True
        or order_result.get("headline", {}).get("model_free_unknown_stages") != 1024
        or len(order) != 256
        or set(order) != set(range(256))
        or len(top128) != 128
        or len(residual) != 128
        or set(top128) & set(residual)
        or _sha256(bytes(order))
        != order_result["analysis"]["complete_cell_order_uint8_sha256"]
        or _sha256(bytes(top128))
        != order_result["analysis"]["top128_cell_order_uint8_sha256"]
        or target.get("information_boundary", {}).get("target_generation_label_available")
        is not False
    ):
        raise RuntimeError("A281 A278-A280 semantic gate failed")
    _assert_secret_free(target)
    _assert_secret_free(order_result)

    CausalReader, reader_source = _load_reader(dotcausal_src)
    reader = CausalReader(str(ORDER_CAUSAL), verify_integrity=True)
    gaps = list(reader._gaps)
    if (
        reader.version != 1
        or reader.api_id != "a280"
        or len(gaps) != 1
        or gaps[0].get("expected_object_type")
        != "execute_frozen_top128_then_exact_residual_schedule_on_cross_material_target"
    ):
        raise RuntimeError("A281 A280 Causal gap differs")

    a276_protocol_path = _path(master["anchors"]["A276_protocol"]["path"])
    a277_protocol_path = _path(master["anchors"]["A277_protocol"]["path"])
    a276_protocol = json.loads(a276_protocol_path.read_bytes())
    a277_protocol = json.loads(a277_protocol_path.read_bytes())
    anchors = {
        "A278_master": _anchor(MASTER, MASTER_SHA256),
        "A279_target": _anchor(TARGET, TARGET_SHA256),
        "A280_symbolic": _anchor(SYMBOLIC, SYMBOLIC_SHA256),
        "A280_result": _anchor(ORDER_RESULT, order_result_sha256),
        "A280_causal": _anchor(ORDER_CAUSAL, order_causal_sha256),
        "A280_measurement": _anchor(ORDER_MEASUREMENT, order_measurement_sha256),
        "A280_runner": _anchor(ORDER_RUNNER),
        "A276_protocol": _anchor(
            a276_protocol_path, master["anchors"]["A276_protocol"]["sha256"]
        ),
        "A276_runner": _anchor(
            _path(master["anchors"]["A276_runner"]["path"]),
            master["anchors"]["A276_runner"]["sha256"],
        ),
        "A277_protocol": _anchor(
            a277_protocol_path, master["anchors"]["A277_protocol"]["sha256"]
        ),
        "A277_runner": _anchor(
            _path(master["anchors"]["A277_runner"]["path"]),
            master["anchors"]["A277_runner"]["sha256"],
        ),
        "public_core": _anchor(
            _path(master["anchors"]["public_core"]["path"]),
            master["anchors"]["public_core"]["sha256"],
        ),
        "symbolic_template": _anchor(
            _path(master["anchors"]["symbolic_template"]["path"]),
            master["anchors"]["symbolic_template"]["sha256"],
        ),
        "ranked_wrapper": _anchor(
            _path(a276_protocol["anchors"]["ranked_helper_wrapper_path"]),
            a276_protocol["anchors"]["ranked_helper_wrapper_sha256"],
        ),
        "ranked_native": _anchor(
            _path(a276_protocol["anchors"]["ranked_helper_source_path"]),
            a276_protocol["anchors"]["ranked_helper_source_sha256"],
        ),
        "ranked_binary": _anchor(
            _path(a276_protocol["anchors"]["ranked_helper_binary_path"]),
            a276_protocol["anchors"]["ranked_helper_binary_sha256"],
        ),
        "independent_reference": _anchor(
            _path(a276_protocol["anchors"]["independent_reference_path"]),
            a276_protocol["anchors"]["independent_reference_sha256"],
        ),
        "residual_wrapper": _anchor(
            _path(a277_protocol["anchors"]["two_pass_wrapper_path"]),
            a277_protocol["anchors"]["two_pass_wrapper_sha256"],
        ),
        "residual_native": _anchor(
            _path(a277_protocol["anchors"]["two_pass_native_path"]),
            a277_protocol["anchors"]["two_pass_native_sha256"],
        ),
        "preflight": _anchor(PREFLIGHT),
        "runner": _anchor(RECOVERY_RUNNER),
    }
    for name, anchor in anchors.items():
        if _file_sha256(_path(anchor["path"])) != anchor["sha256"]:
            raise RuntimeError(f"A281 anchor differs during freeze: {name}")

    schedule = master["frozen_schedule"]
    protocol: dict[str, Any] = {
        "schema": "chacha20-round20-cross-material-composite-recovery-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_after_A280_complete_unlabeled_order_before_any_A281_recovery",
        "anchors": anchors,
        "target": {
            "public_challenge_sha256": target["public_challenge_sha256"],
            "generation_label_available": False,
            "correct_prefix_or_rank_known": False,
            "unknown_assignment_bits": 20,
            "full_residual_domain_assignments": 2**20,
        },
        "frozen_order": {
            "complete_cell_order": order,
            "complete_cell_order_uint8_sha256": _sha256(bytes(order)),
            "top128_cell_order": top128,
            "top128_cell_order_uint8_sha256": _sha256(bytes(top128)),
            "residual_cell_order": residual,
            "residual_cell_order_uint8_sha256": _sha256(bytes(residual)),
            "order_change_permitted": False,
        },
        "solver_schedule": schedule,
        "authentic_causal_readback": {
            "reader_source": reader_source,
            "A280_gap": gaps[0],
            "read_by_root_before_freeze": True,
        },
        "information_boundary": {
            "A278_schedule_frozen_before_A279_target": True,
            "A280_complete_order_frozen_before_A281_recovery": True,
            "target_generation_label_available": False,
            "correct_prefix_or_rank_known": False,
            "confirmation_permitted_only_after_solver_model": True,
            "residual_phase_permitted_only_after_all_top128_cells_exact_UNSAT": True,
            "UNKNOWN_top_half_cell_is_not_elimination": True,
            "UNKNOWN_residual_cell_is_not_elimination": True,
            "any_A281_solver_execution_started": False,
        },
    }
    protocol["scientific_design_sha256"] = _canonical_sha256(
        {
            "target": protocol["target"],
            "frozen_order": protocol["frozen_order"],
            "solver_schedule": protocol["solver_schedule"],
            "information_boundary": protocol["information_boundary"],
        }
    )
    _assert_secret_free(protocol)
    return protocol


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--order-result-sha256", required=True)
    parser.add_argument("--order-causal-sha256", required=True)
    parser.add_argument("--order-measurement-sha256", required=True)
    parser.add_argument("--root-reviewed", action="store_true")
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    protocol = build_protocol(
        order_result_sha256=args.order_result_sha256,
        order_causal_sha256=args.order_causal_sha256,
        order_measurement_sha256=args.order_measurement_sha256,
        root_review_acknowledged=args.root_reviewed,
        dotcausal_src=args.dotcausal_src,
    )
    _atomic_json(args.output, protocol)
    print(
        json.dumps(
            {
                "attempt_id": ATTEMPT_ID,
                "output": str(args.output),
                "protocol_sha256": _file_sha256(args.output),
                "scientific_design_sha256": protocol["scientific_design_sha256"],
                "complete_order_sha256": protocol["frozen_order"][
                    "complete_cell_order_uint8_sha256"
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
