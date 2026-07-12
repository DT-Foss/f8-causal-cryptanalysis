#!/usr/bin/env python3
"""Transfer the retained native full-round Reader to the public A152 relation."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_NATIVE = _import_sibling(
    "shake_native_window_solver.py",
    "shake_a152_native_fullround_reader_transfer_native_base",
)
_BASE = _NATIVE._BASE
_WINDOW = _NATIVE._WINDOW
_BITSLICED = _NATIVE._BITSLICED

ATTEMPT_ID = "A165"
SCHEMA = "shake-a152-native-fullround-reader-transfer-v1"
PROTOCOL_SCHEMA = "shake-a152-native-fullround-reader-transfer-protocol-v1"
PROTOCOL_FILENAME = "shake_a152_native_fullround_reader_transfer_v1.json"
PROTOCOL_SHA256 = "66369688662b77a5a9b5fe49ab3bad5f6a513e809260e5293773dd8b3fe42498"
A152_FILENAME = "shake_symbolic_r1_width24_prospective_transfer_v1.json"
A152_SHA256 = "0e01e3e6ff0b9a80ff66ad6614f846305188d96a4497ca38857eac81097a1561"
NATIVE_FILENAME = "shake_native_window_solver_v1.json"
NATIVE_SHA256 = "8497ccb7938da721b71876cf481bcc4175b7f5b25c5f3300a87e09a6f123e604"
NATIVE_CAUSAL_FILENAME = "shake_native_window_solver_v1.causal"
NATIVE_CAUSAL_SHA256 = "f90cf74a0d97f07b0d037639dc9d9beee2e0f7dec3360c51ebf802e27e04550f"
NATIVE_SOURCE_SHA256 = "3189f301d25b1bc38c867dae840edb3c8e710ffa5960e02035b43a72c0889d81"
SEED = 260_592_673
WINDOW_BITS = 24
THREADS = 10
STREAM_PACKS = 262_144
FILTER_LANES = 2
RESULT_FILENAME = "shake_a152_native_fullround_reader_transfer_v1.json"
CAUSAL_FILENAME = "shake_a152_native_fullround_reader_transfer_v1.causal"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    raw = path.read_bytes()
    if _sha256(raw) != PROTOCOL_SHA256:
        raise RuntimeError("A165 frozen protocol hash differs")
    protocol = json.loads(raw)
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_before_A165_candidate_execution"
        or protocol.get("anchors", {})
        .get("A152_prospective_instance", {})
        .get("sha256")
        != A152_SHA256
        or protocol.get("anchors", {}).get("native_reader", {}).get("sha256")
        != NATIVE_SHA256
        or protocol.get("anchors", {})
        .get("native_reader", {})
        .get("causal_sha256")
        != NATIVE_CAUSAL_SHA256
        or protocol.get("anchors", {})
        .get("native_reader", {})
        .get("native_source_sha256")
        != NATIVE_SOURCE_SHA256
    ):
        raise RuntimeError("A165 frozen protocol identity differs")
    return protocol


def _load_anchor_gates(results_dir: Path) -> dict[str, Any]:
    a152_path = results_dir / A152_FILENAME
    native_path = results_dir / NATIVE_FILENAME
    native_causal_path = results_dir / NATIVE_CAUSAL_FILENAME
    source_path = Path(__file__).with_name("shake_bitsliced_native.c")
    observed = {
        "A152_result_sha256": _file_sha256(a152_path),
        "native_result_sha256": _file_sha256(native_path),
        "native_causal_sha256": _file_sha256(native_causal_path),
        "native_source_sha256": _file_sha256(source_path),
    }
    expected = {
        "A152_result_sha256": A152_SHA256,
        "native_result_sha256": NATIVE_SHA256,
        "native_causal_sha256": NATIVE_CAUSAL_SHA256,
        "native_source_sha256": NATIVE_SOURCE_SHA256,
    }
    if observed != expected:
        raise RuntimeError("A165 A152/native anchor hash gate failed")

    native = json.loads(native_path.read_bytes())
    if (
        native.get("schema") != "shake-native-window-solver-v1"
        or native.get("retained") is not True
        or native.get("native_build", {}).get("source_sha256")
        != NATIVE_SOURCE_SHA256
        or native.get("parameters", {}).get("permutation_rounds") != 24
        or 24 not in native.get("parameters", {}).get("window_bits", [])
    ):
        raise RuntimeError("A165 retained native Reader anchor differs")

    reader = CryptoCausalReader(native_causal_path)
    if (
        reader.file_sha256 != NATIVE_CAUSAL_SHA256
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A165 native Causal Reader anchor differs")
    rows = reader.triplets(include_inferred=False)
    recipes = [
        row["attrs"]["reader_recipe"]
        for row in rows
        if row["mechanism"] == "reader_executable_native_fullround_consistency"
        and row["trigger"].startswith("shake128:")
    ]
    if len(recipes) != 1:
        raise RuntimeError("A165 did not read one exact SHAKE128 native recipe")
    recipe = recipes[0]
    if (
        recipe.get("native_source_sha256") != NATIVE_SOURCE_SHA256
        or recipe.get("permutation_rounds") != 24
        or recipe.get("candidates_per_machine_word") != 64
        or recipe.get("filter_lanes") != FILTER_LANES
        or recipe.get("full_confirmation")
        != "independent_scalar_complete_rate_equality"
    ):
        raise RuntimeError("A165 native Reader recipe differs")
    return {
        **observed,
        "native_causal_graph_sha256": reader.graph_sha256,
        "native_causal_provenance_verified": True,
        "native_reader_recipe": recipe,
    }


def _public_relation_summary(
    template: np.ndarray,
    target: np.ndarray,
    positions: np.ndarray,
    variant: Any,
) -> dict[str, Any]:
    coordinate_list = [int(value) for value in positions]
    return {
        "variant": variant.name,
        "seed": SEED,
        "window_bits": len(coordinate_list),
        "capacity_window_positions": coordinate_list,
        "capacity_window_start_bit": coordinate_list[0],
        "capacity_window_stop_bit_exclusive": coordinate_list[-1] + 1,
        "cleared_template_sha256": _sha256(
            template.astype("<u8", copy=False).tobytes()
        ),
        "target_rate_lanes": variant.rate_lanes,
        "target_rate_bits": variant.rate_bits,
        "target_rate_sha256": _sha256(
            target[:, : variant.rate_lanes].astype("<u8", copy=False).tobytes()
        ),
        "instrumented_assignment_included": False,
    }


def _prepare_public_relation(
    protocol: dict[str, Any],
) -> tuple[dict[str, np.ndarray], dict[str, Any]]:
    variant = _BASE.VARIANTS["shake128"]
    generated = _NATIVE._problem(variant, WINDOW_BITS, SEED)
    template = _WINDOW._clear_window(
        generated["base_state"],
        variant,
        generated["positions"],
    )
    public = {
        "template": template.copy(),
        "target": generated["target"].copy(),
        "positions": generated["positions"].copy(),
    }
    summary = _public_relation_summary(
        public["template"],
        public["target"],
        public["positions"],
        variant,
    )
    frozen = protocol["public_relation"]
    expected = {
        "variant": frozen["variant"],
        "seed": frozen["seed"],
        "window_bits": frozen["window_bits"],
        "capacity_window_start_bit": frozen["capacity_window_start_bit"],
        "capacity_window_stop_bit_exclusive": frozen[
            "capacity_window_stop_bit_exclusive"
        ],
        "cleared_template_sha256": frozen["cleared_template_sha256"],
        "target_rate_bits": frozen["target_rate_bits"],
        "target_rate_sha256": frozen["target_rate_sha256"],
    }
    if any(summary.get(key) != value for key, value in expected.items()):
        raise RuntimeError("A165 regenerated public A152 relation differs")
    del generated
    return public, summary


def _control_target(target: np.ndarray) -> np.ndarray:
    control = target.copy()
    control[0, 0] ^= np.uint64(1)
    return control


def _independent_confirm(
    template: np.ndarray,
    target: np.ndarray,
    positions: np.ndarray,
    variant: Any,
    assignment: int,
) -> dict[str, Any]:
    candidate = _WINDOW._inject_candidates(
        template,
        variant,
        positions,
        np.array([assignment], dtype=np.uint64),
    )
    output = _BASE._keccak_f1600(candidate)[:, : variant.rate_lanes]
    expected = target[:, : variant.rate_lanes]
    return {
        "assignment": assignment,
        "complete_rate_match": bool(np.array_equal(output, expected)),
        "rate_lanes_checked": variant.rate_lanes,
        "rate_bits_checked": variant.rate_bits,
        "candidate_rate_sha256": _sha256(output.astype("<u8", copy=False).tobytes()),
        "target_rate_sha256": _sha256(expected.astype("<u8", copy=False).tobytes()),
        "implementation": "independent_NumPy_lane_core",
    }


def _enumerate_public_relation(
    *,
    kernel: Any,
    public: dict[str, np.ndarray],
    variant: Any,
    recipe: dict[str, Any],
    threads: int,
    stream_packs: int,
    checkpoint_path: Path | None = None,
    resume: bool = True,
) -> dict[str, Any]:
    positions = public["positions"]
    template = public["template"]
    target = public["target"]
    window_bits = len(positions)
    candidate_count = 1 << window_bits
    pack_count = (candidate_count + 63) // 64
    if (
        recipe["permutation_rounds"] != 24
        or recipe["candidates_per_machine_word"] != 64
        or recipe["filter_lanes"] != FILTER_LANES
        or threads < 1
        or stream_packs < 1
    ):
        raise RuntimeError("A165 executable Reader plan differs")
    next_pack = 0
    factual_filtered: list[int] = []
    control_filtered: list[int] = []
    fingerprint = {
        "schema": "shake-a152-native-transfer-checkpoint-v1",
        "variant": variant.name,
        "rate_lanes": variant.rate_lanes,
        "window_bits": window_bits,
        "ordered_capacity_window_positions": [int(value) for value in positions],
        "candidate_count": candidate_count,
        "threads": threads,
        "stream_packs": stream_packs,
        "native_source_sha256": NATIVE_SOURCE_SHA256,
        "cleared_template_sha256": _sha256(
            template.astype("<u8", copy=False).tobytes()
        ),
        "target_rate_sha256": _sha256(
            target[:, : variant.rate_lanes].astype("<u8", copy=False).tobytes()
        ),
        "control_target_rate_sha256": _sha256(
            _control_target(target)[:, : variant.rate_lanes]
            .astype("<u8", copy=False)
            .tobytes()
        ),
    }
    if checkpoint_path is not None and resume and checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_text())
        if any(checkpoint.get(key) != value for key, value in fingerprint.items()):
            raise RuntimeError("A165 checkpoint fingerprint differs")
        next_pack = int(checkpoint["next_pack"])
        factual_filtered = [int(value) for value in checkpoint["factual_filtered"]]
        control_filtered = [int(value) for value in checkpoint["control_filtered"]]
        if (
            next_pack < 0
            or next_pack > pack_count
            or any(value < 0 or value >= next_pack * 64 for value in factual_filtered)
            or any(value < 0 or value >= next_pack * 64 for value in control_filtered)
            or len(factual_filtered) != len(set(factual_filtered))
            or len(control_filtered) != len(set(control_filtered))
        ):
            raise RuntimeError("A165 checkpoint progress is invalid")

    wrong_target = _control_target(target)
    resumed_pack_count = next_pack
    while next_pack < pack_count:
        batch_count = min(stream_packs, pack_count - next_pack)
        factual_masks, control_masks = kernel.filter_masks(
            template,
            variant.rate_lanes,
            positions,
            window_bits,
            next_pack,
            batch_count,
            target,
            wrong_target,
            FILTER_LANES,
            threads,
        )
        factual_filtered.extend(
            _BITSLICED._indices_from_masks(
                factual_masks,
                next_pack,
                candidate_count,
            )
        )
        control_filtered.extend(
            _BITSLICED._indices_from_masks(
                control_masks,
                next_pack,
                candidate_count,
            )
        )
        next_pack += batch_count
        if checkpoint_path is not None:
            _NATIVE._atomic_json(
                checkpoint_path,
                {
                    **fingerprint,
                    "next_pack": next_pack,
                    "factual_filtered": factual_filtered,
                    "control_filtered": control_filtered,
                },
            )

    factual_confirmations = [
        _independent_confirm(template, target, positions, variant, candidate)
        for candidate in factual_filtered
    ]
    control_confirmations = [
        _independent_confirm(template, wrong_target, positions, variant, candidate)
        for candidate in control_filtered
    ]
    factual_full = [
        row["assignment"] for row in factual_confirmations if row["complete_rate_match"]
    ]
    control_full = [
        row["assignment"] for row in control_confirmations if row["complete_rate_match"]
    ]
    if not factual_full:
        raise RuntimeError("A165 complete-domain Reader returned no exact public model")
    return {
        "window_bits": window_bits,
        "logical_candidate_count": candidate_count,
        "candidate_pack_width": 64,
        "packed_state_count": pack_count,
        "native_threads": threads,
        "stream_pack_count": stream_packs,
        "stream_batch_count": (pack_count + stream_packs - 1) // stream_packs,
        "resumed_pack_count": resumed_pack_count,
        "newly_executed_pack_count": pack_count - resumed_pack_count,
        "complete_domain_executed": next_pack == pack_count,
        "early_stop_used": False,
        "filter_rate_lanes": FILTER_LANES,
        "filter_rate_bits": FILTER_LANES * 64,
        "factual_filter_matches": factual_filtered,
        "factual_full_matches": factual_full,
        "factual_confirmations": factual_confirmations,
        "control_target_rule": "flip_bit_0_of_first_public_target_rate_lane",
        "control_filter_matches": control_filtered,
        "control_full_matches": control_full,
        "control_confirmations": control_confirmations,
        "unique_exact_public_model": len(factual_full) == 1,
        "control_target_rejected": len(control_full) == 0,
        "packed_evaluation_reduction_factor": candidate_count / pack_count,
        "instrumented_assignment_input_used": False,
        "A152_posthoc_assignment_read_before_candidate_execution": False,
    }


def _load_posthoc_after_execution(results_dir: Path, recovered: list[int]) -> dict[str, Any]:
    payload = json.loads((results_dir / A152_FILENAME).read_bytes())
    posthoc = payload["posthoc_comparison"]
    actual = int(posthoc["instrumented_assignment"])
    return {
        "A152_instrumented_assignment": actual,
        "read_only_after_complete_domain_execution": True,
        "used_for_candidate_generation_filtering_or_confirmation": False,
        "recovered_assignments": recovered,
        "unique_reconstruction_matches_A152_instrumented_assignment": recovered
        == [actual],
        "A152_instrumented_assignment_independent_check": posthoc[
            "instrumented_assignment_independent_check"
        ],
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_a152_native_fullround_reader_transfer",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "logical_candidates": 1 << WINDOW_BITS,
            "native_threads": THREADS,
        },
    )
    ids = [
        "shake128-native-retained-fullround-reader-recipe",
        "shake128-a152-public-fullround-relation",
        "shake128-a165-complete-packed-domain-execution",
        "shake128-a165-independent-complete-rate-confirmation",
        "shake128-a165-posthoc-prospective-instance-comparison",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="retained_native_candidate_axis_Reader",
        mechanism="reopen_the_hash_pinned_native_causal_artifact_and_extract_its_SHAKE128_executable_recipe",
        outcome="A165:verified_native_fullround_recipe",
        confidence=1.0,
        evidence_kind="retained_Causal_Reader_recipe",
        source=NATIVE_CAUSAL_SHA256,
        attrs={"anchor_gates": payload["anchor_gates"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A165:verified_native_fullround_recipe",
        mechanism="regenerate_only_the_cleared_template_target_rate_and_window_coordinates_and_match_A152_public_fingerprints",
        outcome="A165:verified_A152_public_relation",
        confidence=1.0,
        evidence_kind="hash_pinned_public_relation",
        source=A152_SHA256,
        provenance=[ids[0]],
        attrs={"public_relation": payload["public_relation"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A165:verified_A152_public_relation",
        mechanism="enumerate_all_2^24_assignments_in_64_candidate_native_packs_without_early_stop",
        outcome="A165:complete_262144_pack_filter_result",
        confidence=1.0,
        evidence_kind="complete_native_candidate_domain_execution",
        source=payload["execution_sha256"],
        provenance=[ids[1]],
        attrs={"execution": payload["execution"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A165:complete_262144_pack_filter_result",
        mechanism="evaluate_every_128_bit_filter_candidate_with_the_independent_24_round_NumPy_lane_core_over_all_1344_rate_bits",
        outcome="A165:exact_fullround_public_model_set",
        confidence=1.0,
        evidence_kind="independent_complete_rate_confirmation",
        source=payload["confirmation_sha256"],
        provenance=[ids[2]],
        attrs={
            "factual_confirmations": payload["execution"]["factual_confirmations"],
            "control_confirmations": payload["execution"]["control_confirmations"],
        },
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A165:exact_fullround_public_model_set",
        mechanism="only_after_complete_execution_read_the_A152_posthoc_assignment_and_compare_it_with_the_reconstruction",
        outcome="A165:prospective_instance_native_reconstruction",
        confidence=1.0,
        evidence_kind="post_execution_anchor_comparison",
        source=_canonical_sha256(payload["posthoc_comparison"]),
        provenance=[ids[3]],
        attrs={"posthoc_comparison": payload["posthoc_comparison"]},
    )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    if (
        len(rows) != len(ids)
        or set(by_id) != set(ids)
        or not reader.verify_provenance()
        or [by_id[edge_id]["provenance"] for edge_id in ids]
        != [[], [ids[0]], [ids[1]], [ids[2]], [ids[3]]]
        or any(
            by_id[left]["outcome"] != by_id[right]["trigger"]
            for left, right in zip(ids[:-1], ids[1:], strict=True)
        )
    ):
        raise RuntimeError("A165 Causal provenance chain failed validation")
    return {
        "stats": stats,
        "explicit_triplets": len(rows),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    anchors = _load_anchor_gates(results_dir)
    public, summary = _prepare_public_relation(protocol)
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "public": public,
        "public_relation": summary,
        "candidate_execution_started": False,
    }


def run(
    *,
    results_dir: Path,
    output: Path,
    causal_output: Path,
    build_dir: Path,
    checkpoint_path: Path,
    cc: str,
    resume: bool,
) -> dict[str, Any]:
    analysis = analyze(results_dir)
    variant = _BASE.VARIANTS["shake128"]
    library_path, native_build = _NATIVE._compile_native(build_dir, cc)
    if native_build["source_sha256"] != NATIVE_SOURCE_SHA256:
        raise RuntimeError("A165 compiled native source differs")
    kernel = _NATIVE.NativeBitSliceKernel(library_path)
    current_build_gate = _NATIVE._cross_implementation_gate(kernel, SEED ^ 0xA165)
    execution = _enumerate_public_relation(
        kernel=kernel,
        public=analysis["public"],
        variant=variant,
        recipe=analysis["anchor_gates"]["native_reader_recipe"],
        threads=THREADS,
        stream_packs=STREAM_PACKS,
        checkpoint_path=checkpoint_path,
        resume=resume,
    )
    if not execution["complete_domain_executed"]:
        raise RuntimeError("A165 did not execute the complete candidate domain")
    posthoc = _load_posthoc_after_execution(
        results_dir,
        execution["factual_full_matches"],
    )
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "A152_NATIVE_FULLROUND_MODEL_RECONSTRUCTION_RETAINED"
            if execution["unique_exact_public_model"]
            and posthoc["unique_reconstruction_matches_A152_instrumented_assignment"]
            else "A152_NATIVE_FULLROUND_MODEL_SET_RETAINED"
        ),
        "result": (
            "The retained native Causal Reader executes the complete A152 24-bit "
            "public relation and independently confirms every exact full-round model."
        ),
        "scope": (
            "Known-complement SHAKE128 state-window reconstruction over the complete "
            "2^24 declared capacity-window domain and all 1,344 next-rate bits."
        ),
        "parameters": {
            "variant": "SHAKE128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "logical_candidate_count": 1 << WINDOW_BITS,
            "native_threads": THREADS,
            "stream_pack_count": STREAM_PACKS,
            "volatile_wallclock_excluded_from_canonical_result": True,
        },
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": analysis["protocol"]["protocol_state"],
            "reader_plan": analysis["protocol"]["reader_plan"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "public_relation": analysis["public_relation"],
        "native_build": native_build,
        "current_build_cross_implementation_gate": current_build_gate,
        "execution": execution,
        "execution_sha256": _canonical_sha256(
            {
                key: value
                for key, value in execution.items()
                if key not in {"factual_confirmations", "control_confirmations"}
            }
        ),
        "confirmation_sha256": _canonical_sha256(
            {
                "factual": execution["factual_confirmations"],
                "control": execution["control_confirmations"],
            }
        ),
        "posthoc_comparison": posthoc,
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _atomic_write(output, raw)
    if checkpoint_path.exists():
        checkpoint_path.unlink()
    reader = CryptoCausalReader(causal_output)
    if (
        _sha256(output.read_bytes()) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or reader.graph_sha256 != causal["graph_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A165 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "complete_domain_executed": execution["complete_domain_executed"],
        "factual_filter_matches": execution["factual_filter_matches"],
        "factual_full_matches": execution["factual_full_matches"],
        "control_full_matches": execution["control_full_matches"],
        "unique_reconstruction_matches_A152": posthoc[
            "unique_reconstruction_matches_A152_instrumented_assignment"
        ],
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument("--results-dir", type=Path, default=research_root / "results" / "v1")
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        default=research_root / "results" / "v1" / RESULT_FILENAME,
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=research_root / "results" / "v1" / CAUSAL_FILENAME,
    )
    parser.add_argument(
        "--checkpoint",
        type=Path,
        default=research_root / "results" / "v1" / (
            "shake_a152_native_fullround_reader_transfer_v1.checkpoint.json"
        ),
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=Path(__file__).parents[2] / "build" / "native",
    )
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument(
        "--resume",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    args = parser.parse_args(argv)
    if args.analyze_only:
        analysis = analyze(args.results_dir.resolve())
        print(
            json.dumps(
                {
                    "protocol_sha256": PROTOCOL_SHA256,
                    "anchor_gates": analysis["anchor_gates"],
                    "public_relation": analysis["public_relation"],
                    "candidate_execution_started": False,
                },
                sort_keys=True,
            )
        )
        return
    if args.output.resolve() == args.causal_output.resolve():
        raise ValueError("JSON and Causal output paths must be distinct")
    print(
        json.dumps(
            run(
                results_dir=args.results_dir.resolve(),
                output=args.output.resolve(),
                causal_output=args.causal_output.resolve(),
                build_dir=args.build_dir.resolve(),
                checkpoint_path=args.checkpoint.resolve(),
                cc=args.cc,
                resume=args.resume,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
