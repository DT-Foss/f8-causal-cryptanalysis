#!/usr/bin/env python3
"""A340: build a target-conditioned Causal W46 prefix order before A325."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import math
import os
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np
import zstandard

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
ARTIFACTS = RESEARCH / "artifacts/a340_chacha20_r20_w46_target_conditioned_causal"

DESIGN = CONFIGS / "chacha20_round20_w46_target_conditioned_causal_order_a340_design_v1.json"
PREFLIGHT = RESULTS / "chacha20_round20_w46_target_conditioned_causal_order_a340_preflight_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_target_conditioned_causal_order_a340_order_v1.json"
MEASUREMENT = (
    RESULTS / "chacha20_round20_w46_target_conditioned_causal_order_a340_measurement_v1.json.zst"
)
CAUSAL = RESULTS / "chacha20_round20_w46_target_conditioned_causal_order_a340_order_v1.causal"
REPORT = RESULTS / "chacha20_round20_w46_target_conditioned_causal_order_a340_order_v1.md"
BASE_CNF = ARTIFACTS / "a340_chacha20_r20_w46_b1_base.cnf"

A325_PROTOCOL = CONFIGS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A325_PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_progress_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A296_RUNNER = RESEARCH / "experiments/chacha20_round20_causal_search_gain_panel_a296.py"
A296_RESULT = RESULTS / "chacha20_round20_causal_search_gain_panel_a296_v1.json"
A297_RUNNER = RESEARCH / "experiments/chacha20_round20_w32_causal_search_gain_panel_a297.py"
A223_SOURCE = RESEARCH / "experiments/chacha20_round20_capacity_moonshot_a223.py"
A223_CONFIG = CONFIGS / "chacha20_round20_capacity_moonshot_a223_v1.json"
A251_WRAPPER = RESEARCH / "experiments/chacha20_fresh_clause_identity.py"
A275_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_selected_channel_target_replication_measure.py"
)
A275_PROTOCOL = CONFIGS / "chacha20_round20_selected_channel_target_replication_v1.json"
A340_TEST = ROOT / "tests/test_chacha20_round20_w46_target_conditioned_causal_order_a340.py"
A340_REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_target_conditioned_causal_order_a340.sh"

ATTEMPT_ID = "A340"
DESIGN_SHA256 = "f7ee025053719c1b5c9f08cf3c141e708b2fb2f1a66c2e61f32bd0c1611c4566"
ANCHOR_SHA256 = {
    A325_PROTOCOL: "480fe15f22c87df1b9422c1dc8cfcf5a9add147f65b6631d25e94d66b5255a2c",
    A296_RUNNER: "7b2a4423e71c87751389fcccea05839ad5ca2b8524d6c821d9f23cb7b30dd936",
    A296_RESULT: "2cf8aa4fbd37889baa0a7740724b7751746d037dd2482a63261327abb7e6f45d",
    A297_RUNNER: "f5700d37179c82969fb458d5cd184656641f65e5962e82cfa6fa1ff48b3ca60f",
    A223_SOURCE: "f41b70c549392101a4a2cdf1499f69ac897912682a5696da79ef3533fa55e0e0",
    A223_CONFIG: "9b60f65be6415b4ac3738881336bfe8397328e0d216882f684db1c3da9b3a79f",
    A251_WRAPPER: "3a1d63d223712997519f72143ebcc3e5725a8f8659eadbd9389465dd0fe654f6",
    A275_RUNNER: "218815280ce978aba16ba857db80828424e390cc1d141a1be3d33fb330c4e56b",
    A275_PROTOCOL: "d6e753defe3eba1e9989e8e6f792a6e731d8371487788917db0d7cff518c75f9",
}
WIDTH = 46
PREFIX_BITS = 12
COARSE_BITS = 8
CELLS = 1 << PREFIX_BITS
COARSE_CELLS = 1 << COARSE_BITS
HORIZONS = [1, 2, 4, 8]
FEATURE_INDICES = [502, 504, 505, 508, 509, 510, 511, 514]
WATCHDOG_SECONDS = 2.0
ZSTD_LEVEL = 10
MASK32 = 0xFFFFFFFF

RAW = "A325_raw_linf_baseline"
TARGET_CAUSAL = "A340_target_conditioned_causal_fine"
WAVEFRONT = "raw_causal_min_rank_wavefront_protected"
BORDA = "raw_causal_equal_borda"
HASH_CONTROL = "A325_public_hash_control"
CANDIDATE_NAMES = (RAW, TARGET_CAUSAL, WAVEFRONT, BORDA, HASH_CONTROL)

DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")
sys.path.insert(0, str(DOTCAUSAL_SRC))


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load A340 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A296 = load_module(A296_RUNNER, "a340_a296_common")
sha256 = A296.sha256
file_sha256 = A296.file_sha256
canonical_bytes = A296.canonical_bytes
canonical_sha256 = A296.canonical_sha256
atomic_bytes = A296.atomic_bytes
atomic_json = A296.atomic_json
relative = A296.relative
path_from_ref = A296.path_from_ref
anchor = A296.anchor


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A340 {label} is not an exact 4,096-cell cover")
    return order


def order_sha256(order: Sequence[int]) -> str:
    return sha256(b"".join(cell.to_bytes(2, "big") for cell in exact_order(order, "hash")))


def rank_vector(order: Sequence[int]) -> list[int]:
    ranks = [0] * CELLS
    for rank, cell in enumerate(exact_order(order, "rank vector"), 1):
        ranks[cell] = rank
    return ranks


def min_rank_wavefront(raw: Sequence[int], causal: Sequence[int]) -> list[int]:
    raw_ranks = rank_vector(raw)
    causal_ranks = rank_vector(causal)
    return exact_order(
        sorted(
            range(CELLS),
            key=lambda cell: (
                min(raw_ranks[cell], causal_ranks[cell]),
                raw_ranks[cell] + causal_ranks[cell],
                raw_ranks[cell],
                causal_ranks[cell],
                cell,
            ),
        ),
        "factor-two wavefront",
    )


def equal_borda(raw: Sequence[int], causal: Sequence[int]) -> list[int]:
    raw_ranks = rank_vector(raw)
    causal_ranks = rank_vector(causal)
    return exact_order(
        sorted(
            range(CELLS),
            key=lambda cell: (
                raw_ranks[cell] + causal_ranks[cell],
                min(raw_ranks[cell], causal_ranks[cell]),
                max(raw_ranks[cell], causal_ranks[cell]),
                raw_ranks[cell],
                causal_ranks[cell],
                cell,
            ),
        ),
        "equal Borda",
    )


def wavefront_guarantee(
    wavefront: Sequence[int], raw: Sequence[int], causal: Sequence[int]
) -> dict[str, Any]:
    wave_ranks = rank_vector(wavefront)
    raw_ranks = rank_vector(raw)
    causal_ranks = rank_vector(causal)
    best = [min(raw_ranks[cell], causal_ranks[cell]) for cell in range(CELLS)]
    violations = [cell for cell in range(CELLS) if wave_ranks[cell] > 2 * best[cell]]
    worst = max(range(CELLS), key=lambda cell: wave_ranks[cell] / best[cell])
    return {
        "statement": "R_wavefront(cell) <= 2 * min(R_raw_linf(cell), R_target_conditioned_causal(cell))",
        "violations": len(violations),
        "first_violation_cell": violations[0] if violations else None,
        "maximum_rank_ratio_to_best_source": wave_ranks[worst] / best[worst],
        "maximum_ratio_cell": worst,
        "wavefront_rank_one_based": wave_ranks[worst],
        "best_source_rank_one_based": best[worst],
    }


def spearman(left: Sequence[int], right: Sequence[int]) -> float:
    left_ranks = rank_vector(left)
    right_ranks = rank_vector(right)
    squared = sum((a - b) ** 2 for a, b in zip(left_ranks, right_ranks, strict=True))
    return 1.0 - 6.0 * squared / (CELLS * (CELLS * CELLS - 1))


def public_hash_order(public_challenge_sha256: str) -> list[int]:
    seed = bytes.fromhex(public_challenge_sha256)
    return exact_order(
        sorted(
            range(CELLS),
            key=lambda cell: hashlib.sha256(
                b"A340|A325-public-hash-control|" + seed + cell.to_bytes(2, "big")
            ).digest(),
        ),
        "public-hash control",
    )


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A340 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    measurement = design.get("measurement_contract", {})
    order = design.get("order_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema")
        != "chacha20-round20-w46-target-conditioned-causal-order-a340-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_before_any_A325_execution_candidate_prefix_or_result"
        or measurement.get("unknown_key_bits") != WIDTH
        or measurement.get("conflict_horizons") != HORIZONS
        or measurement.get("selected_feature_indices") != FEATURE_INDICES
        or measurement.get("reader_refits") != 0
        or measurement.get("target_labels_used") != 0
        or tuple(order.get("candidate_sequence", ())) != CANDIDATE_NAMES
        or order.get("primary_operator") != TARGET_CAUSAL
        or order.get("protected_operator") != WAVEFRONT
        or order.get("A325_existing_protocol_or_order_rewritten") is not False
        or order.get("candidate_execution_by_A340") is not False
        or boundary.get("A325_public_output_allowed_as_measurement_input") is not True
        or boundary.get("A325_hidden_assignment_available_at_design_freeze") is not False
        or boundary.get("A325_execution_started_at_design_freeze") is not False
        or boundary.get("A325_result_available_at_design_freeze") is not False
        or boundary.get("target_labels_used_from_A325") != 0
        or boundary.get("reader_coefficients_refit_on_A325") is not False
        or boundary.get("A325_protocol_modified") is not False
    ):
        raise RuntimeError("A340 frozen design semantics differ")
    for key, value in design["source_anchors"].items():
        if key.endswith("_path"):
            anchor(
                ROOT / value,
                design["source_anchors"][key.removesuffix("_path") + "_sha256"],
            )
    return design


def assert_pre_a325_execution() -> None:
    if A325_PROGRESS.exists() or A325_RESULT.exists():
        raise RuntimeError("A340 must freeze before any A325 execution or result")


def load_a325_protocol() -> dict[str, Any]:
    anchor(A325_PROTOCOL, ANCHOR_SHA256[A325_PROTOCOL])
    protocol = json.loads(A325_PROTOCOL.read_bytes())
    challenge = protocol.get("public_challenge", {})
    if (
        protocol.get("schema") != "chacha20-round20-holdout-selected-w46-recovery-a325-protocol-v1"
        or protocol.get("selected_operator") != "raw_nearest_prototype_Linf"
        or challenge.get("unknown_key_bits") != WIDTH
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("public_output_blocks") != 8
        or len(challenge.get("target_words", [])) != 8
        or len(challenge.get("known_zeroed_key_words", [])) != 8
    ):
        raise RuntimeError("A340 A325 public protocol gate failed")
    if canonical_sha256(challenge) != protocol["public_challenge_sha256"]:
        raise RuntimeError("A340 A325 public challenge hash differs")
    return protocol


def bridge_challenge(protocol: Mapping[str, Any]) -> dict[str, Any]:
    source = protocol["public_challenge"]
    known = [int(value) & MASK32 for value in source["known_zeroed_key_words"]]
    masks = [0, 0xFFFFC000, *([MASK32] * 6)]
    values = [value & mask for value, mask in zip(known, masks, strict=True)]
    bridge = {
        "challenge_id": "A340-bridge-" + str(source["challenge_id"]),
        "rounds": 20,
        "block_count": 8,
        "counter_schedule": "base_plus_block_index_mod_2^32",
        "counter_start": int(source["counter_start"]),
        "nonce_words": [int(value) for value in source["nonce_words"]],
        "known_key_bits": 256 - WIDTH,
        "known_key_mask_words": masks,
        "known_key_value_words": values,
        "unknown_key_bits": WIDTH,
        "unknown_global_bit_interval": [0, WIDTH - 1],
        "unknown_bit_numbering": "little_endian_bit0_upward_across_key_words_k0_through_k7",
        "unknown_assignment_included": False,
        "unknown_assignment_value_included": False,
        "full_key_included": False,
        "secret_used_only_for_target_construction": True,
        "secret_discarded_after_target_construction": True,
        "generation_entropy_source": "python_secrets_token_bytes_OS_CSPRNG",
        "target_words": [
            [int(word) & MASK32 for word in block] for block in source["target_words"]
        ],
        "target_block_sha256": list(source["target_block_sha256"]),
        "control_target_words": [int(word) & MASK32 for word in source["control_target_words"]],
        "control_target_block_sha256": source["control_target_block_sha256"],
    }
    return bridge


def w46_source_formula(a223: Any, challenge: dict[str, Any]) -> str:
    """Correct A223's non-nibble-aligned known-suffix literal for W46.

    A223's established widths have nibble-aligned residual boundaries.  W46
    leaves an 18-bit known suffix in key word 1, so a hexadecimal SMT literal
    has a 20-bit sort.  Replace that single generated assertion with the exact
    18-bit binary literal while leaving every cipher equation byte-identical.
    """

    formula = A296.b1_formula(a223, challenge, WIDTH)
    remainder = WIDTH % 32
    word = WIDTH // 32
    known_width = 32 - remainder
    known = int(challenge["known_key_value_words"][word]) >> remainder
    generated = f"(assert (= ((_ extract 31 {remainder}) k{word}) #x{known:0{known_width // 4}x}))"
    corrected = f"(assert (= ((_ extract 31 {remainder}) k{word}) #b{known:0{known_width}b}))"
    if formula.count(generated) != 1 or corrected in formula:
        raise RuntimeError("A340 W46 known-suffix correction boundary differs")
    formula = formula.replace(generated, corrected)
    if formula.count(corrected) != 1 or generated in formula:
        raise RuntimeError("A340 W46 known-suffix correction failed")
    return formula


def preflight() -> dict[str, Any]:
    if PREFLIGHT.exists() or ARTIFACTS.exists():
        raise FileExistsError("A340 preflight artifacts already exist")
    assert_pre_a325_execution()
    design = load_design()
    protocol = load_a325_protocol()
    bridge = bridge_challenge(protocol)
    a223 = load_module(A223_SOURCE, "a340_a223_preflight")
    config = json.loads(A223_CONFIG.read_bytes())
    a223._toolchain_gates(config)  # noqa: SLF001
    a223._validate_challenge(bridge, width=WIDTH)  # noqa: SLF001
    formula = w46_source_formula(a223, bridge)
    ARTIFACTS.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="a340_w46_b1_map_", dir=ARTIFACTS.parent) as temporary:
        directory = Path(temporary)
        temporary_cnf = directory / "base.cnf"
        export = a223._export_cnf(  # noqa: SLF001
            formula=formula,
            output=temporary_cnf,
            config=config,
            label="A340_W46_B1_TARGET_CONDITIONED",
        )
        raw = temporary_cnf.read_bytes()
        lines = raw.splitlines(keepends=True)
        header = lines[0].split() if lines else []
        if len(header) != 4 or header[:2] != [b"p", b"cnf"]:
            raise RuntimeError("A340 base CNF header differs")
        context = {
            "width": WIDTH,
            "formula": formula,
            "formula_bytes": len(formula.encode()),
            "formula_sha256": sha256(formula.encode()),
            "base_path": temporary_cnf,
            "base_raw": raw,
            "base_body": b"".join(lines[1:]),
            "base_body_sha256": sha256(b"".join(lines[1:])),
            "variable_count": int(header[2]),
            "clause_count": int(header[3]),
            "base_export": export,
        }
        probes = [
            a223._coordinate_probe(  # noqa: SLF001
                context=context,
                dimension=dimension,
                config=config,
                directory=directory,
            )
            for dimension in range(-1, math.ceil(math.log2(WIDTH)))
        ]
        mapping = a223._decode_mapping(  # noqa: SLF001
            [(dimension, units) for _, dimension, units, _ in probes],
            width=WIDTH,
        )
        ARTIFACTS.mkdir(parents=False, exist_ok=False)
        atomic_bytes(BASE_CNF, raw)
    if file_sha256(BASE_CNF) != export["sha256"]:
        raise RuntimeError("A340 persisted base CNF hash differs")
    synthetic = A296.synthetic_reader_mapping(mapping, WIDTH)
    _a275, _model, _a291, indices, helper = A296._reader_stack()  # noqa: SLF001
    if list(indices) != FEATURE_INDICES:
        raise RuntimeError("A340 selected Reader feature identity differs")
    assert_pre_a325_execution()
    payload = {
        "schema": "chacha20-round20-w46-target-conditioned-causal-order-a340-preflight-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "A325_PUBLIC_OUTPUT_CONDITIONED_W46_CNF_AND_READER_FROZEN_PRE_EXECUTION",
        "design_sha256": DESIGN_SHA256,
        "A325_protocol_sha256": ANCHOR_SHA256[A325_PROTOCOL],
        "A325_public_challenge_sha256": protocol["public_challenge_sha256"],
        "bridge_challenge_sha256": canonical_sha256(bridge),
        "unknown_key_bits": WIDTH,
        "diagnostic_target_blocks": 1,
        "formula_bytes": len(formula.encode()),
        "formula_sha256": sha256(formula.encode()),
        "CNF": anchor(BASE_CNF, export["sha256"]),
        "CNF_header": export["header"],
        "CNF_export": export,
        "source_one_literals_bit0_upward": mapping,
        "source_mapping_sha256": canonical_sha256(mapping),
        "synthetic_reader_mapping": synthetic,
        "synthetic_reader_mapping_sha256": canonical_sha256(synthetic),
        "partition_coordinates_high_to_low": list(range(WIDTH - 1, WIDTH - 9, -1)),
        "fine_extension_coordinates_high_to_low": list(range(WIDTH - 9, WIDTH - 13, -1)),
        "coordinate_probes": [row[3] for row in probes],
        "reader_contract": {
            "selected_feature_indices": list(indices),
            "conflict_horizons": HORIZONS,
            "reader_refits": 0,
            "target_labels_used": 0,
            "helper": anchor(helper),
        },
        "information_boundary": {
            **design["information_boundary"],
            "A325_progress_absent_at_preflight": True,
            "A325_result_absent_at_preflight": True,
            "public_output_used_for_CNF": True,
            "hidden_assignment_prefix_or_filter_outcome_used": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A325_protocol": anchor(A325_PROTOCOL, ANCHOR_SHA256[A325_PROTOCOL]),
            "A296_runner": anchor(A296_RUNNER, ANCHOR_SHA256[A296_RUNNER]),
            "A296_result": anchor(A296_RESULT, ANCHOR_SHA256[A296_RESULT]),
            "A223_source": anchor(A223_SOURCE, ANCHOR_SHA256[A223_SOURCE]),
            "A223_config": anchor(A223_CONFIG, ANCHOR_SHA256[A223_CONFIG]),
            "A251_wrapper": anchor(A251_WRAPPER, ANCHOR_SHA256[A251_WRAPPER]),
            "A275_runner": anchor(A275_RUNNER, ANCHOR_SHA256[A275_RUNNER]),
            "A275_protocol": anchor(A275_PROTOCOL, ANCHOR_SHA256[A275_PROTOCOL]),
            "runner": anchor(Path(__file__)),
            "test": anchor(A340_TEST),
            "reproducer": anchor(A340_REPRO),
        },
    }
    payload["commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "A325_protocol_sha256": payload["A325_protocol_sha256"],
            "A325_public_challenge_sha256": payload["A325_public_challenge_sha256"],
            "formula_sha256": payload["formula_sha256"],
            "CNF_sha256": payload["CNF"]["sha256"],
            "source_mapping_sha256": payload["source_mapping_sha256"],
            "reader_contract": payload["reader_contract"],
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(PREFLIGHT, payload)
    return {
        "attempt_id": ATTEMPT_ID,
        "preflight": relative(PREFLIGHT),
        "preflight_sha256": file_sha256(PREFLIGHT),
        "commitment_sha256": payload["commitment_sha256"],
        "formula_sha256": payload["formula_sha256"],
        "CNF": payload["CNF"],
        "mapping_sha256": payload["source_mapping_sha256"],
    }


def load_preflight(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PREFLIGHT) != expected_sha256:
        raise RuntimeError("A340 preflight hash differs")
    payload = json.loads(PREFLIGHT.read_bytes())
    if (
        payload.get("schema")
        != "chacha20-round20-w46-target-conditioned-causal-order-a340-preflight-v1"
        or payload.get("design_sha256") != DESIGN_SHA256
        or payload.get("A325_protocol_sha256") != ANCHOR_SHA256[A325_PROTOCOL]
        or payload.get("unknown_key_bits") != WIDTH
        or payload.get("reader_contract", {}).get("selected_feature_indices") != FEATURE_INDICES
        or payload.get("reader_contract", {}).get("reader_refits") != 0
        or payload.get("reader_contract", {}).get("target_labels_used") != 0
    ):
        raise RuntimeError("A340 preflight semantics differ")
    for row in payload["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    anchor(path_from_ref(payload["CNF"]["path"]), payload["CNF"]["sha256"])
    return payload


def write_measurement(value: Mapping[str, Any]) -> dict[str, Any]:
    raw = canonical_bytes(value)
    compressed = zstandard.ZstdCompressor(
        level=ZSTD_LEVEL,
        threads=0,
        write_checksum=True,
        write_content_size=True,
        write_dict_id=False,
    ).compress(raw)
    atomic_bytes(MEASUREMENT, compressed)
    return {
        "path": relative(MEASUREMENT),
        "raw_bytes": len(raw),
        "raw_sha256": sha256(raw),
        "compressed_bytes": len(compressed),
        "compressed_sha256": sha256(compressed),
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    from dotcausal.io import CausalReader, CausalWriter

    coarse = "A340:zero_refit_coarse_Causal_field"
    fine = "A340:complete_target_conditioned_fine_order"
    terminal = "A340:protected_target_conditioned_W46_portfolio"
    writer = CausalWriter(api_id="a340w46")
    writer._rules = []
    writer.add_rule(
        name="public_output_to_model_free_Causal_field",
        description="A325's actual public output is compiled into one fresh W46 CNF and measured at four shallow horizons for every high-byte cell.",
        pattern=["A325_public_W46_output", "unchanged_A272_selected_channel_Reader"],
        conclusion="A340_zero_refit_coarse_Causal_field",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="coarse_field_to_complete_fine_order",
        description="The exact Reader-ranked high-byte cells are extended by reflected Gray4 over the next four W46 coordinates.",
        pattern=["A340_zero_refit_coarse_Causal_field", "fixed_reflected_Gray4_extension"],
        conclusion="A340_complete_target_conditioned_fine_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="target_conditioned_order_to_factor_two_protection",
        description="The target-conditioned order and A325 raw Linf form a min-rank wavefront with a pointwise factor-two bound.",
        pattern=["A340_complete_target_conditioned_fine_order", "A325_raw_Linf_order"],
        conclusion="A340_protected_target_conditioned_W46_portfolio",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A325:public_W46_output",
        mechanism="fresh_one_block_W46_CNF_256_cells_x_four_model_free_horizons",
        outcome=coarse,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["measurement_summary"], sort_keys=True),
        evidence="PUBLIC_OUTPUT_ONLY_ZERO_TARGET_LABELS_ZERO_MODELS",
        domain="AI-native target-conditioned solver inference",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=coarse,
        mechanism="unchanged_selected_channel_readout_then_reflected_Gray4_extension",
        outcome=fine,
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(
            {
                "coarse_order_sha256": payload["coarse_order_uint8_sha256"],
                "fine_order_sha256": payload["order_uint16be_sha256"][TARGET_CAUSAL],
            },
            sort_keys=True,
        ),
        evidence="COMPLETE_4096_CELL_TARGET_CONDITIONED_ORDER",
        domain="Causal rank-field amplification",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=fine,
        mechanism="exact_raw_Linf_min_rank_wavefront_with_factor_two_bound",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["wavefront_guarantee"], sort_keys=True),
        evidence="ZERO_POINTWISE_GUARANTEE_VIOLATIONS",
        domain="protected target-conditioned search ordering",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A325:public_W46_output",
        mechanism="materialized_target_conditioning_and_rank_protection_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A340_target_conditioned_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A340 target-conditioned W46 Causal portfolio",
        entities=["A325:public_W46_output", coarse, fine, terminal],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="single_independently_confirmed_A325_prefix_ranked_in_target_conditioned_and_control_orders",
        confidence=1.0,
        suggested_queries=[
            "After independent A325 confirmation, does the public-output-conditioned Causal order or its protected wavefront reach the W46 prefix before copied raw Linf?"
        ],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a340w46"
        or len(explicit) != 3
        or len(rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A340 authentic Causal reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(CAUSAL),
        "sha256": file_sha256(CAUSAL),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "reader_source": anchor(Path(inspect.getsourcefile(CausalReader) or "")),
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def measure(expected_preflight_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, MEASUREMENT, CAUSAL, REPORT)):
        raise FileExistsError("A340 measurement artifacts already exist")
    assert_pre_a325_execution()
    design = load_design()
    frozen = load_preflight(expected_preflight_sha256)
    protocol = load_a325_protocol()
    a275, model, _a291, indices, helper = A296._reader_stack()  # noqa: SLF001
    wrapper = load_module(A251_WRAPPER, "a340_clause_wrapper_measure")
    started = time.perf_counter()
    raw_run = wrapper.run_fresh_clause_identity(
        helper=helper,
        cnf=BASE_CNF,
        mode="A340_W46_target_conditioned_numeric_unlabeled",
        order=[f"{value:08b}" for value in range(COARSE_CELLS)],
        key_one_literals_bit0_through_bit19=frozen["synthetic_reader_mapping"],
        conflict_horizons=HORIZONS,
        watchdog_seconds=WATCHDOG_SECONDS,
        external_timeout_seconds=3600.0,
    )
    stable_run = {
        key: value
        for key, value in raw_run.items()
        if key not in {"command", "process_elapsed_seconds"}
    }
    stages = stable_run.get("stages", [])
    cells = stable_run.get("cells", [])
    if (
        len(stages) != COARSE_CELLS * len(HORIZONS)
        or len(cells) != COARSE_CELLS
        or any(stage.get("status") != "unknown" for stage in stages)
        or any(stage.get("model_bits_bit0_through_bit19") for stage in stages)
        or any(stage.get("watchdog_fired") for stage in stages)
        or any(cell.get("final_status") != "unknown" for cell in cells)
        or stable_run.get("all_watchdogs_clear") is not True
    ):
        raise RuntimeError("A340 model-free complete measurement gate failed")
    measurement = {
        "schema": "chacha20-round20-w46-target-conditioned-causal-order-a340-measurement-v1",
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "preflight_sha256": expected_preflight_sha256,
        "A325_protocol_sha256": ANCHOR_SHA256[A325_PROTOCOL],
        "A325_public_challenge_sha256": protocol["public_challenge_sha256"],
        "unknown_key_bits": WIDTH,
        "order_name": "numeric_high8_unlabeled",
        "partition_coordinates_high_to_low": frozen["partition_coordinates_high_to_low"],
        "free_bits_per_coarse_cell": WIDTH - COARSE_BITS,
        "run": stable_run,
        "volatile_process_elapsed_seconds": time.perf_counter() - started,
        "target_label_available_to_measurement": False,
        "label_used_for_feature_construction_or_scoring": False,
        "complete_candidate_cover": len(cells) == COARSE_CELLS,
    }
    matrix = a275._target_feature_matrix(measurement)  # noqa: SLF001
    contributions = a275.standardized_contributions(
        matrix,
        means=model.means,
        scales=model.scales,
        coefficients=model.coefficients,
    )
    scores = contributions[:, indices].sum(axis=1)
    coarse = [int(value) for value in a275._candidate_order(scores)]  # noqa: SLF001
    if len(coarse) != COARSE_CELLS or set(coarse) != set(range(COARSE_CELLS)):
        raise RuntimeError("A340 coarse Reader order is not exact")
    causal_fine = exact_order(A296.fine_order(coarse), TARGET_CAUSAL)
    raw = exact_order(protocol["selected_W46_order"], RAW)
    orders = {
        RAW: raw,
        TARGET_CAUSAL: causal_fine,
        WAVEFRONT: min_rank_wavefront(raw, causal_fine),
        BORDA: equal_borda(raw, causal_fine),
        HASH_CONTROL: public_hash_order(protocol["public_challenge_sha256"]),
    }
    orders = {name: orders[name] for name in CANDIDATE_NAMES}
    hashes = {name: order_sha256(order) for name, order in orders.items()}
    if len(set(hashes.values())) != len(CANDIDATE_NAMES):
        raise RuntimeError("A340 expected five distinct orders")
    guarantee = wavefront_guarantee(orders[WAVEFRONT], raw, causal_fine)
    if guarantee["violations"] != 0 or guarantee["maximum_rank_ratio_to_best_source"] > 2:
        raise RuntimeError("A340 factor-two guarantee failed")
    ledger = write_measurement(measurement)
    assert_pre_a325_execution()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-target-conditioned-causal-order-a340-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_A325_EXECUTION_PUBLIC_OUTPUT_CONDITIONED_CAUSAL_ORDER_AND_PROTECTION_FROZEN",
        "design_sha256": DESIGN_SHA256,
        "preflight_sha256": expected_preflight_sha256,
        "A325_protocol_sha256": ANCHOR_SHA256[A325_PROTOCOL],
        "A325_public_challenge_sha256": protocol["public_challenge_sha256"],
        "candidate_sequence": list(CANDIDATE_NAMES),
        "primary_operator": TARGET_CAUSAL,
        "protected_operator": WAVEFRONT,
        "orders": orders,
        "order_uint16be_sha256": hashes,
        "unique_order_count": len(set(hashes.values())),
        "coarse_order": coarse,
        "coarse_order_uint8_sha256": sha256(bytes(coarse)),
        "score_field": np.asarray(scores, dtype=np.float64).tolist(),
        "score_field_sha256": canonical_sha256(np.asarray(scores, dtype=np.float64).tolist()),
        "selected_feature_indices": list(indices),
        "measurement": ledger,
        "measurement_summary": {
            "coarse_cells": len(cells),
            "model_free_UNKNOWN_stages": len(stages),
            "models_returned": 0,
            "watchdogs_fired": 0,
            "reader_refits": 0,
            "target_labels_used": 0,
        },
        "wavefront_guarantee": guarantee,
        "operator_geometry": {
            "raw_vs_target_conditioned_causal_spearman": spearman(raw, causal_fine),
            "raw_vs_public_hash_spearman": spearman(raw, orders[HASH_CONTROL]),
            "target_conditioned_causal_vs_public_hash_spearman": spearman(
                causal_fine, orders[HASH_CONTROL]
            ),
        },
        "information_boundary": {
            **design["information_boundary"],
            "A325_progress_absent_at_measurement_commitment": True,
            "A325_result_absent_at_measurement_commitment": True,
            "A325_public_output_used": True,
            "A325_hidden_assignment_prefix_or_filter_outcome_used": False,
            "candidate_executions_performed_by_A340": 0,
            "A325_protocol_modified": False,
        },
        "future_evaluation_contract": design["future_evaluation_contract"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "preflight": anchor(PREFLIGHT, expected_preflight_sha256),
            "A325_protocol": anchor(A325_PROTOCOL, ANCHOR_SHA256[A325_PROTOCOL]),
            "A296_runner": anchor(A296_RUNNER, ANCHOR_SHA256[A296_RUNNER]),
            "A296_result": anchor(A296_RESULT, ANCHOR_SHA256[A296_RESULT]),
            "A251_wrapper": anchor(A251_WRAPPER, ANCHOR_SHA256[A251_WRAPPER]),
            "A275_runner": anchor(A275_RUNNER, ANCHOR_SHA256[A275_RUNNER]),
            "A275_protocol": anchor(A275_PROTOCOL, ANCHOR_SHA256[A275_PROTOCOL]),
            "runner": anchor(Path(__file__)),
            "test": anchor(A340_TEST),
            "reproducer": anchor(A340_REPRO),
        },
    }
    payload["commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "preflight_sha256": expected_preflight_sha256,
            "A325_protocol_sha256": payload["A325_protocol_sha256"],
            "A325_public_challenge_sha256": payload["A325_public_challenge_sha256"],
            "candidate_sequence": payload["candidate_sequence"],
            "order_uint16be_sha256": payload["order_uint16be_sha256"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "measurement": ledger,
            "score_field_sha256": payload["score_field_sha256"],
            "coarse_order_uint8_sha256": payload["coarse_order_uint8_sha256"],
            "order_uint16be_sha256": payload["order_uint16be_sha256"],
            "wavefront_guarantee": payload["wavefront_guarantee"],
            "operator_geometry": payload["operator_geometry"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A340 — public-output-conditioned Causal W46 order\n\n"
            f"- Model-free trajectory stages: **{len(stages):,} / 1,024 UNKNOWN**\n"
            "- Reader refits / target labels / models: **0 / 0 / 0**\n"
            "- Complete target-conditioned fine cells: **4,096 / 4,096**\n"
            f"- Raw/Causal Spearman: **{payload['operator_geometry']['raw_vs_target_conditioned_causal_spearman']:.8f}**\n"
            f"- Factor-two violations: **{guarantee['violations']}**\n"
            f"- Exact distinct frozen orders: **{payload['unique_order_count']} / 5**\n"
            "- A325 candidate executions / protocol changes: **zero / zero**\n"
            "- Authentic AI-native Causal readback: **3 linked explicit + 1 inferred edge**\n"
        ).encode(),
    )
    return {
        "attempt_id": ATTEMPT_ID,
        "result": relative(RESULT),
        "result_sha256": file_sha256(RESULT),
        "commitment_sha256": payload["commitment_sha256"],
        "measurement_sha256": payload["measurement_sha256"],
        "Causal_sha256": payload["causal"]["sha256"],
        "measurement_summary": payload["measurement_summary"],
        "order_uint16be_sha256": payload["order_uint16be_sha256"],
        "wavefront_guarantee": payload["wavefront_guarantee"],
        "operator_geometry": payload["operator_geometry"],
    }


def analyze() -> dict[str, Any]:
    response: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "preflight_exists": PREFLIGHT.exists(),
        "result_exists": RESULT.exists(),
    }
    if PREFLIGHT.exists():
        response["preflight_sha256"] = file_sha256(PREFLIGHT)
    if RESULT.exists():
        payload = json.loads(RESULT.read_bytes())
        response.update(
            {
                "result_sha256": file_sha256(RESULT),
                "commitment_sha256": payload["commitment_sha256"],
                "measurement_sha256": payload["measurement_sha256"],
                "measurement_summary": payload["measurement_summary"],
                "order_uint16be_sha256": payload["order_uint16be_sha256"],
                "wavefront_guarantee": payload["wavefront_guarantee"],
                "operator_geometry": payload["operator_geometry"],
            }
        )
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--measure", metavar="PREFLIGHT_SHA256")
    action.add_argument("--analyze", action="store_true")
    args = parser.parse_args()
    if args.preflight:
        payload = preflight()
    elif args.measure:
        payload = measure(args.measure)
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
