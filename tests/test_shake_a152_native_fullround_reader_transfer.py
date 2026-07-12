from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake_a152_native_fullround_reader_transfer.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_a152_native_fullround_reader_transfer_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS_DIR / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "4a3312fe50686744d3db56a5c228128e7106fe071d672128459bda481f675ed0"
CAUSAL_SHA256 = "be53ad7b6948abe7465b41a50bc4128ff8f20aa3150a32936927f309ddbac02e"
CAUSAL_GRAPH_SHA256 = "1ef4fe5a6ced7cfe84d86f6d8dffe1788f915cb77f03b6ade629bcd1bfd007c3"


def test_frozen_protocol_and_causal_reader_bind_the_public_transfer() -> None:
    protocol = MODULE._load_protocol_gate()
    anchors = MODULE._load_anchor_gates(RESULTS_DIR)
    assert protocol["reader_plan"]["logical_candidate_count"] == 16_777_216
    assert protocol["reader_plan"]["packed_state_count"] == 262_144
    assert protocol["reader_plan"]["early_stop_allowed"] is False
    assert protocol["reader_plan"]["instrumented_assignment_input_used"] is False
    assert anchors["A152_result_sha256"] == MODULE.A152_SHA256
    assert anchors["native_result_sha256"] == MODULE.NATIVE_SHA256
    assert anchors["native_causal_sha256"] == MODULE.NATIVE_CAUSAL_SHA256
    assert anchors["native_causal_provenance_verified"] is True
    recipe = anchors["native_reader_recipe"]
    assert recipe["permutation_rounds"] == 24
    assert recipe["candidates_per_machine_word"] == 64
    assert recipe["filter_lanes"] == 2
    assert recipe["full_confirmation"] == "independent_scalar_complete_rate_equality"


def test_regenerated_A152_runtime_relation_contains_no_assignment() -> None:
    protocol = MODULE._load_protocol_gate()
    public, summary = MODULE._prepare_public_relation(protocol)
    assert set(public) == {"template", "target", "positions"}
    assert summary["capacity_window_positions"] == list(range(143, 167))
    assert summary["cleared_template_sha256"] == (
        "8dd7a73132ae11987e86866552701cc7d093771ec911ee94883d114d3afb33d2"
    )
    assert summary["target_rate_sha256"] == (
        "435edcaaa1288f8b812aea055dacc9aadc6dc1dd7416a2102459d2bc7526141c"
    )
    assert summary["instrumented_assignment_included"] is False


def test_independent_complete_rate_gate_accepts_only_the_A152_model() -> None:
    protocol = MODULE._load_protocol_gate()
    public, _ = MODULE._prepare_public_relation(protocol)
    variant = MODULE._BASE.VARIANTS["shake128"]
    accepted = MODULE._independent_confirm(
        public["template"],
        public["target"],
        public["positions"],
        variant,
        9_279_571,
    )
    rejected = MODULE._independent_confirm(
        public["template"],
        public["target"],
        public["positions"],
        variant,
        9_279_570,
    )
    assert accepted["complete_rate_match"] is True
    assert accepted["rate_bits_checked"] == 1_344
    assert accepted["candidate_rate_sha256"] == accepted["target_rate_sha256"]
    assert rejected["complete_rate_match"] is False


def test_native_reader_executes_a_complete_small_public_domain(tmp_path: Path) -> None:
    variant = MODULE._BASE.VARIANTS["shake128"]
    generated = MODULE._NATIVE._problem(variant, 8, 0xA165)
    public = {
        "template": MODULE._WINDOW._clear_window(
            generated["base_state"],
            variant,
            generated["positions"],
        ),
        "target": generated["target"],
        "positions": generated["positions"],
    }
    actual = MODULE._WINDOW._extract_window(
        generated["base_state"],
        variant,
        generated["positions"],
    )
    library, build = MODULE._NATIVE._compile_native(tmp_path / "native")
    assert build["source_sha256"] == MODULE.NATIVE_SOURCE_SHA256
    kernel = MODULE._NATIVE.NativeBitSliceKernel(library)
    recipe = MODULE._load_anchor_gates(RESULTS_DIR)["native_reader_recipe"]
    checkpoint = tmp_path / "small.checkpoint.json"
    result = MODULE._enumerate_public_relation(
        kernel=kernel,
        public=public,
        variant=variant,
        recipe=recipe,
        threads=2,
        stream_packs=2,
        checkpoint_path=checkpoint,
        resume=True,
    )
    assert result["complete_domain_executed"] is True
    assert result["logical_candidate_count"] == 256
    assert result["packed_state_count"] == 4
    assert result["stream_batch_count"] == 2
    assert result["factual_full_matches"] == [actual]
    assert result["control_full_matches"] == []
    assert result["unique_exact_public_model"] is True
    assert result["instrumented_assignment_input_used"] is False


def test_retained_a165_artifacts_are_hash_pinned_and_reader_valid() -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A165"
    assert payload["evidence_stage"] == (
        "A152_NATIVE_FULLROUND_MODEL_RECONSTRUCTION_RETAINED"
    )
    assert payload["protocol_gate"]["artifact_sha256"] == MODULE.PROTOCOL_SHA256
    assert payload["anchor_gates"]["A152_result_sha256"] == MODULE.A152_SHA256
    assert payload["anchor_gates"]["native_result_sha256"] == MODULE.NATIVE_SHA256
    assert payload["anchor_gates"]["native_causal_sha256"] == (
        MODULE.NATIVE_CAUSAL_SHA256
    )
    assert payload["anchor_gates"]["native_source_sha256"] == (
        MODULE.NATIVE_SOURCE_SHA256
    )
    assert payload["anchor_gates"]["native_causal_provenance_verified"] is True
    assert payload["execution_sha256"] == (
        "ac8e9820e4b501b2eda98c68e0d16ab579685ccdc9b7de0bea24dc307a63d5fc"
    )
    assert payload["confirmation_sha256"] == (
        "81fcf52e58b3a66ade72204d121a804581dab1d36e2167510e4d77e3a859ed37"
    )
    execution = payload["execution"]
    assert execution["logical_candidate_count"] == 16_777_216
    assert execution["candidate_pack_width"] == 64
    assert execution["packed_state_count"] == 262_144
    assert execution["resumed_pack_count"] == 0
    assert execution["newly_executed_pack_count"] == 262_144
    assert execution["complete_domain_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["factual_filter_matches"] == [9_279_571]
    assert execution["factual_full_matches"] == [9_279_571]
    assert execution["control_filter_matches"] == []
    assert execution["control_full_matches"] == []
    assert execution["unique_exact_public_model"] is True
    assert execution["control_target_rejected"] is True
    assert execution["instrumented_assignment_input_used"] is False
    assert execution["A152_posthoc_assignment_read_before_candidate_execution"] is False
    confirmation = execution["factual_confirmations"]
    assert len(confirmation) == 1
    assert confirmation[0]["assignment"] == 9_279_571
    assert confirmation[0]["complete_rate_match"] is True
    assert confirmation[0]["rate_bits_checked"] == 1_344
    assert confirmation[0]["candidate_rate_sha256"] == (
        confirmation[0]["target_rate_sha256"]
    )
    assert payload["current_build_cross_implementation_gate"] == {
        "exact_match": True,
        "input_sha256": "1a4a5fac1453fa4cb3fe044cc8951f694b1850fe3104bb9f94f9cf6e57337176",
        "output_sha256": "2588e848ab326b7ffd9c5e1aa5a7937cd1327f7fb1b7dedbe87a0e665d00adfd",
        "state_bits_checked": 102_400,
        "states": 64,
    }
    posthoc = payload["posthoc_comparison"]
    assert posthoc["read_only_after_complete_domain_execution"] is True
    assert posthoc["used_for_candidate_generation_filtering_or_confirmation"] is False
    assert posthoc["A152_instrumented_assignment"] == 9_279_571
    assert posthoc["recovered_assignments"] == [9_279_571]
    assert posthoc["unique_reconstruction_matches_A152_instrumented_assignment"] is True
    lowered = raw.decode().lower()
    assert '"wallclock_seconds"' not in lowered
    assert '"elapsed_seconds"' not in lowered
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    assert len(rows) == 5
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "shake128-native-retained-fullround-reader-recipe",
        "shake128-a152-public-fullround-relation",
        "shake128-a165-complete-packed-domain-execution",
        "shake128-a165-independent-complete-rate-confirmation",
        "shake128-a165-posthoc-prospective-instance-comparison",
    ]
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
        [ids[3]],
    ]
