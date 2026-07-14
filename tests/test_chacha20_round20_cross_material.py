from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
PREFLIGHT = (
    ROOT
    / "research/experiments/chacha20_round20_cross_material_symbolic_preflight.py"
)
RUNNER = ROOT / "research/experiments/chacha20_round20_cross_material_measure.py"
PUBLIC = ROOT / "research/experiments/chacha20_round20_public_core.py"
TEMPLATE = ROOT / "research/experiments/chacha20_round20_symbolic_template.py"
MASTER = ROOT / "research/configs/chacha20_round20_cross_material_composite_master_v1.json"
TARGET = ROOT / "research/configs/chacha20_round20_cross_material_target_v1.json"
SYMBOLIC = ROOT / "research/configs/chacha20_round20_cross_material_symbolic_template_v1.json"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a280_analyze_loads_the_frozen_cross_material_chain() -> None:
    master = json.loads(MASTER.read_bytes())
    target = json.loads(TARGET.read_bytes())
    symbolic = json.loads(SYMBOLIC.read_bytes())
    measurement = master["frozen_schedule"]["measurement"]
    assert measurement["complete_256_candidate_cover_before_scoring"] is True
    assert measurement["conflict_horizons"] == [1, 2, 4, 8]
    assert len(measurement["feature_indices"]) == 8
    assert target["information_boundary"]["target_candidate_order_known"] is False
    assert target["information_boundary"]["target_measurement_started"] is False
    assert symbolic["target_independence"]["A279_target_words_read"] is False


def test_a280_symbolic_formula_is_independent_of_target_words() -> None:
    public = _load(PUBLIC, "a280_public_invariance_test")
    template = _load(TEMPLATE, "a280_template_invariance_test")
    master = json.loads(MASTER.read_bytes())
    target = json.loads(TARGET.read_bytes())
    symbolic = json.loads(SYMBOLIC.read_bytes())
    dummy = public.build_known_challenge(
        master["cross_material_public_template"], low20=0
    )
    dummy_formula = template.symbolic_formula(public, dummy).encode()
    target_formula = template.symbolic_formula(public, target["public_challenge"]).encode()
    assert dummy_formula == target_formula
    assert hashlib.sha256(target_formula).hexdigest() == symbolic[
        "symbolic_R20_template"
    ]["formula_sha256"]
    assert symbolic["target_independence"]["A279_target_words_read"] is False


def test_a280_cross_material_mapping_is_exact_and_public_specific() -> None:
    symbolic = json.loads(SYMBOLIC.read_bytes())
    inherited_path = ROOT / symbolic["anchors"]["inherited_symbolic_protocol"]["path"]
    inherited = json.loads(inherited_path.read_bytes())
    current = symbolic["symbolic_R20_template"]
    old = inherited["symbolic_R20_template"]
    assert symbolic["compile_manifest"]["all_mapping_probes_exact_unit_deltas"] is True
    assert symbolic["compile_manifest"]["mapping_probe_count"] == 102
    assert len(current["key_one_literals_bit0_through_bit19"]) == 20
    assert (
        current["key_one_literals_bit0_through_bit19"]
        != old["key_one_literals_bit0_through_bit19"]
        or current["output_one_literal_matrix_sha256"]
        != old["output_one_literal_matrix_sha256"]
    )


def test_a280_secret_gate_rejects_labels() -> None:
    runner = _load(RUNNER, "a280_secret_gate_test")
    with pytest.raises(RuntimeError, match="secret-bearing field"):
        runner._assert_secret_free({"unknown_assignment": 7})


def test_a280_preflight_has_no_target_dependency() -> None:
    source = PREFLIGHT.read_text()
    assert "cross_material_target_v1" not in source
    assert "A279_target_words_read\": False" in source
