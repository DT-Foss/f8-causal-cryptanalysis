from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).parents[1]
PREFLIGHT = ROOT / "research/experiments/chacha20_round20_selected_channel_prospective_preflight.py"
RUNNER = ROOT / "research/experiments/chacha20_round20_selected_channel_prospective_validation.py"


def _load():
    spec = importlib.util.spec_from_file_location("a272_preflight", PREFLIGHT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_runner():
    spec = importlib.util.spec_from_file_location("a272_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a272_second_panel_is_deterministic_balanced_and_disjoint() -> None:
    module = _load()
    first = module.prospective_design()
    second = module.prospective_design()
    assert first == second
    module.validate_design(first)
    prior_prefixes, prior_suffixes, prior_low20 = module._prior_levels()
    assert not {row["prefix8"] for row in first} & prior_prefixes
    assert not {row["suffix12"] for row in first} & prior_suffixes
    assert not {row["low20"] for row in first} & prior_low20


def test_a272_protocol_freezes_one_posthoc_hypothesis_before_new_data(tmp_path: Path) -> None:
    module = _load()
    module.OUTPUT = tmp_path / "not-existing-a272.json"
    protocol = module.build_protocol()
    selected = protocol["selected_hypothesis"]
    assert selected["feature_indices"] == [502, 504, 505, 508, 509, 510, 511, 514]
    assert protocol["controls"]["view_count"] == 1
    assert protocol["prospective_design"]["rows_sha256"]
    assert protocol["information_boundary"]["any_A272_solver_measurement_started_before_freeze"] is False
    assert selected["model_refit_or_coefficient_update_permitted"] is False


def test_a272_single_view_evaluation_uses_complete_shared_xor_controls() -> None:
    rows = []
    fields = []
    for prefix_index, truth in enumerate((11, 37, 81, 146, 224)):
        for suffix_index in range(4):
            rows.append(
                {
                    "label": f"synthetic_p{prefix_index:02d}_s{suffix_index:02d}",
                    "prefix_index": prefix_index,
                    "prefix8": truth,
                }
            )
            scores = np.zeros(256)
            scores[truth] = 1.0
            fields.append(scores)
    result = _load_runner()._evaluate_scores(rows, fields)
    assert len(result["prospective_rows"]) == 20
    assert result["mean_log2_rank"] == 0.0
    assert result["exact_shared_xor_p"] == 1 / 256
    assert result["positive_prefix_groups"] == 5
