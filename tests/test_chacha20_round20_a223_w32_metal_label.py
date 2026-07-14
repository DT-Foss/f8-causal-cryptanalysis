from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).parents[1]
MODULE_PATH = (
    ROOT
    / "research"
    / "experiments"
    / "chacha20_round20_a223_w32_metal_label.py"
)
RESULT_PATH = (
    ROOT
    / "research"
    / "results"
    / "v1"
    / "chacha20_round20_a223_w32_metal_label_v1.json"
)

SPEC = importlib.util.spec_from_file_location("a224_w32_metal_label_tested", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_a224_result_contains_complete_domain_and_eight_block_confirmation() -> None:
    result = json.loads(RESULT_PATH.read_bytes())
    assert result["schema"] == MODULE.SCHEMA
    assert result["attempt_id"] == MODULE.ATTEMPT_ID
    assert result["metal_execution"]["logical_candidate_count"] == 1 << 32
    assert result["metal_execution"]["stream_batch_count"] == 16
    assert result["metal_execution"]["complete_domain_executed"] is True
    assert result["metal_execution"]["early_stop_used"] is False
    assert result["metal_execution"]["control_filter_matches"] == []
    assert result["confirmation"]["recovered_key_word0_hex"] == "0x901c330a"
    assert result["confirmation"]["block_matches"] == [True] * 8
    assert result["confirmation"]["output_bits_checked"] == 4096
    assert result["confirmation"]["flipped_control_rejected"] is True


def test_a224_recomputed_label_and_trajectory_ranks_are_exact() -> None:
    challenge, _, observations = MODULE._load_inputs()
    result = json.loads(RESULT_PATH.read_bytes())
    word0 = result["confirmation"]["recovered_key_word0"]
    assert MODULE._confirm(challenge, word0)["all_blocks_match"] is True
    readout = MODULE._trajectory_readout(observations, word0)
    assert readout["true_prefix8"] == "10010000"
    assert readout["true_prefix_gray_order_execution_rank"] == 225
    assert readout["true_cell_ranks"]["conflicts"]["rank"] == 4
    assert readout["true_cell_ranks"]["decisions"]["rank"] == 4
    assert readout["true_cell_ranks"]["constraint_coherence"]["rank"] == 4
    assert readout["true_cell_ranks"]["coherence_local_residual"]["rank"] == 8
    assert readout["best_observed_true_cell_rank"] == 4
    assert readout["true_cell_in_top16_on_any_fixed_view"] is True
