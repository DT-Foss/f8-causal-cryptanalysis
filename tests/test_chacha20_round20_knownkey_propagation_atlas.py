from __future__ import annotations

import hashlib
import json
from pathlib import Path

from arx_carry_leak.crypto_causal import CryptoCausalReader


ROOT = Path(__file__).parents[1]
CONFIG = ROOT / "research" / "configs" / "chacha20_round20_knownkey_propagation_atlas_v3.json"
PREREVEAL = ROOT / "research" / "results" / "v1" / "chacha20_round20_knownkey_propagation_atlas_v3_prereveal.json"
RESULT = ROOT / "research" / "results" / "v1" / "chacha20_round20_knownkey_propagation_atlas_v3.json"
CAUSAL = RESULT.with_suffix(".causal")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_a214c_protocol_and_prereveal_are_hash_sealed() -> None:
    assert _sha256(CONFIG) == "aa5b7af87c74cbffe7f6d3e50332cc65c07f084435edb4314b32e4904b625698"
    assert _sha256(PREREVEAL) == "10f34b191ad4441c1aba09832f37ae8f32c7fdee19f9b0ac36f817f1a9e58451"
    prereveal = json.loads(PREREVEAL.read_bytes())
    assert prereveal["schema"] == "chacha20-round20-knownkey-propagation-atlas-prereveal-v3"
    assert prereveal["target_key_available_during_this_artifact"] is False
    assert prereveal["R20_solver_output_read_during_this_artifact"] is False
    assert prereveal["all_model_weights_headers_and_orders_frozen"] is True
    assert len(prereveal["target_candidate_orders"]) == 6
    assert prereveal["symbolic_template_manifest"]["all_mapping_probes_exact_unit_deltas"] is True


def test_a214c_retains_the_predeclared_representation_boundary() -> None:
    payload = json.loads(RESULT.read_bytes())
    assert payload["evidence_stage"] == "KNOWNKEY_PROPAGATION_ATLAS_REPRESENTATION_BOUNDARY"
    assert payload["prereveal_sha256"] == _sha256(PREREVEAL)
    assert payload["target_collision_with_atlas"] is False
    assert payload["prereveal"]["complete_key_label_null"]["lower_tail_plus_one_p"] == 0.15384615384615385
    assert payload["target_ranks"]["F5_multiview_consensus"] == 727365
    assert not any(
        payload["consensus_top_k_hits"][str(value)] for value in (1, 8, 32, 256, 1024)
    )
    assert payload["confirmation"]["all_blocks_match"] is True
    assert payload["confirmation"]["output_bits_checked"] == 4096
    assert payload["confirmation"]["control_first_block_match"] is False


def test_a214c_causal_reader_verifies_corrected_boundary() -> None:
    payload = json.loads(RESULT.read_bytes())
    reader = CryptoCausalReader(CAUSAL)
    assert reader.verify_provenance()
    assert reader.graph_sha256 == payload["causal_artifact"]["graph_sha256"]
    assert reader.file_sha256 == payload["causal_artifact"]["file_sha256"]
    assert any(
        row["outcome"] == "A214:KNOWNKEY_PROPAGATION_ATLAS_REPRESENTATION_BOUNDARY"
        for row in reader.triplets()
    )
