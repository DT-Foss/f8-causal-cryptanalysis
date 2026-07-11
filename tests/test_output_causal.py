import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalReader
from arx_carry_leak.output_causal import derive_edges, evaluate_holdout, reverse_rank, save_output_graph


def test_direct_output_graph_compresses_and_reverse_queries(tmp_path) -> None:
    rng = np.random.default_rng(11)
    source = rng.integers(0, 256, size=(400, 4), dtype=np.uint8)
    outcome = rng.integers(0, 256, size=(400, 4), dtype=np.uint8)
    outcome[:, 2] = (source[:, 1] & np.uint8(0xF0)) | np.uint8(7)
    edges = derive_edges(source, outcome, bins=16, routes=4, seed=12, max_edges=32)
    assert edges
    path = tmp_path / "output.causal"
    stats = save_output_graph(str(path), experiment="test", condition="synthetic", parameters={"bins": 16}, source=source, outcome=outcome, edges=edges)
    reader = CryptoCausalReader(path)
    assert stats["triplets"] == len(edges)
    ranked = reverse_rank(reader, condition="synthetic", observed_delta=outcome[0], bins=16)
    assert ranked
    holdout = evaluate_holdout(reader, condition="synthetic", source=source, outcome=outcome, bins=16, routes=4, seed=13)
    assert holdout["reverse_coverage"] > 0
