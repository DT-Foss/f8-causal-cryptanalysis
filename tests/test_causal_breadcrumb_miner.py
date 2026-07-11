def test_breadcrumb_miner_reads_real_causal_artifacts() -> None:
    from pathlib import Path
    from research.experiments.causal_breadcrumb_miner import mine

    payload = mine(Path(__file__).parents[1] / "research/results/v1")
    assert payload["edge_count"] > 1000
    assert payload["positive_edge_count"] > 100
    assert payload["family_mechanism_compositions"]
