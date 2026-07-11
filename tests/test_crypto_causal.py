from pathlib import Path

from arx_carry_leak.crypto_causal import (
    CryptoCausalBuilder,
    CryptoCausalReader,
    ExactRule,
)


def _graph() -> CryptoCausalBuilder:
    builder = CryptoCausalBuilder(experiment="test", parameters={"seed": 42})
    builder.add_rule(ExactRule("chain", "causes", "causes", "causes", 0.8))
    builder.add_triplet(
        edge_id="e1",
        trigger="A",
        mechanism="causes",
        outcome="B",
        confidence=0.9,
        evidence_kind="measured",
        source="test",
    )
    builder.add_triplet(
        edge_id="e2",
        trigger="B",
        mechanism="causes",
        outcome="C",
        confidence=0.8,
        evidence_kind="algebraic",
        source="test",
    )
    return builder


def test_exact_closure_has_source_provenance(tmp_path: Path) -> None:
    builder = _graph()
    inferred = builder.infer_exact_closure(max_hops=3)
    assert len(inferred) == 1
    assert inferred[0].trigger == "A"
    assert inferred[0].outcome == "C"
    assert inferred[0].provenance == ("e1", "e2")

    path = tmp_path / "evidence.causal"
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    assert stats["explicit_triplets"] == 2
    assert stats["inferred_triplets"] == 1
    assert reader.graph_sha256 == stats["graph_sha256"]
    assert reader.file_sha256 == stats["file_sha256"]
    assert reader.verify_provenance()


def test_serialization_is_bit_deterministic(tmp_path: Path) -> None:
    first = _graph()
    second = _graph()
    first.infer_exact_closure(max_hops=3)
    second.infer_exact_closure(max_hops=3)
    path_a = tmp_path / "a.causal"
    path_b = tmp_path / "b.causal"
    first.save(path_a)
    second.save(path_b)
    assert path_a.read_bytes() == path_b.read_bytes()
