from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "research/experiments/chacha20_round20_operation_flow_preflight.py"


def _load() -> object:
    spec = importlib.util.spec_from_file_location("a261_preflight_test_module", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load()


def test_a261_preflight_is_explicitly_public_and_label_blind() -> None:
    assert MODULE.ATTEMPT_ID == "A261"
    assert MODULE.SCHEMA == "chacha20-round20-operation-flow-preflight-v1"
    assert MODULE.OUTPUT.name.endswith("operation_flow_preflight_v1.json")


def test_a261_capture_uses_and_restores_frozen_decoder() -> None:
    class FakeA260:
        def __init__(self) -> None:
            self.decode_vectorized_mapping = lambda exports: (((1,) * 32),)

        def _prepare_operation_topology(self, *args: object) -> tuple[object, dict, dict]:
            mapping = self.decode_vectorized_mapping({})
            assert mapping == (((1,) * 32),)
            digest = MODULE._sha256(
                MODULE.np.asarray(mapping, dtype="<i4").tobytes()
            )
            return object(), {}, {"signed_one_literal_matrix_sha256": digest}

    fake = FakeA260()
    original = fake.decode_vectorized_mapping
    digest = MODULE._sha256(
        MODULE.np.asarray((((1,) * 32),), dtype="<i4").tobytes()
    )
    topology, mapping, _, _ = MODULE._prepare_with_exact_mapping(
        fake,
        {"operation_tap_preflight": {"signed_one_literal_matrix_sha256": digest}},
        object(),
        object(),
        Path("."),
    )
    assert topology is not None
    assert mapping == (((1,) * 32),)
    assert fake.decode_vectorized_mapping is original
