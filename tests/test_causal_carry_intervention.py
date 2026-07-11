from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

import numpy as np

from arx_carry_leak.ciphers import get_generator


def _load_suite():
    path = Path(__file__).parents[1] / "research/experiments/causal_carry_intervention_suite.py"
    spec = spec_from_file_location("causal_carry_intervention_suite", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_speck_carry_counterfactual_exact_identity() -> None:
    suite = _load_suite()
    generator = get_generator("speck32_64")
    raw, block_bytes, _ = generator(128, 22, 42)
    raw_next, _, _ = generator(128, 23, 42)
    first = np.frombuffer(raw, dtype=np.uint8).reshape(-1, block_bytes)
    second = np.frombuffer(raw_next, dtype=np.uint8).reshape(-1, block_bytes)
    _, check = suite._speck_counterfactual("speck32_64", first, second, 22, 42)
    assert check["all_factual_transitions_verified"]
    assert check["all_carry_identities_verified"]


def test_threefish_counterfactual_preserves_factual_alignment() -> None:
    suite = _load_suite()
    generator = get_generator("threefish256")
    raw, block_bytes, _ = generator(32, 72, 42)
    raw_next, _, _ = generator(32, 73, 42)
    first = np.frombuffer(raw, dtype=np.uint8).reshape(-1, block_bytes)
    second = np.frombuffer(raw_next, dtype=np.uint8).reshape(-1, block_bytes)
    _, check = suite._threefish_counterfactual(first, second, 72, 42)
    assert check["all_factual_transitions_verified"]
    assert check["all_affine_neighbor_identities_verified"]
