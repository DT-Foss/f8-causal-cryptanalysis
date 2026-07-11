from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

import numpy as np


def _load_suite():
    path = Path(__file__).parents[1] / "research/experiments/mlkem_causal_serialization_suite.py"
    spec = spec_from_file_location("mlkem_causal_serialization_suite", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_standard_codec_and_bitplane_are_exact_bit_bijections() -> None:
    suite = _load_suite()
    rng = np.random.default_rng(42)
    for width, count in ((10, 512), (11, 1024)):
        values = rng.integers(0, 1 << width, size=count, dtype=np.uint16)
        standard = suite._encode(values, width)
        planes = suite._bitplane_encode(values, width)
        assert np.array_equal(suite._decode(standard, width, count), values)
        assert len(standard) == len(planes) == width * count // 8
        assert sum(byte.bit_count() for byte in standard) == sum(
            byte.bit_count() for byte in planes
        )


def test_compression_occupancy_matches_q_3329_preimage_counts() -> None:
    suite = _load_suite()
    ten = np.bincount(
        suite._compress_field(np.arange(suite.Q, dtype=np.uint16), 10), minlength=1024
    )
    eleven = np.bincount(
        suite._compress_field(np.arange(suite.Q, dtype=np.uint16), 11), minlength=2048
    )
    assert dict(zip(*np.unique(ten, return_counts=True), strict=True)) == {3: 767, 4: 257}
    assert dict(zip(*np.unique(eleven, return_counts=True), strict=True)) == {1: 767, 2: 1281}
