"""Fast functional gates for the real PQC backend used by the research suite."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys


def _load_suite():
    path = Path(__file__).parents[1] / "research/experiments/pqc_output_control_suite.py"
    spec = spec_from_file_location("pqc_output_control_suite", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_mlkem_and_mldsa_functional_gates() -> None:
    suite = _load_suite()
    targets = {target.name: target for target in suite.TARGETS}
    for name in ("mlkem512", "mldsa44"):
        outputs, verified = suite._operation_collector(targets[name], fixed_key=True, count=2, seed=42)
        assert verified
        assert len(outputs) == 2
        assert all(outputs)


def test_f8_output_has_expected_shape() -> None:
    suite = _load_suite()
    import numpy as np

    rows = np.arange(32 * 64, dtype=np.uint8).reshape(64, 32)
    result = suite._f8_output(rows)
    assert result["tested_pairs"] >= 0
    assert 0.0 <= result["significant_rate"] <= 1.0
