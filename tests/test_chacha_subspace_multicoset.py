from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys


def _load_suite():
    path = Path(__file__).parents[1] / "research/experiments/chacha_subspace_multicoset_suite.py"
    spec = spec_from_file_location("chacha_subspace_multicoset_for_test", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_summary() -> None:
    suite = _load_suite()
    result = suite._summary([1.0, 2.0, 3.0])
    assert result["mean"] == 2.0
    assert result["minimum"] == 1.0
    assert result["maximum"] == 3.0
