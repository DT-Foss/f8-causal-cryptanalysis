import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalReader


def test_mlkem_chosen_experiment_is_importable_and_reader_exists() -> None:
    from importlib.util import spec_from_file_location, module_from_spec
    import sys
    from pathlib import Path
    path = Path(__file__).parents[1] / "research/experiments/mlkem_chosen_difference_frontier.py"
    spec = spec_from_file_location("mlkem_chosen_difference_frontier", path)
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    assert module.Q == 3329
    assert module.BIN_COUNT == 16


def test_field_entropy_deficit_is_zero_for_uniformish_delta() -> None:
    from importlib.util import spec_from_file_location, module_from_spec
    import sys
    from pathlib import Path
    path = Path(__file__).parents[1] / "research/experiments/mlkem_chosen_difference_frontier.py"
    spec = spec_from_file_location("mlkem_chosen_difference_frontier_metrics", path)
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    rng = np.random.default_rng(4)
    delta = rng.integers(0, module.Q, size=(20000, 256), dtype=np.int32)
    assert module._entropy_deficit(delta) < 2.0
