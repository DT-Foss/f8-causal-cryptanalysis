def test_signature_module_imports_and_classifies_synthetic_batches() -> None:
    import importlib.util
    import sys
    from pathlib import Path
    import numpy as np
    path = Path(__file__).parents[1] / "research/experiments/aes_input_causal_signature.py"
    spec = importlib.util.spec_from_file_location("aes_input_causal_signature", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    rng = np.random.default_rng(3)
    first = rng.integers(0, 256, size=(200, 4), dtype=np.uint8)
    second = first.copy()
    second[:, 0] ^= np.uint8(0xF0)
    probs, background = module._model({0: [first], 1: [second]}, [0, 1], 16)
    predicted, _ = module._classify(probs, background, first, 16)
    assert predicted == 0
