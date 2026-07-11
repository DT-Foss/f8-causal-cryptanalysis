def test_round_signature_imports() -> None:
    import importlib.util
    import sys
    from pathlib import Path
    path = Path(__file__).parents[1] / "research/experiments/aes_round_causal_signature.py"
    spec = importlib.util.spec_from_file_location("aes_round_causal_signature", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    assert module._CLASS_RE.search("x:class_r3-identity").group(1) == "r3-identity"
