def test_aes_output_causal_codec_imports() -> None:
    import importlib.util
    import sys
    from pathlib import Path
    path = Path(__file__).parents[1] / "research/experiments/aes_output_causal_codec.py"
    spec = importlib.util.spec_from_file_location("aes_output_causal_codec", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    assert module._sign_flip([1.0, 1.0, 1.0]) == 0.25
