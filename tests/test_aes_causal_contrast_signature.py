def test_contrast_signature_imports() -> None:
    import importlib.util, sys
    from pathlib import Path
    path=Path(__file__).parents[1]/"research/experiments/aes_causal_contrast_signature.py";spec=importlib.util.spec_from_file_location("aes_causal_contrast_signature",path);assert spec and spec.loader
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);assert module._O.search("x:entropy_contrast_byte_3").group(1)=="3"
