def test_chacha_contrast_signature_imports():
    import importlib.util,sys
    from pathlib import Path
    path=Path(__file__).parents[1]/"research/experiments/chacha_causal_contrast_signature.py";spec=importlib.util.spec_from_file_location("chacha_causal_contrast_signature",path);assert spec and spec.loader
    m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);assert m._O.search("x:entropy_contrast_byte_63").group(1)=="63"
