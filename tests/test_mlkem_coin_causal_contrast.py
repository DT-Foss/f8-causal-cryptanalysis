def test_mlkem_coin_causal_imports():
    import importlib.util,sys
    from pathlib import Path
    path=Path(__file__).parents[1]/"research/experiments/mlkem_coin_causal_contrast.py";spec=importlib.util.spec_from_file_location("mlkem_coin_causal_contrast",path);assert spec and spec.loader
    m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);assert m._O.search("x:ciphertext_entropy_contrast_byte_7").group(1)=="7"
