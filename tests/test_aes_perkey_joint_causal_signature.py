def test_perkey_joint_signature_imports() -> None:
    import importlib.util, sys
    from pathlib import Path
    path=Path(__file__).parents[1]/"research/experiments/aes_perkey_joint_causal_signature.py"
    spec=importlib.util.spec_from_file_location("aes_perkey_joint_causal_signature",path); assert spec and spec.loader
    module=importlib.util.module_from_spec(spec); sys.modules[spec.name]=module; spec.loader.exec_module(module)
    assert module._load_joint().__name__ == "aes_round_joint_causal_signature_perkey"
