def test_joint_signature_imports() -> None:
    import importlib.util, sys
    from pathlib import Path
    path=Path(__file__).parents[1]/"research/experiments/aes_round_joint_causal_signature.py"
    spec=importlib.util.spec_from_file_location("aes_round_joint_causal_signature",path); assert spec and spec.loader
    module=importlib.util.module_from_spec(spec); sys.modules[spec.name]=module; spec.loader.exec_module(module)
    assert module._TRIGGER.search("x:class_r3-identity:source_byte_2:bin_1").group(1)=="r3-identity"
