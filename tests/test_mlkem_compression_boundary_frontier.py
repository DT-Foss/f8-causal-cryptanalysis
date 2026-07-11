def test_compression_boundary_module_imports() -> None:
    import importlib.util
    import sys
    from pathlib import Path
    path = Path(__file__).parents[1] / "research/experiments/mlkem_compression_boundary_frontier.py"
    spec = importlib.util.spec_from_file_location("mlkem_compression_boundary_frontier", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    assert module._compress(module.np.asarray([0, 3328]), 10).shape == (2,)
