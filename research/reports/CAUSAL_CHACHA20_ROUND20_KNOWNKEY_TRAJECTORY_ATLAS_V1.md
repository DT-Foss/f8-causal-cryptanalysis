# ChaCha20 R20 Known-Key Solver-Trajectory Atlas (A218)

**Evidence stage:** `FULLROUND_R20_TRAJECTORY_REPRESENTATION_BOUNDARY_RETAINED`

A218 measures two retained CaDiCaL operators at a fixed 32-conflict horizon on 16 known full-round keys, selects every model choice on eight disjoint keys, repeats the complete selection under 64 whole-key null assignments, and freezes a 256-cell order for a newly committed target before opening its salted secret.

## Prospective target result

- True prefix rank: **211 / 256**
- True prefix: `01011000`
- Complete cell-order SHA-256: `6d645e4c19563655dc1a14cf48dd9faf6679cc7891d9a87ca9836f15f59d0661`
- All eight R20 blocks match: `True`
- Output bits independently checked: `4096`
- Flipped control rejected: `True`

## Selected transparent readout

- Feature family: `F5_all`
- Reader: `ridge_logistic`
- Ridge lambda: `0.01`
- Validation ranks: `[146, 190, 78, 117, 254, 197, 9, 174]`
- Validation mean log2 rank: `6.767381514`
- Selection-matched whole-key null p: `0.953846154`

## Information boundary

- Target commitment: `cc0b6e5f5c1fcd1c13ed7de31444d8dd34befd756bc53f3b96d2d0b284846d21`
- Prereveal SHA-256: `389fbfa38a8d93269e8a270ce69cf484f996c6364d2d3c6840d003627e5ee29e`
- The prereveal runner never opened the secret file or target label.
- The target order, selected model, complete validation grid, and all 64   selection-matched null grids were atomically written before reveal.

## Reproduction

```bash
PYTHONPATH=src .venv/bin/python research/experiments/chacha20_round20_trajectory_corpus.py
PYTHONPATH=src .venv/bin/python research/experiments/chacha20_round20_knownkey_trajectory_atlas.py
PYTHONPATH=src .venv/bin/python research/experiments/chacha20_round20_knownkey_trajectory_atlas_reveal.py
```

- Protocol SHA-256: `037b415e25e0956a2d8b13cd0bd62a838c50dce6b831ddc8734bd03ed2ec44c7`
- Measurement SHA-256: `6d5eaae124427eb8cbefe0ca8842d8e42b8b746c3cc2996747d0fd0de56c6901`
- Causal graph SHA-256: `31e32cf06d53cc7b2816d0f0432350901fb48d30f7ac052141e2603de088b417`
