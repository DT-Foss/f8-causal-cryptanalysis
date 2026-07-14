# A250 — ChaCha20-R20 nonlinear fresh-state Product-of-Experts

A frozen diagonal-Gaussian Product-of-Experts tests whether the typed A249 trajectory signal is band-shaped rather than linearly separable. Every outer prefix is absent from both model fitting and hyperparameter selection.

## Result

- Evidence stage: **FULLROUND_R20_FRESH_NONLINEAR_POE_BOUNDARY**
- Outer-holdout mean log2 rank: **6.486609685517**
- Uniform reference: **6.578110496970**
- Rank-information gain: **0.091500811452 bits**
- Exact shared-XOR p: **0.375000000000**
- Prefix folds with positive gain: **4 / 5**
- Best shared XOR offset: **80**

## Outer folds

| Prefix | Shrinkage | Cap | Mean log2 rank | Model SHA-256 |
|---:|---:|---:|---:|---|
| 0 | 0.9 | 0.25 | 5.981814 | `2af7d1515cd57cd985d0c00c0222382ad7052abdc67b24a891d731a87490d0e3` |
| 1 | 0.9 | 2.0 | 7.613432 | `a20db4f6198b10505b5f1802e2798c4abda98a373e1eff9a721aa4ea6810e283` |
| 2 | 0.9 | 0.5 | 6.075754 | `14d8d399b6077b4e40a5355f4d8eee2d7bce51761e3a03d27fe1f7cc620e3e5e` |
| 3 | 0.9 | 2.0 | 6.299820 | `c71f6a86ab5d0cf2392e71facdc30c5238d41b86a071d9cbb10d70501c19b3cb` |
| 4 | 0.9 | 0.25 | 6.462229 | `7486b77af61722040f05f1db53567d4b35132a0f1b93711b09a1cf9976a3e634` |

## Authentic AI-native Causal readback

- Reader integrity: **True**
- Explicit / inferred: **4 / 1**
- Next gap: **exact_propagated_variable_and_clause_identity_reader**
