# A268 — Prospective ChaCha20-R20 trajectory-shape validation

A single A267 model and twenty disjoint key rows were frozen before any A268 target or solver measurement. Every new key then executed a complete 256-candidate fresh-state cover and was scored without refit.

## Result

- Evidence stage: **FULLROUND_R20_PROSPECTIVE_TRAJECTORY_SHAPE_BOUNDARY**
- Mean log2 rank: **6.209494578474**
- Uniform reference: **6.578110496970**
- Bit gain: **+0.368615918495**
- Positive prospective prefix groups: **3/5**
- Exact shared-XOR p: **0.207031250000**
- Frozen gate passed: **False**

## Authentic AI-native Causal readback

- Reader integrity: **True**
- Explicit / materialized: **3 / 1**
- Next gap: **local_pairwise_intervention_on_A268_without_model_refit**

All twenty solver shards were complete before finalization. The retained result uses the corrected terminal `_pNN` label parser; no solver shard was recomputed for this parser-only correction.
