# A251 — ChaCha20-R20 exact learned-clause identity reader

This frozen experiment captures exact shallow-CDCL learned clauses from fresh candidate solvers, projects away all eight candidate-assumption variables, and evaluates a nested prefix-blind Product-of-Experts across five unseen prefix groups.

## Result

- Evidence stage: **FULLROUND_R20_EXACT_CLAUSE_IDENTITY_REPRESENTATION_BOUNDARY**
- Outer-holdout mean log2 rank: **6.681361104711**
- Uniform reference: **6.578110496970**
- Rank-information gain: **-0.103250607742 bits**
- Exact shared-XOR p: **0.492187500000**
- Prefix folds with positive gain: **1 / 5**
- Reverse-order exact identity: **True**
- Captured accepted clauses: **35081**

## Outer folds

| Prefix | Min support | Beta | Cap | Retained tokens | Mean log2 rank |
|---:|---:|---:|---:|---:|---:|
| 0 | 3 | 1.0 | 1.0 | 800 | 7.012929 |
| 1 | 4 | 2.0 | 2.0 | 574 | 7.422788 |
| 2 | 2 | 2.0 | 1.0 | 2141 | 6.857364 |
| 3 | 3 | 2.0 | 2.0 | 751 | 7.147388 |
| 4 | 4 | 0.5 | 2.0 | 342 | 4.966337 |

## Authentic AI-native Causal readback

- Reader integrity: **True**
- Explicit / inferred: **5 / 1**
- Next gap: **public_CNF_semantic_topology_and_graph_distance_reader**
