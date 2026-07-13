# ChaCha20 R20 retained-state operator diversity (A217)

**Evidence stage:** `FULLROUND_R20_OPERATOR_DIVERSITY_MECHANISM_LOCALIZED`

Numeric and true reflected-Gray8 traverse the same complete 256-cell R20 CNF cover with the same solver build and budget. Both recover the same independently confirmed model and agree on every cell status. Their aggregate work is nearly identical, but their same-prefix telemetry is strongly path-dependent.

| Metric | Same-prefix Spearman | Kendall tau-b | Gray/Numeric total |
|---|---:|---:|---:|
| `decisions` | 0.084691 | 0.056340 | 0.999077 |
| `conflicts` | 0.092591 | 0.058927 | 0.985961 |
| `search_propagations` | 0.040094 | 0.027696 | 0.999488 |

- Cross-operator linear CKA: `0.043672083`
- 1,024-row-permutation upper-tail p: `0.002926829`
- Mean Numeric-to-Gray multivariate affine R2: `0.109817829`
- Position Kendall tau-b: `0.501960784`
- Consecutive Hamming distance Numeric / Gray8: `1.968627` / `1.000000`

The small but permutation-significant CKA component identifies shared formula structure, while the low CKA, low affine predictability, near-zero same-prefix rank correlations, and matching aggregate totals reject the scaled-copy model. Traversal order changes the learned-state path over the common substrate.

- Protocol SHA-256: `099455d5ecd7ae5a20817a065533a64162b90611ed9451e82f20c50e5603c5dc`
- Measurement SHA-256: `720d0abeccf99e7e62cbd9fc225b5574e95b211d3685f35250bc8464aaca6e7f`
- Causal graph SHA-256: `7f784465484f382ae79b2ac0edc03096dae03080f829052f1881f965b5364f0e`
