# A224 — A223-W32 Metal label and trajectory readout

## Outcome

- Recovered key word 0: `0x901c330a`
- True A223 prefix: `10010000`
- Full Metal domain executed: `4294967296` candidates
- Independent confirmation: `4096` output bits across eight blocks
- Best true-cell rank among the fixed trajectory views: **4 / 256**

## Fixed trajectory readout

| View | Direction | True-cell rank | Target value |
|---|---:|---:|---:|
| `conflicts` | ascending | 4 / 256 | 84 |
| `decisions` | ascending | 4 / 256 | 100 |
| `search_propagations` | descending | 252 / 256 | 17818625 |
| `propagations_per_decision` | descending | 226 / 256 | 178186.25 |
| `propagations_per_conflict` | descending | 173 / 256 | 212126.488 |
| `conflicts_per_decision` | ascending | 27 / 256 | 0.84 |
| `constraint_coherence` | descending | 4 / 256 | 7.6379831 |
| `coherence_local_residual` | descending | 8 / 256 | 0.538620982 |

The label was unavailable in A223 and was reconstructed only by the complete Metal W32 pass. The trajectory observations themselves are unchanged from A223.
