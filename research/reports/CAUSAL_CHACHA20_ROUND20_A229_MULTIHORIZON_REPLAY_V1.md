# A231 — A229 multi-horizon replay (scalar ranking superseded)

The raw H8/H16 measurements in A231 remain valid. The scalar ranks below used
competition ranking and therefore treated large constant-value ties as rank
one. Use the tie-aware deterministic readback in
`CAUSAL_CHACHA20_ROUND20_A231_TIEAWARE_READ_V1.md` instead.

- Leave-one-key-out top-64 hits: **6 / 7**
- Leave-one-key-out ranks: `[1, 1, 252, 1, 1, 1, 1]`

## Globally strongest scalar readers (descriptive)

| Reader | Ranks | Top-64 | Median | Worst |
|---|---|---:|---:|---:|
| `one_shot_h8.h8.active_variables_cumulative_delta.desc` | [1, 1, 1, 1, 1, 1, 1] | 7/7 | 1 | 1 |
| `one_shot_h8.h8.active_variables_stage_delta.desc` | [1, 1, 1, 1, 1, 1, 1] | 7/7 | 1 | 1 |
| `one_shot_h8.h8.irredundant_clauses_cumulative_delta.desc` | [1, 1, 1, 1, 1, 1, 1] | 7/7 | 1 | 1 |
| `one_shot_h8.h8.irredundant_clauses_stage_delta.desc` | [1, 1, 1, 1, 1, 1, 1] | 7/7 | 1 | 1 |
| `one_shot_h16_wd30.h16.irredundant_clauses_cumulative_delta.desc` | [1, 2, 1, 2, 1, 2, 2] | 7/7 | 2 | 2 |
| `one_shot_h16_wd30.h16.irredundant_clauses_stage_delta.desc` | [1, 2, 1, 2, 1, 2, 2] | 7/7 | 2 | 2 |
| `one_shot_h16_wd30.h16.active_variables_cumulative_delta.desc` | [2, 2, 2, 2, 2, 2, 2] | 7/7 | 2 | 2 |
| `one_shot_h16_wd30.h16.active_variables_stage_delta.desc` | [2, 2, 2, 2, 2, 2, 2] | 7/7 | 2 | 2 |
| `one_shot_h8.h8.active_variables_cumulative_delta.asc` | [2, 2, 2, 2, 2, 2, 2] | 7/7 | 2 | 2 |
| `one_shot_h8.h8.active_variables_stage_delta.asc` | [2, 2, 2, 2, 2, 2, 2] | 7/7 | 2 | 2 |
| `one_shot_h8.h8.irredundant_clauses_cumulative_delta.asc` | [2, 2, 2, 2, 2, 2, 2] | 7/7 | 2 | 2 |
| `one_shot_h8.h8.irredundant_clauses_stage_delta.asc` | [2, 2, 2, 2, 2, 2, 2] | 7/7 | 2 | 2 |
| `one_shot_h16_wd30.h16.active_variables_cumulative_delta.asc` | [3, 3, 3, 3, 3, 3, 3] | 7/7 | 3 | 3 |
| `one_shot_h16_wd30.h16.active_variables_stage_delta.asc` | [3, 3, 3, 3, 3, 3, 3] | 7/7 | 3 | 3 |
| `one_shot_h16_wd30.h16.irredundant_clauses_cumulative_delta.asc` | [4, 3, 4, 3, 4, 3, 3] | 7/7 | 3 | 4 |
| `one_shot_h16_wd30.h16.irredundant_clauses_stage_delta.asc` | [4, 3, 4, 3, 4, 3, 3] | 7/7 | 3 | 4 |
