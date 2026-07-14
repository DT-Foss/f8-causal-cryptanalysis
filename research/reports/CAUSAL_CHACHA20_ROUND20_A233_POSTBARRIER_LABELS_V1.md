# A234 — A233 post-barrier labels

A233 completed all seven prospective top-64 searches before this artifact recovered any missing W32 label.

| Challenge | Word 0 | True prefix | Frozen H16 rank | Selected |
|---:|---:|---:|---:|---:|
| 0 | `0xdc5d709a` | `11011100` | 193 | False |
| 1 | `0xe5831b6d` | `11100101` | 217 | False |
| 2 | `0xd4c8aa4b` | `11010100` | 140 | False |
| 3 | `0xbc11d30f` | `10111100` | 213 | False |
| 4 | `0x3034b310` | `00110000` | 171 | False |
| 5 | `0xc9cce7eb` | `11001001` | 173 | False |
| 6 | `0x89b7e8da` | `10001001` | 10 | True |

## Descriptive scalar readback

These rows are post-barrier diagnostics, not prospectively frozen readers.

| Reader | Ranks | Median | Top-64 hits |
|---|---|---:|---:|
| `one_shot_h16_wd30.h16.cumulative_decisions.desc` | 31, 16, 243, 178, 79, 53, 196 | 79 | 3/7 |
| `one_shot_h16_wd30.h16.stage_decisions.desc` | 31, 16, 243, 178, 79, 53, 196 | 79 | 3/7 |
| `one_shot_h16_wd30.h16.cumulative_search_propagations.desc` | 64, 40, 117, 44, 86, 84, 247 | 84 | 3/7 |
| `one_shot_h16_wd30.h16.stage_search_propagations.desc` | 64, 40, 117, 44, 86, 84, 247 | 84 | 3/7 |
| `one_shot_h16_wd30.h16.redundant_clauses_cumulative_delta.asc` | 187, 108, 53, 49, 130, 180, 212 | 130 | 2/7 |
| `one_shot_h16_wd30.h16.redundant_clauses_stage_delta.asc` | 187, 108, 53, 49, 130, 180, 212 | 130 | 2/7 |
| `one_shot_h16_wd30.h16.elapsed_seconds.asc` | 124, 137, 43, 220, 185, 124, 44 | 124 | 2/7 |
| `one_shot_h16_wd30.h16.cumulative_decisions.asc` | 226, 241, 16, 79, 178, 204, 61 | 178 | 2/7 |
| `one_shot_h16_wd30.h16.stage_decisions.asc` | 226, 241, 16, 79, 178, 204, 61 | 178 | 2/7 |
| `one_shot_h16_wd30.h16.elapsed_seconds.desc` | 133, 120, 214, 37, 72, 133, 213 | 133 | 1/7 |
| `one_shot_h16_wd30.h16.cumulative_search_propagations.asc` | 193, 217, 140, 213, 171, 173, 10 | 173 | 1/7 |
| `one_shot_h16_wd30.h16.stage_search_propagations.asc` | 193, 217, 140, 213, 171, 173, 10 | 173 | 1/7 |

The frozen A233 reader recovered 1/7 and therefore did not establish a transferable fourfold candidate-domain reduction. The labels above convert every miss into a complete H16 training and diagnosis row.
