# A232 — Tie-aware A231 readback

A231's raw H8/H16 measurements are valid. Its original scalar ranking is superseded because competition rank treated large ties as rank one.

- Best tie-aware reader: `one_shot_h16_wd30.h16.cumulative_search_propagations.asc`
- Ranks: `[64, 4, 136, 188, 38, 17, 37]`
- Top-64 hits: **5 / 7**
- Median rank: **38**
- Leave-one-key-out ranks: `[64, 4, 136, 188, 38, 17, 188]`

This reader is posthoc calibration and must be frozen on fresh challenges before a recovery claim.
