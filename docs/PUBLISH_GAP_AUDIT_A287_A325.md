# Publication gap audit: A287--A325

This audit compares the active research ledger and artifacts against the
previous public repository head `ee7be6f994eb829d6112a574e76bad2d92bf266c`.
It is the release-selection record for version 0.5.0.

## Confirmed recovery records added

| Record | Published state | Result object |
|---|---|---|
| CHACHA20KR43 | Complete `2^43` residual domain executed; unique factual model; empty matched control; 8,192 independently recomputed output bits | `research/results/v1/chacha20_round20_w43_metal_record_v1.json` |
| A294 | W24 strict-subset recovery at rank 202/4,096; 827,392/16,777,216 assignments upper bound | `research/results/v1/chacha20_round20_w24_causal_ordered_metal_a294_v1.json` |
| A295 | Independent frozen order on the A294 target; W24 strict-subset recovery at rank 2,605/4,096 | `research/results/v1/chacha20_round20_w24_fine_selected_channel_a295_v1.json` |
| A296 | Eight confirmed strict-subset recoveries: four W24 and four zero-refit W28 transfers | `research/results/v1/chacha20_round20_causal_search_gain_panel_a296_v1.json` |
| A297 | Four confirmed zero-refit W32 strict-subset recoveries | `research/results/v1/chacha20_round20_w32_causal_search_gain_panel_a297_v1.json` |
| A303 | W32 calibrated strict-subset recovery at rank 3,801/4,096 | `research/results/v1/chacha20_round20_w32_dominance_pruned_companion_a303_v1.json` |
| A302/A304 | A302 frozen order executed by the independently qualified A304 grouped engine; W43 strict-subset recovery at rank 2,473/4,096 | `research/results/v1/chacha20_round20_w43_grouped_engine_a304_v1.json` |
| A305 | W43 A299-order replay through the grouped engine; strict-subset recovery at rank 2,114/4,096 | `research/results/v1/chacha20_round20_w43_a299_grouped_replay_a305_v1.json` |
| A309 | W43 width-conditioned portfolio; strict-subset recovery at rank 4,044/4,096 | `research/results/v1/chacha20_round20_w43_width_conditioned_band_portfolio_a309_v1.json` |
| A313 | W44 width-conditioned/Fine/baseline portfolio; strict-subset recovery at rank 2,753/4,096 after exactly 11,824,044,965,888 of `2^44` assignments | `research/results/v1/chacha20_round20_w44_width_conditioned_fine_portfolio_a313_v1.json` |

The release therefore adds one complete-domain record and 19 confirmed
strict-subset executions. Together with the preceding public batches, the
archive contains 13 complete-domain residual-key recoveries and 24
strict-subset executions across 23 distinct targets.

## Completed non-recovery records added

- A287--A293 retain exact global, cross-solver, partition, reverse, model-free
  ordering, and refined-budget boundaries leading to A294/A295.
- A298--A301 retain the W32/W43 model-free fields and frozen operator orders.
- A304, A307, A311, and A324 retain exact target-free grouped-engine
  qualification at W43, W44, W45, and W46.
- A308, A310, and A312 retain complete target-blind orders and the exact
  post-confirmation rank-only counterfactual.
- A314 retains only its complete model-free W45 order and authentic Causal
  artifact. It is not published as a recovery.
- A315, A317, and A319 retain their completed post-confirmation rank-only
  evaluations; A316, A318, and A320 retain target-blind W45 order commitments.
- A321 retains the completed independent-holdout operator selection and exact
  W45 deployment order.
- A323 retains the completed target-blind cross-width operator-stability audit
  and its authentic Causal graph.

## Frozen designs without outcome claims

- A322: the W45 execution protocol is published; the live production outcome
  and progress state are excluded.
- A325: the W46 execution protocol was frozen before A322 produced an outcome;
  no W46 production result is published.

## Deliberate exclusions

- A306 has no completed result row or confirmed result artifact.
- A322 remains live and A325 has no production outcome; neither is claimed.
- Checkpoints, local builds, raw solver traces, generated CNF files, and active
  execution state are excluded. Their frozen hashes and generating sources
  remain in the portable records where applicable.

The automated publication gate enforces the required confirmed records and the
absence of A322/A325 outcome files.
