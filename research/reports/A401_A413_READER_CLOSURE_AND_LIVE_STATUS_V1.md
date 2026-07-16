# A401--A413 Reader closure and live status

This ledger is the current closure for the W50 known-key Reader branch and supersedes the freeze-time state phrases in the append-only attempt table.

| Attempt | Current evidence | Exact retained result |
|---|---|---|
| A401 | `COMPLETE_W50_KNOWNKEY_DIRECT12_TRAIN_ONLY_SELECTION_AND_EIGHT_TARGET_HOLDOUT_RETAINED` | The fixed 8/8 split did not transfer: selected holdout geometric mean rank `1527.5218` versus best baseline `1365.5972`, factor `0.893995234`, additional gain `-0.161660954` bit. Result SHA `347b3756...e702`. |
| A402 | `A401_HELDOUT_QUALIFICATION_BOUNDARY_RETAINED_NO_PRODUCTION_RECOVERY_QUEUED` | A401's predeclared gate closed exactly; no production order and no recovery execution were emitted. Result SHA `67e8cdbb...8a95`. |
| A404 | `SIXTEEN_FOLD_OUTOFFOLD_QUALIFIED_FULLFIT_READER_APPLIED_TO_A388` | Genuine 16-fold LOO improved geometric mean rank from `1627.8449` to `1406.4291`, factor `1.157431`, gain `+0.210926471` bit; fullfit Reader is views `[0,3,7]` under `minimum_rank_then_sum`. Result SHA `ded81a43...80e1`; production-order SHA `578c8a...3351`. |
| A405 | Executable protocol frozen and queued | A404's distinct production order is bound for complete W50 recovery. Protocol file SHA `eb90aa1a...c8e2`; protocol commitment `59190483...0582`; execution enabled. |
| A406 | `WEIGHTED_OUTOFFOLD_BOUNDARY_RETAINED_AGAINST_COMPLETE_765_BASELINE` | The 36,969-member weighted family reaches geometric mean rank `1617.8361` versus the complete 765-Reader baseline `1406.4291`, factor `0.869327`, gain `-0.202028712` bit. Result SHA `d4734225...8c7`. |
| A407 | Conditional gate closed | A406 did not pass its predeclared transfer gate, so no weighted production recovery was emitted. |
| A408 | `NESTED_FISHER_OUTOFFOLD_BOUNDARY_RETAINED_AGAINST_A406` | Nested Fisher reaches geometric mean rank `2446.0379`, factor `0.661410905` and `-0.596381264` bit versus A406. Result SHA `61c1a328...f32`. |
| A409 | Conditional gate closed | A408 did not pass its predeclared nested gate, so no Fisher production recovery was emitted. |
| A410 | `NESTED_PROTOTYPE_OUTOFFOLD_BEATS_A408_AND_APPLIES_ZERO_REFIT_TO_A388` | Nonlinear prototype geometry improves over A408 by factor `1.601551345` and `+0.679470051` bit, winning 10/16 folds. The fixed model is `log_absdiff36` + mean-squared L2 + all prototypes. Result SHA `d631fcc5...284e`; production-order SHA `c878c53d...52ef`. |
| A411 | Executable protocol frozen and queued | A410's distinct production order is bound for complete W50 recovery. Protocol file SHA `94f24bdc...05f`; protocol commitment `d9d42391...d85`; execution enabled. |
| A412 | Frozen and measuring | A404/A410 hybrid selection uses 16 entirely fresh fields followed by a separate 16-field holdout: 32 fields, 131,072 complete cells and 524,288 solver stages. Implementation SHA `f08665ec...7067`; public-corpus SHA `f7859b38...65a2`; zero measurement labels and zero production labels/refits. |
| A413 | Design and implementation preflight | A 155-member density/location-shape family was frozen conceptually before the first A412 field completed. A genuine resumable nested A401 selection fixes one model before any A412 label or score; all 32 A412 fields then become an external zero-refit panel. Design SHA `3dcf61da...5f7a`. |

The eight live Metal recoveries remain untouched. The held slot queue launches A397 Direct12, then A405, then A411 as capacity becomes available.
