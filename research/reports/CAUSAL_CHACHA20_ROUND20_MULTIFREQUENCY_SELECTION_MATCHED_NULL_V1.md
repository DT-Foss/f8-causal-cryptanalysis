# ChaCha20 R20 multi-frequency selection-matched null (A216N)

**Evidence stage:** `MULTIFREQUENCY_MODEL_SELECTION_EXPLAINED`

A216N is a post-discovery bias-control for A216. It repeats the complete four-representation by five-shrinkage optimizer independently for every group under each of 64 deterministic training-label permutations. Thus the null receives exactly the same validation-set model-selection opportunity as the observed statistic.

| Statistic | Observed | Null maximum | Add-one p | Beats all nulls |
|---|---:|---:|---:|---:|
| Macro | 0.07714844 | 0.08066406 | 0.10769231 | False |
| Group 0 | 0.07519531 | 0.09277344 | 0.46153846 | False |
| Group 1 | 0.08203125 | 0.08593750 | 0.10769231 | False |
| Group 2 | 0.07617188 | 0.08789062 | 0.33846154 | False |
| Group 3 | 0.08007812 | 0.08398438 | 0.15384615 | False |
| Group 4 | 0.07226562 | 0.08886719 | 0.69230769 | False |

The unpermuted optimized replay reproduces every A216 selected model, top-1/mean-rank metric, predicted-class hash, and true-rank hash exactly. No target output or target label is evaluated in A216N.

A216's public target rank remains 1,041,965 / 1,048,576 and therefore remains a standard-output rank boundary regardless of this validation-only selection-control outcome.

- Protocol SHA-256: `3f1d74666165432a4bebd9e559deb5dc619c573fa77c937fc3084efcb5e0f351`
- A216 result anchor: `f85eb6034123b4aa5cae6114e35565bb3e613800f4102f04ae631edbc6e380da`
- Measurement SHA-256: `32be62887fb637701d533e38c4931a233e840edc7d2ff0aa78cb117b3837cd71`
- Result measurement payload SHA-256: `65f3421cecf608bfe877c769c11269e8dd4535edb5bca63664a5062c6d8b3c60`
- Causal graph SHA-256: `9f91ea76425ae907e0a822b35b935f985fb6391dc937e611b2bef69376477f86`
