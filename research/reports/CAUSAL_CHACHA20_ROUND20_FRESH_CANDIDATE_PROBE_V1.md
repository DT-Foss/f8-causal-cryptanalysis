# A242 — ChaCha20-R20 fresh-state candidate-prefix reader

Every one of the 256 eight-bit prefix candidates was applied to a fresh copy of the same unsolved full-round ChaCha20 CNF. The single development key selected cumulative search propagations after horizon 2; the score and direction were then frozen before twenty disjoint validation keys were executed.

## Primary result

- Evidence stage: **FULLROUND_R20_FRESH_PREFIX_SINGLE_CHANNEL_BOUNDARY**
- Validation keys: **20**
- Mean log2 rank: **6.996445542817**
- Uniform reference: **6.578110496970**
- Mean rank-information gain: **-0.418335045847 bits**
- Exact shared-XOR p-value: **0.894531250000**
- Best shared XOR offset: **76** (observed label offset is 0)

## Execution and controls

- Complete validation candidate cover: **5120**
- Fresh solver instances: **5120**
- Numeric/reverse nonvolatile identity: **True**
- Early stop: **False**

## Authentic AI-native Causal readback

- Reader integrity: **True**
- Explicit / inferred triplets: **5 / 1**
- Rules / clusters / gaps: **2 / 2 / 1**
- Next gap: **typed_multichannel_propagation_contradiction_reader**

## Per-key primary ranks

| Label | Prefix | Value | Midrank | log2 rank |
|---|---:|---:|---:|---:|
| `a220_select_p00_fit_s00` | 85 | 109973 | 130.0 | 7.022368 |
| `a220_select_p00_fit_s01` | 85 | 111205 | 108.0 | 6.754888 |
| `a220_select_p00_fit_s02` | 85 | 145548 | 248.0 | 7.954196 |
| `a220_select_p00_fit_s03` | 85 | 109977 | 130.0 | 7.022368 |
| `a220_select_p01_fit_s00` | 106 | 146692 | 36.0 | 5.169925 |
| `a220_select_p01_fit_s01` | 106 | 146729 | 85.0 | 6.409391 |
| `a220_select_p01_fit_s02` | 106 | 146715 | 41.0 | 5.357552 |
| `a220_select_p01_fit_s03` | 106 | 146086 | 59.0 | 5.882643 |
| `a220_select_p02_fit_s00` | 200 | 74086 | 239.0 | 7.900867 |
| `a220_select_p02_fit_s01` | 200 | 146684 | 153.0 | 7.257388 |
| `a220_select_p02_fit_s02` | 200 | 146675 | 135.0 | 7.076816 |
| `a220_select_p02_fit_s03` | 200 | 146914 | 152.0 | 7.247928 |
| `a220_select_p03_fit_s00` | 159 | 75348 | 160.0 | 7.321928 |
| `a220_select_p03_fit_s01` | 159 | 146297 | 189.0 | 7.562242 |
| `a220_select_p03_fit_s02` | 159 | 144928 | 247.0 | 7.948367 |
| `a220_select_p03_fit_s03` | 159 | 147535 | 41.0 | 5.357552 |
| `a220_select_p04_fit_s00` | 36 | 75378 | 199.0 | 7.636625 |
| `a220_select_p04_fit_s01` | 36 | 145975 | 187.0 | 7.546894 |
| `a220_select_p04_fit_s02` | 36 | 74913 | 204.0 | 7.672425 |
| `a220_select_p04_fit_s03` | 36 | 145729 | 227.0 | 7.826548 |
