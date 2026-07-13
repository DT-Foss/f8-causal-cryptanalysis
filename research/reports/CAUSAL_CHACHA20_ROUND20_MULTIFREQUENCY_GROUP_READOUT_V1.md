# ChaCha20 R20 multi-frequency group readout (A216)

**Evidence stage:** `GROUP_SPECIFIC_MULTIFREQUENCY_TRANSFER`

A216 transfers O1's multi-frequency write into five complete Z16 Fourier character banks, one for each four-bit group. Model selection and 64 phase-label nulls use only 1,024 disjoint known-key holdouts; the standard eight-block R20 target is scored after the prereveal is written.

| Group | Representation | Shrinkage | Validation top-1 | Mean rank |
|---:|---|---:|---:|---:|
| 0 | `per_block_byte_histograms` | 0.90 | 0.075195 | 8.5596 |
| 1 | `per_block_byte_histograms` | 0.00 | 0.082031 | 8.2529 |
| 2 | `adjacent_block_xor_bits_pm1` | 0.50 | 0.076172 | 8.6494 |
| 3 | `per_block_byte_histograms` | 0.75 | 0.080078 | 8.1934 |
| 4 | `per_block_bit_rfft_magnitudes` | 0.75 | 0.072266 | 8.6162 |

- Validation macro top-1: `0.077148`
- Maximum of 64 label-null macros: `0.067969`
- Beats all label nulls: `True`
- Public R20 target rank: `1,041,965` / 1,048,576
- Postseal target: `0xe4934`

The complete 16-harmonic bank is an exact coordinate transform of the class prototypes; it is not counted as 16 independent observations. The experiment tests whether those target-blind class means transfer, not whether Fourier notation alone creates information.

- Protocol SHA-256: `ea006add56f38767892bd2981db1829d546c535af305e3281c92a1ac67f7e803`
- Prereveal SHA-256: `f0eee4aecb4f691ebb05fc03515b4b27e88d594d70d3eb1b269ea6d9a8fadb99`
- Measurement SHA-256: `aa931bca62098372f0dd56655e43cbd2380127c50eaa75256006e72c4fe32b85`
- Causal graph SHA-256: `1cd390513ab537b4dd3b64ea97c2c1488e4557c47b620a8d628de26ed81bd9a2`
