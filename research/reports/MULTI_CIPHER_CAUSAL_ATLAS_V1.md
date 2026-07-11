# Multi-Cipher Causal Atlas V1

## Result in one sentence

A common 32-byte information heatmap finds reproducible output-layout
fingerprints at ChaCha prefixes R1--R2 and AES prefix R1, a reproducible
anti-fingerprint at AES prefix R2, and null behavior at ChaCha R3 and at all
tested full-round classical and PQC outputs.

## Measurement

For ordered 32-byte rows, the atlas computes

`M[i,j] = I(row_t[i] >> 5 ; (row_t[j] XOR row_t+1[j]) >> 5)`.

Two controls are retained separately:

1. `layout = M(observed) - mean(M(arbitrary row permutation))`;
2. `operation order = M(observed) - mean(M(whole-operation permutation))`.

ChaCha's two 32-byte halves remain one 64-byte operation in the second control.
For PQC, every complete row of a ciphertext or signature remains attached to
its operation. This prevents a within-serialization motif from being reported
as dependence between independent cryptographic operations.

The AES reduced-round path is a genuine prefix: MixColumns is retained in
rounds 1--9 and omitted only in round 10. The historical LiveCASI reduced-round
AES generator uses shortened-final-round semantics and is intentionally not
used for this atlas. Full AES-128 and ChaCha20 implementations pass the FIPS-197
and RFC-8439 vectors in `tests/test_atlas.py`.

## Broad atlas

The broad run used 4,000 rows, 5 seeds, 8 row/operation permutations and 999
similarity-null draws over 18 configurations:

- random bytes;
- ChaCha R1, R2, R3, R4 and R20;
- AES R1, R2, R3, R4 and R10;
- SIMON32/64 R8 and R32;
- Threefish-256 R72;
- ML-KEM-512/768, ML-DSA-44 and HQC-128 public outputs.

The full-round outputs and PQC outputs all remained at the random baseline in
this statistic. For example, mean layout excess was `-0.0000036` for ChaCha
R20, `+0.0000324` for AES R10, `+0.0000071` for SIMON R32, `+0.0000145` for
Threefish R72, and between `-0.0000332` and `+0.0000178` for the four PQC
targets. None had a stable paired row-order effect.

## Frontier confirmation

The focused confirmation used 10,000 rows, 10 seeds, 16 permutations and 4,999
similarity-null draws.

| target | mean observed MI | row-null MI | mean excess | strongest positive edge | paired two-sided p |
|---|---:|---:|---:|---:|---:|
| random bytes | 0.003531658 | 0.003537157 | -0.000005499 | 0.000753 | 0.261719 |
| ChaCha R1 | 0.009547458 | 0.013137618 | -0.003590160 | 0.906631 | 0.001953 |
| ChaCha R2 | 0.010015521 | 0.006859783 | +0.003155738 | 0.787118 | 0.001953 |
| ChaCha R3 | 0.003537146 | 0.003540282 | -0.000003136 | 0.000703 | 0.664063 |
| AES R1 | 0.021416557 | 0.003493302 | +0.017923254 | 0.372185 | 0.001953 |
| AES R2 | 0.002619843 | 0.003528156 | -0.000908313 | 0.000495 | 0.001953 |

All three positive early-round fingerprints also survive whole-operation
permutation at `p=0.001953`. ChaCha R3 is indistinguishable from random bytes.

AES R2 is a distinct negative result rather than an ordinary null: 992 of its
1,024 mean fingerprint edges lie below the row-permutation expectation, with a
minimum edge of `-0.00197436`. The sequential counter traversal produces a more
uniform quantized transition table than arbitrary reordering. This direction
reversal is reproducible across all ten seeds.

## Cross-configuration overlay

Similarity is the cosine between mean layout fingerprints. Its null samples
independent residual heatmaps from the retained row permutations; all 15 pair
tests in the focused run are BH-corrected.

| pair | cosine | null p | BH q |
|---|---:|---:|---:|
| ChaCha R1 / ChaCha R2 | +0.440503 | 0.0002 | 0.0010 |
| ChaCha R1 / AES R1 | +0.333169 | 0.0002 | 0.0010 |
| AES R1 / AES R2 | -0.293760 | 0.0002 | 0.0010 |
| ChaCha R2 / AES R1 | +0.105479 | 0.0162 | 0.0492 |
| ChaCha R2 / AES R2 | -0.075726 | 0.0164 | 0.0492 |

The ChaCha/AES R1 overlap is concentrated at the byte positions activated by
the common counter traversal and 32-byte packing. It is a measured shared
output motif and a concrete target for intervention; it is not evidence that
the ARX and SPN round functions share an internal cause.

## Next mechanism tests implied by the atlas

1. Replace the counter input independently with Gray-code, random-permutation,
   affine and sparse-bit traversals while holding key and round function fixed.
2. Split ChaCha's within-block half transition from its between-block transition
   and intervene on feed-forward addition.
3. Align AES heatmaps by state coordinates before and after ShiftRows and
   MixColumns to test whether the AES R2 anti-fingerprint follows diffusion or
   input enumeration.
4. Apply the paper's conditional code and carry-ablation machinery only to the
   surviving cells, rather than averaging 1,024 mostly-null edges.
5. For PQC, retain operation boundaries and move to exposed internal
   transitions; the public-output atlas establishes the correct null baseline.

## Reproduction and artifacts

Run `./scripts/reproduce_multi_cipher_atlas.sh`. Authoritative outputs are:

- `results/v1/multi_cipher_causal_atlas_v1.json` and `.causal`;
- `results/v1/multi_cipher_frontier_confirm_v1.json` and `.causal`;
- both fingerprint and similarity PNGs;
- `results/v1/ATLAS_SHA256SUMS`.

PQC bytes use backend/OS cryptographic randomness, so their replay class is
statistical. Classical target bytes and all permutation routes are exactly
seeded.
