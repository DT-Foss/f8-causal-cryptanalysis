# Balanced BvN route causal controls v1

## Purpose

The sparse Birkhoff--von Neumann (BvN) construction is used here as a
*control design*, never as a modification of a cipher or PQC primitive. Each
route is a global bijection of sample indices, with identity and adjacent
cyclic alignments excluded. An intervention therefore retains the exact
multiset of analysed rows while removing precisely one relation:

- for F8, the true same-block `R -> R+1` pairing; or
- for CASI/F8-O, the row order in an already-public serialization.

The route ensemble is reproducible from its seed and verifies both bijectivity
and zero forbidden alignments. It is a stronger diagnostic than an arbitrary
shuffle because the null is explicitly balanced and its intervention is named.

This report interprets two retained artifacts:

- `../results/v1/bvn_route_causal_v2.json` -- corrected-cipher positive and
  negative controls;
- `../results/v1/pqc_bvn_route_controls_v1.json` -- real PQC public-output
  controls.

Neither artifact supplies key recovery, an internal-round PQC trace, or an
IND-CPA/IND-CCA statement.

## Calibration: paired dependence versus order

The v2 calibration uses five seeds, 5,000 blocks per seed and 64 routes per
seed. All route checks report a bijection and zero forbidden alignments.

| Measurement | Actual mean | BvN route-null mean | Aggregate two-sided route p | Reading |
|---|---:|---:|---:|---|
| Speck32/64 full round -> full round + 1 F8 | 0.1500 | 0.05442 | 0.00610 | The known-key cross-round F8 result survives a pairing-preserving-marginals control. |
| Simon32/64 full round -> full round + 1 F8 | 0.0250 | 0.04925 | 0.4792 | Clean negative control. |
| Speck32/64, round 2 CASI | 1928.79 | 34.59 | n/a (one ordered stream) | The operational CASI value is strongly dependent on row order in this setup. |

The CASI entry is deliberately not a significance claim: it is one ordered
stream and 64 route observations, not an independent-seed study. Its function
is diagnostic: an elevated score can be a serialization/order property even
when every byte row is held fixed. Future CASI claims should carry this
route-order control where row order is material.

## PQC public-output route controls

The PQC artifact uses real `pqcrypto==0.4.0` operations, fixed keys, three
independently seeded message streams, 128 operations per stream, a 1,200-row
analysis cap and 32 BvN routes per stream. Each KEM/signature stream passed its
functional decapsulation/verification gate. The route randomization test draws
one route per seed 20,000 times and compares the resulting mean to the
observed ordered mean.

| Target / statistic | Actual mean | Route-null mean | Two-sided route p | Bounded interpretation |
|---|---:|---:|---:|---|
| ML-KEM-512 CASI | 1.01381 | 1.00457 | 0.16229 | No route-order departure in the full rerun. |
| ML-KEM-512 F8-O | 0.05111 | 0.04842 | 0.49188 | No ordered-adjacent-output effect in the full rerun. |
| ML-DSA-44 CASI | 1.11847 | 1.73908 | 0.47398 | No route-order departure in the full rerun. |
| ML-DSA-44 F8-O | 0.04427 | 0.04966 | 0.22149 | No ordered-adjacent-output effect in the full rerun. |

An earlier pilot showed a small ML-KEM CASI route difference, but it did not
replicate in the complete fresh-backend rerun retained here. This is exactly
why a seed-explicit route gate belongs in the workflow: the bounded conclusion
is now that neither target showed a stable public-output order effect in this
design. The ML-DSA result neither refutes nor upgrades earlier output-only
CASI observations, because output length, random backend coins and sampling
protocol differ; it demonstrates why this control must accompany such
observations.

## Native ML-KEM representation trace: BvN re-pairing

The same construction is now in `mlkem_ntt_trace_suite.py`, applied to the
native PQClean `poly_decompress -> ntt` trace. It routes the NTT row of each
operation globally while retaining every NTT row exactly, so the only changed
relation is coefficient-to-NTT operation pairing. The refreshed retained
artifact `../results/v1/mlkem_ntt_trace_field.json` uses 1,000 operations and
16 BvN routes for each ML-KEM parameter set. Every one of the 3,000 KEM
roundtrips and 3,000 decompress/recompress checks passed; every route was
bijective with zero forbidden alignments.

| Variant | Byte F8 actual | Byte BvN-null mean | Field F8-Fq actual | Field BvN-null mean |
|---|---:|---:|---:|---:|
| ML-KEM-512 | 0.01611 | 0.01630 | 0.05859 | 0.05322 |
| ML-KEM-768 | 0.01489 | 0.01622 | 0.03516 | 0.04932 |
| ML-KEM-1024 | 0.01526 | 0.01655 | 0.05078 | 0.05225 |

The actual rates sit in the observed BvN route ranges for all six readings.
These are single trace runs with route controls, not independent replicate
studies, so the table intentionally gives no p-value. It strengthens the
bounded conclusion: the exposed decompression/NTT representation transition
does not provide a stable F8 mechanism under either byte or field framing.

## Workflow rule

For any new PQC experiment with a sequential byte-row statistic:

1. retain the actual ordered statistic;
2. run globally routed BvN bijections on the same retained rows;
3. record route validity, seeds, route count and both tail probabilities;
4. classify an effect as public ordering/serialization unless a source-matched
   internal representation trace establishes more.

The next high-value use is an instrumented, source-matched ML-KEM
`indcpa_enc` trace. At each source-level boundary (noise, NTT, reduction,
compression, packing), the same route control can distinguish a genuine
same-operation transition from a trace collection or serialization artifact.
