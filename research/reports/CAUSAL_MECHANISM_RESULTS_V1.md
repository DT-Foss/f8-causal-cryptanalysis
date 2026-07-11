# Causal mechanism results v1

## Outcome

Four controlled experiment families now separate observed association,
representation effects and operation-level mechanisms. The central results are:

1. full-round Speck F8 is causally mediated by modular-addition carry across
   every official Speck block/key-size variant in the repository;
2. full-round Threefish F8 is not carry-mediated: its dominant mechanism is an
   affine neighboring-word reuse identity in the MIX layer;
3. the ML-KEM compression-isolation signal attributed to LWE noise is explained
   by the public unequal-preimage occupancy of `Compress_d`; and
4. ordinary one- and two-stage lossless compressors do not reveal structure in
   raw full-round cipher output, while an explicitly conditioned code does
   recover the F8 dependence as code-length gain.

These are mechanism and measurement results. They do not constitute key
recovery, plaintext recovery, an IND-CPA/IND-CCA result, or a break of ML-KEM.

## 1. Speck: direct carry intervention

For a Speck state `(x,y)` and next-round key `k`, the factual transition is

```text
a       = ROR_alpha(x)
x'      = (a + y) XOR k
y'      = ROL_beta(y) XOR x'
```

The intervention fixes `(x,y,k,alpha,beta)` and changes only addition carry:

```text
x_cf    = (a XOR y) XOR k
y_cf    = ROL_beta(y) XOR x_cf
```

For every tested row, the following identity was checked exactly:

```text
factual_next XOR carry_free_next = ((a + y) XOR (a XOR y)) repeated in both words.
```

Paper-scale parameters are 20,000 blocks, ten independent deterministic keys,
the final eight transitions and 16 balanced BvN routes per transition. All
transition reconstructions and all carry identities passed.

| Variant | Factual F8 | BvN null | `do(carry=0)` | Factual−CF | BvN p | Carry-ablation p |
|---|---:|---:|---:|---:|---:|---:|
| Speck32/64 | 0.16641 | 0.05120 | 0.05000 | 0.11641 | 0.00010 | 0.001953 |
| Speck48/72 | 0.13368 | 0.04873 | 0.04306 | 0.09063 | 0.00010 | 0.001953 |
| Speck48/96 | 0.13403 | 0.04998 | 0.04757 | 0.08646 | 0.00010 | 0.001953 |
| Speck64/96 | 0.11074 | 0.05035 | 0.04473 | 0.06602 | 0.00010 | 0.001953 |
| Speck64/128 | 0.11016 | 0.04910 | 0.05078 | 0.05938 | 0.00010 | 0.001953 |
| Speck96/96 | 0.08924 | 0.05015 | 0.05139 | 0.03785 | 0.00010 | 0.001953 |
| Speck96/144 | 0.08776 | 0.05020 | 0.04931 | 0.03845 | 0.00010 | 0.001953 |
| Speck128/128 | 0.07896 | 0.04936 | 0.04941 | 0.02954 | 0.00010 | 0.001953 |
| Speck128/192 | 0.07896 | 0.04980 | 0.04741 | 0.03154 | 0.00010 | 0.001953 |
| Speck128/256 | 0.07803 | 0.04983 | 0.05054 | 0.02749 | 0.00010 | 0.001953 |

The counterfactual reaches the nominal/BvN null for every variant. This is the
first retained result in this repository that attributes the Speck F8 signal to
one round-function mechanism rather than only showing that true pairing matters.

SIMON32/64, which contains no modular addition, remains a clean negative control:
factual rate `0.04688`, BvN `0.04973`, two-sided `p=0.6871`.

Raw evidence:
`../results/v1/causal_carry_intervention_paper_scale.json`.

## 2. Threefish: affine state reuse, not carry

Threefish remains above the BvN pairing null (`0.06445` versus `0.04975`,
`p=0.00010`), but replacing all additions in the tested round transition with
XOR does not reduce the statistic (`0.06547`, paired `p=0.4277`).

The carry-free MIX exposes the actual mechanism. For lanes 0 and 2, including
subkey-injection rounds, the suite verifies on every row:

```text
Delta_word0 = old_word1 XOR fixed_round_constant0
Delta_word2 = old_word3 XOR fixed_round_constant2
```

Without an injection the constants are zero. Modular addition adds carry noise
to these affine neighbor identities; it does not create them. This explains why
carry ablation slightly increases, rather than removes, the information signal.

The result changes the correct interpretation of the Threefish finding: it is a
paired one-round state-reuse distinguisher induced by the MIX topology, not a
carry-specific leak.

## 3. ML-KEM: corrected compression cause

The previous A/B/C/D design used this control for Stream C:

```text
Y <- Uniform({0,...,2^d-1}).
```

That is not the counterfactual corresponding to a uniform pre-compression field
element. The correct control is

```text
X <- Uniform(Z_q);  Y = Compress_d(X),  q=3329.
```

Let `m=2^d`, `a=floor(q/m)` and `r=q mod m`. Exactly `r` compressed symbols
have `a+1` preimages and `m-r` have `a` preimages. Therefore the theoretical
total-variation distance from a uniform output alphabet is

```text
TV(Compress_d(U(Z_q)), U({0,...,m-1})) = r(m-r)/(m q).
```

| Width | Preimage occupancy | Theoretical TV | Real observed TV | Mean reduced chi-square vs corrected model |
|---|---|---:|---:|---:|
| `d=10`, ML-KEM-512 | 257 symbols ×4; 767 ×3 | 0.057825 | 0.06000 | 1.0032 |
| `d=10`, ML-KEM-768 | 257 symbols ×4; 767 ×3 | 0.057825 | 0.05887 | 0.9979 |
| `d=11`, ML-KEM-1024 | 1281 symbols ×2; 767 ×1 | 0.144112 | 0.14436 | 1.0031 |

The real compressed coefficients fit the corrected uniform-field quantizer model
with mean goodness-of-fit p-values `0.439`, `0.503` and `0.467`. The matched
synthetic control produces the same fit.

The original-output CASI values also fail to separate from the corrected
uniform-field-through-`Compress_d` arm:

| Variant | Real CASI | Corrected control CASI | Paired p | Real F8-O | Control F8-O | Paired p |
|---|---:|---:|---:|---:|---:|---:|
| ML-KEM-512 | 1.1215 | 1.1181 | 0.9648 | 0.05186 | 0.05059 | 0.6953 |
| ML-KEM-768 | 1.4675 | 1.2949 | 0.4883 | 0.04971 | 0.04932 | 0.9277 |
| ML-KEM-1024 | 1.2008 | 1.1115 | 0.2930 | 0.05078 | 0.04863 | 0.4375 |

Standard, bit-plane and globally routed coefficient serializations preserve the
same compressed values, bit count and byte length exactly. None produces a
replicated CASI/F8-O difference. Thus the retained evidence supports public
quantizer occupancy, not an LWE-noise-specific output signature.

Raw evidence:
`../results/v1/mlkem_causal_serialization_v2.json`.

## 4. Real compressor cascades

The full-round output of all twelve F8 targets was processed through six
representative lossless compressor families:

- DEFLATE/zlib;
- BWT/bzip2;
- LZMA;
- Zstandard;
- LZ4; and
- Brotli.

All 36 ordered two-stage paths were tested, including repeated algorithms, with
ten seeds and a length-matched random control. All 5,040 paired paths (10,080
individual target/control stream roundtrips) were lossless. After paired tests and Benjamini-Hochberg correction,
no target had an emergent stage-two path. Differences were at header/block
overhead scale (typically below `3e-4` of input length) and every cascade q-value
was non-significant.

This closes the direct hypothesis: generic lossless compression, including
double compression in either order, does not surface the cross-round structure
from a single full-round ciphertext stream.

Raw evidence:
`../results/v1/compression_cascade_causal_v1.json`.

## 5. Causal conditional code-length distinguisher

Generic compressors do not know the F8 conditioning variables. Once the source
and delta formula is supplied, dependence has an exact compression meaning:

```text
G_ij = H(Delta_j) - H(Delta_j | X_i) = I(X_i; Delta_j).
```

`G_ij` is the ideal number of bits saved per quantized delta symbol by coding
with the correctly paired source byte. BvN re-pairing supplies the finite-sample
null.

Across all ten Speck variants, factual gain exceeds BvN with `p=0.001953` and
`do(carry=0)` collapses it to BvN with the same paired p-value. Speck32/64 gives:

```text
factual mean gain = 0.0152945 bit/symbol
BvN mean gain     = 0.0035464 bit/symbol
carry-free gain   = 0.0035807 bit/symbol
```

SIMON is null (`0.0034607` versus BvN `0.0035323`, `p=0.1895`).

Threefish gives:

```text
factual mean gain       = 0.0191343 bit/symbol
BvN mean gain           = 0.0035420 bit/symbol
carry-free mean gain    = 0.0503529 bit/symbol
factual max-edge gain   = 1.01269 bit/symbol
carry-free max-edge gain= 2.99985 bit/symbol
```

The approximately three-bit maximum is the complete entropy of an eight-bin
quantized neighbor word, exactly as predicted by the affine identity. This
provides an information-theoretic explanation of both cipher families with one
formula: carries create the conditionable code gain in Speck, while carries mask
an underlying affine code gain in Threefish.

Raw evidence:
`../results/v1/causal_information_compression_v1.json`.

## Causal graph artifacts

Every experiment additionally emits a typed `.causal` graph. The custom reader
verifies canonical-graph SHA-256 and source-edge provenance. No fuzzy inference
is enabled. The format and implementation audit is in
`../CAUSAL_FORMAT_AUDIT.md`.
