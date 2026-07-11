# PRESENT-128 Full-Round Causal F8 Transfer v1

## Result

PRESENT-128 is the thirteenth retained full-round F8 configuration in this
workspace.  The measured object is the known-key cross-round boundary
`E_31(P,K) -> E_32(P,K)` on matched plaintexts.  The transfer from PRESENT-80
was predicted before measurement: changing the key schedule from 80 to 128
bits should leave the S-box/pLayer mechanism intact.

The prediction survived five fresh confirmation keys.  Every factual score was
above every matched BvN repair route:

| confirmation key | factual MI | maximum BvN MI | Z |
|---:|---:|---:|---:|
| 0 | 0.556552 | 0.002867 | 749.68 |
| 1 | 0.533881 | 0.002089 | 1267.42 |
| 2 | 0.561067 | 0.002809 | 832.08 |
| 3 | 0.554793 | 0.002469 | 945.86 |
| 4 | 0.525482 | 0.002227 | 1390.45 |

## Measurement protocol

1. Gate the implementation with the official PRESENT-128 zero-key,
   zero-plaintext vector `96db702a2e6900af`.
2. On three discovery keys and 2,000 matched plaintexts per key, compute the
   complete 64x64 MI grid between `E_31` bits and `E_31 xor E_32` bits.
3. Score every cell against twelve shared, bijective BvN row-repair routes.
4. Serialize the top sixteen discovery cells into `.causal`.
5. Re-open the file with `CryptoCausalReader`; reconstruct the fixed cells from
   the Reader only.
6. Confirm those cells on five unseen keys, 5,000 fresh plaintexts per key and
   fresh shared BvN banks.

The discovery graph contains sixteen cells because selection occurred before
the mechanism was known.  The exact graph below replaces it as the minimal
mechanism representation; it contains only the seven population-nonzero
edges.

## Exact mechanism

PRESENT's round recurrence gives the identity

```text
E_(r+1)(P,K) = pLayer(SBoxLayer(E_r(P,K))) xor K_(r+1).
```

Therefore, for `X = E_r(P,K)` and `D = E_r(P,K) xor E_(r+1)(P,K)`, target bit
`t` obeys

```text
D[t] = X[t] xor SBoxLayer(X)[pLayer^-1(t)] xor K_(r+1)[t].
```

The public key bit is a constant outcome flip and leaves MI unchanged.  When
`t` and `pLayer^-1(t)` lie in different nibbles, balanced S-box output is
masked by an independent uniform `X[t]`; every individual source-bit MI is
exactly zero.  PRESENT has a same-nibble preimage only at the four pLayer fixed
points `0, 21, 42, 63`.

Exhaustive enumeration of the sixteen public S-box inputs leaves exactly seven
nonzero cells:

| source -> target | exact population MI | five-key observed mean MI |
|---|---:|---:|
| 3 -> 0 | 0.130812 | 0.126068 |
| 20 -> 21 | 0.033822 | 0.035475 |
| 23 -> 21 | 0.142397 | 0.138333 |
| 40 -> 42 | 0.033822 | 0.033753 |
| 43 -> 42 | 0.033822 | 0.034056 |
| 60 -> 63 | 0.033822 | 0.033744 |
| 62 -> 63 | 0.142397 | 0.143701 |

This is a complete single-bit classification:

- exactly 7 of 4,096 cells have nonzero population MI;
- the other 4,089 cells have exactly zero population MI;
- the empirical blind-discovery ranks 1--7 equal those seven cells exactly;
- all seven survive every BvN bank on all five fresh keys;
- exact total MI is `0.5508934151`; observed mean is `0.5451297798`, a
  `1.05%` sampling difference;
- the seven fixed-point cells carry `564.37x` the measured MI of seven
  source-matched adjacent non-fixed controls.

The implementation recurrence was also checked in 576 exact equalities over
three keys, 64 plaintexts and rounds 1, 7 and 31.  This is an algebraic
mechanism gate, not a repeat of an established full-round statistical run.

## Consequence

The PRESENT F8 result is not merely correlated with a vague permutation-cycle
feature.  Its complete support and magnitude are determined by:

1. the adjacent-round recurrence;
2. the pLayer fixed points;
3. the seven nonzero input-bit correlations of `x xor S(x)` at the associated
   S-box coordinates.

The derivation is independent of the round number and of the 80- versus
128-bit key schedule.  This both explains the established PRESENT-80 result
and predicts PRESENT-128 before its measurement.  It also supplies a static
criterion for future SPN transfers: compute same-S-box-cell fixed routes first,
then enumerate the local `x xor S(x)` support before spending samples.

## Artifacts and hashes

- `present128_fullround_causal_f8_v1.json`:
  `7c6341b0d10d878a5a60717d0a3358e0a5e50d50225c68e8757685b33d9eb123`
- discovery `.causal`:
  `f8f912e0aa3e60735d8f500406930c53fcf6aa93e15af8b84b91a2500f60036c`
- `present128_fixedpoint_causal_mechanism_v1.json`:
  `9461abb8e8d55a0cc7cefefcf004a263ee5b2fab2e38712d7a7313d77414f4b5`
- localization `.causal`:
  `f63a74fa4f79242d035e48011496dd4a4a08e45bd00040139676b7cac69a378d`
- `present_fullround_exact_mechanism_v1.json`:
  `c06944063dbc83829d677402be2f0dd7b281e6070a1ea32dc81c205cbd20c398`
- minimal exact seven-edge `.causal`:
  `50bad071f023815d55ec8b1451ecb7d25d8fa07a00775ba9541c306da427d661`

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/present128_fullround_causal_f8.py \
  --output research/results/v1/present128_fullround_causal_f8_v1.json \
  --causal-output research/results/v1/present128_fullround_causal_f8_v1.causal

PYTHONPATH=.:src .venv/bin/python \
  research/experiments/present128_fixedpoint_causal_mechanism.py \
  --output research/results/v1/present128_fixedpoint_causal_mechanism_v1.json \
  --causal-output research/results/v1/present128_fixedpoint_causal_mechanism_v1.causal

PYTHONPATH=.:src .venv/bin/python \
  research/experiments/present_fullround_exact_mechanism.py \
  --output research/results/v1/present_fullround_exact_mechanism_v1.json \
  --causal-output research/results/v1/present_fullround_exact_mechanism_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_present_exact_mechanism.py tests/test_ciphers.py
PYTHONPATH=.:src .venv/bin/python scripts/validate_causal_artifacts.py
```
