# FEAL-32X Full-Round Reader Relation v1

## Result

FEAL-32X contributes a new full-round cipher configuration at the genuine
32-round endpoint.  Its useful representation is not a 1-bit marginal score:
the complete 32-bit R30 right half is reconstructed exactly from the R30-to-R32
left-half difference and the known two-byte R30 subkey.

```text
left_R30 xor left_R32 = F(right_R30, K30)
```

The executable inverse is stored inside `.causal`, re-opened with
`CryptoCausalReader`, and applied from the Reader on five fresh keys.

| confirmation block | factual 32-bit matches | 16 BvN routes: total 32-bit matches | previous-round-subkey matches |
|---:|---:|---:|---:|
| key 0 | 8,000/8,000 | 0 | 0 |
| key 1 | 8,000/8,000 | 0 | 0 |
| key 2 | 8,000/8,000 | 0 | 0 |
| key 3 | 8,000/8,000 | 0 | 0 |
| key 4 | 8,000/8,000 | 0 | 0 |

Across all five blocks, the factual path reconstructs `160,000/160,000`
bytes and `40,000/40,000` complete 32-bit words.  The BvN byte accuracy is
`0.3867%--0.4781%` at its per-key mean/maximum range, consistent with unrelated
byte alignment, and no repaired route yields one complete word.

This is retained as full-round configuration 14 in the cipher track, after the
thirteen established/PRESENT-128 configurations.  SHA-2's separate
full-compression results are counted in the hash track rather than inflating
the cipher numbering.

## Primary-source gate

The implementation is a clean Python/Numpy transcription of NTT's FEAL-NX
equations.  The run is blocked unless all of the following official FEAL-32X
values agree:

- key: `0123456789ABCDEF0123456789ABCDEF`;
- plaintext: `0000000000000000`;
- ciphertext: `9C9B54973DF685F8`;
- internal initial state: `196A9AB1F97F1B21`;
- internal R32 state: `932DDF1603E932D4`;
- first eight two-byte round subkeys:
  `7519 71F9 84E9 4886 88E5 523B 4EA4 7ADE`.

Primary material:

- NTT [FEAL specification, vectors and reference-code index](https://info.isl.ntt.co.jp/crypt/eng/archive/feal/specifications.html);
- reference source `call-6.txt`, SHA-256
  `8bc1d200610a029c7f1869da7b63a8f3780f1bbb5acacb037611cba4f999190f`;
- vector archive `call-5.zip`, SHA-256
  `d2560183dcd4d79ca83389427009a6f2dc85648241b7f6b2d15dc0163d367949`.

The original candidate was FEAL-8 from a secondary KAT.  Primary-source
inspection replaced it with FEAL-32X: NTT's current reference case has a
128-bit key, 32 standard rounds, complete intermediate vectors and a genuine
R30-to-R32 endpoint that needs no synthetic round.

## Why the single-bit graph is quiet

The prediction-first first pass scanned the complete 32x32 bit grid between
`right_R30` and `left_R30 xor left_R32`.  The Feistel identity itself passes
exactly:

- discovery: `36,000/36,000` byte equalities;
- five confirmation keys: `28,000/28,000` per key.

Yet the Reader-fixed aggregate bit score remains on its BvN distribution, with
confirmation Z values `-0.99, -0.59, -1.05, -0.45, -0.02`.  This is the
representation boundary, not absence of dependence: FEAL's pairwise XORs make
each individual input bit a poor marginal coordinate even though the complete
round function is reversible.

The two-stage result is therefore informative in both directions:

1. a raw single-bit MI graph does not expose the FEAL relation;
2. a formula-aligned joint Reader representation reconstructs all 32 bits
   exactly.

## Exact Reader inverse

For input bytes `(x0,x1,x2,x3)` and round-key bytes `(k0,k1)`, define

```text
u  = x0 xor x1 xor k0
v  = x2 xor x3 xor k1
f1 = ROL2(u + v + 1)
f2 = ROL2(f1 + v)
f0 = ROL2(x0 + f1)
f3 = ROL2(x3 + f2 + 1)          (all additions mod 256)
```

The inverse recipe serialized in `.causal` is

```text
x0 = ROR2(f0) - f1
v  = ROR2(f2) - f1
u  = ROR2(f1) - v - 1
x3 = ROR2(f3) - f2 - 1
x1 = x0 xor u xor k0
x2 = x3 xor v xor k1            (all subtractions mod 256)
```

The graph contains five explicit triplets: four algebraic stages and one
composed Reader-executable inverse.  Confirmation deliberately discards the
writer-side recipe object, re-opens the file, locates the typed inverse edge,
and executes only the operation list obtained from the Reader.

The previous-round-subkey control reconstructs exactly two of four bytes —
`x0` and `x3`, whose inverse formulas do not use `k0/k1` — but zero complete
words.  That byte pattern is itself an exact localization of where the two
round-key bytes enter the relation.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/feal32x_fullround_distance2_causal.py \
  --output research/results/v1/feal32x_fullround_distance2_causal_v1.json \
  --causal-output research/results/v1/feal32x_fullround_distance2_causal_v1.causal

PYTHONPATH=.:src .venv/bin/python \
  research/experiments/feal32x_fullround_reader_inverse.py \
  --output research/results/v1/feal32x_fullround_reader_inverse_v1.json \
  --causal-output research/results/v1/feal32x_fullround_reader_inverse_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q tests/test_feal32x_fullround_causal.py
PYTHONPATH=.:src .venv/bin/python scripts/validate_causal_artifacts.py
```

## Artifact hashes

- marginal-boundary JSON:
  `faf1a94d92cc54ca82a5741d7ad34978085aa8c871ecd01def9c7cb566bc0456`
- 16-edge discovery `.causal`:
  `9461ab99924dd162ab3fb3e568e221b3f534dfa3924ffe950a911d34fd5a5cd3`
- Reader-inverse JSON:
  `900b0bb8fc7b756b2596a1dab482db2a146899490758866efedc6fb831293cd5`
- five-edge executable `.causal`:
  `dfd8565a926c8b53ecaa5dabdb563770a1af5707402ae57630d5e5bb475c60e3`
