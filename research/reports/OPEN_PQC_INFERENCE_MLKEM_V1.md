# Open PQC Inference: ML-KEM Compressed-v to NTT Baseline

## Scope

This is a public representation experiment, not an ML-KEM attack.  It does
not use secret keys, invalid-ciphertext acceptance, IND-CPA/IND-CCA games, or
key recovery.  The question is whether a fixed compressed-v bit mutation
produces a parameter-set-specific or statistically exceptional structure after
the public implementation chain `poly_decompress -> NTT`.

## Frozen transfer

Real ML-KEM ciphertexts were generated for ML-KEM-512, -768 and -1024.  For
each of five independent runs, 300 ciphertexts were collected and the
decapsulation shared secret was checked.  Eight fixed compressed-v bits were
frozen before the transfer (`0,1,7,15,31,63,95,127`).  Each bit was flipped in
the public v byte string, decompressed by the exported PQClean function, and
transformed by the exported NTT.  The primary statistic is the summed entropy
deficit of 16 quantized `Z_3329` difference bins across the 256 NTT
coefficients.

Two controls were retained:

1. independent row re-pairing of the exact mutated output multiset;
2. row-wise random one-bit mutations of the same compressed-v rows.

## Result

| variant | fixed-bit effect vs repairing | fixed-bit-vs-random range | exact five-seed p | functional gates |
|---|---:|---:|---:|---:|
| ML-KEM-512 | 886.715 .. 887.380 | 586.271 .. 586.927 | 0.0625 for every bit | 1500/1500 |
| ML-KEM-768 | 886.730 .. 887.128 | 586.243 .. 586.572 | 0.0625 for every bit | 1500/1500 |
| ML-KEM-1024 | 886.770 .. 887.202 | 585.097 .. 585.615 | 0.0625 for every bit | 1500/1500 |

The large matched-vs-repaired effect is real public NTT locality, but it is
nearly invariant across the three parameter sets.  With five seed pairs, the
exact two-sided sign-flip test is `0.0625`, so no bit passes the frozen
`p<=0.01` criterion.  The same-type random-mutation control still differs,
showing that a fixed bit position is more structured than a row-wise random
position; that is an expected positional intervention, not a PQC frontier.

## Boundary

This closes the fixed compressed-v mutation line as a baseline.  It does not
support a new ML-KEM distinguisher or a security claim.  A future PQC attempt
must remove this known public linear/locality component — for example by
conditioning on the mutation byte/bit plane or by testing a nonlinear
compression-boundary statistic — before interpreting any excess.

## Artifacts

- Frozen config: `configs/mlkem_chosen_difference_variants_v1.json`, SHA-256
  `680fc3162cae1b8d7e7f07574bc4c40b212537f79a2f391a075e4a03153ec63d`.
- Full transfer: `results/v1/mlkem_chosen_difference_variants_v1.json`, SHA-256
  `477ad66f93039e1d773cda3a5fae13d12401b1c685067f8a730eb1bbff3831d0`.
- Causal graph: `results/v1/mlkem_chosen_difference_variants_v1.causal`, SHA-256
  `81b7d505bc87e8ac02012d8f673895d3b050fdedc26eb729e4ef96956e4d2aef`.

The `.causal` file contains 24 typed edges and passed immediate
`CryptoCausalReader` read-back.
