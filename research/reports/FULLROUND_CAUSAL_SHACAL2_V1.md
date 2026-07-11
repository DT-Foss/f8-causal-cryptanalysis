# SHACAL-2 Full-Round Cancellation Reader v1

## Result

SHACAL-2 contributes full-round cipher configuration 15.  At the final
R63-to-R64 boundary, the two updated words share the same 32-bit `T1` term:

```text
a64 = T1 + T2
e64 = d63 + T1                    mod 2^32
```

Modular subtraction removes `T1` exactly:

```text
a64 - e64 = T2 - d63
d63 = T2 - (a64 - e64)
T2  = Sigma0(a63) + Maj(a63,b63,c63)   mod 2^32.
```

A three-edge `.causal` graph stores this composition.  Confirmation re-opens
the file, obtains the typed operation list from `CryptoCausalReader`, and uses
that Reader recipe to reconstruct `d63`.

| fresh key | factual d63 words | 16 BvN routes: total word matches | wrong-Sigma word matches | maximum BvN bit accuracy |
|---:|---:|---:|---:|---:|
| 0 | 8,000/8,000 | 0 | 0 | 50.1473% |
| 1 | 8,000/8,000 | 0 | 0 | 50.1801% |
| 2 | 8,000/8,000 | 0 | 0 | 50.1965% |
| 3 | 8,000/8,000 | 0 | 0 | 50.1176% |
| 4 | 8,000/8,000 | 0 | 0 | 50.1414% |

The factual path gives `40,000/40,000` exact 32-bit words and
`1,280,000/1,280,000` exact bits.  Across 80 BvN repair routes and five
wrong-formula blocks there is not one full-word match.  Both controls remain
at 50% bit accuracy.

## Correctness gate

The vectorized 64-round implementation imports the SHA-256 constants from the
vendored PQClean source and follows Bouncy Castle's SHACAL-2 key expansion and
round equations.  Measurement cannot start until two NESSIE vectors pass:

1. 512-bit key `80 || 00...00`, zero plaintext ->
   `361AB6322FA9E7A7BB23818D839E01BDDAFDF47305426EDD297AEDB9F6202BAE`;
2. NESSIE set 8.0, key bytes `00..3F`, plaintext
   `98BCC104...1CA45430` -> ciphertext `00112233...DCEDFE0F`.

Primary implementation/test material:

- Bouncy Castle [SHACAL-2 engine](https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/crypto/engines/Shacal2Engine.java), raw SHA-256
  `fe457dec8a1679c8e49c0705ba861e45a4e754c3de9f7dc335cf90625daae08c`;
- Bouncy Castle [NESSIE vector test](https://github.com/bcgit/bc-java/blob/main/core/src/test/java/org/bouncycastle/crypto/test/Shacal2Test.java), raw SHA-256
  `5d5b3ca6bb22b88efabf42d1fa9f50cc3e3abe39d25a87f4d74d7d629105ee1e`.

## Mechanism significance

This is distinct from the SHA-2 feed-forward result:

- SHA-256/SHA-512 feed-forward uses `H_out = H_in + W_final` after the full
  compression schedule and exposes a same-lane carry channel.
- SHACAL-2 has no feed-forward.  Its final round creates two outputs containing
  the same `T1`; subtracting those outputs cancels the complete nonlinear,
  key- and schedule-dependent `T1` branch.

The three retained Reader edges are therefore:

1. `(a63,b63,c63) -> T2` through `Sigma0 + Majority`;
2. `(a64,e64) -> T2-d63` through shared-`T1` cancellation;
3. their composition -> exact `d63` reconstruction.

The wrong-formula control replaces the `Sigma0` rotations `(2,13,22)` with
the unrelated `(6,11,25)` set.  It returns zero words and 49.74%--50.11% bits,
localizing the result to the actual SHACAL-2 equation rather than generic word
arithmetic.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shacal2_fullround_cancellation_reader.py \
  --output research/results/v1/shacal2_fullround_cancellation_reader_v1.json \
  --causal-output research/results/v1/shacal2_fullround_cancellation_reader_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shacal2_fullround_cancellation.py
PYTHONPATH=.:src .venv/bin/python scripts/validate_causal_artifacts.py
```

## Artifact hashes

- result JSON:
  `f0b28b72714bddf6e4a300a500ebebc4b1a3f5a1db398d82e962727314b7807c`
- three-edge executable `.causal`:
  `3b05b239fe4b9c23a8394cff3ee9c0e6a63c8da76b8824e99e0a423db74489a8`
