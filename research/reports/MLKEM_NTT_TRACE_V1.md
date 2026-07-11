# ML-KEM NTT trace v1

Raw results:

- `research/results/v1/mlkem_ntt_trace_field.json` — byte plus field F8-Fq, SHA-256 `d5c7f1480551617cf1ee78a7a4e0219fb35c008ef4864f83c79a9e19fad0918c`

## Design

For 1,000 real ML-KEM ciphertexts each of ML-KEM-512, ML-KEM-768 and
ML-KEM-1024, the experiment extracts the actual `v` polynomial, calls the
PQClean `poly_decompress`, `poly_compress`, and `ntt` functions exported by
the pinned `pqcrypto==0.4.0` arm64 wheel, then measures the following
transitions:

1. packed `v` bytes to decompressed coefficient bytes;
2. coefficient bytes to NTT-state bytes; and
3. field-aware coefficients to NTT state modulo `q=3329`.

Each coefficient-to-NTT transition has five independently row-shuffled NTT
controls.  The experiment verifies KEM decapsulation for every operation and
requires `poly_compress(poly_decompress(v)) == v` for every operation.

## Result

All 3,000 decapsulations and all 3,000 exact recompressions passed.

| Variant | Byte F8 `coeff→NTT` | Byte shuffled range | F8-Fq `coeff→NTT` | F8-Fq shuffle mean |
|---|---:|---:|---:|---:|
| ML-KEM-512 | 0.0174 | around 0.016 | 0.0664 | around 0.05 |
| ML-KEM-768 | 0.0189 | around 0.017 | 0.0508 | around 0.05 |
| ML-KEM-1024 | 0.0166 | around 0.017 | 0.0547 | around 0.05 |

Neither representation sees a consistent true-transition excess over its
shuffled control.  The standard byte F8 is in fact conservative on the NTT
transition, because its chi-square table treats the strongly quantized
coefficient distribution as sparse.  F8-Fq removes that representation issue,
but still yields no stable transition signal.

This is a positive methodological result, not a negative result to hide: a
known deterministic internal algebraic transition does *not* automatically
make F8 fire.  It rules out a broad class of representation-only false
discoveries before attempting the nonlinear compression and packing stages.

## Reproduction

```bash
.venv/bin/python research/experiments/mlkem_ntt_trace_suite.py \
  --operations 1000 --permutations 5 \
  --output research/results/v1/mlkem_ntt_trace_field.json
```

No cryptographic security, attack, key-recovery, IND-CPA or IND-CCA claim is
within the scope of this trace experiment.
