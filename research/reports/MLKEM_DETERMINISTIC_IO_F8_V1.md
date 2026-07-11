# Deterministic ML-KEM input/output F8 v1

Raw result: `research/results/v1/mlkem_deterministic_io_f8.json`
SHA-256: `c9d262fdd9dca1ca080285083ecab5a0e3fedcae31e6d0dba305c5bcdbd55dfa`

## Design

The pinned PQClean backend exposes deterministic key-generation and
encapsulation APIs.  A fixed deterministic keypair is produced per ML-KEM
variant; 5,000 distinct SHAKE-derived 32-byte encapsulation-coin inputs then
produce ciphertexts and shared secrets. Every operation is decapsulated.

F8-I/O compares the coins to the first 32 public ciphertext bytes and to the
32-byte shared secret, using the same quantized F8 statistic as the ARX work.
Each target receives five independently row-shuffled output controls.

## Result

| Variant | Coins→ciphertext | Shuffled ciphertext mean | Coins→secret | Shuffled secret mean |
|---|---:|---:|---:|---:|
| ML-KEM-512 | 0.0449 | 0.0537 | 0.0557 | 0.0516 |
| ML-KEM-768 | 0.0547 | 0.0531 | 0.0439 | 0.0492 |
| ML-KEM-1024 | 0.0449 | 0.0471 | 0.0352 | 0.0508 |

All 15,000 decapsulation gates passed.  No variant has a stable true-pair
excess over shuffle.  In particular, the input-controlled F8 form does not
turn the deterministic ML-KEM path into a useful output relation signal.

This is not a security proof. It is a sharply defined negative result for one
F8 adaptation under a deterministic test interface.

## Reproduction

```bash
.venv/bin/python research/experiments/mlkem_deterministic_io_f8.py \
  --operations 5000 --permutations 5 \
  --output research/results/v1/mlkem_deterministic_io_f8.json
```
