# SPHINCS+-family boundary controls v1

Raw result: `research/results/v1/sphincs128f_boundary_full.json`
SHA-256: `2b771712008946a37e96cdfcb5b738c3fa11bc367d1feb739d2dfdd097c6b5b7`

## Observation

The earlier hash-signature pilot showed a large fixed-key F8-O rate.  F8-O is
an adjacent-public-row dependence score, so a large variable-length signature
can create a high score through its documented serialization alone.  This
follow-up partitions that ambiguity.

## Controls

For two independent fixed-key runs of 64 real `sphincs_sha2_128f_simple`
signatures, three streams are compared:

1. original concatenation;
2. the same complete signatures in random order; and
3. the same complete signatures, with only their internal 32-byte rows
   independently permuted.

Every first signature verifies.  The target is labelled `SPHINCS+ / SLH-DSA
family` because `pqcrypto` exposes the legacy SPHINCS+ API name; this is not a
FIPS 205 conformance test.

## Result

| Seed | Original F8-O | Whole-signature permutation | Within-signature row permutation |
|---:|---:|---:|---:|
| 42 | 0.4375 | 0.4414 | 0.0488 |
| 1051 | 0.3965 | 0.3955 | 0.0557 |

The entire effect survives whole-signature reordering and disappears only when
the row order *inside* each signature is destroyed.  It is therefore an
intra-signature public serialization marker.  It says nothing about secret-key
recovery, message forgery, a security reduction, or an external
cryptanalytic distinguisher.

## Reproduction

```bash
.venv/bin/python research/experiments/pqc_output_control_suite.py \
  --targets sphincs128f --operations 64 --seeds 2 --permutations 2 \
  --output research/results/v1/sphincs128f_boundary_full.json
```
