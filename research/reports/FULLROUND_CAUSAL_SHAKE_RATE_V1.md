# SHAKE Full-Round Rate Projection Readers v1

## Result

After absorption, SHAKE applies the complete 24-round Keccak-f[1600]
permutation and copies the rate lanes into the squeeze output.  A complete
first squeeze block therefore reconstructs the post-permutation rate state
exactly:

| XOF | rate | capacity | state fraction exposed by one full rate block |
|---|---:|---:|---:|
| SHAKE128 | 1,344 bits / 21 lanes | 256 bits / 4 lanes | 84% |
| SHAKE256 | 1,088 bits / 17 lanes | 512 bits / 8 lanes | 68% |

The 42-edge `.causal` artifact stores every lane copy, one executable Reader
per XOF, and one complete-basis projection proof per rate/capacity split.

| Reader | exact states | exact 64-bit lanes | exact bits |
|---|---:|---:|---:|
| SHAKE128 complete first rate block | 40,000/40,000 | 840,000/840,000 | 53,760,000/53,760,000 |
| SHAKE256 complete first rate block | 40,000/40,000 | 680,000/680,000 | 43,520,000/43,520,000 |

Together the Readers reconstruct `80,000/80,000` rate states,
`1,520,000/1,520,000` lanes, and `97,280,000/97,280,000` bits after the full
permutation.  A 32-byte output prefix separately reconstructs the first four
lanes exactly in all 80,000 cases.

This is the exact FIPS 202 squeeze projection.  It does not reconstruct the
capacity lanes from one rate block and is not enlarged into a secret-recovery
statement.

## Projection dimension theorem

For each variant, all 1,600 coordinate basis vectors are passed through the
rate projection:

- every rate basis vector maps to a unique output coordinate;
- every capacity basis vector maps to zero.

Thus the projection rank and kernel dimension are exactly

```text
SHAKE128: rank 1344, kernel 256
SHAKE256: rank 1088, kernel 512.
```

At this immediate output boundary, fixing a full rate block leaves precisely
the capacity-coordinate degrees of freedom.  This is a complete coordinate
proof, not an estimate from sampled states.

## Correctness and controls

The vectorized Keccak implementation is independently gated at three levels:

1. the standard 25-lane `Keccak-f[1600](0)` permutation vector;
2. embedded FIPS 202 empty-message outputs for SHAKE128 and SHAKE256;
3. complete-rate-block equality with Python/OpenSSL `hashlib` for empty,
   `abc`, and 80 fresh random messages from the production runs.

All gates pass.  The specification source is
[NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final).

Each variant uses five fresh 8,000-message families and sixteen
fixed-point-free BvN routes.  Across 160 route banks there is no complete state
and no complete 64-bit lane match.  Cyclic lane rotation and reversing the
eight bytes within every lane also produce zero lanes and about 50% bits,
localizing both lane order and little-endian representation.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_fullround_rate_reader.py \
  --output research/results/v1/shake_fullround_rate_reader_v1.json \
  --causal-output research/results/v1/shake_fullround_rate_reader_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_fullround_rate_reader.py
```

## Artifact hashes

- result JSON:
  `bc26f486e5f0941684b44ae95dbbbc15e63329c1224eda070eb194aeac6d468c`
- 42-edge executable `.causal`:
  `ea9c48a7cd29093e779ff516e561c3e5ac441d1d4d4f20e1579e30c3e0ab45fa`
