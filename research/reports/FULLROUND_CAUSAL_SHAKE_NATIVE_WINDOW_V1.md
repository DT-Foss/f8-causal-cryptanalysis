# SHAKE Native State-Window Consistency v1

## Result

A self-contained C11/POSIX implementation now executes the candidate-axis
bit-sliced Keccak-f[1600] Reader with ten worker threads and bounded streaming
memory.  It preserves all 24 rounds and extends exact known-complement
state-window consistency to 32 variable capacity coordinates for both SHAKE
variants.

| variant | variable coordinates | logical candidates | packed states | exact consistent assignment | independent-target matches |
|---|---:|---:|---:|---:|---:|
| SHAKE128 | 24 | 16,777,216 | 262,144 | 9,665,699 | 0 |
| SHAKE128 | 28 | 268,435,456 | 4,194,304 | 153,789,222 | 0 |
| SHAKE256 | 24 | 16,777,216 | 262,144 | 598,536 | 0 |
| SHAKE256 | 28 | 268,435,456 | 4,194,304 | 63,935,659 | 0 |
| SHAKE128 | 32 | 4,294,967,296 | 67,108,864 | 3,384,693,180 | 0 |
| SHAKE256 | 32 | 4,294,967,296 | 67,108,864 | 153,225,470 | 0 |

Every assignment equals the instrumented ground truth.  The first two lanes of
the next rate block leave exactly one assignment, and an independent scalar
implementation then confirms equality over the complete rate.  Across the two
native artifacts, 9,160,359,936 logical candidates are represented by
143,130,624 machine-word candidate packs.

The 32-coordinate result evaluates a complete four-billion-element assignment
space for each SHAKE variant.  It is 256 times the logical width of the original
20-coordinate scalar baseline and sixteen times the 28-coordinate production
case.

## Independent semantic gates

The native path is not trusted from its own output:

1. 64 independent random 1,600-bit states are evaluated by the C kernel and by
   the existing scalar/vectorized Keccak implementation.  All
   `102,400/102,400` output bits match.
2. For both SHAKE128 and SHAKE256, every native candidate mask in a complete
   12-coordinate problem is compared byte-for-byte with the NumPy bit-sliced
   implementation.  Both factual and independent-target mask arrays match.
3. The final candidate is evaluated again by the independent scalar Keccak core
   and checked against every lane of the next rate block.
4. The eight-edge `.causal` graph is reopened with `CryptoCausalReader`; the
   executable recipe includes the native source hash, pack width, full-round
   count, coordinate convention, filter lanes, and scalar confirmation rule.

The C source used for both production artifacts has SHA-256
`3189f301d25b1bc38c867dae840edb3c8e710ffa5960e02035b43a72c0889d81`.

## Execution structure

The kernel fuses four operations that previously crossed the Python/NumPy
boundary:

```text
64 assignments -> candidate-axis bit planes -> Keccak-f[1600]
               -> exact two-lane masks -> scalar complete-rate confirmation
```

The 32-coordinate run streams 4,194,304 candidate packs at a time.  Its two
mask arrays therefore use at most 67,108,864 bytes, independent of the complete
67,108,864-pack search width.  Each completed chunk is written atomically to a
checkpoint; an interrupted run resumes at the next unprocessed pack without
accepting cached final conclusions.

## Scope

The rate and every capacity coordinate outside the declared window are fixed.
The observed object is the next full-round rate block.  The result establishes
exact mathematical state-window consistency at widths 24, 28, and 32; the
logical work remains `2^k` and is not described as unrestricted recovery of all
256 or 512 capacity coordinates.

Correctness inherits the Keccak zero-state, FIPS 202, and `hashlib` gates.
Specification source: [NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final).

## Reproduction

Standard native production:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_native_window_solver.py \
  --window-bits 24,28 \
  --output research/results/v1/shake_native_window_solver_v1.json \
  --causal-output research/results/v1/shake_native_window_solver_v1.causal
```

Extended 32-coordinate production with bounded memory and resumable chunks:

```bash
./scripts/reproduce_shake_native_extended.sh
```

Focused semantic gates:

```bash
PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_native_window_solver.py
```

## Artifact hashes

- 24/28 result JSON:
  `8497ccb7938da721b71876cf481bcc4175b7f5b25c5f3300a87e09a6f123e604`
- 24/28 eight-edge `.causal`:
  `f90cf74a0d97f07b0d037639dc9d9beee2e0f7dec3360c51ebf802e27e04550f`
- 32 result JSON:
  `d09e629aca7a429a38cb1228234ea2e7ad4777be262066fdf6ce11dc2dc33ddc`
- 32 eight-edge `.causal`:
  `0c3b9bda81de51a2f5a60b717d93960de532372c02d08e1446a6a8518dbf65da`
