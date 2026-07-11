# BLAKE3 Full-Compression Output Reader and Borrow Spectrum v1

## Full seven-round output relations

Let `L_i,H_i` be the low/high words of the 512-bit BLAKE3 working state
immediately after round 7, and let `CV_i` be the input chaining value.  The
reference output transform is

```text
O_i     = L_i xor H_i
O_(i+8) = H_i xor CV_i                 for i = 0..7.
```

This creates two distinct output boundaries:

1. the first 32 output bytes expose the eight exact lane-pair XORs
   `L_i xor H_i`;
2. the complete 64-byte compression output plus the known input CV separates
   every final lane:

```text
H_i = O_(i+8) xor CV_i
L_i = O_i xor O_(i+8) xor CV_i.
```

The 25-edge `.causal` artifact stores the sixteen reference equations, eight
direct three-term low-lane cancellations, and an executable 16-word Reader
recipe.  Confirmation re-opens the file with `CryptoCausalReader` before
reconstructing the post-round state.

| evidence object | exact states | exact words | exact bits |
|---|---:|---:|---:|
| first-32-byte pair-XOR projection | 40,000/40,000 | 320,000/320,000 | 10,240,000/10,240,000 |
| full-output plus CV Reader | 40,000/40,000 | 640,000/640,000 | 20,480,000/20,480,000 |

Across 80 fixed-point-free BvN routes, 640,000 routed state comparisons return
zero complete states and zero complete words.  Rotating the CV lanes or high
output lanes also returns zero words and about 50% bits.

The complete-state statement requires the full 64-byte compression output and
the input CV.  A standalone 32-byte digest carries the eight pair-XOR words,
not the separated 512-bit state.

## Output-half symmetry breadcrumb

Swapping the two 32-byte output halves before applying the Reader preserves
all eight low words and changes all eight high words.  This is an exact
localization rather than a failed control:

```text
L_i = O_i xor O_(i+8) xor CV_i
```

is symmetric in the two output words, whereas

```text
H_i = O_(i+8) xor CV_i
```

requires their designated roles.  The five seed blocks therefore retain
320,000/320,000 low words, zero complete states, and about 75% aggregate bit
accuracy under the half swap.  The eight symmetric low-lane edges are explicit
in the final causal graph.

## XOR-to-subtraction borrow theorem

Replacing both Reader XOR operations with modular subtraction produces
60.6% bit accuracy rather than a featureless 50% control.  Write `b_k` for the
borrow into bit `k` of `O_high - CV` and `d_k` for the borrow into bit `k` of
`O_low - H_sub`.  Exact binary subtraction gives

```text
H_sub[k] = H[k] xor b_k
L_sub[k] = L[k] xor b_k xor d_k.
```

Consequently:

```text
H_sub[k] = H[k]  iff b_k = 0
L_sub[k] = L[k]  iff b_k = d_k.
```

For independent uniform input bits, exhaustive enumeration of `(L_k,H_k,CV_k)`
gives the exact transition matrix on states `(b_k,d_k) = 00,01,10,11`:

```text
        next 00  01  10  11
from 00      5/8 1/8 1/8 1/8
from 01      1/4 1/2   0 1/4
from 10      1/4   0 1/2 1/4
from 11      1/8 1/8 1/8 5/8
```

Starting in `00`, the high-word bit-match probabilities begin
`1, 3/4, 5/8, 9/16, ...` and approach `1/2`; the low-word probabilities begin
`1, 3/4, 11/16, 43/64, ...` and approach `2/3`.  Averaging both halves over a
32-bit word predicts

```text
178830935602388300231 / 295147905179352825856
  = 0.6059027777741398.
```

| check | analytic | observed on 40,000 compressions |
|---|---:|---:|
| aggregate bit accuracy | 0.605902777774 | 0.605925537109 |
| 64-cell spectrum correlation | 1.0 | 0.999969129501 |
| complete-word matches | 85.7194 expected | 87 observed |
| binary borrow identities | exact | 20,480,000/20,480,000 |

Both low and high word substitutions have the same exact complete-word
survival probability `(3/4)^31`.  The four-edge borrow `.causal` artifact
stores the state machine and word-survival law; the analytic spectrum is
computed only after the recipe is read back from that artifact.

## Correctness gate

The vectorized core follows the BLAKE3 team's
[reference implementation](https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs),
raw SHA-256
`6e89a18be72e3c4d838644e1796e04d896cb4a16bd7bb803d4380d7a363fbfd2`.
Before measurement, the independent single-chunk XOF path must match all 131
bytes of seven cases from the
[official test-vector set](https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json),
raw SHA-256
`dcb91ea8accc77e6d6e632af7cdc1a99a9f3ae78cf648da595c7d064db32f624`.
The selected lengths `0,1,63,64,65,1023,1024` cover empty input, both sides of
the block boundary, and both sides of the single-chunk endpoint.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/blake3_fullcompression_reader.py \
  --output research/results/v1/blake3_fullcompression_reader_v1.json \
  --causal-output research/results/v1/blake3_fullcompression_reader_v1.causal

PYTHONPATH=.:src .venv/bin/python \
  research/experiments/blake3_output_borrow_spectrum.py \
  --output research/results/v1/blake3_output_borrow_spectrum_v1.json \
  --causal-output research/results/v1/blake3_output_borrow_spectrum_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_blake3_fullcompression_reader.py \
  tests/test_blake3_output_borrow_spectrum.py
```

## Artifact hashes

- full-compression Reader JSON:
  `d4278a637b28ea81fb34a9de8f840f6c534750eea5656dc49a62720622617b07`
- 25-edge full-compression `.causal`:
  `9c19c46e3f3d96d5273926c0da048377854fd60a1af17f460b05214f6f3cf280`
- borrow-spectrum JSON:
  `a15d89ca73b252cf99790c9b4e8d09c70c10e78b0ebdb056197ca24ff5a9cfde`
- four-edge borrow `.causal`:
  `6770b4f9344886bd3a9774ff95b2ea2f1b14597f1542fa985dc6c4e7797fcb07`
