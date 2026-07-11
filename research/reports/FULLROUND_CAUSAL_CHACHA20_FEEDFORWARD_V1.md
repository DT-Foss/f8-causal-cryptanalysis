# ChaCha20 Full-Round Feed-Forward Readers and Carry Spectrum v1

## Result

ChaCha20 contributes cipher full-round configuration 16 through the standard
20-round block-function endpoint.  For each 32-bit lane,

```text
output[i] = core20[i] + initial[i] mod 2^32
core20[i] = output[i] - initial[i] mod 2^32.
```

The initial words split into two observability classes:

- lanes `0..3,12..15` contain the public constants, block counter and nonce;
- lanes `4..11` contain the key words.

The 18-edge `.causal` artifact therefore stores two executable recipes:

1. a public Reader that accepts no key lanes and reconstructs eight selected
   post-round-20 core words, or 256 bits;
2. a known-key Reader that reconstructs all sixteen core words, or 512 bits.

| Reader | exact states | exact words | exact bits |
|---|---:|---:|---:|
| public constants/counter/nonce | 40,000/40,000 | 320,000/320,000 | 10,240,000/10,240,000 |
| complete known initial state | 40,000/40,000 | 640,000/640,000 | 20,480,000/20,480,000 |

Each of five fresh fixed-key/fixed-nonce families contains 8,000 random
counters.  Across 80 BvN routes per Reader, neither route family produces a
complete reconstructed state or one complete 32-bit word.

The public projection is an exact internal full-round endpoint relation.  It
does not take the key as input and does not output key words; reconstructing
the public-position core lanes is kept distinct from key reconstruction.

## Addend-localization controls

The formula controls preserve every lane whose addend remains correctly
assigned, which localizes the Reader rather than merely randomizing it:

| changed addend | exact public words per 8,000-row seed | explanation |
|---|---:|---|
| counter replaced by `counter-1` | 56,000/64,000 | seven unaffected lanes remain exact |
| three nonce words cyclically rotated | 40,000/64,000 | constants plus counter remain exact |
| four constants cyclically rotated | 32,000/64,000 | counter plus nonce remain exact |

No complete eight-lane state remains exact in any of these controls.

Correctness is gated by the full block-function vector from
[RFC 8439 section 2.3.2](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.3.2):
key bytes `00..1f`, counter `1`, nonce `000000090000004a00000000`, output
`10f1e7e4...a2503c4e`.  The same vector is also checked against the older
repository implementation.

## XOR-peeling carry theorem

The information-bearing formula control replaces exact subtraction with

```text
xor_peeled[i] = output[i] xor initial[i].
```

Let `c_k` be the carry into bit `k` of `core + initial`.  The exact bit
equation is

```text
xor_peeled[k] = core[k] xor c_k,
```

so the peeled bit matches precisely when `c_k=0`.

Condition on the actual initial-word bit `a_k` and let `p_k=P(c_k=1)`, with
`p_0=0`.  Under a balanced core bit the Reader-loaded recurrence is

```text
a_k = 0: p_(k+1) = p_k / 2
a_k = 1: p_(k+1) = (1 + p_k) / 2
bit-match probability = 1 - p_k.
```

This predicts a distinct 32-bit profile for each of the sixteen real addend
words rather than imposing one generic carry curve.

| full-round spectrum check | predicted | observed |
|---|---:|---:|
| aggregate bit accuracy | 0.551270681975 | 0.551214941406 |
| 512-cell lane/bit correlation | 1.0 | 0.999953411373 |
| RMSE | 0 | 0.001934743059 |
| complete words | 62.1485 expected | 60 observed |
| binary output/peeling identities | exact | 40,960,000/40,960,000 |

Rotating the predicted addend profile by one lane reduces correlation to
`0.358019732102` and raises RMSE to `0.226939414999`.  Thus the spectrum is
attached to the actual ChaCha initial-lane values, not only to global bit
position.

For a fixed initial word `A`, complete XOR-peeling survival has the conditional
probability

```text
2^(-popcount(A & 0x7fffffff)).
```

Only carries entering bits 1 through 31 matter; this conditional law predicts
the observed full-word count without fitting parameters to the core output.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_fullround_feedforward_reader.py \
  --output research/results/v1/chacha20_fullround_feedforward_reader_v1.json \
  --causal-output research/results/v1/chacha20_fullround_feedforward_reader_v1.causal

PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_feedforward_xor_carry_spectrum.py \
  --output research/results/v1/chacha20_feedforward_xor_carry_spectrum_v1.json \
  --causal-output research/results/v1/chacha20_feedforward_xor_carry_spectrum_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_chacha20_fullround_feedforward_reader.py \
  tests/test_chacha20_feedforward_xor_carry_spectrum.py
```

## Artifact hashes

- full-round Reader JSON:
  `af1a7199c5eb45daf415246565b9bf2f4e0eb6a723ffc92bba8f8d7452a3c3e2`
- 18-edge Reader `.causal`:
  `ed86f9b3fcae2e06a099d841aece72b896b86a3611ced1f10314fc66d72ed302`
- conditional carry-spectrum JSON:
  `c7f25aa44b2d2df315f5a1637fb4e115bf4acab649b91006224fc5a88889d426`
- three-edge carry `.causal`:
  `71c1da4984474bdc31818259d6b9f33ae8a656bf2df65daa503739bb044e3146`
