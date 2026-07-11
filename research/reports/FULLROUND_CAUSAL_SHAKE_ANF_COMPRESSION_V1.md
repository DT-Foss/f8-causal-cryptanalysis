# SHAKE Shared-ANF Compression Cascade v1

## Result

A lossless shared-monomial transform exposes exact structure in complete SHAKE
state-function truth spaces that is invisible to generic compression on the raw
R3 representation.  Each raw record contains all 1,600 state coordinates over
all `2^16` capacity-window assignments: 13,107,200 bytes.

| variant | round | shared monomials | best raw bytes | best ANF bytes | ANF advantage over best raw |
|---|---:|---:|---:|---:|---:|
| SHAKE128 | 0 | 17 | 6,432 | 324 | 19.85x |
| SHAKE128 | 1 | 27 | 42,452 | 816 | 52.02x |
| SHAKE128 | 2 | 275 | 493,464 | **11,052** | **44.65x** |
| SHAKE128 | 3 | 7,447 | 12,964,852 | **634,196** | **20.44x** |
| SHAKE128 | 4 | 65,254 | 13,107,200 | 12,781,204 | 1.026x |
| SHAKE128 | 24 | 65,536 | 13,107,200 | 13,127,016 | 0.998x |
| SHAKE256 | 0 | 17 | 6,184 | 324 | 19.09x |
| SHAKE256 | 1 | 27 | 44,688 | 836 | 53.45x |
| SHAKE256 | 2 | 277 | 508,092 | **11,472** | **44.29x** |
| SHAKE256 | 3 | 7,529 | 13,069,684 | **658,864** | **19.84x** |
| SHAKE256 | 4 | 65,235 | 13,107,200 | 12,812,416 | 1.023x |
| SHAKE256 | 24 | 65,536 | 13,107,200 | 13,127,032 | 0.998x |

At round 3, the best raw paths retain 98.91% and 99.71% of the original bytes.
The raw representation is therefore practically incompressible.  The exact
ANF transform followed by LZMA retains only 4.84% and 5.03%, giving total
compression ratios of 20.67x and 19.89x from the same complete truth spaces.

At round 2, the transformed paths reach total ratios of 1,185.96x and
1,142.54x.  Compared with the best compression applied directly to the raw
records, the transformed representations are 44.65x and 44.29x smaller.

## The representation mechanism

The transform applies an exact GF(2) Möbius transform independently to every
state coordinate, takes the global union of all occurring monomials, and stores
that dictionary once beside a packed `basis x 1600` coefficient matrix.

The basis frontier is sharp:

| round | SHAKE128 basis / 65,536 | SHAKE256 basis / 65,536 | maximum degree |
|---:|---:|---:|---:|
| 0 | 17 | 17 | 1 |
| 1 | 27 | 27 | 2 |
| 2 | 275 | 277 | 4 |
| 3 | 7,447 | 7,529 | 7 |
| 4 | 65,254 | 65,235 | 14 |
| 24 | 65,536 | 65,536 | 16 |

Thus R3 is globally coupled but still represented by only about 11.4% of the
available monomial dictionary.  R4 uses more than 99.5%, and R24 uses every
possible monomial.  The compression advantage disappears at exactly the same
R3->R4 transition located independently by the Boolean-influence and ANF-density
frontiers.

## Interaction graph correction

The shared basis also distinguishes compression from variable factorization.
The monomial primal graph has 0 of 120 possible variable-pair edges at R0, 10
at R1, and all 120 from R2 onward in both variants.  R2 remains extraordinarily
compressible because 1,600 formulas reuse only 275/277 low-degree features, not
because the variables split into independent components.

This refines A132: R2 is the last incomplete influence-support layer, while R1
is the last observed layer with a non-complete monomial interaction graph.  The
useful R2 object is a shared-feature dictionary for a round-split Reader.

## Generic and double compression

The experiment applies zlib level 9, bzip2 level 9, and LZMA preset 6 to both
the raw and ANF representations.  For R2 and R3 it additionally evaluates all
six ordered pairs of distinct codecs in both directions.  Some second stages
improve a weaker first stage, but no two-codec cascade beats the best single
LZMA path in any retained representation.

The mechanism is therefore the formula-space transform, not repeated generic
compression.  Generic compression becomes effective only after the shared ANF
dictionary exposes the cross-coordinate reuse.

## Exact Reader artifact

`shake_anf_dictionary_v1.anfpack` stores the SHAKE128/256 R2 and R3 records in
the documented `F8ANFPK1` binary format.  Its four records occupy 3,167,858
bytes versus 52,428,800 raw bytes.  `ANFDictionaryPackReader` reopens the file,
expands each shared coefficient matrix, applies the inverse Möbius transform,
and matches all 419,430,400 persisted truth values exactly.

The production run also performs a complete in-memory roundtrip for every one
of the 12 R0/R1/R2/R3/R4/R24 records: 1,258,291,200 additional exact truth-value
checks.

## Independent gates

- The known-function Möbius gate recovers exact degrees 0, 1, 2 and 3.
- Candidate-axis conversion matches 8,192 independently extracted values.
- Round composition matches 102,400 scalar Keccak state bits.
- Every observed record contains all `2^16 x 1,600` truth values.
- The binary pack is reopened from disk rather than trusted from writer-side
  arrays.
- The six-edge `.causal` artifact is reopened with `CryptoCausalReader` and
  passes provenance validation.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_anf_compression_cascade.py \
  --window-bits 16 \
  --rounds 0,1,2,3,4,24 \
  --pack-rounds 2,3 \
  --cascade-rounds 2,3 \
  --output research/results/v1/shake_anf_compression_cascade_v1.json \
  --causal-output research/results/v1/shake_anf_compression_cascade_v1.causal \
  --pack-output research/results/v1/shake_anf_dictionary_v1.anfpack

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_anf_compression_cascade.py
```

## Artifact hashes

- result JSON:
  `0ee682c51f5d86b8a6cd7fb62ec34d71c979d6a75888bac966855e8cb32cf524`
- six-edge `.causal`:
  `5772b58ed396aebd4829aeee359fead1655440b73d5564aac7c5bb0e5c863d36`
- four-record `F8ANFPK1`:
  `8ddffb70f3ad76621c42a3077d10478d167283bf003e855ea651481543ccf8f6`
