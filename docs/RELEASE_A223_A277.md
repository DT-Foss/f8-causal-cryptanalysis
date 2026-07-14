# A223--A277 publication snapshot

This release extends the reproducible record from A223 through A277. It binds
the capacity and post-barrier studies, nine independently confirmed full-round
partial-key recovery records, the fresh Reader series, and the two-target
ChaCha20 R20 selected-channel chain to their exact sources, configurations,
results, Causal artifacts, tests, and reproduction entry points.

The release boundary is exact: A278--A281 and the PRESENT-128 work in progress
are not included and no result from them is claimed here.

## Capacity and post-barrier chain

| Attempts | Retained result |
| --- | --- |
| A223 | The complete seven-arm capacity moonshot executes without a confirmed model. |
| A224 | The complete `2^32` post-barrier label places the best unchanged trajectory at rank 4. |
| A225 | The same label procedure is completed over the `2^40` transfer domain. |
| A226 | The frozen dual-order minimax validation is weak and is retained as a boundary. |
| A227--A228 | The prospective top-4 route does not recover the target; its true-cell rank is 64. |
| A229--A230 | The top-64 replay recovers 0 of 7 held-out targets. |
| A231--A232 | Tie-aware ranks are `[64, 4, 136, 188, 38, 17, 37]`; 5 of 7 are posthoc top-64. |
| A233--A234 | A disjoint replay yields 1 of 7 top-64; the exact binomial upper tail is `0.86651611328125`. |
| A235 | The authoritative Causal semantic readback reproduces the retained chain. |

UNKNOWN observations remain UNKNOWN. They are not relabeled as UNSAT or as
evidence that a model is absent.

## Independently confirmed full-round recovery records

Each row executed the complete declared residual domain with no early stop. A
factual target produces one full-output match and the bit-flipped control
produces zero. The recovered candidate is checked by an implementation
independent of the accelerator kernel.

| Attempt | Primitive | Residual domain | Assignment | Confirmed output | Accelerator seconds |
| --- | --- | ---: | ---: | ---: | ---: |
| A237 | Speck32/64 | `2^42` | `3099631123999` | 64 bits | `959.8156910734251` |
| A240 | Threefish-256 | `2^38` | `68427043728` | 256 bits | `860.7408324554563` |
| A244 | Speck64/128 | `2^44` | `17005369072308` | 128 bits | `4663.661081965547` |
| A246 | SIMON64/128 | `2^43` | `4109884320956` | 128 bits | `4070.0485156532377` |
| A248 | RC5-32/12/16 | `2^40` | `964575894496` | 128 bits | `4593.603102961555` |
| A253 | PRESENT-80 | `2^38` | `250884064964` | 128 bits | `4244.285444871988` |
| A256 | Ascon-AEAD128 | `2^40` | `56559342585` | 384 bits | `4615.997359492816` |
| AES-W41 | AES-128 | `2^41` | `1914598048454` | 256 bits | `2255.3558697528206` |
| A264 | Salsa20/20 | `2^42` | `1767048180590` | 512 bits | `3153.3164217788726` |

The Speck and SIMON rows use corrected, known-answer-test-passing reference
implementations. They do not reuse the invalid historical Nano implementations
described in `research/CODE_VERSION_LEDGER.md`.

## Fresh Reader series

The selected score, exact null probability, and retained status are:

| Attempt | Score | Exact/null-adjusted p | Retained |
| --- | ---: | ---: | --- |
| A249 | `+0.190240132998` | `0.29296875` | no |
| A250 | `+0.091500811452` | `0.375` | no |
| A251 | `-0.103250607742` | `0.4921875` | no |
| A259 | `-0.190073368025` | `0.546875` | no |
| A260 | `-0.148006498487` | `0.52734375` | no |
| A261 | `-0.331444067324` | `0.7421875` | no |
| A262 | `-0.436741023906` | `0.8359375` | no |
| A265 | `+0.609253427408` | `0.9765625` | no |
| A266 | `-0.428159963595` | `0.77734375` | no |
| A267 | `+1.329883446168` | `0.01953125` | yes |
| A268 | `+0.368615918495` | `0.20703125` | no |
| A270 | `+0.062855042631` | `0.375` | no |
| A271 | `+1.216796267632` | `0.2734375` familywise | no |
| A272 | `+1.618751710092` | `0.00390625` | yes |

The non-retained rows remain useful measurements: they determine which channel,
representation, and combination rules do not transfer under their frozen nulls.

## Two-target selected-channel chain

- A273 freezes a complete 256-cell order without a target label. Its selected
  top 128 cells cover `2^19` residual assignments.
- A274 solves 90 of those 128 cells (368,640 assignments) and recovers low20
  `0x987f0`. Two independent ChaCha20 implementations match all 4,096 output
  bits and the flipped-target control fails.
- A275 repeats the prereveal ordering protocol on a distinct target. The target
  label is unavailable during order construction.
- A276 proves all 128 selected cells exactly UNSAT, covering 524,288 assignments.
  This is a certified selected-half boundary, not a recovery claim.
- A277 imports those 128 exact UNSAT cells into one retained global solve. The
  solve returns SAT in `293.342` seconds within the frozen 300-second budget and
  recovers low20 `0x5a770`. Two independent implementations match all 4,096
  output bits and the flipped-target control fails. The confirmed model is found
  before complete remaining-half enumeration; no new exact UNSAT prefix cell is
  claimed by the global phase.

## Reproduction and integrity

The release entry point is:

```bash
./scripts/reproduce_a223_a277.sh
```

It first verifies `research/results/v1/A223_A277_SHA256SUMS`, then executes the
focused test list in `research/results/v1/A223_A277_TESTS.txt`, and finally reads
every retained `.causal` artifact through the appropriate legacy or AI-native
Reader. Individual experiment scripts remain available for exact protocol
inspection and controlled reruns. Production-scale complete-domain accelerator
runs are not silently launched by the release entry point.
