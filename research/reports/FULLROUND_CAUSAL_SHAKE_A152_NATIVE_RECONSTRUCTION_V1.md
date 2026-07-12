# SHAKE A152 Native Full-Round Reconstruction v1

## Result

A165 transfers the retained native candidate-axis Causal Reader to the exact
prospective SHAKE128 instance frozen and executed in A152.  It enumerates the
complete 24-bit capacity-window domain, retains every candidate matching the
first 128 public rate bits, and independently evaluates every retained
candidate over all 24 Keccak-f[1600] rounds and all 1,344 public rate bits.

The complete result is:

| Quantity | Result |
|---|---:|
| logical candidates | 16,777,216 |
| native 64-candidate packs | 262,144 |
| packs freshly executed | 262,144 |
| resumed packs | 0 |
| 128-bit filter matches | 1 |
| independent 1,344-bit full matches | 1 |
| reconstructed assignment | **9,279,571** |
| bit-flipped-target filter matches | 0 |
| bit-flipped-target full matches | 0 |

The A152 posthoc assignment is not read until the complete domain and both
target arms have executed.  It is then loaded solely for comparison and equals
the independently reconstructed assignment exactly.  A165 therefore converts
A152's symbolic resource boundary into a retained, assignment-free full-round
model reconstruction on the same prospectively generated instance.

## Public input boundary

The native enumeration function receives exactly three runtime objects:

```text
cleared 1,600-bit state template
public 1,344-bit next-rate target
ordered capacity-window coordinates [143, 167)
```

It receives no base state containing the hidden bits, assignment, projection,
stored model, A152 posthoc field, or symbolic-solver observation.  The public
relation is regenerated from A152's hash-derived seed and must match these
frozen fingerprints before execution:

- cleared template:
  `8dd7a73132ae11987e86866552701cc7d093771ec911ee94883d114d3afb33d2`;
- complete target rate:
  `435edcaaa1288f8b812aea055dacc9aadc6dc1dd7416a2102459d2bc7526141c`;
- coordinates: every capacity bit from 143 through 166 inclusive;
- seed: 260,592,673.

The declared scope is exact known-complement state-window reconstruction: 24
unknown capacity bits, the other state bits known, all 24 specified rounds, and
the complete 1,344-bit SHAKE128 rate observation.  It is a full-round model
search over the complete declared domain; it does not substitute a claim about
an unrestricted 256-bit-capacity preimage problem.

## Causal Reader execution

A165 does not reconstruct the native method from prose.  It opens the retained
native `.causal` artifact with `CryptoCausalReader`, verifies provenance, and
extracts the unique SHAKE128 executable recipe.  The recipe fixes:

- 24 Keccak-f[1600] rounds;
- 64 candidates per machine word;
- two rate lanes for the native filter;
- independent scalar complete-rate confirmation;
- native source SHA-256
  `3189f301d25b1bc38c867dae840edb3c8e710ffa5960e02035b43a72c0889d81`.

The current compiled kernel is additionally compared with the independent
NumPy implementation on 64 complete random states.  All 102,400 state bits
match exactly before the A152 domain is evaluated.

Candidate order is ascending unsigned integer order.  Ten native threads
evaluate all 262,144 packs in one bounded 4-MiB two-mask batch; no early stop is
allowed.  The parallel control target flips bit zero of the first public rate
lane and traverses the identical complete domain in the same native call.

Checkpoint resumes are fail-closed: the fingerprint binds variant, rate-lane
count, exact ordered coordinates, cleared template, factual target, control
target, native source, window width, thread count and stream size.  Candidate
ranges and duplicates are validated.  The retained production run is fresh and
uses zero resumed packs.

## Independent confirmation

The native 128-bit filter emits assignment 9,279,571.  A separate NumPy lane
implementation injects that assignment into the cleared template, executes all
24 rounds, and compares all 21 rate lanes.  Its candidate and target hashes are
identical:

```text
435edcaaa1288f8b812aea055dacc9aadc6dc1dd7416a2102459d2bc7526141c
```

Only after this gate and complete-domain execution does the runner parse A152's
posthoc record.  The reconstructed singleton set `[9279571]` equals A152's
instrumented singleton exactly.

## Consumer-hardware execution

The retained production invocation was observed externally at:

```text
real 1.61 s
user 10.93 s
sys  0.06 s
```

Hardware: Apple M4 Mac mini, 10 CPU cores, 16 GB memory, arm64.  Wall-clock and
machine metadata are deliberately outside the canonical JSON so reruns retain
the deterministic scientific object rather than a timing hash.  The measured
1.61-second run includes relation gates, native build loading, current-build
cross-check, complete factual/control enumeration, independent confirmation,
Causal construction, and final artifact reopen.

## Retained bindings

- frozen A165 protocol:
  `66369688662b77a5a9b5fe49ab3bad5f6a513e809260e5293773dd8b3fe42498`;
- A152 prospective result anchor:
  `0e01e3e6ff0b9a80ff66ad6614f846305188d96a4497ca38857eac81097a1561`;
- retained native result anchor:
  `8497ccb7938da721b71876cf481bcc4175b7f5b25c5f3300a87e09a6f123e604`;
- retained native Causal anchor:
  `f90cf74a0d97f07b0d037639dc9d9beee2e0f7dec3360c51ebf802e27e04550f`;
- A165 complete-domain execution:
  `ac8e9820e4b501b2eda98c68e0d16ab579685ccdc9b7de0bea24dc307a63d5fc`;
- A165 independent confirmation:
  `81fcf52e58b3a66ade72204d121a804581dab1d36e2167510e4d77e3a859ed37`;
- A165 result JSON:
  `4a3312fe50686744d3db56a5c228128e7106fe071d672128459bda481f675ed0`;
- A165 Causal artifact:
  `be53ad7b6948abe7465b41a50bc4128ff8f20aa3150a32936927f309ddbac02e`;
- canonical A165 Causal graph:
  `1ef4fe5a6ced7cfe84d86f6d8dffe1788f915cb77f03b6ade629bcd1bfd007c3`.

The five-edge A165 Causal chain connects retained native recipe, public A152
relation, complete packed execution, independent complete-rate confirmation,
and post-execution A152 comparison.  `CryptoCausalReader` reopens and verifies
the complete chain.

## Reproduction

Fast protocol, anchor, public-relation, small-domain native, artifact and Reader
gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_a152_native_fullround_reader_transfer.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_a152_native_fullround_reader_transfer.py
```

Fresh full-domain execution:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_a152_native_fullround_reader_transfer.py \
  --no-resume
```

## Consequence

A165 establishes that A152's unresolved Z3 result was a representation and
search-strategy boundary, not an executable barrier for its complete logical
domain.  Candidate-axis packing transforms 16,777,216 logical full-round
assignments into 262,144 native machine-word evaluations and recovers the
unique model in 1.61 seconds on an ordinary Mac mini.

This directly joins the two research lines: the symbolic/Causal work explains
which representations alter solver traversal, while the native Causal Reader
provides exact reconstruction when the remaining domain is enumerable.  The
next high-leverage step is to use A164's universal `0x4e1e28` gauge and suffix
structure to predict stronger symbolic reductions beyond the native exhaustive
window frontier, rather than spending more runs on arbitrary order tweaks.
