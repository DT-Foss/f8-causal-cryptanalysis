# SHAKE256 Native Width-32 Full-Round Reconstruction v1

## Result

A177 executes the prospectively frozen SHAKE256 width-32 relation over its
complete declared candidate domain.  The retained native candidate-axis Causal
Reader evaluates all `2^32` assignments through all 24 Keccak-f[1600] rounds,
filters on the first 128 public rate bits, and independently confirms every
survivor over all 1,088 public rate bits.

The complete result is:

| Quantity | Result |
|---|---:|
| logical candidates | 4,294,967,296 |
| native 64-candidate packs | 67,108,864 |
| stream batches | 64 |
| packs freshly executed | 67,108,864 |
| resumed packs | 0 |
| 128-bit filter matches | 1 |
| independent 1,088-bit full matches | 1 |
| reconstructed assignment | **2,761,171,082** |
| bit-flipped-target filter matches | 0 |
| bit-flipped-target full matches | 0 |

The complete domain executes without early stopping.  Only after that completion
gate does A177 extract the instrumented capacity-window value.  The posthoc
value is 2,761,171,082 and exactly equals the independently reconstructed
singleton.

## Frozen prospective protocol

The protocol was frozen before any A177 candidate execution at
`research/configs/shake256_native_fullround_width32_prospective_v1.json`, with
SHA-256:

```text
f4e3ee4b43a536d7ccf51964de768953019ecf96819f661a50edaa549d6db068
```

Its predeclared prediction is one exact SHAKE256 model over the complete `2^32`
domain and zero exact models for the bit-flipped control.  Its success rule
requires complete-domain execution, a unique complete-rate match, control
rejection, and posthoc identity.

The seed is derived from the retained A176 JSON hash using:

```text
f8-causal:A177:shake256:32:4b609a6f4388c9a759625169aebe94309b808608e061b4f033c66a22cc992a60
```

The derivation SHA-256 is
`287f1840310ee763cceb6275e07ccf081c01681ce034493db880036d3894fbcc`,
and its declared 31-bit seed is 679,417,920.

## Public relation and information boundary

The native enumerator receives the cleared 1,600-bit state template, the public
1,088-bit next-rate target, and the ordered 32-bit capacity window.  The window
contains every position from 184 through 215 inclusive.  The frozen public
fingerprints are:

- ordered-position digest:
  `a11708366dd174e74599b59905cde9969aae3294a3aade1f773e0cd2e9726e39`;
- cleared-template digest:
  `6154abe45a4b15942c808b05a04543b0f827d2901b12a0fb369eb6fa1cf1a962`;
- message digest:
  `2bd95982a2e6dca777191c7bd135e94edbab9d188f5829acbc27c0f29e6bc0bd`;
- full target-rate digest:
  `62f4f1019011f2e380a676e70395092b114b76790ae05a7cee7f2157408c6f6c`;
- bit-flipped control-rate digest:
  `8ea194e51e0c815c163f96ddb7ecd91b81e8b47ecbf98f13b4da3124736cb5f5`.

The protocol contains no instrumented assignment.  The candidate generator,
native filter, and independent confirmation receive no instrumented assignment.
The executor records both `instrumented_assignment_input_used=false` and
`posthoc_assignment_read_before_candidate_execution=false`.  The instrumented
value is extracted exclusively after the complete-domain gate for the final
prospective comparison.

The exact scope is known-complement state-window reconstruction: 32 declared
capacity bits are unknown, all other state bits are fixed by the public
template, and the observation is the complete next 1,088-bit SHAKE256 rate.

## Native complete-domain execution

`CryptoCausalReader` opens the retained native artifact, verifies provenance,
and extracts the SHAKE256 execution recipe.  It fixes:

- SHAKE256 with 512-bit capacity and 17 rate lanes;
- all 24 Keccak-f[1600] rounds;
- 64 candidates per native `uint64_t` pack;
- two rate lanes, or 128 bits, for the native filter;
- independent scalar complete-rate confirmation;
- native source SHA-256
  `3189f301d25b1bc38c867dae840edb3c8e710ffa5960e02035b43a72c0889d81`.

Before enumeration, the current native build is compared against the
independent NumPy implementation on 64 complete states.  All 102,400 state bits
match exactly.

The runner partitions 67,108,864 packs into 64 batches of 1,048,576 packs.
Ten native threads process every batch for both the factual and bit-flipped
control targets.  There is no early-stop branch.  The retained run starts at
pack zero, resumes zero packs, and executes all 67,108,864 packs freshly.

Checkpoint/resume is bound to the protocol hash, native source, seed, window,
ordered-position digest, template, factual target, control target, thread count,
and stream size.  Progress must be batch-aligned and candidate lists must be
unique and confined to the executed prefix.  The completed retained run removes
its checkpoint after writing and reopening the final JSON and Causal artifacts.

The canonical execution-plan digest is:

```text
b9c263610522fcdedda070298bc3e5d4bd81a6f15369c1c7ad1cf1a968f14104
```

The canonical complete-domain execution digest is:

```text
2f5597ba3730a2ab6163db47a3b36ca9a7bad3193c271ec3bc9ed8157a32f84d
```

## Independent complete-rate confirmation

The native 128-bit filter returns exactly assignment 2,761,171,082.  A separate
NumPy lane-core implementation injects that assignment into the cleared
template, executes all 24 rounds, and compares all 17 rate lanes.  All 1,088
bits match.  The independently produced rate digest equals the frozen target
digest:

```text
62f4f1019011f2e380a676e70395092b114b76790ae05a7cee7f2157408c6f6c
```

The bit-flipped control returns no 128-bit filter candidate and no complete-rate
model.  The canonical factual/control confirmation digest is:

```text
c8abd5902d058fb6c7ecd2e12121b81aaf57854c2efbe9808d4202987715a5a9
```

## Causal Reader chain

The retained Causal artifact contains exactly five explicit edges:

1. A176-derived and hash-frozen SHAKE256 width-32 public relation;
2. hash-pinned native SHAKE256 full-round Reader recipe;
3. complete 67,108,864-pack factual/control execution;
4. independent complete-rate confirmation of every filter survivor;
5. post-execution prospective comparison with the instrumented assignment.

Every edge points to its direct predecessor, each predecessor outcome equals
the next trigger, there are no inferred edges, and `CryptoCausalReader` verifies
the complete provenance chain.

Retained hashes:

- A177 result JSON:
  `d6b85ca7f15bc198513cd05100187f2ccc0ab97d1f22a906383ccd4a62eda544`;
- A177 Causal artifact:
  `05ce09d28994ee6e414ff9e62265c20c3ab819b1d2b343240d3c030943a8c5ab`;
- canonical A177 Causal graph:
  `147294256873d0018e064bd181b120b380f273bd0a3279c99e17ce98f9e05055`;
- retained A176 JSON anchor:
  `4b609a6f4388c9a759625169aebe94309b808608e061b4f033c66a22cc992a60`;
- retained native result anchor:
  `8497ccb7938da721b71876cf481bcc4175b7f5b25c5f3300a87e09a6f123e604`;
- retained native Causal anchor:
  `f90cf74a0d97f07b0d037639dc9d9beee2e0f7dec3360c51ebf802e27e04550f`.

## Timing provenance

The interactive production invocation was observed at roughly 247 seconds.
This observation is operational context, not a controlled benchmark.  Volatile
wall-clock timing and machine metadata are deliberately excluded from the
canonical result, and no performance claim is derived from that observation.

## Reproduction

Fast protocol, anchor, public-relation, synthetic resume, retained-artifact and
Causal Reader gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake256_native_fullround_width32_prospective.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake256_native_fullround_width32_prospective.py
```

Fresh complete-domain execution with the default fail-closed checkpoint:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake256_native_fullround_width32_prospective.py
```

To require a fresh start while keeping subsequent checkpoint writes enabled,
remove only the matching A177 checkpoint before invoking the same command.  A
successful run removes that checkpoint after final artifact validation.

## Consequence

A177 extends the retained native full-round reconstruction frontier from the
SHAKE256 width-28 anchor to a prospectively frozen width-32 instance.  It
executes 4,294,967,296 logical assignments as 67,108,864 candidate-axis packs,
recovers one exact model, independently confirms all 1,088 public output bits,
rejects the complete bit-flipped control, and matches the posthoc assignment
exactly.
