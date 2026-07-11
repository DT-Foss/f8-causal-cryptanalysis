# F8-Causal

**Full-Round Distinguishers, Causal Readers, and Reproducible Cryptanalysis**

F8-Causal is David Tom Foss's executable research archive for cross-round F8,
CASI/LiveCASI, and CryptoCausal Reader analysis. It preserves the twelve
original full-round F8 configurations, the Nanjing and Rome conference
evidence, and the subsequent A107--A138 full-round relations as code, typed
`.causal` graphs, result JSON, controls, tests, and SHA-256 manifests.

The central result is a family of **full-round, exactly checkable cryptanalytic
relations** spanning block ciphers, hash compression functions, stream-cipher
permutations, and Keccak-f[1600]. The repository distinguishes four objects
precisely:

- a **distinguisher** separates a tested relation from its registered controls;
- a **Reader** executes a relation stored in an audited `.causal` graph;
- **state reconstruction** recovers the stated internal coordinates under the
  listed known variables;
- **key recovery** is named only where a key is actually recovered. None of the
  results below is relabeled as key recovery.

![SHAKE exact-search frontier](docs/figures/shake_frontier.svg)

## Result landscape

| Evidence | Primitive / endpoint | Full-round result | Attack model and known variables | Recovered object | Primary evidence |
|---|---|---|---|---|---|
| Original anchors | Speck, Threefish, GIFT, PRESENT, TEA, RC5 | 12 full-round F8 configurations across four mechanisms | Known-key internal `state(R)` / `state(R+1)`, matched inputs | Cross-round distinguisher cells | [anchor suite](provenance/fullround_anchors/f8/README.md), [audit](research/reports/SESSION_FULLROUND_IMPORT_AUDIT_V1.md) |
| A107--A109 | PRESENT-128 R31→R32 | Seven-cell exact population support; all five confirmation keys beat every BvN route | Known key, matched plaintext, adjacent internal boundary | Exact F8 support and MI | [report](research/reports/FULLROUND_CAUSAL_PRESENT128_V1.md) |
| A110--A112 | SHA-256 / SHA-512 compression | Exact same-lane feed-forward relation after 64/80 steps and full carry spectrum | Compression input/chaining state known | Eight post-round words; exact carry classes | [report](research/reports/FULLROUND_CAUSAL_SHA2_FEEDFORWARD_V1.md) |
| A113--A114 | FEAL-32X R30→R32 | Reader reconstructs 40,000/40,000 complete 32-bit state halves | Known two-byte round subkey and cross-round left-half difference | R30 right half | [report](research/reports/FULLROUND_CAUSAL_FEAL32X_V1.md) |
| A115 | SHACAL-2 R63→R64 | Shared-`T1` cancellation reconstructs 40,000/40,000 complete words | Known key; internal full-round endpoint | `d63` word | [report](research/reports/FULLROUND_CAUSAL_SHACAL2_V1.md) |
| A116 | SPARKLE-256/384/512 | Exact endpoint projection plus complete-basis linear-order proofs | Public permutation; final state | Pre-final-step left half and full-step inverse state | [report](research/reports/FULLSTEP_CAUSAL_SPARKLE_V1.md) |
| A117--A118 | BLAKE3 compression | Full 64-byte output plus known CV reconstructs all 512 post-round bits; exact coupled-borrow spectrum | Complete compression output and input CV | Post-round compression state | [report](research/reports/FULLCOMPRESSION_CAUSAL_BLAKE3_V1.md) |
| A119--A120 | ChaCha20 block | Public inputs reconstruct eight core lanes; known key reconstructs all sixteen; exact conditional carry spectrum | Standard block output plus constants/counter/nonce; key only for key lanes | Post-round-20 core | [report](research/reports/FULLROUND_CAUSAL_CHACHA20_FEEDFORWARD_V1.md) |
| A121 | SHAKE128 / SHAKE256 | Complete first squeeze block reconstructs every post-permutation rate lane | Public output block | 1,520,000 exact 64-bit lanes over confirmations | [report](research/reports/FULLROUND_CAUSAL_SHAKE_RATE_V1.md) |
| A122 | SHAKE next-block Jacobians | Ten capacity-to-rate Boolean Jacobians have full rank 256/512 | Fixed first-squeeze base; single capacity-bit intervention | Intervention coordinate | [report](research/reports/FULLROUND_CAUSAL_SHAKE_CAPACITY_JACOBIAN_V1.md) |
| A123--A127 | SHAKE consecutive-block windows | Unique exact 8--32-coordinate consistency through all 24 Keccak rounds | Complete first state except declared capacity window; next rate block | Window assignment; 8,589,934,592 candidates at 32 bits | [report](research/reports/FULLROUND_CAUSAL_SHAKE_NATIVE_WINDOW_V1.md) |
| A128--A129 | SHAKE Boolean constraints and prefix frontier | Exact CNF reconstruction at 4/8/12 coordinates; R3 collapse of single-coordinate branch certificates; 32 output bits uniquely identify both tested 16-bit windows | Known first-squeeze-state complement; A128 complete next-rate constraints; A129 one deterministic `2^16` window per variant | Exact assignment and mechanistic solver/observability boundaries | [report](research/reports/FULLROUND_CAUSAL_SHAKE_SOLVER_FRONTIER_V1.md) |
| A130 | SHAKE affine-hull prefix distinguisher/Reader | Exact 128-coordinate GF(2) hull membership leaves only the actual 10-bit prefix in both variants | Known first-squeeze-state complement; one complete 16-bit window truth space per variant; 128 next-rate coordinates | Exact 10-bit window prefix | [report](research/reports/FULLROUND_CAUSAL_SHAKE_AFFINE_HULL_V1.md) |
| A131 | SHAKE algebraic-degree frontier | Restricted coordinate ANFs reach full degree 16 and random-like density at R5, remaining saturated through R24 | Known first-squeeze-state complement; one complete 16-bit window truth space per variant; first 128 rate coordinates | Exact round-localized ANF degree and density | [report](research/reports/FULLROUND_CAUSAL_SHAKE_ALGEBRAIC_DEGREE_V1.md) |
| A132 | SHAKE Boolean-influence frontier | R3 is nearly all-to-all; measured R4, R5, and R24 are completely coupled and influence-balanced in all six exhaustive trials | Known first-squeeze-state complement; three complete 16-bit windows per variant; all 1,600 state coordinates | Exact round-localized 16x1,600 influence matrices | [report](research/reports/FULLROUND_CAUSAL_SHAKE_BOOLEAN_INFLUENCE_V1.md) |
| A133 | SHAKE shared-ANF compression | Formula-space transform yields 20.44x/19.84x R3 advantage over best raw compression; disk Reader reconstructs 419.43M truth values | Known state complement; complete `2^16 x 1,600` restricted truth spaces | Exact shared formula dictionary and coefficient matrix | [report](research/reports/FULLROUND_CAUSAL_SHAKE_ANF_COMPRESSION_V1.md) |
| A134 | SHAKE direct symbolic R2 | Complete 256-/512-coordinate capacity interfaces compile exactly without truth-table materialization | Known starting-state complement and Keccak round equations | All 1,600 exact R2 coordinate formulas | [report](research/reports/SHAKE_SYMBOLIC_R2_ANF_FRONTIER_V1.md) |
| A135 | SHAKE native-XOR full-round Reader | Exact unique reconstruction at 4/8/12 coordinates with 3.53%/17.02%/5.98% of canonical-CNF decisions | Known first-state complement; complete next-rate observation | Exact capacity-window assignment | [report](research/reports/FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_SMT_V1.md) |
| A136 | SHAKE partitioned full-round Reader | Ground-truth-blind 16-branch schedule reconstructs assignment 35,837 and independently matches all 1,344 rate bits | Known first-state complement; complete next rate; exhaustive low-four prefix partition | Verified 16-coordinate model | [report](research/reports/FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_PARTITION_V1.md) |
| A137 | SHAKE symbolic split frontier | R1 minimizes decisions against R2/R3; width-12 R1 is 196.46x below canonical CNF | Matched full-round query; verified width-16 model branch for split comparison | Exact minimum-decision handover interface | [report](research/reports/FULLROUND_CAUSAL_SHAKE_SYMBOLIC_SPLIT_FRONTIER_V1.md) |
| A138 | SHAKE monolithic R1 Reader | Unpartitioned width 16 returns assignment 35,837 in 4,701 decisions and independently matches 1,344/1,344 bits | Known first-state complement; complete next rate; no supplied prefix | Verified 16-coordinate model | [report](research/reports/FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_SCALING_V1.md) |

The complete A107--A138 ledger, including complexity and controls for every
class, is in [docs/RESULTS.md](docs/RESULTS.md). Earlier direct-output,
compression-cascade, AES, ChaCha, PRESENT, Threefish, SIMON, and ML-KEM work is
indexed in the [research report matrix](research/reports/NIGHTRUN_DIRECT_CAUSAL_MATRIX_V1.md)
and the append-only [attempt log](research/ATTEMPT_LOG.md).

## Three connected methods

### F8

F8 evaluates matched states after `R` and `R+1` rounds under the same key and
input, then measures structured dependence between the round-`R` state and the
cross-round difference. The original full-round suite contains Speck32/64,
Speck48/96, Speck64/128, Speck128/256, Threefish-256, Threefish-1024, GIFT-64,
GIFT-128, PRESENT-80, TEA, RC5-32/12/16, and RC5-64/24/24.

### CASI and LiveCASI

CASI is a compression-based structural measurement over cipher outputs.
`src/arx_carry_leak/live_casi_v091/` preserves the LiveCASI 0.9.1 core, while
`src/arx_carry_leak/nano_ciphers.py` supplies the portable 41-cipher Nanjing
registry. CASI and F8 remain separate measurements with separate result
schemas and controls.

### CryptoCausal Reader

`.causal` files are typed evidence graphs, not opaque sidecars. The
`CryptoCausalReader` validates the format version, canonical graph digest,
triplets, inferred-edge provenance, parameters, and executable reconstruction
recipe. Every committed `.causal` artifact is checked by
`scripts/validate_causal_artifacts.py`.

## Reproduce from a fresh clone

```bash
git clone https://github.com/DT-Foss/f8-causal-cryptanalysis.git
cd f8-causal-cryptanalysis
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

Five evidence tiers make cost explicit:

| Tier | Command | Purpose |
|---|---|---|
| `quick` | `./scripts/reproduce_quick.sh` | vectors, focused tests, Reader validation, manifest verification |
| `standard` | `./scripts/reproduce_fullround_transfers.sh` | regenerate A107--A126 transfers and A129--A138 SHAKE frontiers |
| `extended` | `./scripts/reproduce_shake_native_extended.sh` | resumable A127 native 32-coordinate SHAKE enumeration |
| `solver` | `./scripts/reproduce_shake_solver_frontier.sh` | reproduce A128--A138 Boolean, algebraic, compression, symbolic, and partition Readers |
| `anchors` | `./scripts/verify_anchors.sh` | hash-verify the twelve original full-round configurations without rerunning them |

Expected quick-tier terminus:

```text
anchor manifest: OK
full-round transfer manifest: OK
causal artifacts: all valid
```

The native Reader is C11/POSIX and builds with Apple Clang on Apple Silicon or
GCC/Clang on Linux. The 32-coordinate run is bounded-memory, ten-threaded, and
resumable. Full commands, runtimes, expected files, and portability notes are
in [docs/REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md).

## Repository map

```text
src/arx_carry_leak/             installable F8, CASI, Reader, and cipher code
research/experiments/           executable experiments
research/results/               retained JSON, .causal, and SHA-256 manifests
research/reports/               result-level scientific interpretation
research/ATTEMPT_LOG.md         chronological A001--A138 evidence ledger
provenance/fullround_anchors/   committed twelve-configuration F8 snapshot
provenance/dependencies/        minimal licensed source required by an experiment
data/reference/                 Nanjing/Rome reference datasets
paper/                          author-owned TeX, figures, and sanitized slide source
docs/                           methods, results, claims, prior art, publication audit
```

## Citation and authorship

Author and maintainer: **David Tom Foss**. Cite the software metadata in
[`CITATION.cff`](CITATION.cff). The associated conference works are:

- *Persistent Cross-Round Carry Leakage in ARX Ciphers: Detection, Prediction,
  and Topological Classification*, IEEE ICECET 2026, Rome.
- *Compression-Based Trust Verification of Lightweight Ciphers Deployed in
  Nano-IoT Communication Standards*, IEEE NANO 2026, Nanjing.

No DOI is asserted until one is assigned by the relevant publisher or archive.
See [docs/PRIOR_ART.md](docs/PRIOR_ART.md) for the hash- and commit-based public
record.

## License

Original repository code and documentation are BSD-3-Clause licensed. Narrow
vendored and retained historical components keep their own terms and
attribution; see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). The short
[`PATENT_NOTICE.md`](PATENT_NOTICE.md) states that no separate express patent
license is granted and makes no filing claim. Conference paper text and slides
are included as author-owned source material; publisher-formatted PDFs and
peer-review correspondence are excluded.
