# Causal-format method audit for cryptographic use

## Paper anchors

The following local papers were read as the methodological specification:

| Paper | SHA-256 |
|---|---|
| `IRI2026_The_Causal_Format_Embedded_Deterministic_Inference.pdf` | `7e2055c3000aa28eebf64d9e89ff1fbeedffa57b83151b4c965d6e6da07b83e8` |
| `Foss_CompressionIsolationPQC_ICECET2026.pdf` | `7f24041373f971d03502d2bd2158aaf4bc436f5f786f6343fe31edc83ab89bd7` |
| `Foss_CausalGraphCryptanalysis_ICECET2026.pdf` | `3dd925d1dae2f2815bb6d83b34c1351970f2c39950a5887e6d92f6b4a34be51d` |

The reusable principles are deterministic extraction, typed triplets,
mechanism-specific composition, provenance, representation interventions and
explicit null normalization. Generic string similarity is not a valid relation
generator for structured cipher variables.

## Current general builder/reader audit

Audited implementation:
`../andere causal/dotcausal_package/src/dotcausal/`.

The implementation is useful as a general knowledge container, but its current
behavior does not match several properties required by the papers or by a
cryptographic mechanism study:

1. `run_inference` composes pairs drawn from the explicit input only. Inferred
   edges are not fed back into the indices, so it is a two-hop derivation pass,
   not a complete recursive transitive closure.
2. Inferred dictionaries carry an evidence string but no source edge indices
   or `inference_chain`. The writer's stored triplets have such a field, but the
   reader-side inference result does not populate it.
3. Pass 3 uses synonym/token/Jaro-Winkler matching with an automatically chosen
   threshold between 0.72 and 0.88. For entities such as `round_71_word_2`,
   `delta_word_2` and `round_72_word_2`, this would create naming-schema edges.
4. The current writer emits a 64-byte header plus a 32-byte offset table and an
   uncompressed MessagePack-or-JSON body. That differs from the paper's current
   8-byte-header, zlib-compressed sequential format description.
5. Existing Crypto-CASI graph generation combines observations with manually
   encoded architecture/weakness triplets. Consequently, an inferred
   “discovery” can originate from prior ontology rather than an output
   intervention.

These are not reasons to discard the format idea. They define the requirements
for a cryptographic specialization.

## Cryptographic specialization

`src/arx_carry_leak/crypto_causal.py` implements the constrained variant used by
the new experiments:

- 8-byte `CAUSAL` + `uint16` header;
- canonical JSON compressed with zlib;
- embedded SHA-256 of the canonical graph;
- exact typed mechanism rules only;
- recursive exact-rule closure with bounded hop count;
- complete source-edge IDs on every inferred edge;
- one best path per typed edge, preventing correlated re-derivations from being
  counted as independent evidence;
- no synonym, token-overlap or fuzzy pass.

The graph does not infer cryptographic causality from topology. Causal edges
enter only through one of three evidence kinds:

1. an algebraic identity checked on every row;
2. a mechanism intervention with all non-intervened variables fixed; or
3. a paired/BvN randomization control.

This distinction is essential: transitive closure amplifies evidence already
present in the graph, but it cannot turn association into causation.
