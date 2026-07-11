# Prior-art record

## Public identity

Project: **F8-Causal — Full-Round Distinguishers, Causal Readers, and
Reproducible Cryptanalysis**

Author: **David Tom Foss**

Canonical repository:
`https://github.com/DT-Foss/f8-causal-cryptanalysis`

The annotated tag `v0.1.0-prior-art` identifies the first curated public
snapshot. Resolve it without trusting this document:

```bash
git fetch --tags
git rev-parse 'v0.1.0-prior-art^{}'
git tag -v v0.1.0-prior-art  # verifies only when a signing key is configured
```

The tag is annotated but not asserted to be cryptographically signed unless
`git tag -v` succeeds in the consumer's clone.

## Evidence chronology

| Record | Evidence |
|---|---|
| IEEE ICECET 2026, Rome | Author-owned TeX source for *Persistent Cross-Round Carry Leakage in ARX Ciphers: Detection, Prediction, and Topological Classification* |
| IEEE NANO 2026, Nanjing | Author-owned TeX and sanitized presentation source for *Compression-Based Trust Verification of Lightweight Ciphers Deployed in Nano-IoT Communication Standards* |
| 2026-07-11 | Original twelve-configuration F8 suite finalized at source commit `2e23b23e46cd7a413edd5b56a748e4d5e6e62f73` by David Tom Foss |
| 2026-07-11 | A107--A132 append-only experiment ledger: PRESENT-128 through native 32-coordinate SHAKE consistency, exact Boolean reconstruction, prefix observability, affine-hull prefix identification, restricted ANFs, and the Boolean-influence frontier |
| `v0.1.0-prior-art` | First public, audited F8-Causal publication tree |

The conference names and year come from the author's source metadata. No DOI,
publisher pagination, archival acceptance date, or exact presentation date is
invented here.

## Artifact roots

| Artifact | SHA-256 |
|---|---|
| `paper/icecet2026/main.tex` | `450d14503b9549b364f8a121034dfec9a584506527c0f45860ab5001ab3cae64` |
| `paper/nano2026/main.tex` | `1269cfc7c24fb6ad2d3551ccea74f60fde4404967fe8b6710ba3acb8df887ed2` |
| Sanitized Nanjing presentation source | `577607f1e1b2893234836f98999428ace0894a5362b5b85b6609565c1a70356c` |
| `ANCHOR_SHA256SUMS` | `90f50ecdbe01e4de0afa4c858a57d916fc1794344375303a501a301c80e192e8` |
| `FULLROUND_TRANSFER_SHA256SUMS` | `8d61d96da3da0033401fe3b594b60cbf1d1607e764c233900627458df5e41fa8` |
| `SHAKE_NATIVE_EXTENDED_SHA256SUMS` | `64f650b7b44e5db37cd2c53e97e52a20da3e31b5d6a3002b66398b6b3e509371` |
| `SHAKE_SOLVER_FRONTIER_SHA256SUMS` | `8912afe5b4212583e005bb4ac21e8cbcba19a74eb22e3f7a01b29e805775b1ee` |

The manifest digest authenticates the manifest; each manifest in turn lists the
exact result JSON, `.causal`, source, or anchor file digests. Verify all layers
with `scripts/verify_hash_manifest.py`.

## Full-round result identifiers

The stable A107--A132 identifiers are defined in
`research/ATTEMPT_LOG.md`. Their promoted artifacts are immutable inputs to the
publication:

- A107--A109: PRESENT-128 transfer, fixed-point localization, exact theorem;
- A110--A112: SHA-256/SHA-512 feed-forward and carry spectra;
- A113--A114: FEAL-32X representation boundary and exact Reader inverse;
- A115: SHACAL-2 cancellation Reader;
- A116: SPARKLE full-permutation relations;
- A117--A118: BLAKE3 state Reader and coupled-borrow spectrum;
- A119--A120: ChaCha20 public/known-key Readers and conditional carry spectrum;
- A121--A127: SHAKE rate projection, Jacobians, and scalar/bit-sliced/native
  exact state-window reconstruction through 32 coordinates;
- A128--A129: exact Boolean constraint reconstruction and the complete
  round-localized prefix-observability frontier;
- A130: exact full-round affine-hull membership identifying the actual 10-bit
  prefix under the declared known-complement model;
- A131: exact restricted algebraic-degree and coefficient-density frontier.
- A132: exact restricted Boolean-influence support and balance frontier.

## Presentation sanitization

The original PowerPoint was author-owned but contained unrelated editor
metadata in `docProps/core.xml`. The public copy changes only document metadata:
title, subject, creator, and last-modified-by. All slide content, relationships,
and media are retained. The ZIP container passes an integrity test. The public
creator and modifier fields are both `David Tom Foss`.

## Excluded publication material

Publisher-formatted conference PDFs, review exports, decision e-mails, local
archives, virtual environments, caches, nested Git histories, and unrelated
workspace snapshots are not part of this record. Their omission does not remove
the author-owned paper TeX, presentation source, raw result JSON, Reader graphs,
or reproduction code needed to audit the claims.

## How to cite the public snapshot

Use `CITATION.cff`, include the resolved commit of `v0.1.0-prior-art`, and cite
the specific result JSON hash for numeric claims. A GitHub release is a
distribution pointer, not a DOI or long-term archive guarantee.
