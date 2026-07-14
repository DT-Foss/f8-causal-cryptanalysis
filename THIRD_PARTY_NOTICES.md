# Third-party notices

The root BSD-3-Clause license covers original F8-Causal code and documentation by
**David Tom Foss**. The following narrow components retain separate provenance
or terms.

## PQCrypto / PQClean SHA-2 source

File:
`provenance/dependencies/pqcrypto-upstream/pqclean/common/sha2.c`

Purpose: the SHA-2 experiment parses reference constants from this exact file
and records its SHA-256 digest in the result JSON.

Source: Backbone Technologies Ltd.'s `pqcrypto` repository at commit
`ecc7cd21aa9bf67be94c2441bf8b55b457ea72dd`, which contains the PQClean source
tree. Only the required `sha2.c` file is vendored; the nested Git history and
unrelated implementations are excluded.

The file header states that it is based on D. J. Bernstein's public-domain
SUPERCOP SHA-512 implementation. The upstream repository's Apache License 2.0
and NOTICE are retained verbatim at:

- `provenance/dependencies/pqcrypto-upstream/LICENSE`
- `provenance/dependencies/pqcrypto-upstream/NOTICE`

Vendored file SHA-256:
`cfe4588b638a9b8035ce55e8fc27e097cfdc7942a41165b7be0fd1fc9a6a6280`.

The separately installed `pqcrypto==0.4.0` Python package is fetched from the
package index by `requirements.txt`; it is not copied into this repository.

## IEEEtran LaTeX class

File: `paper/icecet2026/IEEEtran.cls`

Version: IEEEtran V1.8b, 2015-08-26.

Copyright notices for Gerry Murray, Silvano Balemi, Jon Dixon, Peter Nüchter,
Juergen von Hagen, and Michael Shell are preserved in the unmodified file
header. The class is distributed under the LaTeX Project Public License (LPPL)
version 1.3 as declared in that header. Canonical license information is
available from the [LaTeX Project](https://www.latex-project.org/lppl/).

Vendored file SHA-256:
`7cdccfe5f14cb32490da19ca2f5b0db2a2647c50bbcbf48f4739abfd16858329`.

## LiveCASI 0.9.1 and original F8 anchor suite

`src/arx_carry_leak/live_casi_v091/` and
`provenance/fullround_anchors/f8/` are earlier MIT-licensed projects by the same
author, David Tom Foss. Their package names and internal imports are retained
for reproducibility. Both retained trees include their own MIT license.

`provenance/dependencies/live_casiv2_legacy.zip` is a six-file source bundle of
LiveCASIv2 2.0.0, also authored by David Tom Foss and retained under its earlier
MIT terms. The adjacent `live_casiv2_legacy.LICENSE` records those terms without
changing the byte-exact ZIP required by the historical replay. The bundle
contains source only and no compiled extension or credential.

## dotcausal 0.3.1 Reader

The minimal `dotcausal` Reader source under `src/arx_carry_leak/_dotcausal/`
is vendored to reopen and integrity-check the AI-native `CAUSAL\0\1`
artifacts without relying on an unpinned external checkout. Its original MIT
license is retained at `provenance/vendor/dotcausal/LICENSE`.

## Scientific names and specifications

Reference implementations follow public specifications and test vectors for
named primitives including Speck, SIMON, Threefish/Skein, PRESENT, GIFT,
SHACAL-2, SPARKLE, BLAKE3, ChaCha20, SHA-2, SHAKE/Keccak, FEAL, ASCON, SKINNY,
KATAN, ML-KEM, ML-DSA, and HQC. Names and trademarks remain with their
respective owners. Inclusion is for scientific interoperability and does not
imply endorsement or certification.

## Conference material

The committed TeX and PowerPoint are author-owned source material by David Tom
Foss. Publisher-formatted PDFs, review exports, and decision correspondence are
not included and remain outside the Git publication.
