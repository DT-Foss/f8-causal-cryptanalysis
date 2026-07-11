# Code-version ledger

This ledger prevents historical paper data from being silently attributed to a
corrected implementation.

## Frozen repository point

- Initial repository HEAD: `97fa868b96771951d5fb2c26aa1785e9d05c4cde`
- Historical Nano cipher snapshot:
  `775d5ad22c5278323fd8c489408f7e1c6cee33816cfc375dd6ca1675a516abdb`
- Historical Nano F8 sweep:
  `f69f4a89d00b81e51333ee763a8cacf35ab38b95459a21e199dc94c9167a9dd8`
- Retained Nano master results:
  `bef5249e901618c18583dadc29cea460c19997e5013e79d85ad0c5c832685331`

At the frozen HEAD, `src/arx_carry_leak/nano_ciphers.py` is byte-identical to
the historical Nano cipher snapshot. Its SHA-256 is `775d5ad...abdb`.

## Validity boundary discovered 2026-07-10

The historical Nano cipher snapshot fails all ten official Speck and all ten
official SIMON known-answer tests. Consequently, every retained historical
Speck/SIMON result is valid only as a replay of that historical program; it is
not evidence about the specified Speck/SIMON primitives until recomputed with a
KAT-passing implementation.

The active worktree corrections change:

- Speck key-schedule indexing;
- SIMON z-sequence orientation and key recurrence;
- the final two bits of SIMON z4;
- matching SIMON controls in the packaged and live-CASI copies.

Current active hashes after those corrections:

- `src/arx_carry_leak/nano_ciphers.py`:
  `c1843ccc4333d3a695c975bc5c8e95d57258039be80d2f0607634fcfaefe219b`
- `src/arx_carry_leak/ciphers.py`:
  `d87b53e7c114cd85fd5794ebe14b50a98989b773524f4363fda62885915da38e`
- `src/arx_carry_leak/live_casi_v091/ciphers.py`:
  `995818e86a95a6379daefa58d553be5ea2517267086b5d419eb290fcbf351873`
- `tests/test_ciphers.py`:
  `ede894a679b9d1cf6478249612ab5bc06152c511a21fd2710011377d174c392e`

These current hashes are checkpoints, not permanent identifiers; the manifest
and run records contain the authoritative hash for every executed artifact.
