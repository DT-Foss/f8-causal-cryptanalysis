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

## A223--A277 public release boundary (2026-07-14)

Release `0.3.0` publishes the completed A223--A277 evidence chain. The
authoritative release manifest is
`research/results/v1/A223_A277_SHA256SUMS`; its focused test inventory is
`research/results/v1/A223_A277_TESTS.txt` and its non-production reproduction
entry point is `scripts/reproduce_a223_a277.sh`.

The release includes corrected, known-answer-test-passing Speck32/64,
Speck64/128, and SIMON64/128 implementations and their independently confirmed
complete-domain recovery records. It does not reinterpret the historical Nano
Speck/SIMON snapshot. A278--A281 and PRESENT-128 are outside this release and no
result from those in-flight attempts is included.

## A278--A286 record release boundary (2026-07-14)

Release `0.4.0` publishes the completed A278--A281 cross-material recovery,
the A282--A286 four-target panel, PRESENT-128 W38, and AES-256 W41. The
authoritative manifest is
`research/results/v1/A278_A286_RECORDS_SHA256SUMS`; the focused test inventory
is `research/results/v1/A278_A286_RECORDS_TESTS.txt`, and the portable entry
point is `scripts/reproduce_a278_a286_records.sh`.

The A286 root confirmation supersedes only the failed A285 aggregate-file
write caused by a nine-byte API id in an eight-byte Causal header field. It
preserves and independently confirms all four completed target results.

## A287--A325 cryptanalysis release boundary (2026-07-15)

Release `0.5.0` publishes the completed CHACHA20KR43 complete-domain record,
18 additional strict-subset ChaCha20-R20 executions, completed model-free
orders and grouped-engine qualifications, and the A323 operator-stability
audit. The authoritative manifest is
`research/results/v1/A287_A325_SHA256SUMS`; its focused test inventory is
`research/results/v1/A287_A325_TESTS.txt`, and its portable entry point is
`scripts/reproduce_a287_a325.sh`.

A313 and A322 are open production executions. Only their frozen design,
protocol, order, runner, and test objects are included; no outcome is claimed.
A314 is included as a completed model-free order only. A306 has no completed
result and A324 is beyond this release boundary.
