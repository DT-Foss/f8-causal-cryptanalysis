# Source inventory and consolidation decisions

All paths below are relative to the former workspace root
`Kryptkram codex/`. Source folders were left untouched.

| Original source | Role | Consolidation |
|---|---|---|
| `Foss_CASI_Nano-IoT 2.pptx` | Nanjing presentation and scope | author-owned deck published under `paper/nano2026/presentation/` after document-metadata sanitization |
| `nano-casi/` | newest Nanjing 41-cipher CASI/F8 dataset and paper | cipher registry vendored; raw/result JSON and paper source copied |
| `live-casi/` | latest LiveCASI package, version 0.9.1 | exact `core.py` and `ciphers.py` vendored in a private namespace |
| `live-casiv2/` | newest F8 discovery tree and Threefish work | canonical findings and selected original experiment scripts preserved under `docs/original/` |
| `ICECET/f8-carry-leak/` | Rome F8 paper and review | TeX/class committed; PDF/review copied to gitignored local archive |
| `causal-keyanalysis/` | earlier causal cryptanalysis and Speck reduced-round work | not copied into active code; recorded as predecessor |
| `live-casi copy/`, `live-casiv2 copy/`, `opus-dev/` | older/duplicate snapshots | excluded after file comparison and newer-version selection |
| `casi-v2/` | earlier standalone CASI V2 package | superseded by the later `live-casiv2` F8 tree |

## Known portability defects repaired

- `nano-casi/f8_sweep.py`, `sweep_runner.py`, `run_nano_casi.py`, and build
  scripts hard-coded one author's local Desktop path.
- F8 code was stored under a test folder and depended on import-path injection.
- Threefish verification printed results but did not fail on a single-vector
  mismatch.
- Experiment output lacked a single stable schema and full environment record.
- Source repositories contained caches, distributions, logs, duplicate test
  trees, and untracked paper/patent material.

The new package removes absolute paths, validates parameters, makes vector
failure return a non-zero status, emits JSON, pins a verified environment,
provides CI, and keeps public and local-only materials separate. Historical run
records use role placeholders such as `<repository>`; numeric output and source
hashes are retained.
