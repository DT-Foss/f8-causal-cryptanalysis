# Located historical dependencies

The graph and temporal F8 scripts import `live_casiv2`. The exact local package
was found at the sibling path `../live-casiv2/live_casiv2` and is byte-identical
to the Desktop copy used by the original scripts. Its six Python sources are
now frozen in the clone-portable import bundle
`provenance/dependencies/live_casiv2_legacy.zip` (SHA-256
`47870d2bc172b5cdd85880f2051bb527e6a73cf7b6a5ec172a3d6a5a499bc37f`).

Hashes on 2026-07-10:

- `__init__.py`: `a46855349aa8dd19b88a0878339ac073584ff777bac79dc2ff77cbdcfa842e81`
- `ciphers.py`: `6ba711da640dea69bb4fcee975f54739934265c757faeed4e33434ea67df0819`
- `cli.py`: `b52cbd4c9e789d228ccba6e6aa19267f95037402bc9f6e5bd0578b6c69cb7ffc`
- `engine.py`: `c155ab1c43f11d537e093d95d8a3bb32a668e37afe00d4053dd5206ea24bc4cb`
- `strategies.py`: `f59e932d2ec82d06f251dd99e07ff965be52faa58a12ccc8eb7831b42c954988`
- `temporal.py`: `9fb4fe4f9d1bfe2dcbcbe41b39c3852cfc0110418f2ea6b0bd9c3536cf18af0a`

The reproduction runner prefers the frozen bundle and records its hash in every
run. The sibling path remains only as a discovery fallback if the bundle is
absent.

## Formula-atlas source JSON

The unnumbered formula-atlas full re-audit reads two local workspace sources
outside this repository.  They are not Python dependencies and are not
vendored.  The builder fails closed on these exact identities before reading
their contents:

| Source path from repository root | SHA-256 |
|---|---|
| `../Mathepaper/formula_atlas_v1.json` | `e376fcc1c24f1dbf44689dfbf554f87d727df38ec9181f0b7272d5e5a2ed0378` |
| `../Mathepaper/formula_source_pages_v1.json` | `8affa048f0bbf3845d6aed1df1e3fb8ac5558f2302f416dbae0acaa382b4533b` |

The retained coverage ledger records both paths and hashes.  A clone without
these source files can inspect the retained JSON and report, but rebuilding or
running `tests/test_formula_atlas_transfer_audit.py` requires hash-identical
copies at the listed sibling paths.

## A188--A203 external SMT portfolios

A188--A190 production portfolios use three external command-line solvers;
A191--A198 and the solver-backed A200/A202/A203 transfers use the same frozen
Bitwuzla identity. A199 and A201 are deterministic public computations without
an external solver. The solvers are not pip dependencies and are not vendored.
Each frozen protocol records and each runner gates the applicable version,
executable digest, and command-line mode:

| Solver | Version | Executable SHA-256 | Production mode |
|---|---|---|---|
| Bitwuzla | 0.9.1 | `9896c88b523114e3eae00d737f1183ca71fbd83a99e8e45fe294715747a2ce7a` | bitblast/preprop with CaDiCaL; prop control |
| Z3 | 4.15.4 | `ae6c8df33db9c9ae9a80b6044e77cd66529a141d8b25f0620f1e89b409594f48` | SMT-LIB2 stdin with five-second CLI wall limit |
| Boolector | 3.2.4 | `ad08034940a968ab4641fd885c75a98220685443240224500b6de0ab23f11edb` | `fun` engine with Lingeling |

The A188--A203 retained-artifact test paths rebuild all portable SMT-LIB2 bytes
and validate the stored solver identity records without invoking or requiring
any of these executables. An explicit new execution is fail-closed unless every
identity required by the applicable frozen protocol matches.

## A204--A207 standalone CNF portfolio

A204 exports the exact Bitwuzla bitblast formulas to DIMACS and calibrates four
standalone SAT engines. A205/A206 and the frozen A207 runner use the retained
CaDiCaL identity. The executable paths themselves are host-local; every frozen
protocol gates version and binary digest:

| Solver | Version | Executable SHA-256 | Role |
|---|---|---|---|
| CaDiCaL | 3.0.0 | `c7b63954503d7fb1c8532efa37689715398683b5dea59d9bf6d80f06169e09b3` | A204 calibration; A204--A207 default/reverse execution |
| Kissat | 4.0.4 | `05d6f3e9c402a1fe8853b0746e384e1b3d1c4a550e255f11daa2461d279aa848` | A204 calibration matrix |
| CryptoMiniSat | 5.14.7 | `c1f313d66f9253964a778455ee84bc64dbe786602b0d85c9d55813d3ee0682fe` | A204 calibration matrix |
| MiniSat | 2.2.1 | `260899613fcfdbb5d1667c4ca57e8a5d75d6ba396109c2209c3e3ff99e9c3ab7` | A204 calibration matrix |

On macOS, `brew bundle` installs the declared standalone-CNF CLI set; exact Z3
4.15.4 comes from the pinned `z3-solver` wheel. Homebrew does not guarantee
historical bottle bytes indefinitely, so the runners still fail
closed when an installed executable differs from the frozen digest. Retained
tests authenticate the recorded observations, models, mappings, order archive,
and Causal provenance without invoking these solvers.
