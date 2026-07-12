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

## A188/A189 external SMT portfolios

A188/A189 production portfolios use three external command-line solvers. They
are not pip dependencies and are not vendored. The frozen protocols and runners
gate the exact version, executable digest, and command-line mode:

| Solver | Version | Executable SHA-256 | Production mode |
|---|---|---|---|
| Bitwuzla | 0.9.1 | `9896c88b523114e3eae00d737f1183ca71fbd83a99e8e45fe294715747a2ce7a` | bitblast/preprop with CaDiCaL; prop control |
| Z3 | 4.15.4 | `ae6c8df33db9c9ae9a80b6044e77cd66529a141d8b25f0620f1e89b409594f48` | SMT-LIB2 stdin with five-second CLI wall limit |
| Boolector | 3.2.4 | `ad08034940a968ab4641fd885c75a98220685443240224500b6de0ab23f11edb` | `fun` engine with Lingeling |

The retained-artifact tests rebuild all portable SMT-LIB2 bytes and validate
the stored solver identity records without invoking these executables. An
explicit new portfolio execution fails closed unless all three identities match
the applicable frozen protocol.
