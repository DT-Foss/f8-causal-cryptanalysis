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
