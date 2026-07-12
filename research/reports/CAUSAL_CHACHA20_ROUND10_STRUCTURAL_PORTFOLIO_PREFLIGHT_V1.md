# ChaCha10 Structural Portfolio Preflight v1

A207's protocol is recorded here strictly at its pre-execution checkpoint. The exact
A205 calibrated portfolio contains 12 structural order permutations; A206 has
already completed both modes of `bidirectional_min_distance`, leaving 11
candidate/mode transfers.  The remaining complete plan contains 352 frozen
cell-mode executions (11 candidates times 32 disjoint prefixes), with no early
stop and a uniform ten-second CaDiCaL budget.

The preflight archive is an 11,145,296-byte NumPy file with shape
`(12, 232191)` and little-endian `int32` rows.  Every row reopens as an exact
permutation, has a distinct digest, and inverse-restores the representative CNF
byte-for-byte.  The archive, metadata, four-edge Causal chain, literal maps,
protocol, execution order, and runner are hash-gated. This document records the
pre-execution state; the subsequently completed, protocol-identical execution
is reported separately in the
[complete boundary report](CAUSAL_CHACHA20_ROUND10_STRUCTURAL_PORTFOLIO_BOUNDARY_V1.md).

```text
protocol       05bbf03fac0f6d817e4af040df070673a6da1e6f618cca8193c860819fb20127
archive runner db8a611629773eb1af545879de04403ff90f821bd98cf12c407bafd0fa5f1bf6
portfolio run  420dc4f30c6bea9da848a4ffe08bcca4b424ff0dbdd7b39b4a0a18f35122cc19
NPY            ea45134552a6ad3bb6c277ec6bd271d22764f902298b78bda568aef57a12f72f
metadata       b6dfb42095d176823c15d36a490297eb24bc85feedb916513b329d52808a73ce
Causal         71295ac95e3a2e5248e5d58cf3a40053bfe2a84f3ce30145f07b5abdbed9a58c
graph          dad19e2848cb3d480713113b45cfc4a65344b3582ada2bccceec1ce9321c061b
```

Fast preflight verification (no solver execution):

```bash
PYTHONPATH=.:src python -m pytest -q \
  tests/test_chacha20_round10_structural_order_archive.py \
  tests/test_chacha20_round10_structural_portfolio.py
```
