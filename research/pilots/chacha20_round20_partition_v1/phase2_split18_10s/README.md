# Round-20 Pilot Phase 2: Controlled Split18 Cut Frontier

Phase 1 executed all 32 split19 cells at 10 seconds per cell and returned
exactly 32 `unknown` outcomes. Its JSON and Causal files are retained
byte-for-byte.

This second phase changes exactly one factor: the midstate cut moves from
split19 to split18. The fresh public challenge, complete `2^20` domain,
32 numeric prefix cells, 15 free bits per cell, Bitwuzla/CaDiCaL engine,
10-second cell budget, order, and no-early-stop rule remain unchanged.

The move is structural rather than assignment-selected: one more ChaCha round
is represented on the inverse side for every cell. All 32 cells are required;
the hidden prefix is never available to the phase-2 runner.

Commands from the repository root:

```bash
PYTHONPATH=.:src python3 \
  research/pilots/chacha20_round20_partition_v1/phase2_split18_10s/runner.py \
  --analyze-only

PYTHONPATH=.:src python3 \
  research/pilots/chacha20_round20_partition_v1/phase2_split18_10s/runner.py

PYTHONPATH=.:src python3 -m pytest -q \
  research/pilots/chacha20_round20_partition_v1/phase2_split18_10s/test_phase2.py
```

The analyze-only and test commands never invoke the solver.
