# A226 — Dual-order minimax transfer

The fixed reader ranks every prefix independently in Numeric and Gray order, then scores it by its worse of the two ranks. Lower is better.

| Feature | Split | N | Median rank | Hit@16 | Hit@32 | Hit@64 |
|---|---|---:|---:|---:|---:|---:|
| `conflicts` | all | 24 | 51.5 | 12 | 12 | 12 |
| `conflicts` | train | 16 | 1.0 | 10 | 10 | 10 |
| `conflicts` | validation | 8 | 141.0 | 2 | 2 | 2 |
| `decisions` | all | 24 | 93.5 | 5 | 6 | 10 |
| `decisions` | train | 16 | 59.0 | 5 | 6 | 9 |
| `decisions` | validation | 8 | 183.0 | 0 | 0 | 1 |
| `constraint_coherence` | all | 24 | 127.5 | 2 | 4 | 8 |
| `constraint_coherence` | train | 16 | 67.0 | 2 | 4 | 8 |
| `constraint_coherence` | validation | 8 | 154.5 | 0 | 0 | 0 |
