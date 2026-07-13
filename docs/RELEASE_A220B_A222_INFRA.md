# A220B/A222 infrastructure supplement

This supplement extends public protocol coverage beyond the A220P evidence
snapshot without adding an A220 or A222 scientific outcome. The author
identity is **David Tom Foss**.

## Published pre-outcome infrastructure

- A220B exact factorial contrasts and deterministic next-probe routing;
- A220B JSON/report/Causal serialization with Reader and idempotence gates;
- A222 same-Reader, same-run-set, all-eight-block equal-weight aggregation;
- A222 exact 32-key disjoint and bit-balanced 8-by-4 known-key ledger;
- A222 exact paired `2^8 = 256` prefix-cluster sign-flip protocol; and
- recursive label/reveal/model rejection, minimal Reader-input projection,
  and counter-block provenance binding.

All ten scientific source, protocol, and test files are authenticated by
`research/results/v1/A220B_A222_INFRA_SHA256SUMS`.

| Artifact | SHA-256 |
|---|---|
| A220B boundary core | `8888b57c21cda56a746c938716f789c92957d5f443899cf477d035054709e7dc` |
| A220B boundary runner | `dd10dd48a37b158d005a0d42c3d4d0fbd59864a75fe2dd0e8d8e79f7e004536d` |
| A220B protocol | `e69cde426e264025aeadd209560b93ec4667ddc8e63faaf98f6459b281a343a5` |
| A222 ensemble core | `e072cdb2db1d3a0f639f9c3bf71c06d428d86140d3f2ac3e73b3809dba36e015` |
| A222 ensemble protocol | `e3ee7ccc583ee778ca832877cf27a0fa9ad5d7c1544429e3b0277b30aa0fab51` |
| A222 32-key design | `633d56ade07ecb30e7c1182fd98f2ba415d1a3d2f90bfbbccbac9ce9791f780f` |
| Ten-file infrastructure manifest | `2b7fe72b80ffa8735ba430ee39a39cc5fb8ae236719857d12147de00a22109af` |

## Explicit non-claims

This supplement publishes no live A220 attempt, shard, checkpoint, selected
Reader, holdout measurement, retention decision, target, secret, A221
artifact, or A222 solver outcome. It does not claim that A220 retained or hit a
boundary, and it does not claim that A222 improves rank or recovers a key.

## Verification

```bash
./scripts/reproduce_a211_a220p.sh
.venv/bin/python scripts/verify_hash_manifest.py \
  research/results/v1/A220B_A222_INFRA_SHA256SUMS
.venv/bin/python scripts/check_publication.py
```

The reproduction script includes the focused 100-test A220B/A222 protocol
suite but launches no production solver collection.
