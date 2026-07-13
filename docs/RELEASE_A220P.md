# A220P publication snapshot

This snapshot extends the audited F8-Causal record through the completed
A220P factorial preflight and publishes the final frozen A220 protocol. The
author identity is **David Tom Foss**.

## Completed evidence added

- A211: two independent complete ChaCha10 retained-state covers recover and
  independently confirm low20 `0x7c596` over all 4,096 observed output bits.
- Standard-R20 transfer: two independent complete covers recover and confirm
  low20 `0xe4934` through all 20 ChaCha rounds plus feed-forward, with 236 key
  bits known. The remaining 255 cells are `UNKNOWN`; uniqueness is not claimed.
- A212--A219: public scheduling, exact propagation, known-key Reader,
  selection-matched-null, operator-diversity, and target-blind execution
  records with their exact measured boundaries.
- A220P: 12 fresh processes covering six traversal directions under staged and
  one-shot schedules. All 3,072 cells and 7,680 stages are retained; every
  cell is `UNKNOWN`, and all parser, identity, continuity, and watchdog gates
  pass. The measured trajectories establish that direction and solve schedule
  are distinct interventions rather than scaled replicas.

## Frozen next protocol

A220 preregisters a 52-key fit/select panel across all 12 trajectories and a
separate 92-key untouched holdout panel. Its public adapter, Reader core,
feature families, matched-null permutation, and test gates are included. The
main collection, Reader selection, and untouched-holdout evaluation are not
complete and therefore have no result claim in this snapshot.

## Cryptographic identities

| Artifact | SHA-256 |
|---|---|
| A211 result | `3dfe525c6340dd911d584c77a925a5eb01b246ff55f0981901f6400fd00d25c2` |
| Standard-R20 transfer result | `a5be062ebce29cbc864ef926c55a1f9dbaadd69c9edcc54aed43552304f8e3f0` |
| A220P retained result | `f5cc99ac3dcf679023e1a32b91b5dae26d94837db08673f23f0f5cb787afd946` |
| A220P scientific measurement projection | `a43f530b72dad576db5623e3c23f8c3dcb3ce666c4159b29d74c9bb7294cfdc7` |
| A220P protocol | `a1f544800f0f2349d6a74ceca041e212a624e74b5a0ade3975e233571eb3e474` |
| Final A220 protocol | `70df07cb4f4f22115e3aa63765de0fca0dd610607cc87356946a188f53fe5645` |
| Final A220 Reader runner | `294e962e639b2058d3cf726949c05206e4ac14a4d663e1b482077f9c49ae8965` |
| Final A220 Reader runner test | `bc9b825f1de9a59ec30fe3fc6c999e699bb5b195a0466413a46cd462622d3d66` |
| A220 Reader core | `df05913df5b5c589eed73c5ab877c2776cbdb78e68338677bd4a1577358c2916` |
| A211--A220P manifest | `b9d66be9555d2f65787390748697ee7a4f77ae8d9b1268b522cf4465a238281b` |

Verify the dedicated manifest and focused retained-evidence suite with:

```bash
python scripts/verify_hash_manifest.py \
  research/results/v1/A211_A220P_SHA256SUMS
./scripts/reproduce_a211_a220p.sh
```

The A220P JSON is retained byte-for-byte because the final A220 protocol binds
that exact whole-file hash. Its inert provenance fields therefore preserve the
original laboratory path strings; no runtime follows those strings during the
retained-evidence gate. Other host paths in this publication update are
replaced with role paths. The 145 MB A215 raw measurement archive exceeds the
publication ceiling and is
not stored in Git. Its exact digest remains bound in the protocol, result, and
report. No sealed secret, checkpoint, compiled helper, unfinished collector,
or unfinished A220 output is included.
