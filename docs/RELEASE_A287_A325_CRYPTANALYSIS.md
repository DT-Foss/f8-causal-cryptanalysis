# A287--A325 full-round ChaCha20 cryptanalysis release

Version 0.5.0 published the initial closed ChaCha20-R20 evidence batch: one new
complete-domain W43 recovery, 19 additional strict-subset executions, exact
grouped-engine qualifications through W46, target-blind model-free order
fields, three pre-reveal-committed operator evaluations, the completed A321
holdout selection, and the A323 cross-width operator audit.

The terminal supplement closes the two executions that were still open at that
snapshot: A322 recovers W45 at rank 1,459 and A325 recovers W46 at rank 77.
Both retain their original pre-result protocols and orders byte-for-byte.

Every recovery executes standard ChaCha20 with all 20 rounds and feed-forward,
uses eight complete public output blocks, rejects the matched one-bit control,
and is confirmed by independent byte- and word-oriented implementations.

## Recovery summary

| Record | Width | Confirmed executions | Factual rank(s) / 4,096 | Search statement |
|---|---:|---:|---|---|
| CHACHA20KR43 | 43 | 1 | complete domain | All `2^43` assignments executed; unique factual model |
| A294 / A295 | 24 | 2 | 202 / 2,605 | Two frozen orders recover the same target in strict subsets |
| A296 | 24 / 28 | 8 | 2,750, 2,948, 1,485, 213 / 1,144, 2,113, 520, 3,019 | Four-target W24 replication plus four-target zero-refit W28 transfer |
| A297 | 32 | 4 | 2,867, 2,032, 926, 3,932 | Four fresh zero-refit strict-subset recoveries |
| A303 | 32 | 1 | 3,801 | Calibrated strict-subset recovery |
| A302/A304 | 43 | 1 | 2,473 | Frozen A302 order through qualified grouped engine |
| A305 | 43 | 1 | 2,114 | Frozen A299 order through qualified grouped engine |
| A309 | 43 | 1 | 4,044 | Width-conditioned portfolio retains a strict subset |
| A313 | 44 | 1 | 2,753 | Frozen three-arm order; 11,824,044,965,888 of `2^44` assignments |
| A322 | 45 | 1 | 1,459 | Frozen A321-selected order; 12,532,714,569,728 of `2^45` assignments |
| A325 | 46 | 1 | 77 | Unchanged A321-selected order; 1,322,849,927,168 of `2^46` assignments |

A294/A295 intentionally test two distinct frozen orders on one target. The
initial batch therefore contains 19 executions across 18 new targets. With the
terminal supplement, A287--A325 contains 21 strict-subset executions and the
repository contains 26 strict-subset executions through A325.

## Completed post-recovery operator records

A315, A317, and A319 evaluate their pre-reveal-committed W44 orders against
the independently confirmed A313 prefix without re-executing candidates. A321
then selects `raw_nearest_prototype_Linf` at rank 2,159/4,096 and deploys its
unchanged paired W45 order. A324 separately qualifies one complete W46 prefix
group (`2^34` assignments across eight slabs) with 147,968 independently
checked boundary bits, a unique synthetic factual assignment, and an empty
matched control.

## Exact terminal boundary

A322 and A325 are completed, independently confirmed recovery records. A314
remains an order-only result. Qualification, order, terminal recovery, and
control artifacts remain separately typed and machine-checked.

## Portable reproduction

```bash
./scripts/reproduce_a287_a325.sh
```

The tier verifies the release manifest, independently recomputes the recovered
ChaCha20 output blocks, tests the completed order/engine/audit objects, and
opens every retained `.causal` file through the authoritative native Reader.
It does not rerun multi-hour production enumeration.

See [the gap audit](PUBLISH_GAP_AUDIT_A287_A325.md) for the exact inclusion and
exclusion decision for every record.
