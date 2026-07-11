# SHAKE Symbolic-R2 Partition Reader v1

## Result

The 16-coordinate SHAKE128 instance that reached the 120-second monolithic
boundary is now reconstructed by an autonomous partitioned Reader.  The Reader
enumerates all 16 low-four-coordinate prefixes in ascending order, without
consulting the instrumented assignment, and solves the exact symbolic-R2 plus
R3--R24 constraint system inside each disjoint branch.

One branch returns SAT and reconstructs assignment **35,837**.  Injecting that
assignment into the independent 24-round Keccak implementation reproduces all
1,344 observed next-rate bits exactly.

| field | value |
|---|---:|
| variable capacity coordinates | 16 |
| fixed coordinates per branch | 4 |
| exhaustive branch schedule | 16/16 prefixes |
| solver workers | 5 |
| SAT branches | 1 |
| model branch | 13 |
| reconstructed assignment | **35,837** |
| SAT-branch decisions | **5,967** |
| SAT-branch conflicts | 1,272 |
| independently checked output | 21 lanes / 1,344 bits |
| complete-rate match | **exact** |

This moves the native-XOR Reader from the monolithic 16-coordinate boundary to
an executable fullround 16-coordinate model reconstruction.  The schedule is
ground-truth blind: branch 13 is not selected or prioritized from the stored
assignment, and the actual prefix is computed only after every branch result
has been collected.

The other 15 branches reach the configured per-branch boundary and therefore
do not supply branch-local UNSAT certificates in this artifact.  A136 claims
the independently verified fullround model reconstruction recorded above;
global uniqueness remains a separate certificate target.  This distinction is
serialized directly as `global_uniqueness_proved: false` rather than inferred
from the single returned model.

## Resource-localized decomposition

The retained configuration uses five single-threaded solver workers on the
10-core, 16-GB reference machine.  An eight-worker probe oversubscribed memory
and CPU enough for all branches, including the model branch, to reach the same
time boundary.  With five workers, the model branch resolves in 5,967 decisions
under the identical exact encoding.  Worker count is therefore part of the
reproducible algorithm configuration, not an unrecorded runtime detail.

Every branch contains:

- the exact Boolean-ring compilation of the first two Keccak rounds;
- one native n-ary XOR equation per R2 state coordinate;
- exact Boolean equations for rounds R3 through R24;
- all 1,344 next-rate target constraints;
- four fixed low-coordinate literals defining a disjoint search partition.

The 16 branches cover the complete 16-coordinate space exactly once.  No target
bit, model bit, or instrumented state coordinate influences their construction
or order.

## Independent model gate

The SAT model is not accepted from solver output alone.  It is injected into
the cleared capacity window and evaluated by the repository's independent
bit-sliced Keccak core through all 24 rounds.  The resulting complete-rate hash
and target hash are identical:

```text
6d23d92d3ae295ffc64a53b5d1c70042a9a2efb73ad0daf6cd923fef31c940e4
```

The model also equals the posthoc instrumented assignment.  Thus both the
external state gate and the internal ground-truth gate converge on 35,837.

## Causal Reader artifact

The `.causal` file stores three provenance-linked operations:

- generate every disjoint fixed-prefix branch exactly once;
- solve the exact symbolic-R2/native-XOR/fullround suffix system per branch;
- inject every returned model into an independent 24-round core and compare the
  complete rate.

The artifact is reopened with `CryptoCausalReader`, and provenance plus the
three-triplet recipe are verified during production.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_partition_reader.py \
  --window-bits 16 \
  --partition-bits 4 \
  --timeout-seconds 60 \
  --max-workers 5 \
  --output research/results/v1/shake_symbolic_r2_partition_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r2_partition_reader_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_partition_reader.py
```

## Artifact hashes

- result JSON:
  `7a09b0e72c46072baead5de18587cbe4706495ed7636733356903db0b6cff5c4`
- three-edge `.causal`:
  `ea16d00421f5174ce0c6cec3156c8f8f243b6a197fead5e16b41d068b8def6de`
