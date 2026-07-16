# A447 premeasurement parallel-import incident

The first A447 measurement invocation used implementation file SHA-256
`05e20941b85632f20735f268cc60a186d0876b8e2274475948b3ee7dabaf9767`.
Its four-worker startup exposed a manual `importlib` initialization race: one
thread observed the shared identity-wrapper module after insertion into
`sys.modules` but before `exec_module` had completed.

Exactly one compressed shard was present when the failed process returned:

- original path: `research/results/v1/chacha20_round20_w46_proof_antecedent_calibration_a447_v1/target_00.json.zst`
- SHA-256: `e5ce654bb23e2769bb3200b2b2c2e64b7f29a54466abb3e069f51651518bd5c8`
- size: `258374` bytes

The shard was neither decompressed nor parsed. No proof feature, truth rank,
operator rank, or scale decision was observed. The shard and its invalidated
implementation file were moved byte-for-byte to
`research/quarantine/A447_failed_parallel_import_freeze_05e20941/` and are
excluded from every A447 scientific result.

The fix serializes manual module initialization with a process-local reentrant
lock, rejects partial modules, removes a module if execution raises, and is
covered by a 64-call/16-worker concurrency test.

The second implementation freeze, SHA-256
`8cb02e3d9f352ea677c94d5da9aece57a22cf82862a94e2c72005b34e830dc9e`,
proved that the identity wrapper itself lazily initialized a second shared
module after the outer lock was released. Again, exactly one unread shard was
present when the process returned:

- original path: `research/results/v1/chacha20_round20_w46_proof_antecedent_calibration_a447_v1/target_00.json.zst`
- SHA-256: `61ed521ca47474d2bbfa7df1fa022266f42162d1d33255711c41c2e396a9247a`
- size: `258428` bytes

It was moved with the invalidated implementation to
`research/quarantine/A447_failed_nested_import_freeze_8cb02e3d/`, without
decompression or parsing, and is excluded from every A447 result.

The complete fix initializes and validates both wrapper layers while holding
the outer lock. The concurrency test now removes both modules, performs 64
parallel complete-chain loads through 16 workers, and requires a single fully
initialized instance at both layers. The two Python wrapper sources are also
explicit implementation anchors. A new implementation commitment is required
before any replacement target measurement.
