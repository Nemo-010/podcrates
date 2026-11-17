# Results of pod-link

The measurements of this crate, one row for each result, the newest last.
The method: `tests/measure.rs` (README, "Measurement"). A result that is
worse than the one before stays in the table. `scripts/check-results.py`
checks the columns.

| Date | Commit | Host | Kernel | Rustc | Input | Runs | Result | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-11-16 | 996f55d | a cloud session, 4 threads, x86_64 | Linux 6.18 | not recorded | bulk-1, 256 MiB, memory carrier | 3 | 2.29 GB/s (2.24 to 2.38) | 2.58 allocations for each frame, 33 KiB allocated for each frame; peak live 4.5 MiB |
| 2026-11-16 | 996f55d | a cloud session, 4 threads, x86_64 | Linux 6.18 | not recorded | bulk-8, 256 MiB, memory carrier | 3 | 2.17 GB/s (2.17 to 2.22) | 2.81 allocations for each frame; peak live 9.4 MiB |
| 2026-11-16 | 996f55d | a cloud session, 4 threads, x86_64 | Linux 6.18 | not recorded | bulk-1, 256 MiB, tcp carrier, loopback | 3 | 1.00 GB/s (0.97 to 1.07) | 5.8 allocations for each frame, 71 KiB for each frame; peak live 3.6 MiB |
| 2026-11-16 | 996f55d | a cloud session, 4 threads, x86_64 | Linux 6.18 | not recorded | bulk-8, 256 MiB, tcp carrier, loopback | 3 | 1.19 GB/s (1.13 to 1.21) | 6.2 allocations for each frame; peak live 6.5 MiB |
| 2026-11-16 | 996f55d | a cloud session, 4 threads, x86_64 | Linux 6.18 | not recorded | rtt-idle, 2000 round trips of 64 bytes, memory / tcp | 1 | p50 36.5 / 61.3 us, p99 212.3 / 111.1 us | the wake latency of the host: p50 19.4 us, p99 59.5 us |
| 2026-11-16 | 996f55d | a cloud session, 4 threads, x86_64 | Linux 6.18 | not recorded | rtt-bulk, 2000 round trips beside a bulk stream, memory / tcp | 1 | p50 60.8 / 232.0 us, p99 463.7 / 1148.0 us | |
| 2026-11-16 | 00077d3 | the same host | Linux 6.18 | not recorded | bulk-1 and bulk-8, 256 MiB, memory and tcp carriers | 3 | memory: 0.00 allocations for each frame (1 stream), 0.01 (8); tcp: 3.2 | after T-778; the throughput of one code varies by 12 % between runs, and the change is under it |
