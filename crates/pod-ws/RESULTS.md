# Results of pod-ws

The measurements of this crate, one row for each result, the newest last.
A result that is worse than the one before stays in the table.
`scripts/check-results.py` checks the columns.

| Date | Commit | Host | Kernel | Rustc | Input | Runs | Result | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-11-17 | 957876d | a cloud session, 4 threads, x86_64 | Linux 6.18 | 1.99.1 | the bridge on both ends (`bridge::bridge`, `Limits::TUNGSTENITE`), 16 MiB in chunks of 49,152 bytes, loopback, release | 20 | 521 to 1165 MiB/s | 521, 578, then 793 to 1165: a warm-up; no split near 75 and 330 MiB/s (T-813) |
