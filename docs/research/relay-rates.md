# The rates of the hosted relays (T-812)

A reading at a time. The tool: `crates/pod-relay/tests/live_measure.rs`
(the input `relay: live_measure` of `live.yml`). For each host: a pair, a
node on the runner whose sessions echo, and one operator session through
the relay: the time to the first echo of 64 bytes, 100 round trips of 64
bytes, then 16 MiB each way at once. Both ends are on the runner, so each
byte crosses the relay two times, and the rate is the rate of each
direction while the other carries the same.

## 2026-11-17, `live.yml` run 44001248788 (a GitHub runner, `ubuntu-24.04`)

| Host | Open | Round trip p50 | p99 | Echo |
| --- | --- | --- | --- | --- |
| `tcp.ssh.relay.ajam.dev` (the default) | 294.0 ms | 49.7 ms | 58.3 ms | 17.33 MiB/s |
| the six seeds of the pool | refused | | | |

Each seed answered the mint of a pair with `503 reverse: unavailable`: the
hosts of the pool serve the forward road, and only the default host makes
pairs of the reverse road. So this tool measures the default host alone.

What the numbers say:

- The 16 MiB each way took about 0.92 s at once; a session moves to a new
  one at 48 MiB (`pod-session`), so a stream at this rate moves about each
  2.8 s of full use, and a copy that keeps the budget of 60 MiB about each
  3.5 s.
- The round trip of about 50 ms is the path from the runner to the relay
  and back, two times (node and operator are both on the runner).
- One run of one runner: no spread over time, no other egress, no forward
  road.

Not measured yet: the seeds (they need a forward session to a target that
the test holds; a runner takes no inbound connection), a rate limit of the
relay over a longer run, the rate from other egresses.
