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

## 2026-11-17, `live.yml` run 44003014747 (the same runner image)

| Host | Open | Round trip p50 | p99 | Echo |
| --- | --- | --- | --- | --- |
| `tcp.ssh.relay.ajam.dev` (the default) | 365.7 ms | 87.7 ms | 245.4 ms | 9.29 MiB/s |

The copy of 5 sessions of 56 MiB (T-835) failed with a broken pipe on the
write of the operator.

## 2026-11-17, `live.yml` run 44004334762 (the same runner image)

| Host | Open | Round trip p50 | p99 | Echo |
| --- | --- | --- | --- | --- |
| `tcp.ssh.relay.ajam.dev` (the default) | 575.5 ms | 141.7 ms | 499.9 ms | 4.57 MiB/s |

The copy failed again; the session named its end: the second session
ended with `NeverReady` ("more than 1048576 bytes of input came before the
node was ready"). A session takes at most 1 MiB from its operator before the
node says that it is ready; the copy wrote at once. The copy now waits for
a byte of the node before it streams. An SSH client waits for the banner of
the server, so a session of podssh does not meet this bound.

What the three runs say:

- The spread between runs of the same hour is large: the echo rate went
  from 17.33 to 9.29 to 4.57 MiB/s, and the p99 of the round trip from 58.3
  to 245.4 to 499.9 ms. One reading does not give the rate of a host; a rank by
  rate needs the median of many sessions (`pod_relay::rates`, T-814).
- At 9.29 MiB/s a session of 48 MiB moves about each 5.2 s of full use.

Not measured yet: the seeds (they need a forward session to a target that
the test holds; a runner takes no inbound connection), a rate limit of the
relay over a longer run, the rate from other egresses.
