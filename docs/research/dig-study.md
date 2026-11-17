# The dig study (2026-11-16)

A reading at a time: an archive of the owner,
`podutils-dig-study-2026-11-16.zip`, read on 2026-11-17 (T-816). The
archive holds 19 design studies of a peer-to-peer system that it names DIG,
written from a reading of its source code (nothing compiled, no test run),
and one measurement of two relays (`poc/`). Six studies (01, 04, 06, 09, 15,
16) were checked against the code of PodUtils by their authors; the others
carry their authors' labels alone. Each file matches the archive's
`MANIFEST.sha256`.

## The measurement of two relays (`poc/`)

The method: one machine (8 vCPU, 14 GiB, Debian 13), the loopback only,
plain `ws://`, no TLS, no loss. Each run sends 16 MiB in chunks of 49,152
bytes with 64 in flight, then 100 round trips of 64 bytes; five runs for
each path. The relays: a local `podssh relay serve` (podssh
1.1.0-beta.3, `--mint anyone --cleartext yes --allow-private`) and a local
`dig-relay` 0.20.4 with its limits of abuse off. The load of the machine
went from 1.18 to 2.00 during the runs.

| Path | MiB/s (min / median / max) | Round trip p50 | Open |
| --- | --- | --- | --- |
| Direct TCP | 1527 / 2162 / 2411 | 36 µs | 0.20 ms |
| podssh relay | 74.7 / 328.6 / 344.8 | 73 µs | 0.84 ms |
| DIG relay, echo | 7.53 / 7.58 / 7.99 | 118 µs | 1.59 ms |
| DIG relay, TCP bridge | 7.96 / 8.37 / 8.64 | 211 µs | 1.92 ms |

- The rate of the podssh relay is in two modes, near 75 MiB/s and near
  330 MiB/s; the archive names no cause (T-813). The bridge of `pod-ws`
  has one mode (521 to 1165 MiB/s). podssh found the cause
  (PodUtils/podssh#299): the multi-thread runtime of tokio places the
  tasks of each socket; with one thread the role has one mode.
- The DIG relay writes each payload as a JSON array of decimal bytes:
  about 3.6 bytes on the wire for each byte of payload. Its default limits
  are 1 MiB/s and 256 frames each second for each connection, 1 GiB in a
  lifetime, and messages of 256 KiB; with them on, it cut the run of 16 MiB
  after 89 ms (T-828).
- Not measured: a hosted relay (the default relay of PodUtils, or
  `relay.dig.net`), a WAN, TLS, loss, more than one stream. 16 MiB is under
  the cap of 64 MiB of a session of the default relay, so no cap was met.

## What the repository has (2026-11-17)

- No measurement of the rate of a relay. The rank of `pod-relay`
  (`rank.rs`, `rank_auto.rs`) orders hosts by the share of failed probes,
  the median and the p95 time to open; `pod-link/tests/measure.rs` (T-777)
  measures the multiplexer of `pod-link`, not a relay (T-812).
- The default relay is `tcp.ssh.relay.ajam.dev:443`, the first of the list
  (`[rank] value = 0` in `ajam-relay.toml`); its six regional seeds follow
  as the pool. A rank for the egress of under 24 h, and recent failures,
  change the order.
- The caps of that relay hold each session: 64 MiB, 12 h, an idle timeout
  of 180 s, frames of 256 KiB. The client keeps a budget of 60 MiB and
  11.5 h, and `pod-session` moves a stream to a new session at 48 MiB or
  11 h; a larger cap of another relay does not raise the budget (T-815).

## The studies and their entries

| Study | Subject | Entry |
| --- | --- | --- |
| 01 | the relay server: one live identity, introductions, liveness deadlines of 30, 90, 120 and 10 s, PROXY trust ranges, a STUN responder (5 each second for each source), a ban after 20 strikes in 60 s for 300 s | T-829 (to podssh) |
| 02, 10 | a ladder of traversal (direct, UPnP, NAT-PMP, PCP, hole punch, relay), gossip | T-832 |
| 03, 11, 12 | typed calls, a catalogue of methods, tiers, a budget of callbacks | T-833, T-831 |
| 04 | an order of sources by measured rate, a relayed-path penalty, an integrity tier that does not decay | T-814 |
| 05, 09, 13, 17, 18 | a DHT, sealed messages, content addressing, storage, sealed secrets | T-832 |
| 06 | a download of ranges from several sources | T-190 |
| 07 | a dial plan by address family | T-825 |
| 08 | a rotation of the identity key; a sync of the parent directory | T-826, T-192 |
| 15 | a signed feed with a rollback floor, a gate of health, a check of loadability | T-830, T-104 |
| 16 | the installer | T-702, T-102 |
| 19 | ledger formats | none: the archive's `INGEST.md` advises against it |
| 02, 03, 05 | a type for the text of a peer | T-827 |
