# The ingest study (2026-11-16)

A reading at a time: an archive of the owner,
`podutils-ingest-report.zip`, read on 2026-11-17 (T-816). It is a design
study, from two references, of the mechanisms of transport, routing and
trust that PodUtils does not have: refA, a single-port proxy router under
GPL-3.0 or later (commit `4c7f9c9de0ca`), and refB, a mesh VPN under
AGPL-3.0 (commit `cca2206302b1`), against podcrates at `567a56c8b51b`. From
them an entry takes designs and stated constants, never code (call C772).
The study holds 31 proposals, a register of 16 defects of the references
not to copy (N1 to N16; for example, refB's ML-KEM key pair comes from the
public X25519 key and gives no post-quantum secrecy), and a plan in six
phases. It holds no measurement of a relay.

## Its measurements (one host, one day, single runs)

- The FEC of refB (symbols of 1200 bytes): an encode of 8 KiB (K=7, R=1)
  at 5.255 Gbit/s, of 32 KiB (K=28, R=3) at 2.751 Gbit/s, of 128 KiB
  (K=110, R=22) at 0.478 Gbit/s; a decode of 32 KiB in about 16 µs, of
  128 KiB in about 148 µs, each with one dropped source symbol.
- The residual loss of an object of K=28 under independent loss: 21.6 %
  with one repair at 3 % loss, 1.335 % with three, 6.64 % with three at
  5 %; to stay under 0.1 %: 3 repairs at 1 %, 5 at 3 %, 7 at 5 %, 11 at
  10 %, 18 at 20 % (10.7 % to 64.3 % of overhead). This table is a
  binomial count for an ideal code, not a run of the codec.
- Sticky selection over 100,000 keys: rendezvous hashing (HRW) with BLAKE2b
  moves 0.2002 of the keys at an add and 0.2503 at a removal for n=4, 0.1000
  and 0.1124 for n=9, 0.0504 and 0.0527 for n=19 (the theory: 1/(n+1) and
  1/n); modulo moves 0.80 to 0.95; HRW with FNV moves 0.5001 at an add for
  n=4.

## Its corrections

The archive has these defects; the numbers above are the corrected ones.

- The prose of RT-2 names 10,000 keys and FNV moves of 25 % and 12.5 %;
  its CSV has 100,000 keys and 0.5001, 0.2496 and 0.1247.
- The table of repairs says 200,000 trials; its harness runs 50,000.
- The table of residual loss is a model, not a measurement (above).
- The column "dropped sources" of the decode table is the index of the one
  dropped symbol, not a count; no decode with no loss was measured.
- The test run of `pod-link` and `pod-e2e` used no `--all-features`: 17 of
  37 test binaries ran no test (T-824); rustup chose toolchain 1.99, not the
  1.100.0 of its metadata.
- Two names of the references are not redacted.
- Its claims of no counter of allocations and no bench in podcrates came
  before T-777 and T-778 of the same day.

## The proposals and their entries

| Proposals | Subject | Entry |
| --- | --- | --- |
| TR-1, TR-2 | forward error correction, a NACK backstop | T-818 |
| TR-3, TR-4 | a ladder of the path MTU, a clamp of the MSS, a class for each flow | T-819 |
| DP-1 to DP-5 | GSO with a fate rule, sharded rings, a pool of source ports, TUN offload, a MAC table in O(1) | T-820 |
| WR-1 to WR-5 | a keyed header mask, cover traffic, a JA4 self-audit (with T-490), a camouflage front, an ML-KEM hybrid | T-821 |
| PK-1 to PK-7 | a threshold CA, a pool of commitments, a vault of nonces, quorum signing, share refresh, a compact certificate, an authorization of enrollment | T-822 |
| RT-1 to RT-5 | tokens in a credential, sticky selection with tiers, a chain length, a quota that reserves | T-823 |
| VF-1 to VF-5 | no allocation, bounded steps, no blocking call, exhaustive equivalence, a record of results | T-824 (VF-1 and VF-5 in part: T-778, T-777) |
| section 9 | references under GPL and AGPL | T-817 (call C772) |
| the gaps of the relay | a measurement of the rate of the hosted relays; the budget under larger caps | T-812, T-815 |
