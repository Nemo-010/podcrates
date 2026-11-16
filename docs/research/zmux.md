# zmux: study note

Subject: the five repositories of the organization `zmuxio` (zmux.io), as
a comparison report of 2026-11-16 measured them against PodUtils. The
report pinned `zmux-spec` at `df3bab4`, `zmux-go` at `d5c25a5`, `zmux-rs`
at `6d7416d`, `zmux-java` at `cd60adc`, `zmux-python` at `e1cd119`, and
podcrates at `62b8223` (version 0.58.0). This note reads the report and
its data; podcrates did not run zmux code, the scripts of the report or
its harness. The report and its data are not in this repository.

Ruling: `docs/decisions.md`, 2026-11-16, "zmux": podcrates copies no zmux
code and contributes nothing to zmux. podcrates takes the technical
knowledge and writes its own designs from it. Calls C750 and C751.

Each line starts with one of these tags:

- Report: a statement of the report that podcrates did not check.
- Measured: a number that the report measured, with its log in the data
  of the report.
- Read: a fact that this note read in the podcrates tree at `567a56c`.
- Inferred: a conclusion of this note.

## 1. What zmux is

### The organization

- Report: one protocol specification (`zmux-spec`), and three
  independent implementations: Go (`zmux-go`), Rust (`zmux-rs`) and Java
  (`zmux-java`). `zmux-python` is a binding over the Rust core, not a
  fourth parser.
- Report: the specification comes first. Its README: "This repository is
  the protocol specification: what goes on the wire, how each endpoint
  must react, and the test vectors that check it."
- Report: 11 Markdown files at the root of the specification (7,596
  lines), and a draft `secure-carrier/SPEC.md` (926 lines). Eight are
  normative for a claim of conformance (`SPEC.md`, `MULTIPATH.md`,
  `RESUME.md`, `EXTENSIONS.md`, `STATE_MACHINE.md`, `REGISTRY.md`,
  `CONFORMANCE.md`, `TRACES.md`). `WIRE_EXAMPLES.md` is generated and
  informative.

### The wire

- Report: the protocol is QMux: the stream and frame model of QUIC
  (RFC 9000) over a reliable byte stream. `SPEC.md` applies the text of
  RFC 9000 "normatively, with the deltas stated here".
  `STATE_MACHINE.md` has a table of eight named deltas.
- Report: the machine-readable registry (`assets/registry.json`) has 32
  frame types, 33 transport parameters, 19 transport errors, 15
  application errors, 4 TLV types of the preamble, 6 fixed values, 36
  limits and 9 labels.
- Inferred: the numbers are QUIC variable-length integers (a package
  `varint` in Go; the corpus rules talk of a minimal encoding). Thus one
  value has more than one encoding, and the specification defines the
  equality of two encoders by value, not by bytes.
- Report: the endpoints exchange transport parameters (the settings of
  each end) in a preamble. A peer learns the limits of the other end
  from it.
- Report: a stream can carry open information (`OPEN_INFO`) when it
  opens. The scripted peer of the interop test takes its commands from
  it.
- Report: packet streams and datagrams exist beside the reliable
  streams.
- Report: the protocol has multipath: one session over more than one
  pipe, with a scheduler (`plain`, `eta`, `round-robin`), and 138 traces
  of 376 test it.
- Report: the protocol has resumption (18 traces), extensions (51
  traces), GREASE, a policy of code-point allocation, lanes and
  priorities.

### The carriers and the security

- Report: carriers: TCP, WebSocket (`zmuxws`), QUIC (`zmuxquic`), HTTP/3
  (`zmuxh3`), HTTP (`zmuxhttp`) and a sealed carrier (`seal`,
  `seal/proto`). The study measured TCP and memory only.
- Report: a TLS exporter binds a new pipe to its session, in two forms
  (join and split bootstrap). The interop test proves both forms between
  Go and Rust.
- Inferred, from the build log of the Rust core: the secure carrier uses
  X25519 with ML-KEM (`libcrux-ml-kem`), AES-GCM and SHA-3. That is a
  hybrid key exchange with a post-quantum part. The draft status of
  `secure-carrier/SPEC.md` agrees: it is not settled.

### The implementations

- Report: the Rust core is sans-I/O. A tokio driver is optional. The core
  has 10 direct dependencies (11 with `libc` on unix) and 346 packages in
  its lock file.
- Report: the Go root module has 2 direct dependencies (`netx`,
  `timeshim`). Go has packages for admission (`admit`) and for traffic
  shaping (`shaping/bundle`, `shaping/machine`).
- Measured: the Rust core writes a bulk transfer with 0.0000 allocations
  for each frame (`core-bulk`), and 0.0005 to 0.0007 over TCP.

### The method of test

- Report: a conformance corpus of 376 traces (7,127 steps) and 157 wire
  entries (57 valid, 100 invalid). Go, Rust and Java each run all 376
  traces (Measured: 0.386 s, 0.47 s and 2.125 s).
- Report: a trace is NDJSON: a header (`profile`, `local_role`, `refs`,
  `findings`, `groups`), then steps from a closed set of 48 operations in
  four classes (3 carrier, 7 peer, 27 application, 11 expectation).
- Report: the six obligations of a runner: apply the profile before the
  first step; run the steps in order and give the step number at a
  failure; move time only at an `advance` step; flush before each
  expectation; a session error is an event, and only an expectation
  decides; after the last step, a close that no `expect_close` covered
  is a failure.
- Report: the peer's bytes are fully scripted. The runner does not
  interpret the peer.
- Report: each trace names the paragraph of the rule that it tests
  (`refs`, for example `SPEC.md#8.2`) and a class of defect (`findings`,
  for example `D-C01`). `CONFORMANCE.md` maps each class (`D-F` flow,
  `D-S` streams, `D-C` close) to a trace, or to the invariant that makes
  the defect impossible.
- Report: one rule of time for the whole specification: a duration T
  fires at the first event where `now >= t0 + T`. A trace asserts at
  `t0 + T - 1 ms` and at `t0 + T`.
- Report: a wire entry has the bytes in hex, the settings and features in
  use, a note, and for an invalid entry the exact error. Expected bytes
  are given two times: as a structure and as hex. An encoder agrees when
  its output is not longer than the input under a minimal encoding,
  decodes to the same value, and encodes again to the same bytes.
- Report: the Go runner asserts the count of traces (`specTraces = 376`).
  A trace that is added or removed with no change of the constant fails.
- Report: generated files are rebuilt in CI, and a diff fails the job.
  The rebuild is deterministic (Measured: an empty `git status` after a
  rebuild in a fresh copy).
- Report: test hooks (keys, nonces, clocks) exist that production
  settings cannot reach. A profile turns off each source of chance
  (keepalive 0, jitter 0), so that a trace tests the specification and
  not a policy.
- Report: interop: a Rust peer binary (13.3 MB) prints `LISTEN ADDRESS`,
  then `ESTABLISHED`. The Go tests find it through an environment
  variable and skip when it is not set. The peer reuses the Rust
  runtime; it is not a second parser. Measured: 10 of 10 tests pass.

### The method of measurement

- Report: the benchmark of the Rust session prints one line for each
  result: `RESULT key=value ...`. Runs and scenarios compare with no
  parse of prose.
- Report: scenarios: `core-bulk` (the core with no carrier), `tcp-bulk`
  (raw TCP, copy, zero copy), `rr` (64-byte round trip on raw TCP),
  `wake` (the wake latency of the host: 100,000 wakes), `rr-under-bulk`
  (64-byte round trip while a bulk stream runs on the same session, with
  the bulk rate alone and with the round trips), `at1` (a latency gate)
  and `mp-bulk` (multipath).
- Report: each bulk line has the CPU seconds for each GB. The multipath
  lines have the live heap of the session (average, peak, after the
  drain, retained) and the bytes in the send and receive buffers.
- Inferred, from the `at1` lines: the latency gate is relative to the
  host. It adds the measured idle p99 and the measured wake p99 of the
  same run to fixed margins (`target_us`, `gate_us`). A slow host gets a
  wider gate; the gate does not need a constant for each host.
- Report: three Go tests assert 0 allocations for each call
  (`testing.AllocsPerRun`). An allocation count does not change with the
  speed of the host, so a gate on it is stable.

## 2. The numbers

One Linux x86-64 host, 8 vCPU, 14 GiB, `rustc` 1.99.1, Go 1.27.0,
2026-11-16. The two sides did not measure the same thing: see the notes
under each table.

### pod-link, the harness of the study

The study wrote a harness of `pod-link` as an ignored integration test.
The memory carrier (two ends in one process, a ring of 1 MiB each way),
the default settings (a window of 1 MiB for a stream, 8 MiB for the
link, frames of 16 KiB), 4 tokio workers, a release build. A byte counts
only when the reader took it and sent back one byte of acknowledgement.
A bulk stream writes in parts of 64 KiB, closes its half, and waits for
the acknowledgement.

| Scenario | Samples | Result |
| --- | --- | --- |
| bulk, 1 stream, 256 MiB | 9 | 1.52 to 2.19 GB/s, median 1.75 |
| bulk, 8 streams, 32 MiB each | 9 | 1.72 to 2.63 GB/s, median 2.51 |
| round trip, 64 bytes, idle, 5,000 rounds | 3 | p50 18, 18, 26 us; p99 49, 50, 66 us |
| round trip, 64 bytes, under a bulk stream of 128 MiB | 3 | p50 19, 23, 18 us; p99 46, 62, 54 us; bulk 2.61, 1.94, 1.92 GB/s |

- Measured: the bulk samples vary by up to about 50 % between runs.
- Inferred: on the memory carrier a round trip under bulk costs almost
  nothing more than an idle one. The writer of a link sends `WINDOW`,
  `PING` and `PONG` before other frames, and takes at most 64 KiB of
  frames for one write (`BATCH` and `queue_limit` in
  `crates/pod-link/src/state.rs`). On a slow carrier the same 64 KiB is
  a long wait (0.5 s at 1 Mbit/s). The memory carrier does not show it.
- Read: the CI runs `cargo test --workspace --all-features`. The study
  ran `pod-link` with its default features: 81 tests passed, and 15 of
  27 test targets had no test: the 14 targets of the carriers whose
  feature was off (dns, h2, icmp, poll, quic, tcp, udp, ws), and the
  doc-tests.
  T-525 recorded 190 passed with all features; the tree at `567a56c` has
  213 test markers in the crate.

### zmux

| Scenario | Runs | Result |
| --- | --- | --- |
| Rust `core-bulk`, copy | 3 | 4.57, 4.45, 4.63 GB/s; 0.0000 allocations for each frame |
| Rust `core-bulk`, zero copy | 3 | 6.39, 6.45, 5.87 GB/s; 0.0000 allocations for each frame |
| Rust `tcp-bulk`, raw TCP | 2 | 2.35, 3.91 GB/s |
| Rust `tcp-bulk`, copy | 2 | 1.37, 1.44 GB/s; 1.05, 1.01 CPU s for each GB |
| Rust `tcp-bulk`, zero copy | 2 | 1.55, 1.64 GB/s; 0.83, 0.78 CPU s for each GB |
| Rust `rr`, raw TCP, 64 bytes | 2 | p50 34.4, 26.6 us; p99 64.5, 54.1 us |
| Rust `wake` | 2 | p50 17.0, 16.1 us; p99 150.4, 145.0 us |
| Rust `rr-under-bulk`, TCP | 2 | p50 169.1, 152.4 us; p99 384.7, 351.4 us; bulk with round trips / bulk alone 0.66, 0.77 |
| Go `BulkTCP`, 64 KiB writes | 3 | 1289.76 to 1307.87 MB/s |
| Go `RRRawTCP` | 3 | 14.2 to 14.8 us for each operation |
| Go `RRUnderBulk` | 3 | p50 175.0 to 178.4 us; p99 359.9 to 379.7 us; bulk 1243 to 1280 MB/s |
| Go `MultipathSpread`, 2 pipes | 3 + 3 | 1558.91 to 1625.92 MB/s; split 58/42 for both policies |
| Rust `mp-bulk`, `plain`, 1 pipe | 2 | 18.36, 18.80 Gbit/s; 0.44 CPU s for each GB |
| Rust `mp-bulk`, `eta`, 1 pipe | 2 | 10.74, 11.27 Gbit/s; 0.93, 0.88 CPU s for each GB |
| Rust `mp-bulk`, `eta`, 2 pipes, 1 stream | 2 | 9.49, 8.42 Gbit/s; split `[100, 0]` |
| Rust `mp-bulk`, `eta`, 4 pipes, 1 stream | 2 | 5.50, 5.73 Gbit/s; split `[100, 0, 0, 0]` |
| Rust `mp-bulk`, `eta`, 4 pipes, 8 streams | 2 | 11.17, 10.29 Gbit/s; peak heap 5,670 and 6,740 KB |

- Report: `core-bulk` has no carrier; the `pod-link` harness has a memory
  carrier and an acknowledgement. `rr-under-bulk` of zmux is on TCP; the
  one of `pod-link` is on memory. Do not rank the two.
- Inferred: the scheduler `eta` on one pipe costs about 40 % of the rate
  and twice the CPU of `plain`. More equal pipes on the loopback give
  less rate, not more, and `eta` put all bytes on the first pipe. The
  report gives no cause. A scheduler over many paths needs a measurement
  against one path before it is a default.

## 3. The claims of the report about PodUtils

| Claim | Verdict | Evidence |
| --- | --- | --- |
| The README of `pod-link` has most of a wire contract: the preface, the 8-byte header, eight frame types, the parity rule, the settings with their limits, the timers | holds | `crates/pod-link/README.md`, sections "The wire" and "Settings"; `crates/pod-link/src/frame.rs` |
| The README is not normative and does not state the order of the checks | holds | The README lists the broken rules but not their order. The order is in the code: `shape` in `crates/pod-link/src/frame.rs`, and `on_data` in `crates/pod-link/src/inbound.rs` (window of the link, then a stream that never existed, then DATA after CLOSE, then the window of the stream). T-774 |
| `pod-link` has no byte corpus | out of date in part | No `.json` or `.ndjson` file in the crate: holds. But `fuzz/seeds/link_frame/` has 6 byte seeds and `fuzz/seeds/link_arq/` 5, and `ci.yml` runs them with 2,000 mutations each at each push (`cargo test --manifest-path fuzz/Cargo.toml --lib`). They check invariants (a decoded frame encodes to bytes that decode to the same frame), not an expected result for each entry. T-775 |
| The tests of `tests/frames.rs` assert bytes but another implementation cannot read them | holds | `crates/pod-link/tests/frames.rs` (`the_header_is_eight_bytes_with_a_24_bit_length`, `broken_headers_fail_by_name`) |
| `pod-link` already has a paused clock in `tests/keepalive.rs` | holds | `crates/pod-link/tests/keepalive.rs` uses `#[tokio::test(start_paused = true)]`; `tests/common/mod.rs` has `RawPeer`, a scripted raw peer |
| The doubling of the window is in `src/settings.rs`; parity and OPEN rules are in `src/link.rs` | wrong place | `settings.rs` documents the doubling; `return_credit` in `crates/pod-link/src/state.rs` does it. Parity is `Role::owns` in `state.rs`; the OPEN rules are `on_open` in `crates/pod-link/src/inbound.rs` |
| The registry can take the enums `FrameType` and `ResetCode` | wrong in part | There is no `FrameType`: the types are the constants of `frame::kind` and the enum `Frame`. `ResetCode` is an open `u32` with three names (`crates/pod-link/src/error.rs`) |
| A corpus needs "a split varint" and "a bad reset code" | wrong | `pod-link` has no varint: each field has a fixed width, big endian. Each reset code is valid. A stream id of the wrong parity is an error of the link (`on_open`), not of the decoder: the corpus needs two layers (T-775, T-776) |
| No first-party benchmark target in the five code repositories | holds for podcrates | No `benches/` directory, no `[[bench]]`, no `criterion` in a manifest of podcrates. T-777 |
| Before the report there was no throughput number for `pod-link` at all | wrong in part | T-525 recorded the poll carrier on the loopback: up 107 to 269 MiB/s, down 54 to 100 MiB/s. No number existed for the multiplexer itself |
| `pod-link` has 17 entries in `[dependencies]` and `libc` on unix | holds | `crates/pod-link/Cargo.toml` |
| The default build of `pod-link` has 44 distinct packages | holds, with a finding | `cargo tree -p pod-link -e normal` gives 59 unique lines. Two stacks of curve25519 and SHA-2 come through `pod-identity`: `ed25519-dalek` 2 takes `curve25519-dalek` 4 and `sha2` 0.10; `x25519-dalek` 3 takes `curve25519-dalek` 5; `pod-identity` takes `sha2` 0.11. T-779 |
| The workspace version is 0.58.0 | out of date | `Cargo.toml:9` is 0.61.0 |
| podnet takes `v0.56.0`, podssh `v0.56.0`, podrunner `v0.52.0`, podvm `v0.58.0` | out of date in part | Read through the forge mirror on 2026-11-16: the root manifest of podnet takes `v0.61.0` (26 places); the one of podrunner takes `v0.52.0` (10 places). podssh and podvm: not read |
| podcrates has 50 crates; 37 carry `SOURCES` | holds | `crates/` has 50 directories, 37 with a `SOURCES` file |
| podcrates has 19 workflows | holds | `.github/workflows/` |
| 7 JSON Schemas, 5 generated from Rust types with a drift gate | holds for the 7 files | `schemas/` holds 7 files; `crates/pod-job/src/schemas.rs` writes them with `POD_JOB_WRITE_SCHEMAS=1` and else fails on a difference, in the normal test run of CI |
| `AGENTS.md:56`: "A public API, a name or a format of the wire can change in any version" | holds | `AGENTS.md` |
| Fuzz replay inside the normal suite is a strength of podnet | holds, and podcrates has it too | `fuzz/src/tests.rs` runs each target on its seeds and 2,000 mutations on stable Rust at each push |
| Planted defects prove that a gate can fail (podrunner) | holds, and podcrates has it too | `plants.yml`, `scripts/plant-each.sh` |
| podssh `doctor_upgrade.rs` polls `try_wait()` and reads no pipe; the child blocks at 65,536 bytes | holds (in podssh) | `podssh doctor` wrote 87,463 bytes; its thread waited in `pipe_write` by the third second. The same class is in podcrates: `crates/pod-term/tests/calibration.rs:171`. T-780, T-781 |
| podnet `seccomp_errnos_match_the_host` assumes a route | holds (in podnet) | With no route the host gives `errno 101` and the backend 0. T-781 |
| Three podvm tests assume the environment of CI (a name that resolves, `XDG_DATA_HOME` not set, `http_proxy` not set) | holds (in podvm) | The logs of the three failures; podvm's `proxy_pull.rs` removes `https_proxy`, `all_proxy` and `no_proxy` in both cases, not `http_proxy`. T-781 |
| A test should name a missing precondition, not time out | holds; podcrates has it as a rule | `docs/design.md`, section 1, rule 11; the guards `need_loopback!`, `need_tool!`, `need_userns!`, `need_root!` of `crates/pod-testkit/src/host.rs` |
| `podssh` carries its own multiplexer | not checked | podcrates did not read the podssh tree for it |
| One carrier at a time for each link | holds, with one case | The split (`crates/pod-link/src/split.rs`) puts one session over an up carrier and a down carrier |

## 4. The lessons for podcrates, in order of value

1. **A normative wire document for `pod-link`, held to the code by a
   test** (T-774, `pod-link`). The rules exist in the README and the
   code; the order of the checks and the rule of the timers exist only
   in the code. Read: the keepalive uses `now >= t0 + T` already
   (`link.rs`, `now >= dead`). Write each rule once, with an id, in
   ASD-STE100 (call C750). A test compares each table of the document
   with the constants of the crate, as `pod-job` does for its schemas.
2. **A table of frames with the result of each** (T-775, `pod-link`).
   Valid entries give the frames; invalid entries give the error by its
   name (`FrameError` has 8 variants). The test asserts the count of
   entries. The entries also become seeds of `link_frame`. The fixed
   widths of `pod-link` make the bytes canonical, so byte equality is
   the right test (unlike the varints of zmux).
3. **Scripted cases of a link on a paused clock, with a table of defect
   classes** (T-776, `pod-link`). `RawPeer` already scripts the peer. A
   case names the rule of T-774 that it tests and a class of defect. The
   table names, for each class, a case or the invariant that makes the
   defect impossible.
4. **A committed measurement of the link** (T-777, `pod-link`). podcrates
   has no benchmark. One `MEASURE key=value` line for each result; bulk
   on 1 and 8 streams; round trip idle and under bulk; on the memory and
   the tcp carrier; allocations for each frame (a counting allocator in
   the test binary); the live bytes of a link; the wake latency of the
   host, so that a later gate on latency is relative to the host. A gate
   on allocations, not on throughput. Call C751: podcrates writes its own
   harness.
5. **Fewer copies and no allocation for each `DATA` frame** (T-778,
   `pod-link`). Read: one write allocates a `Vec` for each frame
   (`stream.rs:135`), the decoder allocates one for each body
   (`frame.rs:265`), and the crate copies each byte six times: two at the
   writer (the `Vec` of the frame, the encode into the batch) and four at
   the reader (`Decoder::push`, the `Vec` of the body, the buffer of the
   stream, the buffer of the caller). The Rust core of zmux measured 0.0000
   allocations for each frame. Measure first with T-777.
6. **One stack of curve25519 and SHA-2 in `pod-identity`** (T-779). The
   dependency list of the study shows two of each in the default build
   of `pod-link`. `ed25519-dalek` 3.0.0 is in `Cargo.lock` already
   (through `russh`), on `curve25519-dalek` 5 and `sha2` 0.11.
7. **A child of a test whose pipes nobody reads** (T-780, `pod-term`,
   `pod-testkit`). The podssh failure of the study has the same form as
   `crates/pod-term/tests/calibration.rs`. A helper of `pod-testkit`
   runs a child within a limit and reads its pipes while it runs.
8. **The findings for the tests of the consumers** (T-781). podcrates
   does not edit a consumer; it sends the evidence by COORD issues.
9. **Head-of-line wait on a slow carrier** (a new fact for T-442). The
   measured round trip under bulk on memory is the same as idle; the
   bounded queue of 64 KiB holds it. The wait shows only on a slow
   carrier, so the test of T-442 uses a shaped carrier.

Knowledge with no entry now:

- A latency gate relative to the host (idle p99 and wake p99 of the same
  run), as `at1` does. T-777 measures the inputs; a gate waits for a
  baseline.
- Open information on the `OPEN` of a stream, packet streams and
  datagrams, transport parameters in a preamble, resumption inside the
  protocol, multipath. `pod-link` has none of them. No consumer asked
  for them; resumption is the layer of `pod-session` below the link
  (call C120); priority is T-442.
- A multipath scheduler costs rate on one path (the `eta` numbers). Any
  multipath work in podcrates (none is planned) measures against one
  path and reports the split of each path.
- A hybrid key exchange with ML-KEM in a secure carrier. podcrates has
  no entry for post-quantum keys; the draft status of the zmux document
  shows that it is not settled.

## 5. What podcrates does not take, and why

- Each copy of zmux code, documents, corpus files, registry files or
  scripts, and each contribution to zmux: the ruling "zmux".
- The harness file of the study and its `scripts/reproduce.sh`: podcrates
  writes its own measurement (C751). The study's harness also opens the
  bulk streams first and tells them apart by the order of accept; a test
  of podcrates names each stream in its own bytes.
- The forms of zmux: NDJSON trace headers, BCP 14 keywords, the names
  of the defect classes. podcrates writes its own forms in ASD-STE100
  (C750).
- QMux compatibility, GREASE, a policy of code points: `pod-link` is a
  private wire with no compatibility (`AGENTS.md`, section 2; design
  rule 3). A new type or code changes the preface version when needed.
- A runner for each language, and a scripted peer in a second language:
  `pod-link` has one implementation, and its corpus is data in the
  crate. Start again when a second implementation of the wire exists.
- A shared conformance crate (`pod-conformance`): one crate reads the
  corpus. Start again when a second crate speaks the wire of `pod-link`.
- A claim of conformance in `--version`: a consumer takes the crates by a
  tag; the tag names the corpus and the code.
- A tool that pins external contracts by SHA-256: `pod-services` and
  `pod-services-watch` check the live services each day already.
- Multipath, resumption and priority specifications for features that
  `pod-link` does not have.
- A new dependency for measurement (`criterion`): an ignored test and a
  counting allocator in the test binary need none, and they keep the
  static rule (design rule 1) out of question.
- An allocation gate as a global allocator in a library crate: design
  rule 7 forbids process singletons; the counter lives in the test
  binary only.
