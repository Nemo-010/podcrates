# pod-transit

The transit road: a carrier of a pair's byte stream through a
magic-wormhole transit relay, by default Least Authority's at
`wss://relay.mw.leastauthority.com` (a WebSocket on port 443 that needs no
account). The relay pairs two connections that name one token and two
sides, says `ok` to both, and copies the bytes. A node waits at the relay
under the pair's token; a client meets it there for each link. Each end
proves the pair's secret to the other at each meeting, so a side that
knows the token alone (as the relay does) gets nothing. Each link is a
byte stream for the resumable layer of `pod-session`, and the caller runs
its end-to-end channel above the layer: the relay is trusted for
availability only.

The base is podssh's `crates/podssh-relay/src/transit/` (without
`link.rs`, which is `pod_session::ws_link`).

## API

| Module | What |
| --- | --- |
| `config` | `Config { url, way, trust, connect_timeout, idle, events }`, `Config::new(url, way)`, `with_trust`, `with_events` |
| `token` | `Keys` (`of_pair(name, connect_token)`, `knowing_only(token)`, `token`, `prove(role, sender, receiver)`, `verify`; no `Debug` shows the token or the key), `Side` (`random(&mut dyn Entropy)`, `parse`, `as_str`), `line(&keys, &side)`, `SALT`, `TOKEN_BYTES`, `SIDE_BYTES`, `PROOF_BYTES` |
| `meet` | `meet(&session, &keys, &side, part, wait, &mut entropy)` (the bytes after the peer's proof), `Part` (`Node`, `Client`; `byte`, `other`), `Missed` (`Alone`, `Dropped`, `Refused`, `SamePart`, `NotProven`, `Broken`); the sans-IO steps `answer(line)`, `peer_nonce(hello, part)`, `take_line(&mut bytes)`; `VERSION`, `NONCE`, `HELLO`, `PROOF_LIMIT` |
| `client` | `Dialer`: `new(config, keys)`, `with_side`, `with_wait`, `url`, `config`, `link()` (a new link to the node); `carry(&dialer, app, settings, note)`, `carry_heard(.., hearing)` (the layer across links); `MEET_LIMIT` |
| `far` | `Node { config, keys, side }`, `KeysNow`, `dial(&config)` (a connection to the relay), `serve(node, settings, budget, open, tell)`, `serve_kept(node, settings, budget, open, keeper)` (for ever; the caller ends it) |
| `link` | `pod_session::ws_link`: `Link::start(session, first)` |
| crate root | `default_url()` (the endpoint `relay` of `leastauthority-transit` of `pod-services`), `Setting` (`Off`, `On(url)`), `setting(variable, value)`, `Failed` |
| `Failed` | `Dial { why, stage, class }`, `Alone`, `Missed { shown, missed }`, `Session`; `stage_and_class()`, `From<Failed> for pod_core::Failure` |

## The words of a meeting

* The token and the proof key are HKDF-SHA256 of the pair's connect token
  (salt `podssh transit, version 1`, info a label, a zero byte and the
  pair's name). The token is 64 hex digits; the relay sees it. The salt
  and the labels hold the name podssh: both ends derive the same words.
* Each end sends `please relay TOKEN for side SIDE\n` alone in the first
  binary message; the relay answers `ok\n` once a second side of the token
  came. A relay never pairs two connections of one side, so each end keeps
  one side for its run.
* After `ok`: a hello each way (the version 1, the part `N` or `C`, a
  nonce of 32 bytes), then a proof each way (HMAC-SHA256 under the proof
  key over a label, the role, the sender's nonce and the receiver's). A
  hello of the same part is a second client of the pair (`SamePart`): the
  client tries again within its wait.

## Features

None. The crate needs tokio and pure Rust alone.

## Settings

| Setting | Default | What |
| --- | --- | --- |
| `Config::url` | none: `default_url()` for Least Authority's | the relay |
| `Config::way` | none | the dialer, the TLS context and the user agent |
| `Config::trust` | `Trust::Default` | the roots of a `wss://` relay |
| `Config::connect_timeout` | `pod_core::backoff::CONNECT_TIMEOUT` (20 s) | each step of a dial |
| `Config::idle` | `pod_ws::DEFAULT_IDLE_TIMEOUT` (90 s) | each read of a connection |
| `Config::events` | `NoEvents` | the lines `transit.client`, `transit.dial`, `transit.wait`, `transit.meeting`, `transit.pause` |
| `Dialer::with_wait` | `MEET_LIMIT` (15 s) | how long a link waits for the node |
| `serve`'s `tell` | none | the sink of the budget lines of the node's keeper |

The crate reads no variable of the environment. `setting(variable, value)`
reads a value that the caller read, and names the caller's variable in a
refusal, never the value.

## Failures

`Failed` keeps the words of the source. Its stage and class: a dial gives
the stage and the class of `pod_ws::ConnectError`; `Alone` and
`Missed::Alone` are `Rendezvous`/`Timeout`; `Dropped` and `SamePart` are
`TempFail`; `Refused` is `Protocol`; `NotProven` is `Refused`; `Broken` is
`Unavailable`; `Session` is `Session`/`Protocol`. `Missed` stays the
reason of one meeting.

## Parity

Each line of the source, as it is here:

- [x] the token, the proof key and the proofs, with the vectors of Python's
  hmac and hashlib;
- [x] the line of the relay with a side, and the side of a run;
- [x] the meeting: the line alone, the relay's answers (`ok`, `bad
  handshake`, `impatient`, other words), the hello, the proofs, the bytes
  after the proof as the first of the link, the liveness of the connection
  while an end waits, the Close of the relay as `Dropped`;
- [x] the client: a link within its wait, a second client of the pair and a
  dropped spare tried again apart by 100 to 600 ms, the count of other
  clients in the words of `Alone`;
- [x] the node: one wait at a time, the next at once after a meeting or the
  relay's own bound on a wait (60 s), the backoff after a failure, the
  sweep of the keeper each 10 s, a keeper shared with another road;
- [x] `carry` and `carry_heard` across links;
- [x] the setting of the road (on, off, a URL; no echo of a bad value).

The differences: the way out, the trust, the bounds and the lines are a
`Config` (podssh: a `ProxyChoice`, a `Trust` and a `Say`); the failures are
`Failed` (podssh: a `String`); `serve` takes the sink of its keeper's
budget lines (podssh: its process sink); `setting` takes the name of the
variable; a hello of another length is refused by `peer_nonce` (podssh read
exactly `HELLO` bytes, so the case did not come up).

## Adoption map

| Consumer | Old path | New path |
| --- | --- | --- |
| podssh | `podssh_relay::transit::{client, far, meet, token}`, `Dialer`, `Node`, `Link`, `Missed`, `Part`, `Keys`, `Side`, `default_url` | `pod_transit::{...}`: `transit/mod.rs` re-exports the crate (`pub use pod_transit::*`) and keeps `ENV`, `Say` and `setting` |
| podssh | `transit::ENV` (`PODSSH_TRANSIT`) | stays in podssh; `transit::setting(value)` calls `pod_transit::setting(ENV, value)` |
| podssh | `Dialer::new(url, keys, trust, proxy, say)` | `Dialer::new(transit::config(url, trust, &proxy, say), keys)`; `transit::config` builds the `Config` with `podssh_ws::client::way(&proxy)`, the trust and the lines of `Say` as events |
| podssh | `far::Node { url, keys, side, trust, proxy, say }` | `Node { config: transit::config(url, trust, &proxy, say), keys, side }` |
| podssh | `far::dial(url, &trust, &proxy)` | `far::dial(&transit::config(..))`; its error is `Failed` (`to_string()` gives the same words) |
| podssh | `far::serve(node, settings, budget, open)` | `far::serve(node, settings, budget, open, session::budget::told())` |
| podssh | `Dialer::link()`, `carry`, `carry_heard` give `Result<_, String>` | `Result<_, Failed>`: `.map_err(|e| e.to_string())` where a `String` is kept |
| podssh | `tests/transit.rs`, `tests/transit_server/`, the plant `t436-transit-same-side` | the tests and the harness of this crate; the plant `transit-same-side`; `PODSSH_TRANSIT_TEST_PYTHON` and `PODSSH_TRANSIT_TEST_SERVER` are `POD_WORMHOLE_TEST_PYTHON` and `POD_WORMHOLE_TEST_SERVER`; `PODSSH_TRANSIT_TEST_PLANT` is `POD_TRANSIT_TEST_PLANT` |
| podssh | PodUtils/podssh:.github/workflows/transit-live.yml | the loopback tests run on each push (`scripts/ci/mailbox-tests.sh`); the live run and its plant are steps of `live.yml` |

The adoption trial is `adoption/podssh/pod-transit.patch` with its `.run`
and `.commit`.

## Tests

`cargo test -p pod-transit`. The unit tests: the token, the proof key and
a proof against the vectors of Python (`token`); a proof for its role and
its order alone; the line of the relay; the setting; the relay's answers,
a line and its bound, and the reading of a hello (`meet`); the stage and
the class of each failure (`failed`).

`tests/transit.rs` runs magic-wormhole's own transit relay
(magic-wormhole-transit-relay, Python) on the loopback, from the packages of
`scripts/ci/wormhole-servers.txt`; with no such Python, each test says why
and passes, unless `POD_WORMHOLE_TEST_SERVER=required`
(`scripts/ci/mailbox-tests.sh` sets it on each push):

- `two_ends_meet_and_carry_one_mib_each_way`;
- `two_ends_of_one_side_never_meet_and_the_client_gives_up_within_its_wait`;
- `a_side_that_knows_the_token_alone_is_refused_by_the_node`;
- `two_clients_of_one_pair_never_take_each_other_for_the_node`;
- `a_session_moves_to_another_road_when_the_transit_relay_stops`;
- `the_harness_takes_only_its_own_child_s_listener_for_a_relay` (Linux,
  python3 alone): the harness takes a relay only when its own child
  listens on the port that it chose (`/proc/net/tcp` and the child's
  files), else it chooses new ports; a listener of another test's relay
  on that port is not the test's relay;
- live (`#[ignore]`, `live.yml`):
  `through_least_authority_two_ends_meet_and_carry_one_mib_each_way`,
  `through_least_authority_a_session_of_the_layer_echoes_one_mib`.

The plants (`scripts/plants/`, group `transit`): `transit-same-side`,
`transit-proof-any-role`, `transit-hello-own-part`,
`transit-refusal-echoes`, `transit-answer-unbounded`,
`transit-harness-any-listener`.

## Sources

`SOURCES` lists each file of podssh at `b9c04657` and the file that it
became.
