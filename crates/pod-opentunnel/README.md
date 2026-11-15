# pod-opentunnel

The OpenTunnel carrier of podssh for the crates of podcrates and their
binaries: a carrier of the reverse road through OpenTunnel
(`opentunnel.xyz`), a blind TLS tunnel with no account. A node makes a
tunnel once (`<id>.opentunnel.xyz` and a bearer token), with a P-256 key and
a CSR that the binary makes, so that the service gets the certificate and
never the key. The node keeps the tunnel in a private file before the bind,
so that each start keeps it and binds no new CSR. The node keeps a bridge:
one WebSocket with the subprotocol `opentunnel` through the caller's way
out. The service sends each visitor's connection over it, still encrypted,
from its ClientHello on, and the node ends TLS with its own key. A client's
leg is TLS by name to `ROUTE.<id>.opentunnel.xyz` on port 443, with no
upgrade: it passes a proxy that refuses the WebSocket upgrade.

Each session over a visitor's connection runs the resumable layer of
`pod-session`. The caller runs the end-to-end channel (`pod-e2e`) above
the layer, so the service is trusted for availability only: it reads the
SNI, the times and the sizes, never the plaintext. The node's route is a
random label, which the wildcard keeps out of the logs of Certificate
Transparency.

The source is podssh's `crates/podssh-relay/src/opentunnel/` at
`b9c0465`. The protocol is anomalyco/opentunnel:docs/protocol.md at v0.6.1.

## API

| Module | What |
| --- | --- |
| (root) | `Service` (`parse`, `hosted`, `authority`, `shown`), `Setting`, `setting(name, value)`, `default_api`, `PORT`, `Say`; re-exports `Dialer`, `carry`, `Name`, `Node`, `Credentials`, `Record`, `Store` |
| `dial` | `tls(Arc<Way>, Trust)`: TLS to the API's host through the caller's `pod_ws::Way`; `tcp(Arc<Way>)`: TCP to a tunnel's name on port 443; `Dial`, `Visit`, `Dialing`, `Io`, `BoxIo`, `CONNECT_LIMIT` |
| `api` | `Api::new(service, dial, user_agent)` (`create`, `bind_csr`, `certificate`, `remove`, `health`, `hurried`, `service`, `dial`, `user_agent`); `Tunnel`, `Created`, `Cert`, `ApiError`, `MAX_BODY`, `REQUEST_LIMIT` |
| `retry` | the retries of the API: `Repeat`, `retryable`, `retry_after_secs`, `bounds`, `wait`, `too_long`, `cloudflare`, `status_words`, `BASE`, `MAX`, `RETRIES` |
| `record`, `provision` | `Credentials` (the key and the CSR of the binary), `Record`, `Store` (`cache(&Places, service, label)`, `in_dirs`, `load`, `save`, `path`, `file_name`), `expiry_secs`; `Provision::new(api, store, credentials, say).run()`, `Provisioned`, `random_route`, `unexpired` |
| `wire`, `bridge`, `conn` | the messages of a bridge (`Up`, `Down`, `decode`, `data_frame`, `split_frame`, `codes`, `route_for_sni`, `fatal`, `attach_words`, `close_words`); `bridge::{request, attach, serve, Attached, Failed}`; a visitor's connection (`conn::{open, Visitor, Held, Outbox, Inbound}`) |
| `far` | `Node { api, record, store, served, provider, say }`, `Node::new(api, record, store, provider, say)`, `name`, `acceptor`; `online(api, store, credentials, provider, say)`, `serve`, `serve_kept`, `bridges`, `TLS_LIMIT` |
| `client` | `Name` (`parse`), `Dialer::new(name, visit, way, trust, say)`, `link`, `Link`; `carry`, `carry_heard` |
| `fuzzing` | (feature `fuzzing`) `message`, `frame`, `tunnel`, `cert`, `service`, `name` |

## Features

| Feature | What |
| --- | --- |
| `fuzzing` | the readers of the fuzz targets `opentunnel_message` and `opentunnel_answer` (`src/fuzzing.rs`); no consumer turns it on |

## Settings

The crate reads no variable of the environment and keeps no process
state.

| Value | Where |
| --- | --- |
| The way out (the proxy, the resolver, the TLS context and its provider) | the `pod_ws::Way` of `dial::tls`, `dial::tcp` and `Dialer::new` |
| The trust of each connection | `pod_tls::Trust` of `dial::tls` and of `Dialer::new` |
| The provider of the node's TLS | `far::online(.., provider, ..)`, `Node::new(.., provider, ..)` |
| The `User-Agent` of each request, and the client of a bridge's attach (podssh: `podssh/VERSION`) | `Api::new(.., user_agent)` |
| The service (podssh: `PODSSH_OPENTUNNEL`) | `setting(name, value)` with the name and the value of the caller's variable; `Service::parse` |
| The place of the record | `Store::cache(&places, ..)` (the caller's `pod_core::files::Places`), or `Store::in_dirs` |
| The keeper of the sessions and its tell of the budget | `far::serve_kept(.., keeper)`; `far::serve` keeps one of its own that tells nothing |
| The lines for the user | `Say`, a callback of text (call C60, T-212) |

## Parity

Against podssh `crates/podssh-relay/src/opentunnel/` at `b9c0465`:

| Capability of podssh | Here |
| --- | --- |
| the API, its retries, the record, the provision (`api.rs`, `retry.rs`, `record.rs`, `provision.rs`) | [x] the same; the record's files are `pod_core::files`, in the caller's places |
| the bridge, its messages and the visitors' connections (`bridge.rs`, `wire.rs`, `conn.rs`) | [x] the same; the user agent and the client of the attach are the caller's |
| the node and its renewal (`far.rs`) | [x] `far`; the TLS server is `pod_tls::server` with the caller's provider |
| the client (`client.rs`), the dials (`dial.rs`: `ProxyChoice`) | [x] `client`, `dial` through the caller's `Way` |
| `ENV`, `setting(value)` | `setting(name, value)`; the consumer keeps its variable |
| `Service::authority` of an IPv6 address on port 443 | [x] fixed: in brackets (call C603) |
| `Service::parse` of a host that is no name and no address | [x] fixed: refused (call C603) |
| the tests of each file; `tests/opentunnel_link.rs`, `opentunnel_interop.rs`, `opentunnel_live.rs`, `opentunnel_stand_in/`, `cleanup/` | [x] the same names |
| the plant `t530-tunnel-not-kept` | [x] `scripts/plants/opentunnel-t530-tunnel-not-kept.*` |
| the workflows `opentunnel-interop.yml` and `opentunnel-live.yml` | `opentunnel-interop.yml` here; the live run is a step of `live.yml` |

Differences, with the choice:

* The variables of the tests are `POD_OPENTUNNEL_TEST_*` and
  `POD_OPENTUNNEL_SERVICE` (podssh: `PODSSH_OPENTUNNEL_TEST_*`,
  `PODSSH_OPENTUNNEL`).
* The fuzz targets `opentunnel_message` and `opentunnel_answer` are new;
  they found the two defects that call C603 fixes.

## Adoption map

### podssh

| Old | New |
| --- | --- |
| `podssh-relay/src/opentunnel/` | `pod_opentunnel`: `podssh_relay::opentunnel` becomes a module of `pub use pod_opentunnel::*` and podssh's `ENV` (`PODSSH_OPENTUNNEL`) |
| `opentunnel::setting(value)` (`node_opentunnel.rs`) | `opentunnel::setting(opentunnel::ENV, value)` |
| `dial::tls(trust, ProxyChoice::FromEnvironment)` (`node_opentunnel.rs`, `funnel_opentunnel.rs`, `doctor/opentunnel.rs`) | `dial::tls(Arc::new(podssh_ws::client::way(&ProxyChoice::FromEnvironment)), trust)` |
| `dial::tcp(ProxyChoice::FromEnvironment)` (`ssh/opentunnel.rs`, `ssh/pinggy.rs`) | `dial::tcp(way)` with the same way |
| `Api::new(service, dial)` | `Api::new(service, dial, &podssh_ws::dial::user_agent())` |
| `Dialer::new(name, visit, trust, say)` | `Dialer::new(name, visit, way, trust, say)` |
| `far::online(api, store, credentials, say)`, `Node::new(api, record, store, say)` | with `podssh_ws::tls::context().provider().clone()` before `say` |
| `Store::cache(&service, label)` | `Store::in_dirs(cache::read_dirs(), cache::candidate_dirs(), &service, label)` |
| `far::serve(..)` (a keeper with `budget::told()`) | `far::serve_kept(.., keeper)` with podssh's keeper |
| `pinggy/`, `localtunnel/`, `hostc/`, `bore/` (`crate::opentunnel::dial::{BoxIo, Dialing, Visit, CONNECT_LIMIT}`, `Say`) | the same items of `pod_opentunnel` |
| `tests/opentunnel_link.rs`, `opentunnel_interop.rs`, `opentunnel_live.rs` | `tests/` here; podssh keeps `tests/opentunnel_stand_in/`, which its CLI tests take by path |
| the plant `t530-tunnel-not-kept` | `scripts/plants/opentunnel-t530-tunnel-not-kept.*` here |
| `.github/workflows/opentunnel-interop.yml`, `opentunnel-live.yml` | `opentunnel-interop.yml` and `live.yml` here |
| `PODSSH_OPENTUNNEL_TEST_*` of the tests | `POD_OPENTUNNEL_TEST_*`, `POD_OPENTUNNEL_SERVICE` |

`adoption/podssh/pod-opentunnel.patch` (at podssh `b9c0465`, after the
patch of `pod-piping`: `pod-opentunnel.needs`) is the hand-off.

## Tests

`cargo test -p pod-opentunnel`: the unit tests of each module (the
messages of the protocol's vectors, the API's answers, the retries, the
record and its private file, the routes, a service's URL), and
`tests/opentunnel_link.rs` against the stand-in OpenTunnel server of
`tests/opentunnel_stand_in/` over pipes: a node makes and keeps a tunnel,
a client echoes 1 MiB by TLS by name, a second start binds no new CSR, the
service's refusals are named, and a session resumes across a cut bridge.
`tests/opentunnel_interop.rs` runs against OpenTunnel's own server in
`opentunnel-interop.yml`, and says that it skipped with no server.
`tests/opentunnel_live.rs` is ignored and runs in `live.yml`. The plants
are `scripts/plants/opentunnel-*` (group `opentunnel`). The fuzz targets
`opentunnel_message` and `opentunnel_answer` read the messages, the
answers, a service's URL and a node's name.

## Sources

`SOURCES` lists each imported file with its blob.
