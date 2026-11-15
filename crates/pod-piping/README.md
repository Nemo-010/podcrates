# pod-piping

The Piping Server carrier of podssh for the crates of podcrates and their
binaries: a carrier of the reverse road through a Piping Server
(`https://ppng.io` by default), for a way out that refuses the WebSocket
upgrade. A Piping Server streams the body of a `POST /PATH` into the
answer to a `GET /PATH`, over plain HTTPS, so both ends dial out and
nothing asks for an upgrade.

The paths come from the pair's secret: the HMAC-SHA-256 of the connect
token over the pair's name. The node waits at its door, a GET on a path
that only the pair's two ends can name. A client posts a hello there that
names a random id for its link, and both ends take the two paths of that
id, one for each way. Each way begins with a mark that the receiver checks
before the layer reads a byte. Each end POSTs its way and GETs the other's:
over HTTP/2 on one connection where the server's TLS offers it, else over
HTTP/1.1. A streamed POST that does not flow within 15 s (a proxy that
holds a body until its end) makes the client ask for numbered POSTs, one
for each piece. With the public servers of `pod-services`, the node and
the client meet at the first server that answers.

Each session over it runs the resumable layer of `pod-session`. The caller
runs the end-to-end channel (`pod-e2e`) above the layer, so the server is
trusted for availability only. `probe` tells a refusal of the upgrade on
the way from the relay's own word: the cue to try the carrier when the user
did not ask for it.

The source is podssh's `crates/podssh-relay/src/piping/` at `b9c0465`.

## API

| Module | What |
| --- | --- |
| (root) | `Say` (where the lines of the carrier go), `FEATURES` (the features of the layer over a Piping Server: `replay.v1`, `heartbeat.v1`); re-exports `Dialer`, `carry`, `Failed`, `Http`, `Node`, `Link`, `Secret`, `Server` |
| `server` | `Server { host, port, prefix }`, `Server::parse` (`https://HOST[:PORT][/PREFIX]`), `authority`, `path`, `holds_bodies` (the fact `streams-request-body` of `pod-services`), `Server::default` (ppng.io), `public()` (each server of kind `piping` of `pod-services`, in order), `default_host`, `PORT` |
| `dial` | `tls(Arc<Way>, Trust)`: TCP through the dialer of the caller's `pod_ws::Way`, then TLS with its context, offering `h2` and `http/1.1` (a caller's own TLS configuration: no ALPN); `Dial`, `Dialing`, `Io`, `BoxIo`, `Proto`, `CONNECT_LIMIT`, `ALPN_H2`, `ALPN_H1` |
| `exchange` | `Http::new(server, dial, user_agent)`: the client of one server (`get`, `get_all`, `post`, `post_stream`, `close`, `proto`, `server`, `user_agent`); `Failed` (`status`, `why`, `waited`, `again`); `Body`, `Upload`, `all`, `delivered`, `delivered_whole` |
| `http1`, `http2` | the requests and the answers of each protocol: `http1::{request, chunk, read_head, Reader, Answer, Framing, Length, LAST_CHUNK}`; `http2::{Conn, get, get_sized, post, post_stream, send_all, next}` |
| `paths` | `Secret` (`of_pair`, `from_bytes`, `door`, `path`, `mark`, `hello`, `read_hello`), `Ends` (`client`, `node`), `LinkId`, `Mode` (`Streamed`, `Numbered`), `Way`, `same`, `hex`, `HELLO_WORD`, `VERSION`, `MARK_BYTES`, `HELLO_MAX` |
| `flow`, `numbered` | a link: `Link` (a byte stream for the layer), `streamed`, `Opening` (`Held`, `Failed`), `HELLO_LIMIT`, `PIPE`; `numbered::open`, `PIECE`, `SMALL_PIECE` |
| `client` | `Dialer::new(secret, http, say)`, `Dialer::with_servers(secret, https, say)`, `link`, `server`, `proto`, `numbered`, `close`; `carry`, `carry_heard` (a session of the layer across links); `DOOR_LIMIT` |
| `far` | `Node { secret, http, fallbacks, say }`, `serve_kept(node, settings, budget, open, keeper)`; `DOOR_REFRESH` |
| `probe` | `upgrade(relay, name, &Way, &Trust, limit)` → `Probe` (`Passes`, `Refused`, `Unknown`); `upgrade_refused(&ConnectError)` |
| `fuzzing` | (feature `fuzzing`) `hello`, `hello_of`, `answer` (an HTTP/1.1 answer read with no runtime), `server` |

## Features

| Feature | What |
| --- | --- |
| `fuzzing` | the readers of the fuzz targets `piping_hello` and `piping_answer` (`src/fuzzing.rs`); no consumer turns it on |

## Settings

The crate reads no variable of the environment and keeps no process
state.

| Value | Where |
| --- | --- |
| The way out (the proxy, the resolver, the TLS context and its provider) | the `pod_ws::Way` of `dial::tls` and of `probe::upgrade` |
| The trust of each connection | `pod_tls::Trust` of `dial::tls` and of `probe::upgrade` |
| The `User-Agent` of each request (podssh: `podssh/VERSION`) | `Http::new(.., user_agent)`; the probe's is `Way::user_agent` |
| The servers, in order | the caller's `Http` values: `Dialer::with_servers`, `Node::fallbacks` (podssh: `PODSSH_PIPING`, else `server::public()`) |
| The settings of the layer, the replay budget, the keeper | `carry(.., Settings, ..)`, `far::serve_kept(.., Settings, budget, .., keeper)` |
| The lines for the user | `Say`, a callback of text (call C60, T-212) |

## Parity

Against podssh `crates/podssh-relay/src/piping/` at `b9c0465`:

| Capability of podssh | Here |
| --- | --- |
| the paths, the hello, the marks (`paths.rs`) | [x] `paths`; the labels of the keys and the word of the hello keep `podssh piping v1` and `podssh-piping`: they name the protocol, so that the ends of each consumer meet |
| the streamed and the numbered link (`flow.rs`, `numbered.rs`) | [x] `flow`, `numbered` |
| HTTP/1.1 and HTTP/2 (`http1.rs`, `http2.rs`, `exchange.rs`) | [x] the same; the user agent is the caller's |
| the TLS dial (`dial.rs`: `podssh_ws::dial::dial` with a `ProxyChoice`, `podssh_ws::tls::config_for`) | [x] `dial::tls(way, trust)`: the dialer and the TLS context of the `Way` |
| the client and the node across the public servers (`client.rs`, `far.rs`) | [x] `client`, `far`; the node's backoff is `pod_core::backoff` (podssh `open::backoff`, the same function) |
| the probe of the upgrade (`probe.rs`: `open_tls` with a `ProxyChoice`) | [x] `probe::upgrade(relay, name, way, trust, limit)` |
| the server's URL and the public servers (`server.rs`) | [x] `server` |
| `USER_AGENT` (`podssh/VERSION`) | the caller's value (`Http::new`, `Way::user_agent`) |
| `Say` | [x] the same callback of text (call C60; the events wait for T-212) |
| the tests of each file; `tests/piping.rs`, `tests/piping_live.rs`, `tests/piping_harness/` | [x] the same names |
| the plants `t437-paths-swapped`, `t575-third-before-second` | [x] `scripts/plants/piping-*` |
| the workflows `piping.yml` and `piping-rate.yml` | the loopback tests: `scripts/ci/piping-tests.sh` in `ci.yml` on each push; the session through ppng.io: `live.yml` (Thursday, by hand); the rates: `live.yml` with `measure` = `piping-rates`; the steps with `podssh node` stay in podssh |

Differences, with the choice:

* The refusals of a hello say "not a hello of this carrier" and "which this
  end does not read" (podssh: "of podssh", "this podssh").
* The variables of the tests are `POD_PIPING_TEST_JS`,
  `POD_PIPING_TEST_RUST` and `POD_PIPING_SERVER` (podssh:
  `PODSSH_TEST_PIPING_JS`, `PODSSH_TEST_PIPING_RUST`, `PODSSH_PIPING`).
* The fuzz targets `piping_hello` and `piping_answer` are new.

## Adoption map

### podssh

| Old | New |
| --- | --- |
| `podssh-relay/src/piping/` | `pod_piping` (the feature `piping` of `podssh-relay` takes the crate); `podssh_relay::piping` becomes `pub use pod_piping::*` |
| `piping::USER_AGENT` | podssh's own `podssh/VERSION`, to `Http::new` |
| `dial::tls(trust, ProxyChoice::FromEnvironment)` (`podssh-cli/src/piping_road.rs`) | `dial::tls(Arc::new(podssh's way), trust)`: the `pod_ws::Way` of podssh's process context |
| `Http::new(server, dial)` | `Http::new(server, dial, USER_AGENT)` |
| `probe::upgrade(relay, name, &trust, &proxy, limit)` (`podssh-cli/src/node_piping.rs`) | `probe::upgrade(relay, name, &way, &trust, limit)` |
| `smee/`, `filehost/` (`crate::piping::{dial, exchange::Failed, http1, paths, flow::Opening, Server, FEATURES}`) | the same items of `pod_piping` |
| `tests/piping.rs`, `tests/piping_live.rs`, `tests/piping_harness/` | `tests/` here |
| the plants `t437-paths-swapped`, `t575-third-before-second` | `scripts/plants/piping-*` here |
| `.github/workflows/piping.yml` (the loopback tests, the live session), `piping-rate.yml` | `ci.yml` and `live.yml` here; podssh keeps the steps of `node_piping` |
| `PODSSH_TEST_PIPING_JS`, `PODSSH_TEST_PIPING_RUST`, `PODSSH_PIPING` of the tests | `POD_PIPING_TEST_JS`, `POD_PIPING_TEST_RUST`, `POD_PIPING_SERVER` |

`adoption/podssh/pod-piping.patch` (at podssh `b9c0465`,
`pod-piping.commit`) is the hand-off.

## Tests

`cargo test -p pod-piping`: the unit tests of each module (the paths,
the hello, the server's URL, the probe's words, HTTP/1.1 against the bytes
of Node's and hyper's answers, the words of a sender's answer, the ALPN of
the dial), and `tests/piping.rs` against nwtgck's own servers on the
loopback (`tests/piping_harness/`): 1 MiB each way through nwtgck's
piping-server over HTTP/1.1 and through piping-server-rust over HTTP/2 and
HTTP/1.1; numbered pieces through a stand-in proxy that holds each body to
its end; the meeting at the second and at the third server; a client of
another pair; the refusal of the upgrade. A test whose server is not there
says "did not run": `scripts/ci/piping-tests.sh` installs both servers and
fails on that line. `tests/piping_live.rs` is ignored and runs in
`live.yml`. The plants are `scripts/plants/piping-*` (group `piping`).
The fuzz targets `piping_hello` and `piping_answer` read a hello, a URL and
an HTTP/1.1 answer.

## Sources

`SOURCES` lists each imported file with its blob.
