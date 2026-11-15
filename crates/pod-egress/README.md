# pod-egress

The roads out that are not the relay. A proxy, a forwarder or a server of
another product carries the bytes to a target, or to a bridge of Tor, or
to a tunnel of Cloudflare:

* `via`: a second forward proxy over TLS (Caddy's forwardproxy, squid's
  `https_port`, h2o), by HTTP/1.1's or HTTP/2's CONNECT, with Basic from a
  private file;
* `forwarder`: a WebSocket forwarder of another product that takes its
  target from the client: in its URL (`{host}`, `{port}`), in a first frame
  of JSON, or by Wisp (`wisp+wss://`); the built-in ones are the services
  of the kind `forwarder` of `pod-services`;
* `wisp`: many TCP streams over one WebSocket, by Mercury Workshop's Wisp
  protocol, versions 1 and 2;
* `wstunnel`: a server of erebe/wstunnel, 9.1 to 11, with its token, its
  path prefix and its `Authorization`;
* `meek` and `webtunnel`: Tor's pluggable transports meek_lite and
  WebTunnel, as lyrebird speaks them, with what they share (`pt`);
* `cloudflare`: the road of `cloudflared access tcp`, with the credentials
  of Cloudflare Access.

This is part 1 of the crate (T-035). Parts 2 and 3 add `vless/`, `vmess/`,
`trojan/`, `shadowsocks/`, `eice/` and `iap/` of podssh-ws.

The base is podssh's `crates/podssh-ws/src/` at `2ffb7cd7`: `via/`,
`forwarder/`, `wstunnel/`, `wisp/`, `meek.rs`, `meek/`, `webtunnel.rs`,
`pt.rs` and `cloudflare.rs`, with their tests.

## API

| Module | What |
| --- | --- |
| crate root | `Note` (`Arc<dyn pod_core::Events>`: a peer's own words), `Duplex` (the stream of a tunnel), `AtEnd`, `Carried`, `Ended`, `Status`, `Form` |
| `carry` | `spawn(session, form, at_end, note, peer)` (a WebSocket session as a byte stream, and the peer's first word), `spawn_bytes(session, at_end, peer)` (each data frame is bytes), `Carried { stream, status }` (`of`, `abort`), `Status` (`get`, `set_once`), `Ended`, `First`, `Form` (`Query`, `Frame`, `Wisp`), `answer(payload)`, `EARLY_WAIT`, `NOTE` (the kind `egress.note`) |
| `end` | `AtEnd` (`Now`, `AfterPeer`), `end_of_input(at, peer_ended, close)` |
| `via` (feature `via`) | `Via` (`parse`, `with_credentials`, `shown`, `names_user`, `has_credentials`), `Dial { way, trust, timeout, offer, auth_file }`, `Offer`, `Version`, `Client` (`new`, `via`, `open(host, port)`; a `pod_core::Dial`), `Opened { stream, version, shared, fell_back }`, `Stream` (`pod_ws::h2_road::Stream`), `DEFAULT_PORT` |
| `forwarder` (feature `forwarder`) | `Template` (`parse`, `form`, `shown`, `fill`, `first_frame`), `Dial { way, trust, timeout, at_end, note }`, `open(template, host, port, dial)`, `Forwarder { template, dial }` (a `pod_core::Dial`), `ForwarderError` (`line`, `stage_and_class`; a `pod_core::Failure`), `builtin` (`builtin()`, `lookup`, `words`, `Builtin`), `HOST`, `PORT`, `WISP`, `RECEIVE_CAP`, and the shared parts again |
| `wisp` (feature `wisp`) | `Wisp` (`connect(url, connect)`, `opened`, `confirms`, `open(host, port, at)`), `Connect { way, trust, timeout, note }`, `WispStream` (`id`, `opened(wait)`, `end`, `close`), `Road { wisp, at_end, shown }` (a `pod_core::Dial`), `WispError` (`stage_and_class`; a `pod_core::Failure`), `End`, `Opened`, `answer`, `packet` (`Packet`, `Info`, `Extension`, `Reason`, `encode`, `decode`, `data`), `PROTOCOL`, `VERSION`, `RECEIVE_CAP`, `NOTE` (the kind `wisp.note`) |
| `wstunnel` (feature `wstunnel`) | `Server` (`parse`, `shown`, `tls`, `host`, `port`, `is_loopback`), `Secret` (`parse`, `is_default`), `check(server, secret)`, `Dial { way, trust, timeout, at_end }`, `open(server, secret, host, port, dial)`, `Tunnel { server, secret, dial }` (a `pod_core::Dial`), `WstunnelError` (`line`, `stage_and_class`; a `pod_core::Failure`), `upgrade` (`request`, `upgrade`, `words`, `SUBPROTOCOL`, `VERSIONS`, `REFUSED_9`, `REFUSED_10`), `claims`, `host_claim`, `sign`, `uuid_text`, `KEY`, `PREFIX`, `DEFAULT_PREFIX`, `RECEIVE_CAP`, `PEER` |
| `pt` (feature `meek` or `webtunnel`) | `Reach { way, trust, wait }`, `HttpUrl` (`parse`, `path`, `shown`), `host_port`, `get` |
| `meek` (feature `meek`) | `Args` (`parse`), `Front`, `open(args, reach)`, `Session` (`shown`, `carry(local)`), `Ended`, `next_poll`, `session_id`, `MAX_PAYLOAD`, `INIT_POLL`, `MAX_POLL`, `MAX_TRIES`, `RETRY_DELAY`, `EXCHANGE_WAIT` |
| `webtunnel` (feature `webtunnel`) | `Args` (`parse`, `shown`, `dial`, `server_name`), `open(args, reach)`, `request`, `check_answer`, `chain_hash` |
| `cloudflare` (feature `cloudflare`) | `Access`, `connect(host, access, way, trust, timeout, idle)`, `connect_loopback(host, port, access, user_agent, timeout, idle)` (feature `plain-ws`), `request`, `refused_by_access`, `PORT`, `PATH`, `MAX_MESSAGE`, `LOGIN_PATH`, `CLIENT_ID`, `CLIENT_SECRET`, `TOKEN` |
| `fuzzing` (feature `fuzzing`) | `wisp_packet`, `wisp_answer` |

## Each road as a dialer

A road that takes its target from the client is a `pod_core::Dial`
(`via::Client`, `forwarder::Forwarder`, `wisp::Road`, `wstunnel::Tunnel`):
a dial of a target opens the road to it before the deadline, and gives the
stream. Each says `names_inside()` (the far end resolves the name), its
`label()` and its `proxy_label()`. A failure is a `pod_core::Failure` with
the stage and the class of the road's error, in the line that names the
road. meek_lite, WebTunnel and the Access client reach one far end that
the bridge or the tunnel names: they are not dialers.

## How a new road joins the crate

1. Put the road in `src/ROAD/` (or `src/ROAD.rs`), behind a feature of its
   name in `Cargo.toml`, with its optional dependencies. `src/lib.rs`
   declares the module under `#[cfg(feature = "ROAD")]`.
2. The road dials through a `pod_ws::Way` and a `pod_tls::Trust` that its
   `Dial` (or its settings struct) holds by value; no `ProxyChoice`, no
   process state, no variable of the environment.
3. A WebSocket road whose server carries the bytes in frames takes
   `carry::spawn` or `carry::spawn_bytes`, and `AtEnd` from `end`; a peer's
   own words go to a `Note`. A tunnel's stream is a `Duplex`.
4. Its error gives `stage_and_class()` and `From<Error> for
   pod_core::Failure`. A road that takes its target from the client is a
   `pod_core::Dial` (a struct of the road and its `Dial`); `road::left`
   and `road::late` bound a dial by its deadline.
5. Its tests go to `tests/ROAD.rs` with `required-features`, its way from
   `tests/common/way.rs`; its plants to `scripts/plants/egress-*.plant`;
   its files and blobs to `SOURCES`; its rows to the tables of this README.
6. Do not change the shared parts (`carry`, `end`, `Note`, `Duplex`,
   `road`) for one road: a change there is its own entry.

## Features

| Feature | What |
| --- | --- |
| `via` | the second proxy (h2, http, bytes, base64, zeroize, tokio-rustls) |
| `forwarder` | the forwarders and the built-in ones (pod-services); turns on `wisp` |
| `wisp` | the Wisp client |
| `wstunnel` | wstunnel (HMAC-SHA-256 of its token) |
| `meek`, `webtunnel` | Tor's pluggable transports (SHA-256) |
| `cloudflare` | the Access road |
| `plain-ws` | `cloudflare::connect_loopback`, for the tests; no binary turns it on |
| `fuzzing` | the readers of the fuzz target `wisp_packet`; no consumer turns it on |

No feature is on by default. Each one is pure Rust.

## Settings

| Setting | Where | What |
| --- | --- | --- |
| the way out | `Dial::way`, `Connect::way`, `Reach::way`, `cloudflare::connect`'s `way` | the dialer (direct, the host's proxy), the TLS context and its words, the user agent |
| the trust | `trust` of each | the roots of each TLS connection |
| the bounds | `timeout`, `wait` | each step of a dial |
| the end of input | `at_end` | a Close at once, or after the peer's end |
| the notes | `note` | the sink of a peer's own words (`egress.note`, `wisp.note`) |
| the credentials file | `via::Dial::auth_file` | how the user names it in the words of a `407` |

The crate reads no variable of the environment. The app's name in the
words of a refusal is the `app` of the TLS words of the way
(`pod_tls::Words`); the user agent is the way's.

## Failures

`via` returns `pod_proxy::DialError` (its stage and class are pod-proxy's).
`ForwarderError`: `Target` is `Connect`/`Usage`; `Connect` is the stage and
the class of `pod_ws::ConnectError`; `Answer` is `WebSocket`/`Protocol`;
`Closed` (the forwarder's Close before the target's bytes) is
`Origin`/`Unavailable`. `WispError`: `Opening` is `WebSocket`/`Protocol`;
`Refused` is `Origin`/`Refused`; `Closed` with 0x48 is `Origin`/`Policy`,
another `Closed` is `Origin`/`Unavailable`; `Gone` and `Failed` are
`WebSocket`/`Unavailable`. `WstunnelError`: `Target` is `Connect`/`Usage`;
`Refused` (each 400 of wstunnel) is `WebSocket`/`Refused`; `NotWstunnel` is
`WebSocket`/`Protocol`. meek_lite, WebTunnel and `pt` keep podssh's
`String`.

## Parity

Each line of the source, as it is here:

- [x] via: the URL, the credentials file, the versions offered, HTTP/1.1's
  and HTTP/2's CONNECT, one HTTP/2 connection for each tunnel that follows,
  HTTP/1.1 after a reset of HTTP/2, the words of a `407` and of a proxy
  with probe resistance;
- [x] the forwarders: the template's forms, the target checked before it
  goes in, the first frame and its answer, the early wait of the query
  form, the notes, the Close before the target's bytes, the built-in ones;
- [x] the carrier of a session: frames of 32 KiB, the notes, the first word,
  the status, the liveness, text frames as bytes (frps);
- [x] the end of input: `Now` and `AfterPeer`;
- [x] Wisp: versions 1 and 2, the credit, the streams, the reasons, the
  message of the day, stream open confirmation, the forwarder's road;
- [x] wstunnel: the server's URL, the secret file, the token and its
  claims, the upgrade and the words of each version;
- [x] meek_lite: the fronts, the polls, the session id, the exchanges and
  their tries;
- [x] WebTunnel: the arguments, the pin of the certificates, the upgrade;
- [x] the Access client: the upgrade of cloudflared, the credentials in
  their headers, a refusal of Access with no credential in it.

The differences: the way out is a `pod_ws::Way` (podssh: a `ProxyChoice`,
the process's TLS context and `podssh/VERSION`); a peer's words go to
`pod_core::Events` (podssh: `Arc<dyn Fn(&str)>`); the structs of a road's
settings own their values (podssh: references); the built-in forwarders are
a function (podssh: a static); the names of the caller are parameters (the
app of the TLS words, `auth_file`); the entropy is pod-core's (podssh:
pod-tls's `OsRandom`); via's stream of HTTP/2 is pod-ws's; each road that
takes a target is a `pod_core::Dial` and its error a `pod_core::Failure`
(new).

## Adoption map

| Consumer | Old path | New path |
| --- | --- | --- |
| podssh | `podssh_ws::{via, forwarder, wstunnel, wisp, meek, webtunnel, pt, cloudflare}` | the same modules of podssh-ws, each `pub use pod_egress::ROAD::*` with podssh's glue: `via::dial(trust, &proxy, timeout, offer)` and `AUTH_FILE`; `forwarder::dial(&trust, &proxy, timeout, at_end, note)`, `forwarder::note(say)`, `forwarder::silent()`; `wstunnel::dial(&trust, &proxy, timeout, at_end)`; `wisp::connect_with(&trust, &proxy, timeout, note)`; `pt::reach(&proxy, trust, wait)`; `cloudflare::connect(host, access, trust, proxy, timeout, idle)` and `USER_AGENT` |
| podssh | `forwarder::carry`, `forwarder::end` (crate-private) | `pod_egress::carry`, `pod_egress::end`, re-exported in podssh's `forwarder` for chisel, upterm, frp, shadowsocks, vless |
| podssh | `via::Dial { trust, proxy, timeout, offer }`, `forwarder::Dial { trust, proxy, .. }`, `wstunnel::Dial { trust, proxy, .. }`, `wisp::Connect { trust, proxy, .. }`, `pt::Reach { proxy, trust, wait }` | the glue functions above, which build each with `podssh_ws::client::way(&proxy)` |
| podssh | `forwarder::Note` of `Arc::new(\|text: &str\| ..)` | `forwarder::note(\|text\| ..)`, or `forwarder::silent()` |
| podssh | `forwarder::builtin::BUILTIN` | `forwarder::builtin::builtin()`; `lookup` gives a `Builtin` by value |
| podssh | `via::Stream::from_parts(send, recv)` (vless) | `pod_ws::h2_road::duplex(send, recv)` |
| podssh | `cloudflare::connect_loopback(host, port, access, timeout, idle)` | `.., access, user_agent, timeout, idle` (feature `plain-ws`) |
| podssh | `wstunnel::upgrade::request(host, secret, token, key)`, `upgrade(stream, request, key)` | `.., key, user_agent)`, `.., key, app)` |
| podssh | `tests/via.rs`, `forwarder.rs`, `live_forwarder.rs`, `meek.rs`, `webtunnel.rs`, `wisp.rs`, `wisp_support/`, `wstunnel.rs`, `cloudflare_access.rs` | the tests of this crate; `tests/common/talker.rs` stays in podssh for its other roads |
| podssh | the plants `t438-wisp-credit`, `t439-via-no-credential`, `t441-wstunnel-wrong-secret` | `egress-wisp-credit`, `egress-via-no-credential`, `egress-wstunnel-wrong-secret` |
| podssh | `PODSSH_TEST_WISP_PYTHON`, `PODSSH_TEST_WISP_REQUIRED`, `PODSSH_TEST_FORWARDER_PLANT` | `POD_EGRESS_TEST_WISP_PYTHON`, `POD_EGRESS_TEST_WISP_REQUIRED`, `POD_EGRESS_TEST_FORWARDER_PLANT` |
| podssh | PodUtils/podssh:.github/workflows/forwarder-live.yml | `.github/workflows/forwarder-live.yml` of podcrates; podssh's `via-interop.yml`, `wstunnel-interop.yml` and `wisp-rate.yml` drive its binary and stay |

The adoption trial is `adoption/podssh/pod-egress.patch` with its `.run`
and `.commit`.

## Tests

`cargo test -p pod-egress --all-features`. The unit tests: via's URL, its
credentials file, its offers, the words of a `407` and of a refusal, the
requests of HTTP/1.1 and HTTP/2; the forwarder's templates, the lines of
its failures, the built-in ones; the carrier's notes, its text frames, its
status, the answer of the frame form; the end of input; Wisp's packets, its
opening, its errors and the forwarder's road; wstunnel's server, secret,
token (against Python's vectors), request and words; meek_lite's polls,
session id, arguments and carry; WebTunnel's arguments, pin, request and
answer; the Access client's request.

The tests of each road against stand-ins on the loopback:

- `tests/via.rs`: `the_credential_goes_with_each_connect_and_a_407_says_what_is_missing`,
  `two_tunnels_share_one_http2_connection`,
  `the_host_s_proxy_carries_the_tls_to_the_second_proxy`,
  `a_connect_that_http2_resets_goes_over_http1`,
  `a_refusal_an_unreachable_target_and_another_name_fail_with_their_words`,
  `the_client_is_a_dialer_and_a_refusal_is_a_typed_failure`;
- `tests/forwarder.rs`: the query and the frame forms, a Close before the
  target's bytes, a failed answer, a pipe's end of input, a target that
  would change the URL, and
  `a_forwarder_is_a_dialer_and_its_close_is_a_typed_failure`;
- `tests/wisp.rs` (with `tests/wisp_support/`): two streams at once, the
  credit, a closed stream, version 2, a credential refused, the
  forwarder's road, a pipe's end of input,
  `a_wisp_road_is_a_dialer_and_a_blocked_target_is_a_typed_failure`, and
  two tests against wisp-server-python where it is installed
  (`POD_EGRESS_TEST_WISP_PYTHON`; `POD_EGRESS_TEST_WISP_REQUIRED` makes a
  missing one a failure);
- `tests/wstunnel.rs`: each server of 9.1 to 11, the secret, the words of
  another version and of another server, a pipe's end of input, `wss://`,
  `a_tunnel_is_a_dialer_and_a_refusal_is_a_typed_failure`;
- `tests/meek.rs`, `tests/webtunnel.rs`: the stand-ins of meek-server and
  of the WebTunnel server;
- `tests/cloudflare_access.rs` (feature `plain-ws`): the upgrade of
  cloudflared line by line, messages of 16 KiB, no Ping, a refusal of
  Access;
- live (`#[ignore]`, `forwarder-live.yml`, each day):
  `tests/live_forwarder.rs`, GitHub's version line through each built-in
  forwarder; `POD_EGRESS_TEST_FORWARDER_PLANT` makes each fail.

The plants (`scripts/plants/`, group `egress`): `egress-wisp-credit`,
`egress-via-no-credential`, `egress-wstunnel-wrong-secret`,
`egress-via-dial-untyped`, `egress-forwarder-close-untyped`,
`egress-wstunnel-refusal-untyped`, `egress-wisp-blocked-untyped`.

The fuzz target `wisp_packet` (`fuzz/`, feature `fuzzing`).

## Sources

`SOURCES` lists each file of podssh at `2ffb7cd7` and the file that it
became.
