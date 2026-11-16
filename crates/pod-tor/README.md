# pod-tor

The road through Tor: a stream to a host and a port through the Tor
network with Arti (arti-client), for a host whose only way out is HTTPS.
Arti builds its circuits as it does anywhere; each connection that it opens
to a relay goes through the caller's way out (`pod_ws::Way`: the dialer of
`pod-proxy` with its proxy and its credentials, and the TLS of the binary),
and only to the ports that the proxy allows. Bridges take the first hops in
place of the relays of the directory, and their two transports that pass
where HTTPS passes, meek_lite and WebTunnel, run in this process through
`pod-egress`, with no other program. An onion service reaches a node by its
onion address: Arti's service in this process, whose each circuit is a
connection out to a relay, so the node binds nothing.

The base is podssh's `crates/podssh-tor` (PodUtils/podssh@T-353, T-385 and
T-578). Arti keeps its directory in SQLite, which is C: the feature
`static-sqlite` of arti-client builds it in, so a binary needs no
libsqlite3, and zig cc builds it for the cross targets (the static probe
links it).

## API

| Module | What |
| --- | --- |
| `client` | `Options { state_dir, cache_dir, way, first_hop_ports, trust_directories, network, bridges, trust }`; `Tor::bootstrap(&options, wait)` (Arti fetches what it lacks of the directory and builds a first circuit), `Tor::connect(host, port, wait)` (the exit resolves the name); `TorStream` (`AsyncRead` and `AsyncWrite` of tokio); `Failure { step, detail, permissions }`; `reachable(ports)`; `Runtime` |
| `bridges` | `Bridge::parse(line)` (a plain bridge `ADDRESS:PORT FINGERPRINT`, or `meek_lite` and `webtunnel` with their arguments; a leading `Bridge` is dropped; a transport of another program is refused), `transport`, `line`; `summary(&bridges)`; `refuse_transports(network)`; `apply(&mut builder, &bridges)` |
| `transport` | `Kind` (`Meek`, `WebTunnel`: `name`, `by_name`, `at` (the sentinel address on the loopback that Arti dials as a SOCKS5 proxy, never dialled), `by_addr`); `Said` (the last failure of a transport); `TRANSPORT_WAIT` |
| `runtime` | `ProxiedTcp::new(way, wait)`, `with_trust`, `said`: the TCP provider of Arti, each relay through the dial of the way out, each sentinel a pipe to the transport in this process; it listens on nothing; `CONNECT_WAIT` |
| `onion` | `Tor::serve_onion(&ServiceOptions)` gives an `Onion` (`address`, `published(wait)`, `accept()`), `Tor::connect_onion(..)`; `ServiceOptions { nickname, port, allowed }`; `Discovery` (`from_secret`, `public`: a key of restricted discovery, as C tor writes it); `bridged(stream)`; `is_onion(host)`; `STOPPED` |

The process installs a default `CryptoProvider` of rustls before
`Tor::bootstrap`: Arti takes the default provider for its own TLS.

## Features

None. The crate builds Arti with `tokio`, `rustls`, `static-sqlite`,
`pt-client`, `onion-service-client`, `onion-service-service`,
`restricted-discovery` and `experimental-api`, and with no compression of
the directory (zstd and xz are C).

## Settings

| Field | What |
| --- | --- |
| `state_dir`, `cache_dir` | Arti's state (its guards, kept between runs, as Tor asks) and its copy of the directory |
| `way` | the way out of each first hop and of each transport of a bridge |
| `first_hop_ports` | the ports that a first hop may have, or `None` for any: through a proxy that allows 443 alone, a guard on 9001 can never be reached. With bridges it does not hold |
| `trust_directories` | Arti does not check the owners and the modes of the directories, which the mounts of a sandbox can fail |
| `network` | the TOML of arti-client of another Tor network (chutney's `arti.toml`), whose authorities replace Tor's; a transport there is refused |
| `bridges` | with any, Arti's first hops are these alone, through their transports |
| `trust` | the roots that the TLS of a transport checks |

## Parity

Each line of the source, as it is here:

- [x] the client: the bootstrap within its wait, the directories of the
  caller, the ports of the first hop, another network's configuration,
  the failures with the step and the kind of Arti's error;
- [x] the TCP provider: each relay by its address through the way out, a
  refusal of the proxy as the error of the connection, no listener;
- [x] the bridges: each form of a line, the refusals, the configuration of
  Arti with the sentinels of the two transports and any first hop;
- [x] the transports: the SOCKS5 handshake of Arti in memory, the arguments
  of the bridge in its user and password, meek_lite and WebTunnel opened
  through the way out, the last failure in the words of the bootstrap;
- [x] the onion services: a node's service with restricted discovery, a
  client's stream to it, the address kept across a start.

The differences: the way out is a `pod_ws::Way` (podssh: a `ProxyChoice`
of podssh-ws and its dial); the trust is `pod_tls::Trust`; meek_lite and
WebTunnel are `pod-egress`'s; a stream of a dial is wrapped in a
`sync_wrapper::SyncWrapper`, as Arti asks for a `Sync` stream; the
variables of the tests are `POD_TEST_TOR_NETWORK` and
`POD_TEST_TOR_ONION_LIVE` (podssh: `PODSSH_TEST_TOR_NETWORK`,
`PODSSH_TEST_TOR_ONION_LIVE`).

## Adoption map

| Consumer | Old path | New path |
| --- | --- | --- |
| podssh | `podssh_tor::{Bridge, Options, Tor, TorStream, Discovery, ServiceOptions, Onion, Failure}`, `podssh_tor::{bridges, onion, runtime, transport}` | `pod_tor::{...}`, the same names |
| podssh | `Options { proxy: ProxyChoice::FromEnvironment, trust, .. }` | `Options { way, trust, .. }`: `way` is the `pod_ws::Way` of podssh's dial and TLS (`podssh_ws::client::way(&proxy)`) |
| podssh | `ProxiedTcp::new(proxy, wait)` | `ProxiedTcp::new(way, wait)` |
| podssh | `PODSSH_TEST_TOR_NETWORK`, `PODSSH_TEST_TOR_BRIDGES` of `scripts/tor-net.sh` | `POD_TEST_TOR_NETWORK`, `POD_TEST_TOR_BRIDGES`; the script is `scripts/tor-net.sh` of podcrates |
| podssh | `crates/podssh-tor/tests/`, the job `tor-net` of `build.yml` for the tests of the crate | the tests of this crate; `tor.yml` (the private network and the onion service) |

## Tests

`cargo test -p pod-tor`. The unit tests: the bridge lines, the refusal of a
transport in a network's file, the configuration of the bridges, the ports
of the first hop, the keys of discovery, the SOCKS5 handshake, the
sentinels. `tests/proxied_tcp.rs` (a stand-in proxy on the loopback):
`each_relay_is_asked_of_the_proxy_by_its_address`,
`a_refusal_of_the_proxy_is_an_error_of_the_connection`,
`it_listens_on_nothing`. `tests/transports.rs` (Arti's own client of a
transport against the sentinels, with stand-ins of the two servers):
`arti_s_client_reaches_a_meek_lite_bridge_through_its_sentinel`,
`arti_s_client_reaches_a_webtunnel_bridge_through_its_sentinel`,
`a_transport_that_cannot_open_fails_the_channel_and_says_why`,
`the_meek_stand_in_refuses_a_post_with_no_session_id`.

`tests/private_network.rs` and `tests/onion_service.rs` run against a
private Tor network of C tor (chutney, `scripts/tor-net.sh`), whose
`arti.toml` `POD_TEST_TOR_NETWORK` names; with none, each says so and
passes. `tor.yml` starts the network and runs them:
`a_stream_through_a_private_network_reaches_the_service`,
`a_node_s_onion_service_carries_a_mebibyte_each_way_and_hides_from_a_stranger`,
`a_second_start_keeps_the_address`; on Tor's own network, by hand with
`POD_TEST_TOR_ONION_LIVE=yes`:
`live_a_throwaway_service_on_tor_s_own_network_carries_a_mebibyte_each_way`.

## Sources

`SOURCES` lists each file of podssh at `0370b0b` and the file that it
became.
