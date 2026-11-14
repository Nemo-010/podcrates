//! The options of RFC 8489 and RFC 8656 against coturn, a server that this
//! crate did not write (T-381): EVEN-PORT and the RESERVATION-TOKEN of the
//! next port, DONT-FRAGMENT, the address families on a server of IPv4
//! alone, the ALPN `stun.turn` over TLS, and the 300 of a second coturn
//! (`--alternate-server`, `--tls-alternate-server`) over UDP and over TLS,
//! with a redirect that the caller's way out refuses. coturn has no nonce
//! cookie and no USERHASH: the mock proves them (`tests/turn_redirect.rs`).
//!
//! `scripts/ci/turn-tests.sh` starts both coturns on 127.0.0.1 and names them
//! in the variables of `tests/common/coturn.rs`; with none each test skips,
//! unless `POD_TURN_TEST_COTURN=required`, which the script sets.

mod common;

use std::sync::Arc;

use common::coturn::{PASSWORD, USER, bound_socket, coturn, echoed, tls_settings, udp_settings, within};
use common::{Refusing, echo_peer};
use pod_core::{Class, Failure, Stage, Target};
use pod_turn::stun::ALLOCATE;
use pod_turn::{AddressError, Allocation, Client, Error, Family, Port, Transport};

/// An Allocate over UDP of `allocation`, on a socket of its own.
async fn allocate(coturn: &common::coturn::Coturn, allocation: Allocation) -> Result<Client, Error> {
    let mut settings = udp_settings(coturn, &bound_socket().await, USER, PASSWORD);
    settings.allocation = allocation;
    within(Client::allocate(settings)).await
}

/// EVEN-PORT with the R bit: an even port and a token; an Allocate with the
/// token, on another 5-tuple, gets the next port. EVEN-PORT alone gets an
/// even port and no token.
#[tokio::test]
async fn an_even_port_keeps_the_next_port_for_its_token() {
    pod_testkit::need_loopback!();
    let Some(coturn) = coturn() else { return };
    let even = allocate(&coturn, Allocation { port: Port::Even, ..Allocation::default() }).await.unwrap();
    assert_eq!((even.relayed_address().port() % 2, even.reservation_token()), (0, None));
    let first = allocate(&coturn, Allocation { port: Port::EvenAndNext, ..Allocation::default() }).await.unwrap();
    let port = first.relayed_address().port();
    assert_eq!(port % 2, 0);
    let token = first.reservation_token().expect("coturn gives a token of the next port");
    let next = allocate(&coturn, Allocation { reservation: Some(token), ..Allocation::default() }).await.unwrap();
    assert_eq!(next.relayed_address(), std::net::SocketAddr::new(first.relayed_address().ip(), port + 1));
    for client in [even, first, next] {
        within(client.close()).await.unwrap();
    }
    println!("coturn: an even port kept the next port for its token");
}

/// DONT-FRAGMENT in the Allocate and in a Send indication: coturn takes
/// both, and the peer's echo comes back.
#[tokio::test]
async fn dont_fragment_goes_in_the_allocate_and_a_send() {
    pod_testkit::need_loopback!();
    let Some(coturn) = coturn() else { return };
    let peer = echo_peer().await;
    let mut client = allocate(&coturn, Allocation { dont_fragment: true, ..Allocation::default() }).await.unwrap();
    within(client.create_permission(peer)).await.unwrap();
    client.send_to(peer, b"df").await.unwrap();
    echoed(&mut client, peer, None, b"df").await;
    within(client.close()).await.unwrap();
    println!("coturn: DONT-FRAGMENT went in the Allocate and a Send");
}

/// coturn relays on 127.0.0.1 alone: IPv4 asked gets IPv4, IPv6 asked gets
/// 440, and both get IPv4. coturn 4.18 names the 440 of IPv6 in
/// ADDRESS-ERROR-CODE (and writes `0.0.0.0:0` for it, which the client
/// drops); coturn 4.6 names nothing.
#[tokio::test]
async fn each_address_family_on_a_server_of_ipv4() {
    pod_testkit::need_loopback!();
    let Some(coturn) = coturn() else { return };
    let ipv4 = allocate(&coturn, Allocation { family: Family::Ipv4, ..Allocation::default() }).await.unwrap();
    assert_eq!(ipv4.relayed_address().ip(), coturn.udp.ip());
    within(ipv4.close()).await.unwrap();
    let e = allocate(&coturn, Allocation { family: Family::Ipv6, ..Allocation::default() }).await.unwrap_err();
    assert!(matches!(e, Error::Server { method: ALLOCATE, code: 440, .. }), "{e:?}");
    let both = allocate(&coturn, Allocation { family: Family::Both, ..Allocation::default() }).await.unwrap();
    assert_eq!(both.relayed_addresses(), [std::net::SocketAddr::new(coturn.udp.ip(), both.relayed_address().port())]);
    println!("coturn: IPv6 got 440, and both families got IPv4");
    match both.address_error() {
        Some(AddressError { family: Family::Ipv6, code: 440, .. }) => {
            println!("coturn: the ADDRESS-ERROR-CODE of IPv6 named 440")
        }
        None => println!("coturn: no ADDRESS-ERROR-CODE"),
        other => panic!("{other:?}"),
    }
    within(both.close()).await.unwrap();
}

/// Over TLS with the ALPN `stun.turn` offered, coturn chooses it; with none
/// offered it chooses none.
#[tokio::test]
async fn the_alpn_stun_turn_is_chosen_over_tls() {
    pod_testkit::need_loopback!();
    let Some(coturn) = coturn() else { return };
    for offer in [true, false] {
        let mut settings = tls_settings(&coturn, true);
        if let Transport::Tls { alpn, .. } = &mut settings.transport {
            *alpn = offer;
        }
        let client = within(Client::allocate(settings)).await.unwrap();
        assert_eq!(client.alpn(), offer.then_some(&b"stun.turn"[..]));
        within(client.close()).await.unwrap();
    }
    println!("coturn: the ALPN stun.turn was chosen over TLS");
}

/// The redirecting coturn answers the first Allocate with 300 and the
/// address of the first coturn: the client allocates there, over UDP and
/// over TLS (the same certificate, the name of the settings).
#[tokio::test]
async fn a_300_of_the_first_allocate_is_followed_to_the_alternate() {
    pod_testkit::need_loopback!();
    let Some(coturn) = coturn() else { return };
    let peer = echo_peer().await;
    let mut settings = udp_settings(&coturn, &bound_socket().await, USER, PASSWORD);
    settings.server = Target::Addr(coturn.redirect_udp);
    let mut client = within(Client::allocate(settings)).await.unwrap();
    assert_eq!(client.server(), &Target::Addr(coturn.udp));
    within(client.create_permission(peer)).await.unwrap();
    client.send_to(peer, b"moved").await.unwrap();
    echoed(&mut client, peer, None, b"moved").await;
    within(client.close()).await.unwrap();

    let mut settings = tls_settings(&coturn, true);
    settings.server = Target::Addr(coturn.redirect_tls);
    let client = within(Client::allocate(settings)).await.unwrap();
    assert_eq!(client.server(), &Target::Addr(coturn.tls));
    within(client.close()).await.unwrap();
    println!("coturn: a 300 of the first Allocate was followed to the alternate server");
}

/// A redirect to an address that the caller's way out refuses fails with
/// the words and the stage of the way out.
#[tokio::test]
async fn a_redirect_that_the_way_out_refuses_fails_with_its_words() {
    pod_testkit::need_loopback!();
    let Some(coturn) = coturn() else { return };
    let mut settings = udp_settings(&coturn, &bound_socket().await, USER, PASSWORD);
    settings.server = Target::Addr(coturn.redirect_udp);
    settings.transport = Transport::Udp(Arc::new(Refusing(coturn.udp)));
    let e = within(Client::allocate(settings)).await.unwrap_err();
    let refused = coturn.udp;
    assert_eq!(e.to_string(), format!("TURN: the redirect to {refused}: the way out refuses {refused}"));
    let failure = Failure::from(e);
    assert_eq!((failure.stage, failure.class), (Stage::Connect, Class::Policy));
    println!("coturn: a redirect that the way out refuses failed with its words");
}
