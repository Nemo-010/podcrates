//! The options of an Allocate of RFC 8656 against the mock server on the
//! loopback: REQUESTED-ADDRESS-FAMILY, ADDITIONAL-ADDRESS-FAMILY with its
//! ADDRESS-ERROR-CODE, EVEN-PORT and the RESERVATION-TOKEN of the next port,
//! and DONT-FRAGMENT in the Allocate and in each Send indication.

mod common;

use std::net::SocketAddr;

use common::{LIMIT, PASSWORD, USER, echo_peer, knobs, seen, udp_mock, udp_settings};
use pod_turn::stun::{ALLOCATE, DONT_FRAGMENT, EVEN_PORT, RESERVATION_TOKEN};
use pod_turn::{AddressError, Allocation, Client, Error, Event, Family, Port};

async fn within<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(pod_testkit::host::scaled(LIMIT), future).await.expect("the test's bound")
}

async fn allocate(addr: SocketAddr, allocation: Allocation) -> Result<Client, Error> {
    let mut settings = common::udp_settings(addr, USER, PASSWORD);
    settings.allocation = allocation;
    within(Client::allocate(settings)).await
}

fn family(family: Family) -> Allocation {
    Allocation { family, ..Allocation::default() }
}

/// Each family: IPv4 asked gets IPv4; IPv6 gets 440 from a server with no
/// IPv6, else IPv6; both get two addresses, or IPv4 and the 440 of IPv6.
#[tokio::test]
async fn each_address_family_gets_its_relayed_addresses() {
    pod_testkit::need_loopback!();
    let no_ipv6 = udp_mock(knobs(false)).await;
    let client = allocate(no_ipv6.addr, family(Family::Ipv4)).await.unwrap();
    assert!(client.relayed_address().is_ipv4() && client.address_error().is_none());
    within(client.close()).await.unwrap();
    let e = allocate(no_ipv6.addr, family(Family::Ipv6)).await.unwrap_err();
    assert!(matches!(e, Error::Server { method: ALLOCATE, code: 440, .. }), "{e:?}");
    let client = allocate(no_ipv6.addr, family(Family::Both)).await.unwrap();
    assert_eq!(client.relayed_addresses().len(), 1);
    let wanted = AddressError { family: Family::Ipv6, code: 440, reason: "no IPv6".into() };
    assert_eq!(client.address_error(), Some(&wanted));
    within(client.close()).await.unwrap();

    let mut both = knobs(false);
    both.ipv6 = true;
    let ipv6 = udp_mock(both).await;
    let client = allocate(ipv6.addr, family(Family::Ipv6)).await.unwrap();
    assert!(client.relayed_address().is_ipv6());
    within(client.close()).await.unwrap();
    let client = allocate(ipv6.addr, family(Family::Both)).await.unwrap();
    let relayed = client.relayed_addresses();
    assert!(relayed.len() == 2 && relayed[0].is_ipv4() && relayed[1].is_ipv6(), "{relayed:?}");
    within(client.close()).await.unwrap();
}

/// An even port, and the next port kept by its token: a second allocation
/// with the token, on its own 5-tuple, gets the next port. A token that the
/// server does not hold gets 508.
#[tokio::test]
async fn an_even_port_keeps_the_next_port_for_its_token() {
    pod_testkit::need_loopback!();
    let mock = udp_mock(knobs(false)).await;
    let even = allocate(mock.addr, Allocation { port: Port::Even, ..Allocation::default() }).await.unwrap();
    assert_eq!(even.relayed_address().port() % 2, 0);
    assert_eq!(even.reservation_token(), None);
    let first = allocate(mock.addr, Allocation { port: Port::EvenAndNext, ..Allocation::default() }).await.unwrap();
    let port = first.relayed_address().port();
    assert_eq!(port % 2, 0);
    let token = first.reservation_token().expect("a token of the next port");
    let next = allocate(mock.addr, Allocation { reservation: Some(token), ..Allocation::default() }).await.unwrap();
    assert_eq!(next.relayed_address().port(), port + 1);
    {
        let control = mock.control.lock().unwrap();
        let allocates: Vec<&Vec<u16>> = control.seen.iter().filter(|s| s.code == 0).map(|s| &s.attributes).collect();
        assert!(allocates[0].contains(&EVEN_PORT) && allocates[1].contains(&EVEN_PORT));
        assert!(allocates[2].contains(&RESERVATION_TOKEN) && !allocates[2].contains(&EVEN_PORT));
    }
    let e = allocate(mock.addr, Allocation { reservation: Some(token), ..Allocation::default() }).await.unwrap_err();
    assert!(matches!(e, Error::Server { method: ALLOCATE, code: 508, .. }), "{e:?}");
    for client in [even, first, next] {
        within(client.close()).await.unwrap();
    }
}

/// DONT-FRAGMENT goes in the Allocate and in each Send indication; a server
/// that cannot set DF answers 420, and the Allocate fails by its code.
#[tokio::test]
async fn dont_fragment_goes_in_the_allocate_and_each_send() {
    pod_testkit::need_loopback!();
    let (mock, peer) = (udp_mock(knobs(false)).await, echo_peer().await);
    let ask = Allocation { dont_fragment: true, ..Allocation::default() };
    let mut client = allocate(mock.addr, ask.clone()).await.unwrap();
    within(client.create_permission(peer)).await.unwrap();
    client.send_to(peer, b"df").await.unwrap();
    match within(client.recv()).await.unwrap() {
        Event::Data { data, .. } => assert_eq!(data, b"echo:df"),
        other => panic!("{other:?}"),
    }
    {
        let control = mock.control.lock().unwrap();
        assert!(control.seen[1].attributes.contains(&DONT_FRAGMENT));
        assert_eq!((control.sent, control.sent_dont_fragment), (1, 1));
    }
    within(client.close()).await.unwrap();

    let mut no_df = knobs(false);
    no_df.dont_fragment = false;
    let mock = udp_mock(no_df).await;
    let e = allocate(mock.addr, ask).await.unwrap_err();
    assert!(matches!(e, Error::Server { method: ALLOCATE, code: 420, .. }), "{e:?}");
    assert_eq!(seen(&mock.control), [(ALLOCATE, 401), (ALLOCATE, 420)]);
    let plain = allocate(mock.addr, Allocation::default()).await.unwrap();
    within(plain.close()).await.unwrap();
}

/// An Allocate that RFC 8656 forbids is refused before any send.
#[tokio::test]
async fn an_allocate_that_the_rfc_forbids_is_refused_before_a_send() {
    pod_testkit::need_loopback!();
    let mock = udp_mock(knobs(false)).await;
    let ask = Allocation { port: Port::Even, reservation: Some([1; 8]), ..Allocation::default() };
    let mut settings = udp_settings(mock.addr, USER, PASSWORD);
    settings.allocation = ask;
    let e = within(Client::allocate(settings)).await.unwrap_err();
    assert!(matches!(e, Error::Usage(_)), "{e:?}");
    assert!(seen(&mock.control).is_empty());
}
