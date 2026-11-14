//! The options of RFC 8489 against the mock server on the loopback: the
//! security features of the nonce (a downgrade fails; username anonymity
//! sends USERHASH), the 300 redirect of an Allocate (once, to another server,
//! with the realm of the first, through the caller's way out, with
//! ALTERNATE-DOMAIN only from an answer signed with SHA-256), and the ALPN
//! `stun.turn` of TURN over TLS (RFC 7443).

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use common::mock::Alternate;
use common::{
    LIMIT, PASSWORD, Refusing, USER, knobs, seen, tls_mock, tls_mock_beside, tls_settings, udp_mock, udp_settings,
};
use pod_core::{Class, Failure, Stage, Target};
use pod_turn::stun::{ALLOCATE, SecurityFeature};
use pod_turn::{Client, Error, Transport};

async fn within<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(pod_testkit::host::scaled(LIMIT), future).await.expect("the test's bound")
}

/// A nonce that announces PASSWORD-ALGORITHMS, in either order of its bits,
/// in a challenge with none: the client fails and sends no second Allocate.
#[tokio::test]
async fn a_challenge_with_no_password_algorithms_fails_as_a_downgrade() {
    pod_testkit::need_loopback!();
    for bits in [SecurityFeature::PasswordAlgorithms.bit(), 0x80_0000] {
        let mut stripped = knobs(true);
        (stripped.cookie, stripped.strip_algorithms) = (Some(bits), true);
        let mock = udp_mock(stripped).await;
        let e = within(Client::allocate(udp_settings(mock.addr, USER, PASSWORD))).await.unwrap_err();
        assert!(matches!(e, Error::Downgrade { method: ALLOCATE }), "{bits:06x}: {e:?}");
        assert!(e.to_string().contains("a downgrade on the path"), "{e}");
        assert_eq!(seen(&mock.control), [(ALLOCATE, 401)], "no request after the downgrade");
    }
}

/// A nonce that announces username anonymity, in either order of its bits:
/// each request sends USERHASH and no USERNAME, with SHA-256 or MD5.
#[tokio::test]
async fn a_nonce_of_username_anonymity_gets_userhash() {
    pod_testkit::need_loopback!();
    let (password, anonymity) = (SecurityFeature::PasswordAlgorithms.bit(), SecurityFeature::UsernameAnonymity.bit());
    for (sha256, bits) in [(true, password | anonymity), (false, anonymity), (false, 0x40_0000)] {
        let mut hashed = knobs(sha256);
        hashed.cookie = Some(bits);
        let mock = udp_mock(hashed).await;
        let mut client = within(Client::allocate(udp_settings(mock.addr, USER, PASSWORD))).await.unwrap();
        mock.control.lock().unwrap().stale_next = 1;
        within(client.refresh()).await.unwrap();
        within(client.close()).await.unwrap();
        let control = mock.control.lock().unwrap();
        assert!(control.seen[1..].iter().all(|s| s.userhash && s.user.is_none()), "{bits:06x}: {:?}", control.seen);
        assert!(control.seen.iter().any(|s| s.code == 438), "the fresh nonce keeps USERHASH");
    }
}

/// With no feature in the cookie the client sends USERNAME.
#[tokio::test]
async fn a_nonce_with_no_feature_gets_username() {
    pod_testkit::need_loopback!();
    let mut plain = knobs(false);
    plain.cookie = Some(0);
    let mock = udp_mock(plain).await;
    let client = within(Client::allocate(udp_settings(mock.addr, USER, PASSWORD))).await.unwrap();
    within(client.close()).await.unwrap();
    let control = mock.control.lock().unwrap();
    assert!(control.seen[1..].iter().all(|s| !s.userhash && s.user.as_deref() == Some(USER)));
}

fn redirect(to: SocketAddr, after_challenge: bool, domain: Option<&str>) -> Option<Alternate> {
    Some(Alternate { to, after_challenge, domain: domain.map(str::to_string) })
}

/// A 300 to the first Allocate, before the challenge as coturn sends it:
/// the client allocates on the named server, with the same user.
#[tokio::test]
async fn a_300_of_the_first_allocate_is_followed_to_the_alternate() {
    pod_testkit::need_loopback!();
    let (first, second) = (udp_mock(knobs(false)).await, udp_mock(knobs(false)).await);
    first.control.lock().unwrap().alternate = redirect(second.addr, false, None);
    let client = within(Client::allocate(udp_settings(first.addr, USER, PASSWORD))).await.unwrap();
    assert_eq!(client.server(), &Target::Addr(second.addr));
    assert_eq!(seen(&first.control), [(ALLOCATE, 300)]);
    assert_eq!(seen(&second.control), [(ALLOCATE, 401), (ALLOCATE, 0)]);
    within(client.close()).await.unwrap();
}

/// A second 300, or a 300 to the same server, is not followed.
#[tokio::test]
async fn a_second_redirect_or_one_to_the_same_server_fails() {
    pod_testkit::need_loopback!();
    let (first, second) = (udp_mock(knobs(false)).await, udp_mock(knobs(false)).await);
    first.control.lock().unwrap().alternate = redirect(second.addr, false, None);
    second.control.lock().unwrap().alternate = redirect(first.addr, false, None);
    let e = within(Client::allocate(udp_settings(first.addr, USER, PASSWORD))).await.unwrap_err();
    match &e {
        Error::Redirected { to, error } => {
            assert_eq!(*to, second.addr);
            assert!(matches!(**error, Error::Alternate { method: ALLOCATE, to, .. } if to == first.addr), "{e:?}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!((seen(&first.control).len(), seen(&second.control).len()), (1, 1), "one redirect alone");

    let itself = udp_mock(knobs(false)).await;
    itself.control.lock().unwrap().alternate = redirect(itself.addr, false, None);
    let e = within(Client::allocate(udp_settings(itself.addr, USER, PASSWORD))).await.unwrap_err();
    assert!(matches!(e, Error::Alternate { to, .. } if to == itself.addr), "{e:?}");
    assert!(e.to_string().contains("(300 Try Alternate)"), "{e}");
}

/// A 300 after the challenge: the new server must give the realm of the
/// first, though the settings name none.
#[tokio::test]
async fn the_alternate_must_give_the_realm_of_the_first_server() {
    pod_testkit::need_loopback!();
    let mut other_realm = knobs(false);
    other_realm.realm = "other.test".into();
    let (first, second) = (udp_mock(knobs(false)).await, udp_mock(other_realm).await);
    first.control.lock().unwrap().alternate = redirect(second.addr, true, None);
    let settings = udp_settings(first.addr, USER, PASSWORD);
    assert_eq!(settings.realm, None);
    let e = within(Client::allocate(settings)).await.unwrap_err();
    match &e {
        Error::Redirected { error, .. } => assert!(
            matches!(&**error, Error::Realm { expected, offered } if expected == "mock.test" && offered == "other.test"),
            "{e:?}"
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(seen(&first.control), [(ALLOCATE, 401), (ALLOCATE, 300)]);
    assert_eq!(seen(&second.control), [(ALLOCATE, 401)], "no key goes to another realm");
}

/// A redirect to an address that the caller's way out refuses fails with
/// the words and the stage of the way out.
#[tokio::test]
async fn a_redirect_that_the_way_out_refuses_fails_with_its_words() {
    pod_testkit::need_loopback!();
    let first = udp_mock(knobs(false)).await;
    let refused: SocketAddr = "127.0.0.1:9".parse().unwrap();
    first.control.lock().unwrap().alternate = redirect(refused, false, None);
    let mut settings = udp_settings(first.addr, USER, PASSWORD);
    settings.transport = Transport::Udp(Arc::new(Refusing(refused)));
    let e = within(Client::allocate(settings)).await.unwrap_err();
    assert_eq!(e.to_string(), format!("TURN: the redirect to {refused}: the way out refuses {refused}"));
    let failure = Failure::from(e);
    assert_eq!((failure.stage, failure.class), (Stage::Connect, Class::Policy));
}

/// Over TLS: ALTERNATE-DOMAIN of a 300 signed with SHA-256 names the
/// certificate to check, so a domain that the certificate does not hold
/// fails at the stage TLS; the same domain in a 300 signed with MD5 is not
/// read, and the name of the settings checks the alternate.
#[tokio::test]
async fn alternate_domain_counts_only_in_a_300_signed_with_sha256() {
    pod_testkit::need_loopback!();
    for sha256 in [true, false] {
        let first = tls_mock(knobs(sha256)).await;
        let second = tls_mock_beside(&first, knobs(sha256)).await;
        first.control.lock().unwrap().alternate = redirect(second.addr, true, Some("elsewhere.test"));
        let result = within(Client::allocate(tls_settings(&first, USER, PASSWORD))).await;
        match (sha256, result) {
            (true, Err(Error::Redirected { to, error })) => {
                assert_eq!(to, second.addr);
                let Error::Connect(failure) = *error else { panic!("{error:?}") };
                assert_eq!(failure.stage, Stage::Tls, "{failure}");
                assert!(failure.chain().contains("elsewhere.test"), "{failure}");
            }
            (false, Ok(client)) => {
                assert_eq!(client.server(), &Target::Addr(second.addr));
                within(client.close()).await.unwrap();
            }
            (sha256, other) => panic!("SHA-256 {sha256}: {:?}", other.map(|c| c.relayed_address())),
        }
    }
}

/// The ALPN `stun.turn`: offered when the transport asks for it, and chosen
/// by a server that serves it; not offered by default.
#[tokio::test]
async fn the_alpn_stun_turn_is_offered_when_asked() {
    pod_testkit::need_loopback!();
    let mut served = knobs(false);
    served.alpn = true;
    let mock = tls_mock(served).await;
    for offer in [true, false] {
        let mut settings = tls_settings(&mock, USER, PASSWORD);
        if let Transport::Tls { alpn, .. } = &mut settings.transport {
            assert!(!*alpn, "Settings::tls offers no ALPN");
            *alpn = offer;
        }
        let client = within(Client::allocate(settings)).await.unwrap();
        assert_eq!(client.alpn(), offer.then_some(&b"stun.turn"[..]));
        within(client.close()).await.unwrap();
    }
    let plain = tls_mock(knobs(false)).await;
    let mut settings = tls_settings(&plain, USER, PASSWORD);
    if let Transport::Tls { alpn, .. } = &mut settings.transport {
        *alpn = true;
    }
    let client = within(Client::allocate(settings)).await.unwrap();
    assert_eq!(client.alpn(), None, "a server with no ALPN chooses none");
    within(client.close()).await.unwrap();
}
