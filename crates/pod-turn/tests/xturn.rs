//! The answer side of the SHA-256 credentials against xturn, a TURN server
//! that this crate did not write (T-631): xturn signs each answer to a
//! request with MESSAGE-INTEGRITY-SHA256 with the SHA-256 key of the
//! request (RFC 8489, 9.2.4), where libjuice signs with MD5 alone
//! (`tests/juice.rs`). A full allocation with SHA-256 and USERHASH, and the
//! client's check of each signed answer: an answer whose
//! MESSAGE-INTEGRITY-SHA256 changed on the way is refused.
//!
//! `scripts/ci/turn-tests.sh` builds xturn at a pinned commit, starts it on
//! 127.0.0.1 with the login below, and names it in
//! `POD_TURN_TEST_XTURN_UDP`. With no such variable each test skips with
//! the reason, unless `POD_TURN_TEST_XTURN=required`, which the script sets.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use common::coturn::{echoed, within};
use common::echo_peer;
use common::recorded::{Recorded, RecordedSource, messages};
use pod_turn::stun::{
    self, ALLOCATE, CHANNEL_BIND, CREATE_PERMISSION, Class, IntegrityError, MESSAGE_INTEGRITY,
    MESSAGE_INTEGRITY_SHA256, NONCE, PASSWORD_ALGORITHM, PASSWORD_ALGORITHMS, PasswordAlgorithm, REFRESH,
    SecurityFeature, USERHASH, USERNAME,
};
use pod_turn::{Client, Credentials, Error, Settings};

/// The made-up login that `scripts/ci/turn-tests.sh` gives xturn.
const USER: &str = "pod-turn-test";
const PASSWORD: &str = "made-up-xturn-password";
/// The realm of xturn's own configuration, which no option changes.
const REALM: &str = "xirsys.com";

/// Where xturn listens, or `None` with a line when no variable names it.
fn xturn() -> Option<SocketAddr> {
    let Some(udp) = std::env::var("POD_TURN_TEST_XTURN_UDP").ok().filter(|v| !v.is_empty()) else {
        assert!(
            std::env::var("POD_TURN_TEST_XTURN").as_deref() != Ok("required"),
            "POD_TURN_TEST_XTURN=required: no xturn here: POD_TURN_TEST_XTURN_UDP names none"
        );
        println!("skipped: POD_TURN_TEST_XTURN_UDP names no xturn");
        return None;
    };
    Some(udp.parse().expect("HOST:PORT of xturn, an IP address"))
}

fn settings(xturn: SocketAddr, socket: &Arc<Recorded>) -> Settings {
    let source = Arc::new(RecordedSource(socket.clone()));
    let mut settings = Settings::udp(pod_core::Target::Addr(xturn), Credentials::new(USER, PASSWORD), source);
    settings.realm = Some(REALM.into());
    settings.software = Some("pod-turn-xturn-test".into());
    settings
}

/// Over UDP: the 401 offers SHA-256 and announces both features; each
/// signed request sends USERHASH, PASSWORD-ALGORITHM SHA-256 and
/// MESSAGE-INTEGRITY-SHA256 alone; a permission, a Send echo, a channel and
/// a ChannelData echo of a peer on the loopback, a Refresh and the close.
/// Each answer to a signed request has MESSAGE-INTEGRITY-SHA256 with the
/// SHA-256 key and no MESSAGE-INTEGRITY.
#[tokio::test]
async fn an_allocation_with_sha256_gets_each_answer_signed_with_sha256() {
    pod_testkit::need_loopback!();
    let Some(xturn) = xturn() else { return };
    let (socket, peer) = (Recorded::bind().await, echo_peer().await);
    let mut client = within(Client::allocate(settings(xturn, &socket))).await.unwrap();
    assert_eq!(client.relayed_address().ip(), xturn.ip());
    assert_ne!(client.relayed_address().port(), 0);
    within(client.create_permission(peer)).await.unwrap();
    client.send_to(peer, b"abc").await.unwrap();
    echoed(&mut client, peer, None, b"abc").await;
    let number = within(client.bind_channel(peer)).await.unwrap();
    client.send(number, b"xyz").await.unwrap();
    echoed(&mut client, peer, Some(number), b"xyz").await;
    within(client.refresh()).await.unwrap();
    within(client.close()).await.unwrap();

    let received = socket.received.lock().unwrap().clone();
    let answers = messages(&received);
    let challenge = answers.iter().find(|m| m.error().and_then(Result::ok).is_some_and(|(c, _)| c == 401));
    let challenge = challenge.expect("a 401 of xturn");
    let nonce = challenge.attribute(NONCE).expect("the nonce of the 401");
    assert!(SecurityFeature::PasswordAlgorithms.announced_by(nonce), "{:?}", String::from_utf8_lossy(nonce));
    assert!(SecurityFeature::UsernameAnonymity.announced_by(nonce), "{:?}", String::from_utf8_lossy(nonce));
    let offered = challenge.attribute(PASSWORD_ALGORITHMS).expect("the PASSWORD-ALGORITHMS of the 401");
    let numbers: Vec<u16> = stun::password_algorithms(offered).unwrap().iter().map(|(n, _)| *n).collect();
    assert!(numbers.contains(&PasswordAlgorithm::Sha256.number()), "{numbers:?}");

    let sent = socket.sent.lock().unwrap().clone();
    let signed: Vec<_> = messages(&sent).into_iter().filter(|m| m.attribute(NONCE).is_some()).collect();
    for request in &signed {
        assert_eq!(request.attribute(USERHASH), Some(stun::userhash(USER, REALM).as_slice()));
        assert_eq!(request.attribute(USERNAME), None);
        assert_eq!(request.attribute(PASSWORD_ALGORITHM), Some(PasswordAlgorithm::Sha256.attribute().as_slice()));
        assert_eq!(request.attribute(MESSAGE_INTEGRITY), None);
        assert!(request.attribute(MESSAGE_INTEGRITY_SHA256).is_some());
    }
    let key = stun::sha256_key(USER, REALM, PASSWORD);
    let mut methods = Vec::new();
    for request in &signed {
        let answer = received.iter().find(|d| stun::decode(d).is_ok_and(|m| m.id == request.id));
        let answer = answer.unwrap_or_else(|| panic!("no answer to the request 0x{:04x}", request.kind));
        let read = stun::decode(answer).unwrap();
        assert_eq!(stun::class_of(read.kind), Class::Success, "0x{:04x}: {:?}", read.kind, read.error());
        assert_eq!(read.attribute(MESSAGE_INTEGRITY), None, "0x{:04x}", read.kind);
        stun::integrity_sha256(answer, &key).unwrap_or_else(|e| panic!("0x{:04x}: {e:?}", read.kind));
        methods.push(stun::method_of(read.kind));
    }
    for method in [ALLOCATE, CREATE_PERMISSION, CHANNEL_BIND, REFRESH] {
        assert!(methods.contains(&method), "no signed answer of 0x{method:04x}: {methods:?}");
    }
    println!("xturn: an allocation with SHA-256 relayed a Send and ChannelData");
    println!("xturn: each answer to a signed request had MESSAGE-INTEGRITY-SHA256 alone");
}

/// An answer whose MESSAGE-INTEGRITY-SHA256 changed on the way is refused:
/// the success of the Allocate, and the success of a Refresh of a live
/// allocation.
#[tokio::test]
async fn an_answer_with_a_changed_sha256_integrity_is_refused() {
    pod_testkit::need_loopback!();
    let Some(xturn) = xturn() else { return };
    let socket = Recorded::bind().await;
    let success = stun::message_type(ALLOCATE, Class::Success);
    socket.tamper(success);
    let e = within(Client::allocate(settings(xturn, &socket))).await.unwrap_err();
    assert_eq!(socket.tamper_pending(), None, "no success of the Allocate came");
    assert!(matches!(&e, Error::Integrity { kind, error: IntegrityError::Mismatch } if *kind == success), "{e:?}");
    println!("xturn: a success of the Allocate with a changed MESSAGE-INTEGRITY-SHA256 was refused");

    let socket = Recorded::bind().await;
    let mut client = within(Client::allocate(settings(xturn, &socket))).await.unwrap();
    let success = stun::message_type(REFRESH, Class::Success);
    socket.tamper(success);
    let e = within(client.refresh()).await.unwrap_err();
    assert_eq!(socket.tamper_pending(), None, "no success of the Refresh came");
    assert!(matches!(&e, Error::Integrity { kind, error: IntegrityError::Mismatch } if *kind == success), "{e:?}");
    within(client.close()).await.unwrap();
    println!("xturn: a success of a Refresh with a changed MESSAGE-INTEGRITY-SHA256 was refused");
}
