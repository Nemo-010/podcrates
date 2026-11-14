//! The SHA-256 credentials of the TURN client against libjuice's TURN
//! server, a server that this crate did not write (T-403, call C576): its
//! 401 has a nonce cookie that announces PASSWORD-ALGORITHMS and username
//! anonymity, and offers SHA-256 and MD5; it checks the request's
//! PASSWORD-ALGORITHMS, PASSWORD-ALGORITHM, USERHASH and
//! MESSAGE-INTEGRITY-SHA256 (RFC 8489, 9.2). coturn has none of them.
//! libjuice signs each answer with MESSAGE-INTEGRITY and the MD5 key alone:
//! `tests/xturn.rs` has the client's check of a MESSAGE-INTEGRITY-SHA256
//! answer.
//!
//! `scripts/ci/turn-tests.sh` builds libjuice at a pinned commit with the
//! program `scripts/ci/juice-turn.c`, starts it on 127.0.0.1 with the login
//! below, and names it in `POD_TURN_TEST_JUICE_UDP`. With no such variable
//! each test skips with the reason, unless `POD_TURN_TEST_JUICE=required`,
//! which the script sets.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use common::LIMIT;
use common::recorded::{Recorded, RecordedSource, messages};
use pod_turn::stun::{
    self, ALLOCATE, Class, IntegrityError, MESSAGE_INTEGRITY, MESSAGE_INTEGRITY_SHA256, NONCE, PASSWORD_ALGORITHM,
    PASSWORD_ALGORITHMS, PasswordAlgorithm, SecurityFeature, USERHASH, USERNAME,
};
use pod_turn::{Client, Credentials, Error, Settings};

/// The made-up login of `scripts/ci/turn-tests.sh` for libjuice.
const USER: &str = "pod-turn-test";
const PASSWORD: &str = "made-up-juice-password";
const REALM: &str = "juice.test";

/// Where libjuice listens, or `None` with a line when no variable names it.
fn juice() -> Option<SocketAddr> {
    let Some(udp) = std::env::var("POD_TURN_TEST_JUICE_UDP").ok().filter(|v| !v.is_empty()) else {
        assert!(
            std::env::var("POD_TURN_TEST_JUICE").as_deref() != Ok("required"),
            "POD_TURN_TEST_JUICE=required: no libjuice here: POD_TURN_TEST_JUICE_UDP names none"
        );
        println!("skipped: POD_TURN_TEST_JUICE_UDP names no libjuice");
        return None;
    };
    Some(udp.parse().expect("HOST:PORT of libjuice, an IP address"))
}

async fn within<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(pod_testkit::host::scaled(LIMIT), future).await.expect("the test's bound")
}

fn settings(juice: SocketAddr, socket: &Arc<Recorded>, password: &str) -> Settings {
    let source = Arc::new(RecordedSource(socket.clone()));
    let mut settings = Settings::udp(pod_core::Target::Addr(juice), Credentials::new(USER, password), source);
    settings.realm = Some(REALM.into());
    settings.software = Some("pod-turn-juice-test".into());
    settings
}

/// Over UDP: the 401 announces both features and offers SHA-256; the
/// signed Allocate sends USERHASH in place of USERNAME, the algorithms of
/// the 401, PASSWORD-ALGORITHM SHA-256 and MESSAGE-INTEGRITY-SHA256 alone,
/// and libjuice takes it: its answer is a success. libjuice signs the
/// success with MESSAGE-INTEGRITY and the MD5 key alone, so the client
/// refuses it (RFC 8489, 9.2.4 asks for MESSAGE-INTEGRITY-SHA256 there).
#[tokio::test]
async fn libjuice_takes_sha256_and_userhash_and_its_md5_answer_is_refused() {
    pod_testkit::need_loopback!();
    let Some(juice) = juice() else { return };
    let socket = Recorded::bind().await;
    let e = within(Client::allocate(settings(juice, &socket, PASSWORD))).await.unwrap_err();
    let success = stun::message_type(ALLOCATE, Class::Success);
    assert!(matches!(&e, Error::Integrity { kind, error: IntegrityError::Missing(_) } if *kind == success), "{e:?}");

    let received = socket.received.lock().unwrap().clone();
    let answers = messages(&received);
    let challenge = answers.iter().find(|m| m.error().and_then(Result::ok).is_some_and(|(c, _)| c == 401));
    let challenge = challenge.expect("a 401 of libjuice");
    let nonce = challenge.attribute(NONCE).expect("the nonce of the 401");
    assert!(SecurityFeature::PasswordAlgorithms.announced_by(nonce), "{:?}", String::from_utf8_lossy(nonce));
    assert!(SecurityFeature::UsernameAnonymity.announced_by(nonce), "{:?}", String::from_utf8_lossy(nonce));
    let offered = challenge.attribute(PASSWORD_ALGORITHMS).expect("the PASSWORD-ALGORITHMS of the 401");
    let numbers: Vec<u16> = stun::password_algorithms(offered).unwrap().iter().map(|(n, _)| *n).collect();
    assert!(numbers.contains(&PasswordAlgorithm::Sha256.number()), "{numbers:?}");

    let sent = socket.sent.lock().unwrap().clone();
    let signed: Vec<_> = messages(&sent).into_iter().filter(|m| m.attribute(NONCE).is_some()).collect();
    let [request] = signed.as_slice() else { panic!("{} signed requests", signed.len()) };
    assert_eq!(request.kind, stun::message_type(ALLOCATE, Class::Request));
    assert_eq!(request.attribute(USERHASH), Some(stun::userhash(USER, REALM).as_slice()));
    assert_eq!(request.attribute(USERNAME), None);
    assert_eq!(request.attribute(PASSWORD_ALGORITHMS), Some(offered));
    assert_eq!(request.attribute(PASSWORD_ALGORITHM), Some(PasswordAlgorithm::Sha256.attribute().as_slice()));
    assert_eq!(request.attribute(MESSAGE_INTEGRITY), None);
    assert!(request.attribute(MESSAGE_INTEGRITY_SHA256).is_some());

    let taken = received.iter().find(|d| stun::decode(d).is_ok_and(|m| m.kind == success));
    let taken = taken.expect("libjuice's success to the Allocate with SHA-256");
    assert_eq!(stun::decode(taken).unwrap().attribute(MESSAGE_INTEGRITY_SHA256), None);
    stun::integrity(taken, &stun::long_term_key(USER, REALM, PASSWORD)).expect("the MD5 key of the success");
    println!("juice: an Allocate with SHA-256 and USERHASH got a success");
    println!("juice: a success signed with MD5 alone was refused");
}

/// A wrong password: libjuice checks MESSAGE-INTEGRITY-SHA256, and the
/// second 401 fails the Allocate.
#[tokio::test]
async fn a_wrong_password_with_sha256_gets_401() {
    pod_testkit::need_loopback!();
    let Some(juice) = juice() else { return };
    let socket = Recorded::bind().await;
    let e = within(Client::allocate(settings(juice, &socket, "not-the-password"))).await.unwrap_err();
    assert!(matches!(e, Error::Server { method: ALLOCATE, code: 401, .. }), "{e:?}");
    let sent = socket.sent.lock().unwrap().clone();
    assert!(messages(&sent).iter().any(|m| m.attribute(MESSAGE_INTEGRITY_SHA256).is_some()));
    println!("juice: a wrong password with SHA-256 got 401");
}
