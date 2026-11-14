//! A client with no user token against the stand-in: a tunnel with
//! anonymous access, a tunnel access token, a missing token where the
//! tunnel has no anonymous entry, a wrong token, and a refused upgrade.
//! Each refusal names the form of the credential, never a token.

mod common;

use std::time::Duration;

use pod_core::Class;
use pod_devtunnel::standin::{Plan, RELAY_PATH, Standin};
use pod_devtunnel::{Credential, Locator, Relay, Step, step_of, steps_of};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::{ACCESS_TOKEN, USER_TOKEN, access, connected_with, plan, report, settings, user, way};

/// One echo through a stream to port 22.
async fn echo(relay: &Relay) {
    let mut stream = relay.open(22).await.unwrap_or_else(|e| panic!("open: {}", e.chain()));
    stream.write_all(b"no account").await.unwrap();
    let mut back = [0u8; 10];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"no account");
}

/// A first connect to a stand-in of `plan` with `credential`: its failure.
async fn refused(plan: Plan, credential: Credential) -> (Standin, pod_core::Failure) {
    let standin = Standin::start(plan).await.unwrap();
    let locator = Locator::parse("standin-box").unwrap();
    let failure = Relay::connect(way(), settings(&standin.base()), locator, credential, report().0).await.unwrap_err();
    (standin, failure)
}

#[tokio::test]
async fn an_anonymous_client_reaches_a_tunnel_with_anonymous_access() {
    pod_testkit::need_loopback!();
    for mints in [false, true] {
        let mut plan = plan();
        plan.anonymous = true;
        plan.mints_for_all = mints;
        let (standin, relay, _) = connected_with(plan, Credential::Anonymous).await;
        echo(&relay).await;
        relay.reconnect().await.unwrap_or_else(|e| panic!("reconnect: {}", e.chain()));
        echo(&relay).await;
        let seen = standin.seen();
        // No Authorization to the API; the upgrade carries the connect
        // token of the answer, or none when the answer holds none.
        assert_eq!(seen.forms, ["none", "none"]);
        let carried = if mints { "fresh" } else { "none" };
        assert_eq!(seen.relay_tokens, [carried, carried], "mints {mints}");
        assert_eq!(standin.minted(), if mints { 2 } else { 0 });
        assert_eq!(relay.sessions(), 2);
    }
}

#[tokio::test]
async fn a_tunnel_access_token_reaches_the_tunnel_with_no_account() {
    pod_testkit::need_loopback!();
    for mints in [false, true] {
        let mut plan = plan();
        plan.access = Some(ACCESS_TOKEN.into());
        plan.mints_for_all = mints;
        let (standin, relay, _) = connected_with(plan, access().into()).await;
        echo(&relay).await;
        let seen = standin.seen();
        assert_eq!((seen.forms, seen.user_ok), (vec!["access"], vec![false]));
        // The caller's own token goes to the relay when the answer holds no
        // connect token.
        let carried = if mints { "fresh" } else { "access" };
        assert_eq!(seen.relay_tokens, [carried], "mints {mints}");
    }
}

#[tokio::test]
async fn no_token_is_refused_where_the_tunnel_has_no_anonymous_access() {
    pod_testkit::need_loopback!();
    let (standin, failure) = refused(plan(), Credential::Anonymous).await;
    assert_eq!((steps_of(&failure), failure.class), (vec![Step::Management], Class::Refused));
    let chain = failure.chain();
    assert!(
        chain.contains(
            "with no token answered HTTP 401: Unauthorized: no token, and the tunnel has no anonymous access"
        ),
        "{chain}"
    );
    let seen = standin.seen();
    assert_eq!((seen.forms, seen.relay_tokens.len(), standin.minted()), (vec!["none"], 0, 0));

    // The relay of the same tunnel refuses an upgrade with no token too.
    let url = pod_ws::url::WsUrl::parse(&format!("ws://{}{RELAY_PATH}bcd123", standin.addr())).unwrap();
    let asking = pod_ws::url::Asking {
        protocol: Some(pod_devtunnel::service::subprotocol()),
        authorization: None,
        alpn: &[],
        limits: pod_ws::Limits::RELAY,
    };
    let way = way();
    let upgrade = pod_ws::url::dial_asking(&url, &asking, &way.ws, &way.trust, Duration::from_secs(10), None).await;
    let Err(refused) = upgrade else { panic!("the relay took an upgrade with no token") };
    let refusal = pod_core::Failure::from(refused);
    assert_eq!(refusal.class, Class::Refused, "{}", refusal.chain());
    assert_eq!(standin.seen().relay_tokens, ["none"]);
}

#[tokio::test]
async fn a_wrong_token_is_refused_by_its_form_and_not_shown() {
    pod_testkit::need_loopback!();
    let mut other = plan();
    other.access = Some("another-made-up-access-token".into());
    let (standin, failure) = refused(other, access().into()).await;
    assert_eq!((step_of(&failure), failure.class), (Some(Step::Management), Class::Refused));
    let chain = failure.chain();
    assert!(
        chain.contains(
            "with a tunnel access token answered HTTP 401: Unauthorized: a token of the scheme tunnel that the tunnel does not take"
        ),
        "{chain}"
    );
    assert!(!chain.contains(ACCESS_TOKEN) && !chain.contains("another-made-up"), "{chain}");
    assert_eq!(standin.seen().forms, ["wrong"]);

    // A user token where the tunnel takes only its access token.
    let mut only_access = plan();
    only_access.authorization = "github another-made-up-user-token".into();
    only_access.access = Some(ACCESS_TOKEN.into());
    let (_, failure) = refused(only_access, user().into()).await;
    let chain = failure.chain();
    assert!(chain.contains("with a GitHub user token answered HTTP 401"), "{chain}");
    assert!(!chain.contains(USER_TOKEN), "{chain}");
}

#[tokio::test]
async fn a_refused_upgrade_names_the_token_that_it_carried() {
    pod_testkit::need_loopback!();
    let cases: [(Credential, &str); 3] = [
        (user().into(), "with the connect token of the answer"),
        (access().into(), "with the caller's tunnel access token"),
        (Credential::Anonymous, "with no token"),
    ];
    for (credential, words) in cases {
        let mut plan = plan();
        plan.access = Some(ACCESS_TOKEN.into());
        plan.anonymous = true;
        let standin = Standin::start(plan).await.unwrap();
        standin.refuse_upgrades(1);
        let locator = Locator::parse("standin-box").unwrap();
        let failure =
            Relay::connect(way(), settings(&standin.base()), locator, credential, report().0).await.unwrap_err();
        assert_eq!(step_of(&failure), Some(Step::WebSocket), "{}", failure.chain());
        assert!(failure.chain().contains(words), "{words}: {}", failure.chain());
    }
}
