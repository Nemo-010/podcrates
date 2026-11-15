//! The built-in forwarders, and the Wisp demo server after them, live:
//! through each, the first line of github.com port 22 is GitHub's version
//! line. They run from GitHub Actions alone, short: one connection to each,
//! one at a time, by `.github/workflows/forwarder-live.yml`, each day and by
//! hand (podssh's rulings Q56 and Q65); ignored here. With
//! `POD_EGRESS_TEST_FORWARDER_PLANT` set, each template names a host under
//! `.invalid` in place of its own, and each check must fail: the plant of
//! the watch.

use std::sync::Arc;
use std::time::Duration;

use pod_egress::forwarder::{self, AtEnd, Dial, Template, builtin};
use pod_proxy::{Environment, ProxyChoice};
use pod_tls::Trust;
use tokio::io::AsyncReadExt;

#[path = "common/way.rs"]
mod way;

const LIMIT: Duration = Duration::from_secs(30);

/// The template of `b`, or its plant: the same path on a host that cannot be.
fn template(b: &builtin::Builtin) -> Template {
    let text = match std::env::var_os("POD_EGRESS_TEST_FORWARDER_PLANT") {
        None => b.template.to_string(),
        Some(_) => {
            // A Wisp server's `wisp+` stays before the scheme.
            let (scheme, rest) = b.template.split_once("://").expect("a ws:// template");
            let at = rest.find('/').unwrap_or(rest.len());
            format!("{scheme}://pod-egress-plant.invalid{}", &rest[at..])
        }
    };
    Template::parse(&text).unwrap()
}

/// GitHub's version line through the forwarder of `word`.
async fn banner(word: &str) {
    let b = builtin::lookup(word).expect("a built-in word");
    let template = template(&b);
    let said = word.to_string();
    let proxy = ProxyChoice::FromEnvironment(Environment::read(&|name| std::env::var_os(name)));
    let road = Dial {
        way: way::through(proxy, &[]),
        trust: Trust::Default,
        timeout: LIMIT,
        at_end: AtEnd::Now,
        note: Arc::new(move |event: pod_core::Event| eprintln!("{said} says: {event}")),
    };
    let carried = match forwarder::open(&template, "github.com", 22, &road).await {
        Ok(carried) => carried,
        Err(e) => panic!("{word}: {}", e.line(template.shown())),
    };
    let mut stream = carried.stream;
    let (mut line, mut byte) = (Vec::new(), [0u8; 1]);
    let read = tokio::time::timeout(LIMIT, async {
        while !line.ends_with(b"\r\n") && line.len() < 256 {
            if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                break;
            }
            line.push(byte[0]);
        }
    })
    .await;
    let text = String::from_utf8_lossy(&line).into_owned();
    assert!(read.is_ok(), "{word}: no line within {LIMIT:?}: {text:?} ({:?})", carried.status.get());
    println!("{word} ({}): {}", template.shown(), text.trim_end());
    assert!(text.starts_with("SSH-2.0-"), "{word}: not GitHub's version line: {text:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live: from GitHub Actions only"]
async fn live_mudlet_gives_github_s_version_line() {
    banner("mudlet").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live: from GitHub Actions only"]
async fn live_ssheasy_gives_github_s_version_line() {
    banner("ssheasy").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live: from GitHub Actions only"]
async fn live_mudix_gives_github_s_version_line() {
    banner("mudix").await;
}

/// The Wisp demo server: its CONNECT to github.com port 22, on
/// a stream of its WebSocket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live: from GitHub Actions only"]
async fn live_wisp_gives_github_s_version_line() {
    banner("wisp").await;
}
