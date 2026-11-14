//! The words of a 502 and of a 403 of `policy:no-rule` on the wire (T-609):
//! a refusal of the upstream proxy shows its status and the proxy, with no
//! body and no credential of the proxy URL; a target that no rule allows
//! names the host or the ports that the rules take.

mod common;

use std::sync::Arc;

use common::*;
use pod_broker::Settings;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// A made-up password of the proxy URL (no credential of a service).
const PASS: &str = "made-up-proxy-pass";
const BODY: &str = "made-up body of the refusal";

/// An upstream proxy on loopback that answers each CONNECT with `status`,
/// a reason phrase of its own and a body.
async fn refusing_proxy(status: u16) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = read_head(&mut stream).await;
                let answer =
                    format!("HTTP/1.1 {status} Its Own Phrase\r\nContent-Length: {}\r\n\r\n{BODY}", BODY.len());
                let _ = stream.write_all(answer.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    at
}

#[tokio::test]
async fn a_refusal_of_the_upstream_proxy_gets_502_with_its_status_and_the_proxy() {
    pod_testkit::need_loopback!();
    let at = refusing_proxy(403).await;
    let proxy = pod_proxy::Proxy::parse(&format!("http://made-up-user:{PASS}@{at}")).unwrap();
    let dial = pod_broker::upstream("pod-broker-test", Some(proxy), Arc::new(pod_proxy::resolve::System::new()));
    let audit = Arc::new(pod_broker::Memory::new());
    let broker = Arc::new(pod_broker::Broker::new(Settings::default(), Answers::public(), dial).with_audit(audit));
    load(&broker, "job1", TOKEN, OPEN);
    let (head, mut rest) = ask(&broker, &connect("example.com:443")).await;
    let body = read_all(&mut rest).await;
    let want = format!(
        "HTTP/1.1 502 Bad Gateway: the upstream proxy http://{at} answered \"403 Forbidden\" to CONNECT {PUBLIC}:443\r\n"
    );
    assert!(head.starts_with(&want), "{head}");
    for text in [&head, &body] {
        assert!(!text.contains(PASS) && !text.contains("made-up-user"), "{text}");
        assert!(!text.contains(BODY) && !text.contains("Its Own Phrase"), "{text}");
    }
}

#[tokio::test]
async fn a_target_that_no_rule_allows_names_the_host_or_the_ports() {
    let far = Far::new(Kind::Echo);
    let (broker, _) = broker(far.clone(), Answers::public());
    let policy = r#"{"schema":1,"mode":"allow","allow":[{"host":"example.com","ports":[443]}]}"#;
    load(&broker, "job1", TOKEN, policy);
    let get = format!("GET http://example.com/ HTTP/1.1\r\n{}\r\n", basic("job1", TOKEN));
    let (head, _) = ask(&broker, &get).await;
    assert!(
        head.starts_with(
            "HTTP/1.1 403 Forbidden: denied by the rule policy:no-rule: \
             the rules of the host example.com take the port 443, not 80\r\n"
        ),
        "{head}"
    );
    let (head, _) = ask(&broker, &connect("other.example:443")).await;
    assert!(
        head.starts_with(
            "HTTP/1.1 403 Forbidden: denied by the rule policy:no-rule: no allow rule names the host other.example\r\n"
        ),
        "{head}"
    );
    assert!(far.dialed().is_empty());
}
