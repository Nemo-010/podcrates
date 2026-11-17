//! The subprotocol of the answer to an upgrade (T-385, RFC 6455 section
//! 4.1): a dial that offered one refuses an answer that names another one,
//! and keeps an answer that names the one offered or none (a Wisp server of
//! version 1 names none).

mod common;

use std::time::Duration;

use pod_tls::Trust;
use pod_ws::client::ConnectError;
use pod_ws::url::{WsUrl, check_chosen, dial_offering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LIMIT: Duration = Duration::from_secs(5);

/// A server of one upgrade on the loopback, whose 101 names `chosen`.
async fn server(chosen: Option<&'static str>) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if tcp.read_exact(&mut byte).await.is_err() {
                return;
            }
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        let key = head
            .lines()
            .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("sec-websocket-key")))
            .map(|(_, v)| v.trim().to_string())
            .unwrap();
        let protocol = chosen.map(|p| format!("Sec-WebSocket-Protocol: {p}\r\n")).unwrap_or_default();
        let answer = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n{protocol}\r\n",
            pod_ws::handshake::accept_key(&key)
        );
        let _ = tcp.write_all(answer.as_bytes()).await;
        tokio::time::sleep(LIMIT).await;
    });
    port
}

async fn dial(chosen: Option<&'static str>, offered: Option<&str>) -> Result<(), ConnectError> {
    let url = WsUrl::parse(&format!("ws://127.0.0.1:{}/relay", server(chosen).await)).unwrap();
    dial_offering(&url, offered, &common::way(), &Trust::Default, LIMIT, None).await.map(drop)
}

#[tokio::test]
async fn an_answer_with_another_subprotocol_is_refused() {
    pod_testkit::need_loopback!();
    let refused = dial(Some("mqtt"), Some("tunnel-relay-client")).await.unwrap_err();
    let words = refused.to_string();
    assert!(matches!(refused, ConnectError::Upgrade(_)), "{words}");
    assert!(words.contains("\"mqtt\"") && words.contains("did not offer"), "{words}");
    let none_offered = dial(Some("mqtt"), None).await.unwrap_err();
    assert!(none_offered.to_string().contains("offered none"), "{none_offered}");
}

#[tokio::test]
async fn an_answer_with_the_one_offered_or_with_none_goes_on() {
    pod_testkit::need_loopback!();
    dial(Some("tunnel-relay-client"), Some("tunnel-relay-client")).await.expect("the one offered");
    dial(None, Some("wisp-v1")).await.expect("none, as a Wisp server of version 1 answers");
    dial(None, None).await.expect("none offered, none named");
}

#[test]
fn the_rule_of_the_choice() {
    assert!(check_chosen(Some("a, b"), Some("B")).is_ok(), "one of a list, in any case");
    assert!(check_chosen(Some("a"), Some("")).is_ok(), "an empty name is none");
    assert!(check_chosen(Some("a"), Some("\x1b[2Jc")).unwrap_err().to_string().contains("[2Jc"));
}
