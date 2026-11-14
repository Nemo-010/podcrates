//! The stand-in of the S3 API that a consumer takes (T-627,
//! PodUtils/podnet#564; feature `s3-standin`): a request with no signature
//! gets 403, and a drop closes the port and each connection, on its own
//! thread and on the runtime of the caller. `tests/s3.rs` proves the rest
//! of the stand-in with the carrier: the signature, the conditions, the
//! listing, the counts and a lost answer.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;

use common::limit;
use pod_link::s3::standin::{Counts, StandIn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const LIST: &[u8] = b"GET /links?list-type=2 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";

/// True when `got` holds a whole answer: its head and the body of its
/// `Content-Length`.
fn whole(got: &[u8]) -> bool {
    let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") else { return false };
    let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
    let len = head.split("content-length:").nth(1).and_then(|v| v.lines().next()?.trim().parse().ok());
    got.len() >= end + 4 + len.unwrap_or(0)
}

/// The answer to the listing, read from `read`.
fn answer(mut read: impl FnMut(&mut [u8]) -> usize) -> String {
    let mut got = Vec::new();
    while !whole(&got) {
        let mut more = [0u8; 1024];
        let n = read(&mut more);
        assert!(n > 0, "the stand-in ended the connection: {}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&more[..n]);
    }
    String::from_utf8_lossy(&got).into_owned()
}

#[test]
fn a_request_with_no_signature_gets_403_and_a_drop_ends_the_thread_of_the_standin() {
    pod_testkit::need_loopback!();
    let standin = StandIn::start_thread(&["links"]).unwrap();
    assert_eq!(standin.url(), format!("http://{}", standin.addr()));
    let mut tcp = TcpStream::connect(standin.addr()).unwrap();
    tcp.set_read_timeout(Some(limit())).unwrap();
    tcp.write_all(LIST).unwrap();
    let answer = answer(|buf| tcp.read(buf).expect("the answer in time"));
    assert!(answer.starts_with("HTTP/1.1 403 "), "a request with no signature gets 403: {answer}");
    assert!(answer.contains("<Code>AccessDenied</Code>"), "{answer}");
    assert_eq!(standin.counts(), Counts { refused: 1, ..Counts::default() }, "the stand-in listed nothing");
    assert!(standin.keys("links", "").is_empty() && standin.keys("missing", "").is_empty());
    let addr = standin.addr();
    drop(standin);
    let mut rest = [0u8; 1];
    let end = tcp.read(&mut rest).expect("the end of the connection in time");
    assert_eq!(end, 0, "a drop closes each connection of the stand-in");
    let again = TcpStream::connect(addr).map(|_| ()).map_err(|e| e.kind());
    assert_eq!(again, Err(std::io::ErrorKind::ConnectionRefused), "a drop closes the port of the stand-in");
}

#[tokio::test]
async fn a_drop_of_a_standin_on_the_runtime_of_the_caller_closes_its_connections() {
    pod_testkit::need_loopback!();
    let standin = StandIn::start(&["links"]).await.unwrap();
    let mut tcp = tokio::net::TcpStream::connect(standin.addr()).await.unwrap();
    tcp.write_all(LIST).await.unwrap();
    let mut got = Vec::new();
    while !whole(&got) {
        let mut more = [0u8; 1024];
        let n = timeout(limit(), tcp.read(&mut more)).await.expect("the answer in time").unwrap();
        assert!(n > 0, "the stand-in ended the connection");
        got.extend_from_slice(&more[..n]);
    }
    assert!(got.starts_with(b"HTTP/1.1 403 "), "{}", String::from_utf8_lossy(&got));
    assert_eq!(standin.counts().refused, 1);
    drop(standin);
    let mut rest = [0u8; 1];
    let end = timeout(limit(), tcp.read(&mut rest)).await.expect("a drop closes each connection of the stand-in");
    assert_eq!(end.unwrap(), 0);
}
