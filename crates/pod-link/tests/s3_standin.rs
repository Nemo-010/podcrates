//! The stand-in of the S3 API that a consumer takes (T-627,
//! PodUtils/podnet#564; feature `s3-standin`): a request with no signature
//! gets 403, a request that a careless peer could send gets an answer and
//! no panic, and a drop closes the port and each connection, on its own
//! thread and on the runtime of the caller. `tests/s3.rs` proves the rest
//! of the stand-in with the carrier: the signature, the conditions, the
//! listing, the counts and a lost answer.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use common::limit;
use pod_link::s3::sign::{self, Signing};
use pod_link::s3::standin::{self, Counts, Object, StandIn};
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

/// A listing of `links` with `query`, signed with the key of the stand-in,
/// on `tcp`: the answer.
async fn list(tcp: &mut tokio::net::TcpStream, standin: &StandIn, query: &[(&str, &str)]) -> String {
    let date = sign::amz_date(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
    let (host, hash) = (standin.addr().to_string(), sign::EMPTY_HASH);
    let fields = [("host", host.as_str()), ("x-amz-content-sha256", hash), ("x-amz-date", date.as_str())];
    let path = "/links";
    let s =
        Signing { method: "GET", path, query, headers: &fields, payload_hash: hash, date: &date, region: "us-east-1" };
    let auth = sign::authorization(&standin::key(), &s);
    let mut out = format!("GET {path}?{} HTTP/1.1\r\nAuthorization: {auth}\r\n", sign::canonical_query(query));
    for (name, value) in fields {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    send(tcp, out.as_bytes()).await
}

/// Send `request` on `tcp`: the answer.
async fn send(tcp: &mut tokio::net::TcpStream, request: &[u8]) -> String {
    tcp.write_all(request).await.unwrap();
    let mut got = Vec::new();
    while !whole(&got) {
        let mut more = [0u8; 1024];
        let n = timeout(limit(), tcp.read(&mut more)).await.expect("the answer in time").unwrap();
        assert!(n > 0, "the stand-in ended the connection: {}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&more[..n]);
    }
    String::from_utf8_lossy(&got).into_owned()
}

#[tokio::test]
async fn a_bad_escape_and_a_listing_of_no_key_get_an_answer_and_no_panic() {
    pod_testkit::need_loopback!();
    let standin = StandIn::start(&["links"]).await.unwrap();
    let object = Object { body: b"x".to_vec(), etag: "\"e\"".into() };
    standin.buckets().get_mut("links").unwrap().insert("a/1".into(), object);
    let mut tcp = tokio::net::TcpStream::connect(standin.addr()).await.unwrap();
    let odd = send(&mut tcp, b"GET /links/%ff%C3%A9%z\xc3\xa9 HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(odd.starts_with("HTTP/1.1 403 "), "a path of bad escapes gets an answer: {odd}");
    let none = list(&mut tcp, &standin, &[("list-type", "2"), ("max-keys", "0")]).await;
    assert!(none.starts_with("HTTP/1.1 200 "), "max-keys=0 gets an answer: {none}");
    assert!(!none.contains("<Key>") && none.contains("<IsTruncated>false</IsTruncated>"), "{none}");
    let one = list(&mut tcp, &standin, &[("list-type", "2"), ("prefix", "a/")]).await;
    assert!(one.contains("<Key>a/1</Key>") && one.contains("<ETag>&quot;e&quot;</ETag>"), "{one}");
    assert_eq!(standin.keys("links", "a/"), ["a/1"]);
    assert_eq!((standin.counts().refused, standin.counts().lists), (1, 2));
}
