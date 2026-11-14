//! The object-storage carrier (T-623) against SeaweedFS, an S3-compatible
//! server that this crate did not write (call C540): the requests of the
//! carrier in path style, `If-None-Match: *` on a PUT and `If-Match` on a
//! GET, the pages of a listing (`start-after`, the continuation token) and
//! the codes of the errors of a real server.
//!
//! The server is `POD_LINK_TEST_S3_ENDPOINT` (`http://127.0.0.1:PORT`), and
//! its bucket `POD_LINK_TEST_S3_BUCKET` (`links` when not set) takes the
//! made-up key of `common::s3::key`. A host with no endpoint skips each
//! test with the reason, unless `POD_LINK_TEST_S3=required`, which
//! `scripts/ci/s3-tests.sh` sets with the pinned release. Each test works
//! under its own prefix, so the tests run side by side in one bucket.

#![cfg(feature = "s3")]

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::tcp::{Direct, id, ring};
use common::{echo, limit, pattern};
use pod_identity::KeyName;
use pod_link::s3::sign::{self, Signing};
use pod_link::s3::{Credentials, Endpoint, S3, S3Listener};
use pod_link::tcp::Keys;
use pod_link::{Carrier, CarrierErrorKind, Link, Listener, Role, Settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// The server and its bucket; none (a skip) when the host names no server.
fn server() -> Option<(Endpoint, String)> {
    let required = std::env::var("POD_LINK_TEST_S3").is_ok_and(|v| v == "required");
    let Some(text) = std::env::var("POD_LINK_TEST_S3_ENDPOINT").ok().filter(|t| !t.is_empty()) else {
        assert!(!required, "POD_LINK_TEST_S3=required, but POD_LINK_TEST_S3_ENDPOINT names no server");
        eprintln!("skip: POD_LINK_TEST_S3_ENDPOINT names no S3-compatible server (scripts/ci/s3-tests.sh)");
        return None;
    };
    let endpoint = Endpoint::parse(&text).unwrap_or_else(|e| panic!("POD_LINK_TEST_S3_ENDPOINT {text:?}: {e}"));
    let bucket = std::env::var("POD_LINK_TEST_S3_BUCKET").ok().filter(|b| !b.is_empty());
    Some((endpoint, bucket.unwrap_or_else(|| "links".into())))
}

/// A prefix that no other run used: the objects of a run stay.
fn fresh(tag: &str) -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("t623/{tag}-{nanos:x}-{:x}", std::process::id())
}

/// A carrier of the identity `n` whose listeners take the identities
/// `clients`, with small objects and pages of 1 key, so that a stream
/// spans many objects and each listing many pages.
fn carrier(n: u8, endpoint: &Endpoint, clients: &[u8]) -> S3 {
    let keys = Keys::new(clients.iter().map(|c| KeyName::Key(id(*c).public())));
    let way = Arc::new(Direct::default());
    let mut s3 = S3::new(ring(), id(n), way, endpoint.clone(), common::s3::key()).with_clients(keys);
    (s3.object, s3.page) = (16 << 10, 1);
    (s3.poll_min, s3.poll_max) = (Duration::from_millis(10), Duration::from_millis(200));
    s3
}

async fn bound(s3: &S3, bucket: &str, prefix: &str) -> S3Listener {
    timeout(limit(), s3.bind(bucket, prefix)).await.expect("the bind in time").expect("the bind")
}

/// The dial address of the listener of the identity 1.
fn at(bucket: &str, prefix: &str) -> String {
    format!("{}@{bucket}/{prefix}", id(1).public().hex())
}

/// One request of the test itself, signed with `key`, over HTTP/1.0 (an
/// answer with no chunks): the status and the body.
async fn request(
    endpoint: &Endpoint,
    key: &Credentials,
    method: &str,
    path: &str,
    query: &[(&str, &str)],
    extra: &[(&str, &str)],
    body: &[u8],
) -> (u16, String) {
    let date = sign::amz_date(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
    let hash = sign::sha256_hex(body);
    let host = format!("{}:{}", endpoint.host, endpoint.port);
    let mut fields = vec![("Host", host.as_str()), ("x-amz-content-sha256", &hash), ("x-amz-date", &date)];
    fields.extend_from_slice(extra);
    let s = Signing { method, path, query, headers: &fields, payload_hash: &hash, date: &date, region: "us-east-1" };
    let auth = sign::authorization(key, &s);
    let query = sign::canonical_query(query);
    let target = format!("{}{}{query}", sign::uri_encode(path, true), if query.is_empty() { "" } else { "?" });
    let mut out = format!("{method} {target} HTTP/1.0\r\nAuthorization: {auth}\r\n");
    for (name, value) in &fields {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut tcp = tokio::net::TcpStream::connect(&host).await.expect("a connection to the server");
    tcp.write_all(out.as_bytes()).await.unwrap();
    tcp.write_all(body).await.unwrap();
    let mut answer = Vec::new();
    timeout(limit(), tcp.read_to_end(&mut answer)).await.expect("an answer in time").unwrap();
    let text = String::from_utf8_lossy(&answer).into_owned();
    let status = text.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or_else(|| panic!("no status: {text}"));
    let body = text.split_once("\r\n\r\n").map_or(String::new(), |(_, b)| b.to_string());
    (status, body)
}

/// The text of each element `name` in `xml`.
fn each<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    let (open, close) = (format!("<{name}>"), format!("</{name}>"));
    xml.split(open.as_str()).skip(1).filter_map(|p| p.split_once(close.as_str())).map(|(v, _)| v).collect()
}

/// The objects of `bucket` under `prefix`, each with its size, each page.
async fn objects(endpoint: &Endpoint, bucket: &str, prefix: &str) -> Vec<(String, u64)> {
    let (mut out, mut token) = (Vec::new(), None::<String>);
    loop {
        let mut query = vec![("list-type", "2"), ("prefix", prefix)];
        if let Some(t) = &token {
            query.push(("continuation-token", t));
        }
        let (status, body) =
            request(endpoint, &common::s3::key(), "GET", &format!("/{bucket}"), &query, &[], &[]).await;
        assert_eq!(status, 200, "the listing of {prefix}: {body}");
        for object in each(&body, "Contents") {
            let size = each(object, "Size").first().and_then(|s| s.parse().ok()).unwrap_or(0);
            out.push((each(object, "Key").first().unwrap_or(&"").replace("&amp;", "&"), size));
        }
        match each(&body, "NextContinuationToken").first() {
            Some(next) if body.contains("<IsTruncated>true</IsTruncated>") => token = Some(next.replace("&amp;", "&")),
            _ => return out,
        }
    }
}

/// The keys of `bucket` under `prefix`.
async fn keys(endpoint: &Endpoint, bucket: &str, prefix: &str) -> Vec<String> {
    objects(endpoint, bucket, prefix).await.into_iter().map(|(k, _)| k).collect()
}

/// Three streams of `size` bytes each way over a link of `dialing` to
/// `door`: each comes back whole.
async fn carries(dialing: &S3, door: &mut S3Listener, address: &str, size: usize) {
    let both = async { tokio::join!(dialing.dial(address), door.accept_peer()) };
    let (near, far) = timeout(limit(), both).await.expect("the dial and the accept in time");
    let (near, far) = (near.expect("the dial"), far.expect("the accept"));
    assert_eq!(far.peer, Some(id(2).public()), "the accept gives the key of the client");
    let dialer = Link::new(near, Role::Dialer, Settings::default()).unwrap();
    let _echo = echo(Link::new(far.io, Role::Listener, Settings::default()).unwrap());
    let mut moves = Vec::new();
    for seed in 0..3u32 {
        let mut stream = dialer.open().unwrap();
        moves.push(tokio::spawn(async move {
            let data = pattern(seed, size);
            let (mut reader, mut writer) = tokio::io::split(&mut stream);
            let send = async {
                writer.write_all(&data).await.unwrap();
                writer.shutdown().await.unwrap();
            };
            let mut back = Vec::new();
            let (_, read) = tokio::join!(send, reader.read_to_end(&mut back));
            read.unwrap();
            assert!(back == data, "stream {seed}: the bytes came back whole");
        }));
    }
    for each in moves {
        timeout(limit(), each).await.expect("the echo in time").unwrap();
    }
    dialer.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_over_the_objects_of_the_server_carries_streams() {
    let Some((endpoint, bucket)) = server() else { return };
    let prefix = fresh("link");
    let mut door = bound(&carrier(1, &endpoint, &[2]), &bucket, &prefix).await;
    let dialing = carrier(2, &endpoint, &[]);
    let listener_key = KeyName::Key(id(1).public());
    let both = async { tokio::join!(dialing.connect(&bucket, &prefix, &listener_key), door.accept_key()) };
    let (near, far) = timeout(limit(), both).await.expect("in time");
    assert_eq!((near.unwrap().1, far.unwrap().1), (id(1).public(), id(2).public()), "each end proved its key");
    carries(&dialing, &mut door, &at(&bucket, &prefix), 128 << 10).await;
    let all = keys(&endpoint, &bucket, &format!("{prefix}/")).await;
    let count = |dir: &str| all.iter().filter(|k| k.starts_with(&format!("{prefix}/{dir}/"))).count();
    assert_eq!(count("open"), 2, "an open object for each session: {all:?}");
    assert!(count("up") > 2 * 8 && count("down") > 2 * 8, "the streams span many objects: {all:?}");
    println!("seaweedfs: a link carried three streams each way over objects");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prune_removes_each_object_read_from_the_server() {
    let Some((endpoint, bucket)) = server() else { return };
    let prefix = fresh("prune");
    let (mut listening, mut dialing) = (carrier(1, &endpoint, &[2]), carrier(2, &endpoint, &[]));
    (listening.prune, dialing.prune) = (true, true);
    let mut door = bound(&listening, &bucket, &prefix).await;
    let address = at(&bucket, &prefix);
    let both = async { tokio::join!(dialing.dial(&address), door.accept()) };
    let (near, far) = timeout(limit(), both).await.expect("in time");
    let (mut near, mut far) = (near.unwrap(), far.unwrap());
    let data = pattern(5, 100 << 10);
    near.write_all(&data).await.unwrap();
    near.shutdown().await.unwrap();
    let mut got = Vec::new();
    timeout(limit(), far.read_to_end(&mut got)).await.expect("the bytes in time").unwrap();
    assert!(got == data, "the bytes came whole");
    far.shutdown().await.unwrap();
    timeout(limit(), near.read_to_end(&mut got)).await.expect("the end in time").unwrap();
    let under = format!("{prefix}/");
    let empty = async {
        while !keys(&endpoint, &bucket, &under).await.is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    if timeout(limit(), empty).await.is_err() {
        panic!("each object was removed: {:?}", keys(&endpoint, &bucket, &under).await);
    }
    println!("seaweedfs: prune removed each object of a session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_server_holds_the_conditions_and_the_pages_of_the_carrier() {
    let Some((endpoint, bucket)) = server() else { return };
    let key = common::s3::key();
    let dir = format!("{}/", fresh("conditions"));
    let (first, second) = (format!("/{bucket}/{dir}a"), format!("/{bucket}/{dir}b"));
    let put = |path: String, body: &'static [u8]| {
        let (endpoint, key) = (endpoint.clone(), key.clone());
        async move { request(&endpoint, &key, "PUT", &path, &[], &[("If-None-Match", "*")], body).await }
    };
    assert_eq!(put(first.clone(), b"one").await.0, 200, "a PUT of a new key");
    let (status, body) = put(first.clone(), b"two").await;
    assert_eq!(status, 412, "a PUT of a key that is there: {body}");
    assert_eq!(put(second.clone(), b"").await.0, 200, "an empty object");
    let (status, body) = request(&endpoint, &key, "GET", &first, &[], &[("If-Match", "\"0123\"")], &[]).await;
    assert_eq!(status, 412, "a GET of another ETag: {body}");
    let (status, body) = request(&endpoint, &key, "GET", &first, &[], &[], &[]).await;
    assert_eq!((status, body.as_str()), (200, "one"), "the first PUT holds");
    let query = [("list-type", "2"), ("prefix", dir.as_str()), ("max-keys", "1")];
    let (status, page) = request(&endpoint, &key, "GET", &format!("/{bucket}"), &query, &[], &[]).await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("<IsTruncated>true</IsTruncated>") && page.contains("<NextContinuationToken>"), "{page}");
    let start = format!("{dir}a");
    let query = [("list-type", "2"), ("prefix", dir.as_str()), ("start-after", start.as_str())];
    let (_, page) = request(&endpoint, &key, "GET", &format!("/{bucket}"), &query, &[], &[]).await;
    assert!(page.contains(&format!("<Key>{dir}b</Key>")) && !page.contains(&format!("<Key>{start}</Key>")), "{page}");
    println!("seaweedfs: If-None-Match, If-Match and the pages of a listing held");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_secret_and_a_missing_bucket_end_the_bind() {
    let Some((endpoint, bucket)) = server() else { return };
    let mut wrong = carrier(1, &endpoint, &[2]);
    wrong.credentials = Credentials::new(common::s3::key().access_key, "another-made-up-secret");
    let e = wrong.bind(&bucket, &fresh("wrong")).await.expect_err("a refused bind");
    assert_eq!(e.kind, CarrierErrorKind::Refused, "{e}");
    assert!(e.to_string().contains("SignatureDoesNotMatch"), "{e}");
    let e = carrier(1, &endpoint, &[2]).bind("missing-t623", "x").await.expect_err("no bucket");
    assert_eq!(e.kind, CarrierErrorKind::NotFound, "{e}");
    assert!(e.to_string().contains("NoSuchBucket"), "{e}");
    println!("seaweedfs: a wrong secret got 403 and a missing bucket 404");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_listener_takes_no_session_older_than_its_bind() {
    let Some((endpoint, bucket)) = server() else { return };
    let prefix = fresh("late");
    let mut early = carrier(2, &endpoint, &[]);
    early.handshake_timeout = Duration::from_secs(3);
    let address = at(&bucket, &prefix);
    let old = tokio::spawn(async move { early.dial(&address).await.err().map(|e| e.kind) });
    let open = format!("{prefix}/open/");
    let opened = async {
        while keys(&endpoint, &bucket, &open).await.is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    timeout(limit(), opened).await.expect("the old session opened");
    let mut door = bound(&carrier(1, &endpoint, &[2]), &bucket, &prefix).await;
    let kind = timeout(limit(), old).await.expect("the old dial ended").unwrap();
    assert_eq!(kind, Some(CarrierErrorKind::Io(std::io::ErrorKind::TimedOut)), "no listener took the old session");
    carries(&carrier(2, &endpoint, &[]), &mut door, &at(&bucket, &prefix), 16 << 10).await;
    println!("seaweedfs: a listener took no session older than its bind");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_budget_ends_a_session_whose_peer_removes_nothing() {
    let Some((endpoint, bucket)) = server() else { return };
    let prefix = fresh("full");
    let mut door = bound(&carrier(1, &endpoint, &[2]), &bucket, &prefix).await;
    let mut dialing = carrier(2, &endpoint, &[]);
    (dialing.budget, dialing.idle) = (64 << 10, Duration::from_secs(1));
    let address = at(&bucket, &prefix);
    let both = async { tokio::join!(dialing.dial(&address), door.accept()) };
    let (near, far) = timeout(limit(), both).await.expect("in time");
    let (mut near, _far) = (near.unwrap(), far.unwrap());
    let data = pattern(1, 256 << 10);
    let wrote = timeout(limit(), async {
        near.write_all(&data).await?;
        near.flush().await?;
        let mut byte = [0u8];
        near.read(&mut byte).await
    })
    .await
    .expect("the end of the session in time");
    let e = wrote.unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::StorageFull, "{e}");
    let held: u64 = objects(&endpoint, &bucket, &format!("{prefix}/up/")).await.iter().map(|(_, n)| n).sum();
    assert!(held <= 64 << 10, "the objects of the dialer keep {held} bytes, past the budget");
    println!("seaweedfs: the budget ended a session whose peer removed nothing");
}
