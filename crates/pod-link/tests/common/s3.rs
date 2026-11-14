//! A stand-in of the S3 API on the loopback, for the tests of the s3
//! carrier: plain HTTP/1.1 with keep-alive, buckets in memory, the PUT of
//! `If-None-Match: *`, the GET of `If-Match`, the DELETE and the
//! `ListObjectsV2` of path style. It checks the SigV4 of each request with
//! the signer of the crate over what it received, and the payload hash
//! with its own SHA-256. It counts its work, and can drop the answer of a
//! PUT that it took.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use pod_link::s3::sign::{self, Credentials, Signing};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The made-up key of the stand-in (listed in .github/secrets-allow.txt).
pub fn key() -> Credentials {
    Credentials::new("PODLINKTESTKEY", "pod-link-test-secret-not-real")
}

/// The counts of a stand-in.
#[derive(Default)]
pub struct Counts {
    pub puts: AtomicUsize,
    pub gets: AtomicUsize,
    pub lists: AtomicUsize,
    pub deletes: AtomicUsize,
    /// PUTs of a key that was there (412).
    pub exists: AtomicUsize,
    /// Requests whose signature failed (403).
    pub refused: AtomicUsize,
    /// The answers of PUTs to drop after the PUT took its object.
    pub lose_puts: AtomicUsize,
    pub lost: AtomicUsize,
}

/// The buckets of a stand-in: each key with its body and its ETag.
pub type Buckets = Arc<Mutex<BTreeMap<String, BTreeMap<String, (Vec<u8>, String)>>>>;

/// A stand-in with its buckets.
pub struct StandIn {
    pub addr: SocketAddr,
    pub objects: Buckets,
    pub counts: Arc<Counts>,
}

impl StandIn {
    /// A stand-in with the empty `buckets`.
    pub async fn start(buckets: &[&str]) -> StandIn {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let objects = Arc::new(Mutex::new(buckets.iter().map(|b| (b.to_string(), BTreeMap::new())).collect()));
        let counts = Arc::new(Counts::default());
        let (o, c) = (objects.clone(), counts.clone());
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(serve(tcp, o.clone(), c.clone()));
            }
        });
        StandIn { addr, objects, counts }
    }

    /// The endpoint of the stand-in.
    pub fn endpoint(&self) -> pod_link::s3::Endpoint {
        pod_link::s3::Endpoint::parse(&format!("http://{}", self.addr)).unwrap()
    }

    /// The keys of `bucket` under `prefix`.
    pub fn keys(&self, bucket: &str, prefix: &str) -> Vec<String> {
        let objects = self.objects.lock().unwrap();
        objects[bucket].keys().filter(|k| k.starts_with(prefix)).cloned().collect()
    }
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(b) = u8::from_str_radix(&text[i + 1..i + 3], 16)
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap()
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

async fn answer(tcp: &mut TcpStream, status: u16, fields: &[(&str, String)], body: &[u8]) -> bool {
    let mut out = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\n", body.len());
    for (name, value) in fields {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    tcp.write_all(&out).await.is_ok()
}

fn error(code: &str) -> Vec<u8> {
    format!("<?xml version=\"1.0\"?><Error><Code>{code}</Code></Error>").into_bytes()
}

/// The fault of the signature of a request, when it has one.
fn unsigned(
    method: &str,
    path: &str,
    query: &[(String, String)],
    fields: &[(String, String)],
    body: &[u8],
) -> Option<&'static str> {
    let field = |n: &str| fields.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
    let auth = field("authorization")?;
    let hash = field("x-amz-content-sha256")?;
    if hash != sign::sha256_hex(body) && !(body.is_empty() && hash == sign::EMPTY_HASH) {
        return Some("XAmzContentSHA256Mismatch");
    }
    let credential = auth.split("Credential=").nth(1)?.split(',').next()?;
    let mut scope = credential.split('/');
    if scope.next()? != key().access_key {
        return Some("InvalidAccessKeyId");
    }
    let region = scope.nth(1)?;
    let signed = auth.split("SignedHeaders=").nth(1)?.split(',').next()?;
    let headers: Vec<(&str, &str)> = signed.split(';').map(|n| (n, field(n).unwrap_or_default())).collect();
    let query: Vec<(&str, &str)> = query.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let date = field("x-amz-date")?;
    let s = Signing { method, path, query: &query, headers: &headers, payload_hash: hash, date, region };
    let want = sign::authorization(&key(), &s);
    (want != auth).then_some("SignatureDoesNotMatch")
}

async fn serve(mut tcp: TcpStream, objects: Buckets, counts: Arc<Counts>) {
    let mut buf = Vec::new();
    loop {
        let end = loop {
            if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break at;
            }
            let mut more = [0u8; 16 << 10];
            match tcp.read(&mut more).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&more[..n]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        buf.drain(..end + 4);
        let mut lines = head.split("\r\n");
        let mut first = lines.next().unwrap_or_default().split(' ');
        let (method, target) = (first.next().unwrap_or_default().to_string(), first.next().unwrap_or_default());
        let fields: Vec<(String, String)> = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        let field = |n: &str| fields.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
        let len: usize = field("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
        while buf.len() < len {
            let mut more = [0u8; 16 << 10];
            match tcp.read(&mut more).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&more[..n]),
            }
        }
        let body: Vec<u8> = buf.drain(..len).collect();
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let path = decode(path);
        let query: Vec<(String, String)> = query
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| p.split_once('=').unwrap_or((p, "")))
            .map(|(k, v)| (decode(k), decode(v)))
            .collect();
        if let Some(code) = unsigned(&method, &path, &query, &fields, &body) {
            counts.refused.fetch_add(1, Ordering::SeqCst);
            if !answer(&mut tcp, 403, &[], &error(code)).await {
                return;
            }
            continue;
        }
        let rest = path.trim_start_matches('/');
        let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
        let q = |n: &str| query.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
        let (status, out_fields, out) = 'reply: {
            let mut all = objects.lock().unwrap();
            let Some(store) = all.get_mut(bucket) else { break 'reply (404, vec![], error("NoSuchBucket")) };
            match (method.as_str(), key.is_empty()) {
                ("PUT", false) => {
                    counts.puts.fetch_add(1, Ordering::SeqCst);
                    if field("if-none-match").as_deref() == Some("*") && store.contains_key(key) {
                        counts.exists.fetch_add(1, Ordering::SeqCst);
                        (412, vec![], error("PreconditionFailed"))
                    } else {
                        let etag = format!("\"{}\"", &sign::hex(&Sha256::digest(&body))[..32]);
                        store.insert(key.to_string(), (body, etag.clone()));
                        (200, vec![("ETag", etag)], vec![])
                    }
                }
                ("GET", false) => {
                    counts.gets.fetch_add(1, Ordering::SeqCst);
                    match store.get(key) {
                        None => (404, vec![], error("NoSuchKey")),
                        Some((_, etag)) if field("if-match").is_some_and(|m| &m != etag) => {
                            (412, vec![], error("PreconditionFailed"))
                        }
                        Some((data, etag)) => (200, vec![("ETag", etag.clone())], data.clone()),
                    }
                }
                ("DELETE", false) => {
                    counts.deletes.fetch_add(1, Ordering::SeqCst);
                    store.remove(key);
                    (204, vec![], vec![])
                }
                ("GET", true) if q("list-type").as_deref() == Some("2") => {
                    counts.lists.fetch_add(1, Ordering::SeqCst);
                    let prefix = q("prefix").unwrap_or_default();
                    let after = q("continuation-token").or(q("start-after")).unwrap_or_default();
                    let max: usize = q("max-keys").and_then(|v| v.parse().ok()).unwrap_or(1000);
                    let keys: Vec<_> =
                        store.iter().filter(|(k, _)| k.starts_with(&prefix) && k.as_str() > after.as_str()).collect();
                    let cut = keys.len() > max;
                    let mut xml = String::from("<?xml version=\"1.0\"?><ListBucketResult>");
                    for (k, (data, etag)) in keys.iter().take(max) {
                        xml.push_str(&format!(
                            "<Contents><Key>{}</Key><ETag>{}</ETag><Size>{}</Size></Contents>",
                            escape(k),
                            escape(etag),
                            data.len()
                        ));
                    }
                    xml.push_str(&format!("<IsTruncated>{cut}</IsTruncated>"));
                    if cut {
                        xml.push_str(&format!(
                            "<NextContinuationToken>{}</NextContinuationToken>",
                            escape(keys[max - 1].0)
                        ));
                    }
                    xml.push_str("</ListBucketResult>");
                    (200, vec![], xml.into_bytes())
                }
                _ => (400, vec![], error("InvalidRequest")),
            }
        };
        if method == "PUT" && status == 200 {
            let lose = counts.lose_puts.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
            if lose.is_ok() {
                counts.lost.fetch_add(1, Ordering::SeqCst);
                return;
            }
        }
        if !answer(&mut tcp, status, &out_fields, &out).await {
            return;
        }
    }
}
