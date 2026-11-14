//! One connection of the stand-in: the requests of HTTP/1.1 in turn, each
//! checked for its signature, then served from the buckets.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{Object, State, Tally, key};
use crate::s3::sign::{self, Signing};

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Some(Ok(b)) = text.get(i + 1..i + 3).map(|h| u8::from_str_radix(h, 16))
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
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

/// The fault of the signature of a request: a request with no signature or
/// a wrong one gets 403, as from a bucket that is not public.
fn unsigned(
    method: &str,
    path: &str,
    query: &[(String, String)],
    fields: &[(String, String)],
    body: &[u8],
) -> Option<&'static str> {
    let field = |n: &str| fields.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
    let (Some(auth), Some(hash), Some(date)) =
        (field("authorization"), field("x-amz-content-sha256"), field("x-amz-date"))
    else {
        return Some("AccessDenied");
    };
    if hash != sign::sha256_hex(body) && !(body.is_empty() && hash == sign::EMPTY_HASH) {
        return Some("XAmzContentSHA256Mismatch");
    }
    let part = |name: &str| auth.split(name).nth(1).and_then(|p| p.split(',').next());
    let (Some(credential), Some(signed)) = (part("Credential="), part("SignedHeaders=")) else {
        return Some("AccessDenied");
    };
    let mut scope = credential.split('/');
    if scope.next() != Some(key().access_key.as_str()) {
        return Some("InvalidAccessKeyId");
    }
    let Some(region) = scope.nth(1) else { return Some("AccessDenied") };
    let headers: Vec<(&str, &str)> = signed.split(';').map(|n| (n, field(n).unwrap_or_default())).collect();
    let query: Vec<(&str, &str)> = query.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let s = Signing { method, path, query: &query, headers: &headers, payload_hash: hash, date, region };
    (sign::authorization(&key(), &s) != auth).then_some("SignatureDoesNotMatch")
}

/// Read into `buf` until it holds `len` bytes; false at the end of the
/// connection.
async fn fill(tcp: &mut TcpStream, buf: &mut Vec<u8>, len: usize) -> bool {
    while buf.len() < len {
        let mut more = [0u8; 16 << 10];
        match tcp.read(&mut more).await {
            Ok(0) | Err(_) => return false,
            Ok(n) => buf.extend_from_slice(&more[..n]),
        }
    }
    true
}

pub(super) async fn serve(mut tcp: TcpStream, state: Arc<State>) {
    let mut buf = Vec::new();
    loop {
        let end = loop {
            if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break at;
            }
            let more = buf.len() + 1;
            if !fill(&mut tcp, &mut buf, more).await {
                return;
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
        if !fill(&mut tcp, &mut buf, len).await {
            return;
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
        let tally = &state.tally;
        if let Some(code) = unsigned(&method, &path, &query, &fields, &body) {
            Tally::add(&tally.refused);
            if !answer(&mut tcp, 403, &[], &error(code)).await {
                return;
            }
            continue;
        }
        let rest = path.trim_start_matches('/');
        let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
        let q = |n: &str| query.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
        let (status, out_fields, out) = 'reply: {
            let mut all = state.buckets();
            let Some(store) = all.get_mut(bucket) else { break 'reply (404, vec![], error("NoSuchBucket")) };
            match (method.as_str(), key.is_empty()) {
                ("PUT", false) => {
                    Tally::add(&tally.puts);
                    if field("if-none-match").as_deref() == Some("*") && store.contains_key(key) {
                        Tally::add(&tally.exists);
                        (412, vec![], error("PreconditionFailed"))
                    } else {
                        let etag = format!("\"{}\"", &sign::sha256_hex(&body)[..32]);
                        store.insert(key.to_string(), Object { body, etag: etag.clone() });
                        (200, vec![("ETag", etag)], vec![])
                    }
                }
                ("GET", false) => {
                    Tally::add(&tally.gets);
                    match store.get(key) {
                        None => (404, vec![], error("NoSuchKey")),
                        Some(o) if field("if-match").is_some_and(|m| m != o.etag) => {
                            (412, vec![], error("PreconditionFailed"))
                        }
                        Some(o) => (200, vec![("ETag", o.etag.clone())], o.body.clone()),
                    }
                }
                ("DELETE", false) => {
                    Tally::add(&tally.deletes);
                    store.remove(key);
                    (204, vec![], vec![])
                }
                ("GET", true) if q("list-type").as_deref() == Some("2") => {
                    Tally::add(&tally.lists);
                    let prefix = q("prefix").unwrap_or_default();
                    let after = q("continuation-token").or(q("start-after")).unwrap_or_default();
                    let max: usize = q("max-keys").and_then(|v| v.parse().ok()).unwrap_or(1000);
                    let keys: Vec<_> =
                        store.iter().filter(|(k, _)| k.starts_with(&prefix) && k.as_str() > after.as_str()).collect();
                    // max-keys=0 lists no key and cuts nothing, as S3 does.
                    let cut = max > 0 && keys.len() > max;
                    let mut xml = String::from("<?xml version=\"1.0\"?><ListBucketResult>");
                    for (k, o) in keys.iter().take(max) {
                        xml.push_str(&format!(
                            "<Contents><Key>{}</Key><ETag>{}</ETag><Size>{}</Size></Contents>",
                            escape(k),
                            escape(&o.etag),
                            o.body.len()
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
            let lose = tally.lose_puts.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
            if lose.is_ok() {
                Tally::add(&tally.lost);
                return;
            }
        }
        if !answer(&mut tcp, status, &out_fields, &out).await {
            return;
        }
    }
}
