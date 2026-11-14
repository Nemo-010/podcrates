//! The client of the S3 API of the s3 carrier: requests of HTTP/1.1 signed
//! with SigV4, over connections through the caller's way out (TLS for an
//! endpoint of `https`), kept alive in a pool. Four calls: a PUT that
//! creates an object only when its key is free, a GET of a known ETag, a
//! page of `ListObjectsV2`, and a DELETE.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pod_core::{Dial, Target};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::time::timeout;

use super::sign::{self, Credentials, EMPTY_HASH, Signing};
use super::xml::{self, Listing};
use crate::carrier::{BoxIo, CarrierError, CarrierErrorKind};
use crate::pin;
use crate::poll::wire::Conn;

/// The most bytes of an answer of a listing.
const MAX_LISTING: usize = 8 << 20;

/// The most bytes of the body of an error.
const MAX_ERROR: usize = 64 << 10;

/// The connections that a client keeps alive.
const POOL: usize = 16;

/// The URL of the endpoint of the S3 API: `http[s]://HOST[:PORT][/BASE]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// `https`: TLS with the caller's configuration.
    pub secure: bool,
    /// A name or an IP address, an IPv6 one with no brackets.
    pub host: String,
    pub port: u16,
    /// The path before the bucket, with no `/` at its end; empty for none.
    pub base: String,
}

impl Endpoint {
    pub fn parse(text: &str) -> Result<Endpoint, String> {
        let form = "give http[s]://HOST[:PORT][/PATH]";
        let lower = text.get(..8).unwrap_or(text).to_ascii_lowercase();
        let (secure, rest) = if lower.starts_with("https://") {
            (true, &text[8..])
        } else if lower.starts_with("http://") {
            (false, &text[7..])
        } else {
            return Err(format!("{text:?} is no URL of HTTP: {form}"));
        };
        if rest.contains(['?', '#', '@']) {
            return Err(format!("{text:?} has a query, a fragment or a user: {form}"));
        }
        let (authority, base) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let (host, port) = match authority.strip_prefix('[') {
            Some(v6) => {
                let (host, tail) = v6.split_once(']').ok_or_else(|| format!("{text:?}: no ] after the address"))?;
                (host, tail.strip_prefix(':'))
            }
            None => match authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            },
        };
        let port = match port {
            Some(p) => p.parse().map_err(|_| format!("{text:?}: the port {p:?} is no number"))?,
            None if secure => 443,
            None => 80,
        };
        if host.is_empty() || port == 0 {
            return Err(format!("{text:?} has no host or port 0: {form}"));
        }
        Ok(Endpoint { secure, host: host.to_string(), port, base: base.trim_end_matches('/').to_string() })
    }

    /// The `Host` of a request, the port only when it is not the scheme's.
    fn authority(&self, host: &str) -> String {
        let host = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
        let default = if self.secure { 443 } else { 80 };
        if self.port == default { host } else { format!("{host}:{}", self.port) }
    }
}

/// Where the bucket goes in a request: `HOST/BUCKET/KEY` (the default,
/// which each server of the S3 API takes), or `BUCKET.HOST/KEY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Style {
    #[default]
    Path,
    VirtualHost,
}

/// A failure of a call: ask again after a wait, or the end.
#[derive(Debug)]
pub(super) enum Fault {
    Again(CarrierError),
    Fatal(CarrierError),
}

impl Fault {
    pub fn into_error(self) -> CarrierError {
        match self {
            Fault::Again(e) | Fault::Fatal(e) => e,
        }
    }
}

/// An answer: its status and its body.
pub(super) struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}

/// What a client needs: the bucket, its endpoint, its key, the TLS of an
/// endpoint of `https` and the way out.
pub(super) struct Client {
    pub name: &'static str,
    pub endpoint: Endpoint,
    pub bucket: String,
    pub style: Style,
    pub region: String,
    pub credentials: Credentials,
    pub tls: Option<Arc<ClientConfig>>,
    pub way: Arc<dyn Dial>,
    pub connect_timeout: Duration,
    pub answer_timeout: Duration,
    pub pool: Mutex<Vec<Conn<BoxIo>>>,
}

impl Client {
    fn err(&self, kind: CarrierErrorKind, text: impl Into<String>) -> CarrierError {
        CarrierError::new(self.name, kind, text)
    }

    fn host(&self) -> String {
        match self.style {
            Style::Path => self.endpoint.host.clone(),
            Style::VirtualHost => format!("{}.{}", self.bucket, self.endpoint.host),
        }
    }

    /// The path of `key` (the bucket itself for none), not encoded.
    fn path(&self, key: &str) -> String {
        match (self.style, key.is_empty()) {
            (Style::Path, true) => format!("{}/{}", self.endpoint.base, self.bucket),
            (Style::Path, false) => format!("{}/{}/{key}", self.endpoint.base, self.bucket),
            (Style::VirtualHost, _) => format!("{}/{key}", self.endpoint.base),
        }
    }

    async fn connect(&self) -> Result<Conn<BoxIo>, CarrierError> {
        let host = self.host();
        let target = match host.parse() {
            Ok(ip) => Target::Addr(std::net::SocketAddr::new(ip, self.endpoint.port)),
            Err(_) => Target::Name { host: host.clone(), port: self.endpoint.port },
        };
        let io = pin::dial(self.name, &*self.way, &target, self.connect_timeout).await?.io;
        if !self.endpoint.secure {
            return Ok(Conn::new(Box::new(io) as BoxIo));
        }
        let config = self.tls.clone().ok_or_else(|| {
            self.err(CarrierErrorKind::Unavailable, "an endpoint of https needs a TLS configuration (S3::with_tls)")
        })?;
        let name = ServerName::try_from(host.clone())
            .map_err(|_| self.err(CarrierErrorKind::Usage, format!("{host:?} is no DNS name and no address")))?;
        let tls = timeout(self.connect_timeout, tokio_rustls::TlsConnector::from(config).connect(name, io))
            .await
            .map_err(|_| self.err(CarrierErrorKind::Io(io::ErrorKind::TimedOut), format!("the TLS of {target}")))?
            .map_err(|e| CarrierError::io(self.name, format!("the TLS of {target}"), e))?;
        Ok(Conn::new(Box::new(tls) as BoxIo))
    }

    /// One request, signed, on a connection of the pool or a new one. The
    /// body of the answer has at most `max` bytes.
    pub async fn send(
        &self,
        method: &str,
        key: &str,
        query: &[(&str, &str)],
        extra: &[(&str, &str)],
        body: &[u8],
        max: usize,
    ) -> Result<Reply, CarrierError> {
        let pooled = self.pool.lock().unwrap_or_else(|e| e.into_inner()).pop();
        let mut conn = match pooled {
            Some(conn) => conn,
            None => self.connect().await?,
        };
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let date = sign::amz_date(now);
        let hash = if body.is_empty() { EMPTY_HASH.to_string() } else { sign::sha256_hex(body) };
        let host = self.endpoint.authority(&self.host());
        let mut fields: Vec<(&str, &str)> =
            vec![("Host", &host), ("x-amz-content-sha256", &hash), ("x-amz-date", &date)];
        if let Some(token) = &self.credentials.session_token {
            fields.push(("x-amz-security-token", token));
        }
        fields.extend_from_slice(extra);
        let path = self.path(key);
        let signing = Signing {
            method,
            path: &path,
            query,
            headers: &fields,
            payload_hash: &hash,
            date: &date,
            region: &self.region,
        };
        let auth = sign::authorization(&self.credentials, &signing);
        let query = sign::canonical_query(query);
        let target = if query.is_empty() {
            sign::uri_encode(&path, true)
        } else {
            format!("{}?{query}", sign::uri_encode(&path, true))
        };
        let mut out = format!("{method} {target} HTTP/1.1\r\nUser-Agent: pod-link\r\nAuthorization: {auth}\r\n");
        for (name, value) in &fields {
            out.push_str(&format!("{name}: {value}\r\n"));
        }
        out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
        let mut out = out.into_bytes();
        out.extend_from_slice(body);
        let exchange = async {
            conn.send(&out).await?;
            let head = conn.head().await?.ok_or(io::ErrorKind::UnexpectedEof)?;
            let status = head.status().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no status"))?;
            let limit = if (200..300).contains(&status) { max } else { MAX_ERROR };
            let mut got = Vec::new();
            if head.chunked() {
                while let Some(chunk) = conn.chunk(limit.saturating_sub(got.len()).max(1)).await? {
                    got.extend_from_slice(&chunk);
                    if got.len() > limit {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "an answer past its size"));
                    }
                }
            } else if let Some(len) = head.length()? {
                if len > limit {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, format!("an answer of {len} bytes")));
                }
                got = conn.body(len).await?;
            }
            Ok::<_, io::Error>((status, got, head.close()))
        };
        let (status, body, close) = timeout(self.answer_timeout, exchange)
            .await
            .map_err(|_| {
                self.err(CarrierErrorKind::Io(io::ErrorKind::TimedOut), format!("no answer to {method} in time"))
            })?
            .map_err(|e| CarrierError::io(self.name, format!("{method} {}", self.endpoint.host), e))?;
        if !close {
            let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
            if pool.len() < POOL {
                pool.push(conn);
            }
        }
        Ok(Reply { status, body })
    }

    /// The failure of an answer of `status`: a refused key or a missing
    /// bucket end the work, a busy or failed server is asked again.
    fn refusal(&self, what: &str, reply: &Reply) -> Fault {
        let code = xml::error_code(&String::from_utf8_lossy(&reply.body)).unwrap_or_default();
        let text = format!("{what} in the bucket {}: {} {code}", self.bucket, reply.status);
        match reply.status {
            403 => Fault::Fatal(self.err(CarrierErrorKind::Refused, text)),
            404 => Fault::Fatal(self.err(CarrierErrorKind::NotFound, text)),
            409 | 429 | 500..=599 => Fault::Again(self.err(CarrierErrorKind::Io(io::ErrorKind::Other), text)),
            _ => Fault::Fatal(self.err(CarrierErrorKind::Io(io::ErrorKind::InvalidData), text)),
        }
    }

    /// Create the object `key` when no object has the key: an object that
    /// is there already (412) is the one of a PUT whose answer was lost.
    pub async fn put(&self, key: &str, body: &[u8]) -> Result<(), Fault> {
        let reply =
            self.send("PUT", key, &[], &[("If-None-Match", "*")], body, MAX_ERROR).await.map_err(Fault::Again)?;
        match reply.status {
            200..=299 | 412 => Ok(()),
            _ => Err(self.refusal("PUT", &reply)),
        }
    }

    /// The object `key` of the ETag `etag`; none when it is not there.
    pub async fn get(&self, key: &str, etag: &str, max: usize) -> Result<Option<Vec<u8>>, Fault> {
        let matched = [("If-Match", etag)];
        let extra: &[(&str, &str)] = if etag.is_empty() { &[] } else { &matched };
        let reply = self.send("GET", key, &[], extra, &[], max).await.map_err(Fault::Again)?;
        match reply.status {
            200 => Ok(Some(reply.body)),
            404 => Ok(None),
            _ => Err(self.refusal("GET", &reply)),
        }
    }

    /// A page of at most `page` keys under `prefix`, after `after` or from
    /// the continuation `token`.
    pub async fn list(
        &self,
        prefix: &str,
        after: Option<&str>,
        token: Option<&str>,
        page: usize,
    ) -> Result<Listing, Fault> {
        let page = page.to_string();
        let mut query = vec![("list-type", "2"), ("prefix", prefix), ("max-keys", page.as_str())];
        if let Some(after) = after {
            query.push(("start-after", after));
        }
        if let Some(token) = token {
            query.push(("continuation-token", token));
        }
        let reply = self.send("GET", "", &query, &[], &[], MAX_LISTING).await.map_err(Fault::Again)?;
        match reply.status {
            200 => Ok(xml::listing(&String::from_utf8_lossy(&reply.body))),
            _ => Err(self.refusal("LIST", &reply)),
        }
    }

    /// Remove the object `key`; one that is gone is no failure.
    pub async fn delete(&self, key: &str) -> Result<(), Fault> {
        let reply = self.send("DELETE", key, &[], &[], &[], MAX_ERROR).await.map_err(Fault::Again)?;
        match reply.status {
            200..=299 | 404 => Ok(()),
            _ => Err(self.refusal("DELETE", &reply)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_endpoint_has_its_scheme_its_host_its_port_and_its_base() {
        let e = Endpoint::parse("https://s3.example.com").unwrap();
        assert_eq!((e.secure, e.host.as_str(), e.port, e.base.as_str()), (true, "s3.example.com", 443, ""));
        let e = Endpoint::parse("http://[::1]:9000/store/").unwrap();
        assert_eq!((e.secure, e.host.as_str(), e.port, e.base.as_str()), (false, "::1", 9000, "/store"));
        assert_eq!(e.authority("::1"), "[::1]:9000");
        for bad in ["s3.example.com", "ftp://x", "http://", "http://h:0", "http://h:x", "http://h/?q", "http://u@h"] {
            assert!(Endpoint::parse(bad).is_err(), "{bad}");
        }
    }
}
