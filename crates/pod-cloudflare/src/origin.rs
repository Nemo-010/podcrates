//! The dial of a forward origin: TCP, TLS, unix sockets, and TLS over
//! unix. An origin is a service on this host or its network: its name does
//! not go to DNS over HTTPS, and its connection does not go through the
//! proxy.

use std::sync::{Arc, Mutex, OnceLock};

use crate::fail::{IoFail, OrFail, Result, bail};
use pod_core::Class;
use pod_core::{BoxedIo, Stage};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

use crate::ingress::{OriginOptions, Service};

/// The dial of the origins of one tunnel: the TLS of the binary, its
/// connectors made once, and the origins whose certificate is not checked
/// that a warning named.
pub struct Origins {
    tls: Arc<pod_tls::Context>,
    verified: OnceLock<TlsConnector>,
    unverified: OnceLock<TlsConnector>,
    seen: Mutex<Vec<String>>,
    report: pod_core::Report,
}

impl Origins {
    pub fn new(tls: Arc<pod_tls::Context>) -> Origins {
        Origins {
            tls,
            verified: OnceLock::new(),
            unverified: OnceLock::new(),
            seen: Mutex::new(Vec::new()),
            report: pod_core::Report::default(),
        }
    }

    /// The lines for the user go to `report`.
    pub fn with_report(mut self, report: pod_core::Report) -> Origins {
        self.report = report;
        self
    }

    /// Dial the origin for a forward service.
    pub async fn dial(&self, service: &Service, options: &OriginOptions) -> Result<BoxedIo> {
        dial(self, service, options).await
    }
}

/// Dial the origin for a forward service.
async fn dial(origins: &Origins, service: &Service, options: &OriginOptions) -> Result<BoxedIo> {
    let timeout = options.connect_timeout;
    let connect = async {
        match service {
            Service::Http(url) => {
                let (host, port, tls) = parse_http_url(url)?;
                let tcp = connect_origin(&host, port).await?;
                if tls {
                    if options.no_tls_verify {
                        origins.note_unverified(url);
                    }
                    origins.tls_wrap(tcp, &host, options.no_tls_verify).await
                } else {
                    Ok(Box::new(tcp) as BoxedIo)
                }
            }
            Service::Unix(path) => dial_unix(origins, path, false, options).await,
            Service::UnixTls(path) => dial_unix(origins, path, true, options).await,
            Service::Tcp(addr) => {
                let (host, port) =
                    split_host_port(addr).or_fail(Stage::Origin, Class::Config, format!("{addr} is not HOST:PORT"))?;
                let s = connect_origin(host, port).await?;
                let _ = s.set_nodelay(true);
                Ok(Box::new(s) as BoxedIo)
            }
            other => bail!(Stage::Origin, Class::Config, "{} is not a forward service", other.describe()),
        }
    };
    match timeout {
        Some(limit) => tokio::time::timeout(limit, connect).await.map_err(|_| {
            crate::fail::new(Stage::Origin, Class::Timeout, format!("origin connect timed out after {limit:?}"))
        })?,
        None => connect.await,
    }
}

/// Dial a filesystem socket, optionally wrapping it in TLS.
#[cfg(unix)]
async fn dial_unix(origins: &Origins, path: &std::path::Path, tls: bool, options: &OriginOptions) -> Result<BoxedIo> {
    let stream =
        UnixStream::connect(path).await.io_fail(Stage::Origin, format!("connecting to unix:{}", path.display()))?;
    if tls {
        if options.no_tls_verify {
            origins.note_unverified(&format!("unix+tls:{}", path.display()));
        }
        origins.tls_wrap(stream, "localhost", options.no_tls_verify).await
    } else {
        Ok(Box::new(stream) as BoxedIo)
    }
}

#[cfg(not(unix))]
async fn dial_unix(
    _origins: &Origins,
    path: &std::path::Path,
    _tls: bool,
    _options: &OriginOptions,
) -> Result<BoxedIo> {
    bail!(Stage::Origin, Class::Unsupported, "unix sockets are not supported on this platform: {}", path.display())
}

impl Origins {
    /// One warning for each origin whose TLS certificate is not checked
    /// (noTLSVerify): the first dial of it says so; the later dials do not
    /// (a warning for each request would fill the log). Gives true for the
    /// first call of `origin`. At most 256 origins are kept.
    pub(crate) fn note_unverified(&self, origin: &str) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if seen.iter().any(|o| o == origin) {
            return false;
        }
        if seen.len() < 256 {
            seen.push(origin.to_string());
        }
        let text = format!("noTLSVerify: the TLS certificate of the origin {origin} is not checked");
        self.report.event(pod_core::Event::warn("origin.no_verify", text));
        true
    }

    async fn tls_wrap<S>(&self, stream: S, server_name: &str, no_verify: bool) -> Result<BoxedIo>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let connector = if no_verify { self.no_verify_connector() } else { self.verified_connector() };
        let name = ServerName::try_from(server_name.to_string()).or_fail(
            Stage::Origin,
            Class::Config,
            format!("invalid TLS server name {server_name:?}"),
        )?;
        let tls =
            connector.connect(name, stream).await.io_fail(Stage::Tls, format!("TLS handshake with {server_name}"))?;
        Ok(Box::new(tls))
    }

    fn verified_connector(&self) -> TlsConnector {
        self.verified
            .get_or_init(|| {
                let context = &self.tls;
                let config = context
                    .client_config_with(&[], &[])
                    .map(Arc::new)
                    .or_else(|err| {
                        let text = format!("{err}; the compiled-in roots alone are used");
                        self.report.event(pod_core::Event::warn("origin.roots", text));
                        pod_tls::client_config(
                            &pod_tls::roots_from_compiled_set(),
                            context.provider().clone(),
                            context.groups().clone(),
                        )
                    })
                    .expect("a configuration over the compiled-in roots");
                TlsConnector::from(config)
            })
            .clone()
    }

    fn no_verify_connector(&self) -> TlsConnector {
        self.unverified
            .get_or_init(|| {
                let provider = self.tls.provider().clone();
                let config = ClientConfig::builder_with_provider(provider.clone())
                    .with_safe_default_protocol_versions()
                    .expect("the protocol versions of the provider")
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
                    .with_no_client_auth();
                TlsConnector::from(Arc::new(config))
            })
            .clone()
    }
}

#[derive(Debug)]
struct NoVerify(Arc<tokio_rustls::rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Convenience: the origin path for a service, used by logs.
pub fn origin_label(service: &Service) -> String {
    match service {
        Service::Unix(path) => format!("unix:{}", path.display()),
        Service::UnixTls(path) => format!("unix+tls:{}", path.display()),
        other => other.describe(),
    }
}

/// The addresses of a name of RFC 6761 for this host: `localhost` and
/// `*.localhost` (issue 119: a static build on a host with no /etc/hosts
/// did not resolve `localhost`).
pub fn local_name(host: &str) -> Option<Vec<std::net::IpAddr>> {
    let name = host.trim_end_matches('.').to_ascii_lowercase();
    (name == "localhost" || name.ends_with(".localhost"))
        .then(|| vec![std::net::IpAddr::from([127, 0, 0, 1]), std::net::IpAddr::from(std::net::Ipv6Addr::LOCALHOST)])
}

/// `HOST:PORT` or `[V6]:PORT`.
pub fn split_host_port(addr: &str) -> Option<(&str, u16)> {
    let (host, port) = addr.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Some((host, port.parse().ok()?))
}

/// Connect to an origin. `localhost` needs no resolver. The error says if
/// the name or the connection failed (issue 119: both were "connecting to
/// HOST:PORT"). An origin name does not go to DNS over HTTPS.
pub async fn connect_origin(host: &str, port: u16) -> Result<TcpStream> {
    let addrs: Vec<std::net::SocketAddr> = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => vec![(ip, port).into()],
        Err(_) => match local_name(host) {
            Some(ips) => ips.into_iter().map(|ip| (ip, port).into()).collect(),
            None => tokio::net::lookup_host((host, port))
                .await
                .io_fail(Stage::Dns, format!("resolving the origin {host}"))?
                .collect(),
        },
    };
    let mut last = None;
    for addr in &addrs {
        match TcpStream::connect(addr).await {
            Ok(tcp) => return Ok(tcp),
            Err(e) => {
                last =
                    Some(crate::fail::caused(Stage::Origin, Class::of_io(e.kind()), format!("connecting to {addr}"), e))
            }
        }
    }
    Err(last
        .unwrap_or_else(|| crate::fail::new(Stage::Dns, Class::NotFound, format!("the origin {host} has no address"))))
}

/// Parse `http(s)://host[:port]` into `(host, port, tls)`.
pub fn parse_http_url(url: &str) -> Result<(String, u16, bool)> {
    let (scheme, rest) =
        url.split_once("://").or_fail(Stage::Origin, Class::Config, "origin URL is missing a scheme")?;
    let tls = match scheme {
        "http" => false,
        "https" => true,
        other => bail!(Stage::Origin, Class::Config, "unsupported origin scheme {other:?}"),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        bail!(Stage::Origin, Class::Config, "origin URL has no host");
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, rest) =
            rest.split_once(']').or_fail(Stage::Origin, Class::Config, "origin URL has an unclosed IPv6 address")?;
        let port = match rest.strip_prefix(':') {
            Some(port) => port.parse().or_fail(Stage::Origin, Class::Config, "origin URL port is invalid")?,
            None if rest.is_empty() => {
                if tls {
                    443
                } else {
                    80
                }
            }
            None => bail!(Stage::Origin, Class::Config, "origin URL has trailing characters after the IPv6 address"),
        };
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if !port.contains(']') => {
                let port: u16 = port.parse().or_fail(Stage::Origin, Class::Config, "origin URL port is invalid")?;
                (host.to_string(), port)
            }
            _ => (authority.to_string(), if tls { 443 } else { 80 }),
        }
    };
    if host.is_empty() {
        bail!(Stage::Origin, Class::Config, "origin URL has no host");
    }
    Ok((host, port, tls))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The warning of an origin with no check of its certificate is an
    /// event for the user, not a line of the crate.
    #[test]
    fn an_unverified_origin_is_an_event() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let kept = seen.clone();
        let events = move |event: pod_core::Event| kept.lock().unwrap().push(event);
        let report = pod_core::Report { events: Arc::new(events), observer: Arc::new(pod_core::NoObserver) };
        let origins = Origins::new(crate::testing::tls()).with_report(report);
        assert!(origins.note_unverified("https://a.test.invalid:8443"));
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!((seen[0].level, seen[0].kind), (pod_core::Level::Warn, "origin.no_verify"));
        assert!(seen[0].text.contains("https://a.test.invalid:8443"), "{}", seen[0].text);
    }

    /// #248: the first dial of an origin with noTLSVerify warns; the next
    /// dials of it do not.
    #[test]
    fn an_unverified_origin_is_named_one_time() {
        let origins = Origins::new(crate::testing::tls());
        let note_unverified = |origin: &str| origins.note_unverified(origin);
        assert!(note_unverified("https://a.test.invalid:8443"));
        assert!(!note_unverified("https://a.test.invalid:8443"));
        assert!(note_unverified("https://b.test.invalid:8443"));
    }

    // Issue 119: localhost needs no resolver (a host with no /etc/hosts).
    #[test]
    fn localhost_is_a_local_name() {
        for name in ["localhost", "LOCALHOST.", "app.localhost"] {
            let ips = local_name(name).unwrap();
            assert_eq!(ips[0], std::net::IpAddr::from([127, 0, 0, 1]), "{name}");
        }
        assert!(local_name("example.com").is_none());
        assert!(local_name("localhost.example.com").is_none());
    }

    #[tokio::test]
    async fn an_origin_on_localhost_connects_and_a_refusal_names_the_address() {
        pod_testkit::need_loopback!();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(connect_origin("localhost", port).await.is_ok());
        drop(listener);
        let err = connect_origin("localhost", port).await.unwrap_err();
        assert!(format!("{err}").contains("connecting to "), "{err}");
        assert!(!format!("{err}").contains("resolving"), "{err}");
        let err = connect_origin("no-such-name.invalid", 80).await.unwrap_err();
        assert!(format!("{err}").contains("resolving the origin"), "{err}");
        assert_eq!(split_host_port("[::1]:8080"), Some(("::1", 8080)));
    }

    #[test]
    fn parses_urls() {
        assert_eq!(parse_http_url("http://127.0.0.1:8080").unwrap(), ("127.0.0.1".into(), 8080, false));
        assert_eq!(parse_http_url("https://example.com").unwrap(), ("example.com".into(), 443, true));
        assert_eq!(parse_http_url("http://example.com/x").unwrap(), ("example.com".into(), 80, false));
        assert_eq!(parse_http_url("https://[::1]:8443").unwrap(), ("::1".into(), 8443, true));
        assert!(parse_http_url("ftp://x").is_err());
        assert!(parse_http_url("http://").is_err());
    }
}
