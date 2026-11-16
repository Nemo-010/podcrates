//! The way out of a network lab (`Options::way_out`), with no network: a
//! stand-in proxy of "the host" on the loopback of the test, with a
//! made-up credential, and two servers behind it (plain text on port 80,
//! TLS of `way-out.test` on port 443, signed by a CA of the test). Each
//! case runs in a new start of this binary, with `https_proxy` and
//! `SSL_CERT_FILE` of the host set for it alone, so that no thread of the
//! test changes the environment (T-713).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};

use crate::way_out_payload::{NAME, REACHED, REFUSED, SECRET, USER};

/// The flag of a new start of this binary that runs one case.
pub const CASE: &str = "--way-out-case";

/// A P-256 key of the test, for rcgen.
struct Key(SigningKey, Vec<u8>);

impl Key {
    fn new() -> Key {
        let mut scalar = [0u8; 32];
        pod_hostprobe::sys::getrandom(&mut scalar).expect("random bytes");
        let k = SigningKey::from_slice(&scalar).expect("a P-256 scalar");
        let public = k.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        Key(k, public)
    }
}

impl rcgen::PublicKeyData for Key {
    fn der_bytes(&self) -> &[u8] {
        &self.1
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for Key {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let s: Signature = self.0.sign(message);
        Ok(s.to_der().as_bytes().to_vec())
    }
}

fn pem(der: &[u8]) -> String {
    use base64::Engine as _;
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = text.as_bytes().chunks(64).map(|l| std::str::from_utf8(l).unwrap()).collect();
    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"))
}

/// The CA of "the real network" as PEM, and the TLS configuration of the
/// server of [`NAME`] that it signs.
fn real_ca() -> (String, Arc<rustls::ServerConfig>) {
    let (ca_key, leaf_key) = (Key::new(), Key::new());
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name.push(rcgen::DnType::CommonName, "pod-lab test real CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&[1]));
    let ca = params.self_signed(&ca_key).expect("the CA");
    let mut leaf = rcgen::CertificateParams::new(vec![NAME.to_string()]).expect("a leaf");
    leaf.serial_number = Some(rcgen::SerialNumber::from_slice(&[2]));
    let issuer = rcgen::Issuer::from_params(&params, &ca_key);
    let leaf = leaf.signed_by(&leaf_key, &issuer).expect("the leaf");
    let pair = pod_tls::server::certified_key(vec![leaf.der().clone()], leaf_key.0.clone()).expect("a pair");
    let config = pod_tls::server::server_config_for(
        Arc::new(pod_tls::crypto::provider()),
        pod_tls::server::Served::new(Some(pair)),
        &[],
    )
    .expect("a server");
    (pem(ca.der()), config)
}

/// Answer one request on `s` with [`REACHED`].
fn reached(s: &mut (impl Read + Write)) {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && matches!(s.read(&mut b), Ok(1)) {
        head.push(b[0]);
    }
    let text = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{REACHED}", REACHED.len());
    let _ = s.write_all(text.as_bytes());
    let _ = s.flush();
}

fn serve(l: TcpListener, tls: Option<Arc<rustls::ServerConfig>>) {
    std::thread::spawn(move || {
        for tcp in l.incoming().flatten() {
            let tls = tls.clone();
            std::thread::spawn(move || match tls {
                None => reached(&mut { tcp }),
                Some(config) => {
                    let Ok(conn) = rustls::ServerConnection::new(config) else { return };
                    let mut s = rustls::StreamOwned::new(conn, tcp);
                    reached(&mut s);
                    s.conn.send_close_notify();
                    let _ = s.flush();
                }
            });
        }
    });
}

/// The stand-in proxy of the host: 407 with no credential or another one,
/// 403 for [`REFUSED`], else a splice to the server of the port.
fn upstream(plain: u16, tls: u16) -> u16 {
    use base64::Engine as _;
    let l = TcpListener::bind("127.0.0.1:0").expect("the proxy of the host");
    let port = l.local_addr().expect("its port").port();
    let want = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{USER}:{SECRET}")));
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && matches!(s.read(&mut b), Ok(1)) {
                head.push(b[0]);
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let line = head.lines().next().unwrap_or("").to_string();
            let auth = head
                .lines()
                .any(|l| l.to_ascii_lowercase() == format!("proxy-authorization: {}", want.to_ascii_lowercase()));
            let to = match line.split(' ').nth(1).unwrap_or("") {
                t if t.starts_with(REFUSED) => None,
                t if t.ends_with(":443") => Some(tls),
                _ => Some(plain),
            };
            let answer: &[u8] = match (auth, to) {
                (false, _) => b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
                (true, None) => b"HTTP/1.1 403 Forbidden\r\n\r\n",
                (true, Some(_)) => b"HTTP/1.1 200 Connection established\r\n\r\n",
            };
            let _ = s.write_all(answer);
            if let (true, Some(p)) = (auth, to)
                && let Ok(t) = TcpStream::connect(("127.0.0.1", p))
            {
                std::thread::spawn(move || splice(s, t));
            }
        }
    });
    port
}

/// Copy each way; at the end of one way, shut the write side of the other.
fn splice(a: TcpStream, b: TcpStream) {
    let (mut a2, mut b2) = (a.try_clone().unwrap(), b.try_clone().unwrap());
    let one = std::thread::spawn(move || {
        let _ = std::io::copy(&mut a2, &mut b2);
        let _ = b2.shutdown(std::net::Shutdown::Write);
    });
    let (mut from, mut to) = (b, a);
    let _ = std::io::copy(&mut from, &mut to);
    let _ = to.shutdown(std::net::Shutdown::Write);
    let _ = one.join();
}

/// The variables of a proxy that a new start of the binary must not get
/// from the test: the proxy of the host is the one of the case alone.
const PROXY_VARIABLES: &[&str] =
    &["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "http_proxy", "HTTP_PROXY", "no_proxy", "NO_PROXY"];

/// Run the payload `kind` in a lab of `profile` with a way out, in a new
/// start of this binary whose host has the proxy of the test.
fn case(profile: &str, kind: &str, line: &str, proxy: u16, roots: &std::path::Path) {
    if !crate::net::userns_here(profile) {
        return;
    }
    let mut c = std::process::Command::new("/proc/self/exe");
    c.args([CASE, profile, kind]);
    for v in PROXY_VARIABLES {
        c.env_remove(v);
    }
    c.env("https_proxy", format!("http://{USER}:{SECRET}@127.0.0.1:{proxy}/"));
    c.env("SSL_CERT_FILE", roots);
    let out = c.output().expect("a new start of the test");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{profile} with a way out: {text}{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(text.trim(), line, "{profile} with a way out");
    println!("{profile} with a way out: ok");
}

/// The work of a new start of this binary ([`CASE`]): the run of one lab
/// with a way out. It does not return.
pub fn one(profile: &str, kind: &str) -> ! {
    let settings = crate::cases::settings();
    let p = pod_lab::find(settings.profiles, profile).expect("a profile");
    let (mut r, w) = std::io::pipe().expect("a pipe");
    let opts = pod_lab::Options { stdout: Some(w.into()), way_out: true, ..pod_lab::Options::default() };
    let out = pod_lab::run(&settings, p, &crate::cases::payload(kind), opts);
    let mut text = String::new();
    r.read_to_string(&mut text).expect("the output of the payload");
    let code = crate::cases::ran(profile, out, &text);
    print!("{text}");
    std::process::exit(code)
}

pub fn all() {
    let (ca, config) = real_ca();
    let roots = std::env::temp_dir().join(format!("pod-lab-way-out-{}.pem", std::process::id()));
    std::fs::write(&roots, ca).expect("the roots of the host");
    let plain = TcpListener::bind("127.0.0.1:0").expect("a plain server");
    let tls = TcpListener::bind("127.0.0.1:0").expect("a TLS server");
    let proxy = upstream(plain.local_addr().unwrap().port(), tls.local_addr().unwrap().port());
    serve(plain, None);
    serve(tls, Some(config));
    case(
        "proxy-only",
        "out-proxy-only",
        "out 200 and reached, port 22 403, refused 502, no direct route, no credential in the lab",
        proxy,
        &roots,
    );
    case(
        "proxy-per-name",
        "out-per-name",
        "out 200 and reached, other.test 504, a literal gets a reset",
        proxy,
        &roots,
    );
    case("proxy-tls-reterminate", "out-reterminate", "out by the proxy CA and reached, port 22 silent", proxy, &roots);
    case("ws-upgrade-refused", "out-ws", "out get reached, upgrade 403", proxy, &roots);
    let _ = std::fs::remove_file(&roots);
}
