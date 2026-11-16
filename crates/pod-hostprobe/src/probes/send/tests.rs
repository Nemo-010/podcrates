//! The parts of the rows that send a packet out, with no process variable:
//! the text of the setting, the URL of a proxy, a `CONNECT` against a
//! listener on the loopback, and the bytes of a handshake.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use super::hello::{self, End};
use super::*;

fn network() -> Network {
    Network {
        name: "example.org".into(),
        port: 443,
        other: Some("other.example".into()),
        closed_port: 22,
        literal: Some("192.0.2.7".parse().unwrap()),
        wait_ms: 1500,
    }
}

#[test]
fn the_setting_crosses_the_variable() {
    let n = network();
    let text = encode(&n).expect("a plain setting");
    assert_eq!(decode(&text), Some(n));
    let bare = Network::new("example.org", 8443);
    assert_eq!(decode(&encode(&bare).unwrap()), Some(bare));
    let v6 = Network { literal: Some("2001:db8::1".parse().unwrap()), ..network() };
    assert_eq!(decode(&encode(&v6).unwrap()), Some(v6));
}

#[test]
fn a_name_that_breaks_the_variable_is_refused() {
    for bad in ["", "a b", "a;port=1", "a=b", "x\u{7f}"] {
        assert_eq!(encode(&Network::new(bad, 443)), None, "{bad:?}");
    }
    assert_eq!(encode(&Network { other: Some("a;b".into()), ..network() }), None);
    assert_eq!(decode("name=a;port=x;other=;closed=22;literal=;wait=1"), None);
    assert_eq!(decode("port=1;other=;closed=22;literal=;wait=1"), None);
}

#[test]
fn the_url_of_a_proxy() {
    let p = proxy_url("HTTPS_PROXY", "http://user:p%40ss@proxy.example:3128/").unwrap();
    assert_eq!((p.host.as_str(), p.port), ("proxy.example", 3128));
    assert_eq!(p.auth.as_deref(), Some(format!("Basic {}", hello::base64(b"user:p@ss")).as_str()));
    let p = proxy_url("https_proxy", "10.0.0.1").unwrap();
    assert_eq!((p.host.as_str(), p.port, p.auth), ("10.0.0.1", 1080, None));
    let p = proxy_url("ALL_PROXY", "HTTP://[2001:db8::2]:8080").unwrap();
    assert_eq!((p.host.as_str(), p.port), ("2001:db8::2", 8080));
}

#[test]
fn a_reason_of_a_url_names_the_variable_alone() {
    for (value, word) in [
        ("socks5://secret:pw@proxy.example:1080", "not http"),
        ("http://secret@[2001:db8::2:8080", "no ']'"),
        ("http://secret@proxy.example:port", "not a number"),
        ("http://secret@:8080", "no host"),
    ] {
        let why = proxy_url("HTTPS_PROXY", value).unwrap_err();
        assert!(why.starts_with("HTTPS_PROXY ") && why.contains(word), "{value}: {why}");
        assert!(!why.contains("secret") && !why.contains("proxy.example"), "{value}: {why}");
    }
}

#[test]
fn the_target_of_a_connect() {
    assert_eq!(authority("example.org", 443), "example.org:443");
    assert_eq!(authority("2001:db8::1", 443), "[2001:db8::1]:443");
}

/// A proxy on the loopback that reads one head, gives it back through the
/// channel and writes `answer`.
fn one_proxy(answer: &'static [u8]) -> (ProxyUrl, std::sync::mpsc::Receiver<String>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("a listener on the loopback");
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && s.read(&mut b).unwrap_or(0) == 1 {
            head.push(b[0]);
        }
        let _ = tx.send(String::from_utf8_lossy(&head).into_owned());
        let _ = s.write_all(answer);
        std::thread::sleep(Duration::from_millis(300));
    });
    (ProxyUrl { host: "127.0.0.1".into(), port, auth: Some("Basic dTpw".into()) }, rx)
}

#[test]
fn a_connect_sends_the_credential_only_when_asked() {
    pod_testkit::need_loopback!();
    let wait = Duration::from_secs(5);
    let (p, rx) = one_proxy(b"HTTP/1.1 200 Connection established\r\n\r\n");
    let got = connect(&p, "example.org:443", true, wait).expect("a connect");
    assert!(matches!(got, Got::Status(200, _)));
    let head = rx.recv().unwrap();
    assert!(head.starts_with("CONNECT example.org:443 HTTP/1.1\r\n"), "{head}");
    assert!(head.contains("Proxy-Authorization: Basic dTpw\r\n"), "{head}");

    let (p, rx) = one_proxy(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
    assert!(matches!(connect(&p, "example.org:443", false, wait), Ok(Got::Status(407, _))));
    assert!(!rx.recv().unwrap().contains("Proxy-Authorization"));
}

#[test]
fn a_connect_with_no_status_names_its_end() {
    pod_testkit::need_loopback!();
    let wait = Duration::from_secs(5);
    let (p, _rx) = one_proxy(b"");
    assert!(matches!(connect(&p, "example.org:22", true, wait), Ok(Got::End(End::Closed))));
    let (p, _rx) = one_proxy(b"SSH-2.0-x\r\n\r\n");
    assert!(matches!(connect(&p, "example.org:22", true, wait), Ok(Got::End(End::Garbled))));
}

#[test]
fn a_refused_connect_is_a_denial_that_names_no_host() {
    pod_testkit::need_loopback!();
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let o = dial("127.0.0.1", port, Duration::from_secs(2), "the proxy").unwrap_err();
    assert_eq!(o.verdict, crate::verdict::Verdict::Denied, "{o:?}");
    assert!(o.reason.contains("the proxy") && !o.reason.contains("127.0.0.1"), "{}", o.reason);
}

#[test]
fn the_client_hello_is_one_record_with_the_name() {
    let r = hello::client_hello(Some("example.org"), [7; 32]);
    assert_eq!(&r[..3], &[0x16, 3, 1]);
    assert_eq!(usize::from(u16::from_be_bytes([r[3], r[4]])), r.len() - 5);
    assert_eq!(r[5], 1, "a ClientHello");
    assert!(r.windows(11).any(|w| w == b"example.org"));
    let bare = hello::client_hello(None, [7; 32]);
    assert!(!bare.windows(11).any(|w| w == b"example.org"));
    assert_eq!(r.len() - bare.len(), 4 + 2 + 3 + 11, "the server_name extension alone");
}

/// A DER item of `tag` with `body`.
fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 0x80 {
        out.push(body.len() as u8);
    } else {
        out.extend_from_slice(&[0x82, (body.len() >> 8) as u8, body.len() as u8]);
    }
    out.extend_from_slice(body);
    out
}

/// A certificate with the fields that the reader walks: version, serial,
/// algorithm, issuer, validity, subject.
fn cert(issuer: &str, subject: &str) -> Vec<u8> {
    let name = |n: &str| der(0x30, &der(0x0c, n.as_bytes()));
    let mut tbs = der(0xa0, &der(0x02, &[2]));
    tbs.extend(der(0x02, &[1]));
    tbs.extend(der(0x30, &der(0x06, &[0x2a])));
    tbs.extend(name(issuer));
    tbs.extend(der(0x30, &[]));
    tbs.extend(name(subject));
    let mut body = der(0x30, &tbs);
    body.extend(der(0x30, &der(0x06, &[0x2a])));
    body.extend(der(0x03, &[0]));
    der(0x30, &body)
}

/// The records of a server: a ServerHello and a Certificate with `chain`,
/// in records of at most `cut` bytes.
fn records(chain: &[Vec<u8>], cut: usize) -> Vec<u8> {
    let mut hs = vec![2, 0, 0, 2, 3, 3];
    let mut list = Vec::new();
    for c in chain {
        list.extend_from_slice(&(c.len() as u32).to_be_bytes()[1..]);
        list.extend_from_slice(c);
    }
    let mut body = (list.len() as u32).to_be_bytes()[1..].to_vec();
    body.extend(list);
    hs.push(11);
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend(body);
    let mut out = Vec::new();
    for part in hs.chunks(cut) {
        out.extend_from_slice(&[0x16, 3, 3]);
        out.extend_from_slice(&(part.len() as u16).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

#[test]
fn the_chain_of_the_server_across_records() {
    let chain = vec![cert("CA one", "example.org"), cert("Root", "CA one")];
    for cut in [7, 64, 4096] {
        let got = hello::server_certificates(&mut records(&chain, cut).as_slice()).expect("the chain");
        assert_eq!(got, chain, "records of {cut} bytes");
    }
    let alert = [0x15, 3, 3, 0, 2, 2, 40];
    assert_eq!(hello::server_certificates(&mut alert.as_slice()), Err(End::Alert(40)));
    assert_eq!(hello::server_certificates(&mut &b"HTTP/1.1 400"[..]), Err(End::Garbled));
    assert_eq!(hello::server_certificates(&mut &[0x16, 3, 3][..]), Err(End::Closed));
}

#[test]
fn the_certificate_of_the_file_that_issued_the_chain() {
    let leaf = cert("CA one", "example.org");
    let (ca_one, ca_two) = (cert("Root", "CA one"), cert("Root", "CA two"));
    let pem = |certs: &[&Vec<u8>]| {
        let mut text = String::from("junk\n");
        for c in certs {
            text.push_str(&format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", hello::base64(c)));
        }
        text.into_bytes()
    };
    let file = hello::pem_certificates(&pem(&[&ca_two, &ca_one]));
    assert_eq!(file, vec![ca_two.clone(), ca_one.clone()]);
    assert_eq!(hello::issuer_in(std::slice::from_ref(&leaf), &file), Some(2));
    assert_eq!(hello::issuer_in(std::slice::from_ref(&leaf), &hello::pem_certificates(&pem(&[&ca_two]))), None);
    assert_eq!(hello::issuer_subject(&leaf).map(|(i, _)| i.len()), Some(2 + 2 + 6));
}

#[test]
fn base64_as_basic_takes_it() {
    for (raw, text) in [(&b""[..], ""), (b"f", "Zg=="), (b"fo", "Zm8="), (b"foo", "Zm9v"), (b"u:p@ss", "dTpwQHNz")] {
        assert_eq!(hello::base64(raw), text);
    }
}

#[test]
fn the_end_of_a_read_error() {
    use std::io::{Error, ErrorKind};
    assert_eq!(End::of(&Error::from(ErrorKind::ConnectionReset)), End::Reset);
    assert_eq!(End::of(&Error::from(ErrorKind::WouldBlock)), End::Silent);
    assert_eq!(End::Alert(112).word(), "alert-112");
}
