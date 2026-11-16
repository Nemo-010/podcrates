use std::io::{Read, Write};
use std::net::TcpListener;

use super::{Upstream, certificate_blocks, dial, host_pem_from, proxy_of};
use crate::net::is_lab_name;

/// A made-up credential of the tests (`.github/secrets-allow.txt`).
const USER: &str = "upstream-user";
const PASSWORD: &str = "made-up-upstream-secret";

#[test]
fn a_proxy_url_gives_its_host_its_port_and_its_credential() {
    use base64::Engine as _;
    let basic = |pair: &str| Some(format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(pair)));
    let got = proxy_of("HTTPS_PROXY", &format!("http://{USER}:{PASSWORD}@127.0.0.1:3129/")).unwrap();
    let want = Upstream::Proxy { host: "127.0.0.1".into(), port: 3129, auth: basic(&format!("{USER}:{PASSWORD}")) };
    assert_eq!(got, want);
    // A %XX of the user and a host of IPv6 with no port: curl's 1080.
    let got = proxy_of("https_proxy", "a%40b:c%3Ad@[::1]").unwrap();
    assert_eq!(got, Upstream::Proxy { host: "::1".into(), port: 1080, auth: basic("a@b:c:d") });
    let got = proxy_of("ALL_PROXY", "proxy.test:8080").unwrap();
    assert_eq!(got, Upstream::Proxy { host: "proxy.test".into(), port: 8080, auth: None });
    // A reason names the variable alone.
    let why = proxy_of("HTTPS_PROXY", &format!("https://{USER}:{PASSWORD}@proxy.test")).unwrap_err();
    assert!(why.contains("HTTPS_PROXY") && !why.contains(PASSWORD) && !why.contains("proxy.test"), "{why}");
    let why = proxy_of("HTTPS_PROXY", &format!("http://{USER}:{PASSWORD}@proxy.test:x")).unwrap_err();
    assert!(!why.contains(PASSWORD) && !why.contains("proxy.test"), "{why}");
}

#[test]
fn the_names_of_the_lab_stay_in_the_lab() {
    for name in [
        "listed.test",
        "other.test",
        "localhost",
        "a.localhost",
        "127.0.0.1",
        "192.0.2.9",
        "::1",
        "fd00:6c61:62::1",
        "::ffff:127.0.0.1",
        "0.0.0.0",
    ] {
        assert!(is_lab_name(name), "{name}");
    }
    for name in ["relay.example", "192.0.3.1", "10.0.0.1", "2001:db8::1", "listed.test.example"] {
        assert!(!is_lab_name(name), "{name}");
    }
}

/// A server on the loopback that answers each line with `got LINE`.
fn echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut b = [0u8; 64];
            let n = s.read(&mut b).unwrap_or(0);
            let _ = s.write_all(format!("got {}", String::from_utf8_lossy(&b[..n])).as_bytes());
        }
    });
    port
}

/// A stand-in proxy of the host on the loopback: 407 with no credential or
/// another one, else a `CONNECT` to `127.0.0.1:PORT` of the target port.
fn upstream_proxy() -> u16 {
    use base64::Engine as _;
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let want = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{USER}:{PASSWORD}")));
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let Ok(head) = crate::net::wire::read_head(&mut s) else { continue };
            if crate::net::wire::header(&head, "proxy-authorization") != Some(want.as_str()) {
                let _ = s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
                continue;
            }
            let to = crate::net::wire::first_line(&head).1.rsplit_once(':').map(|(_, p)| p.to_string());
            match to.and_then(|p| std::net::TcpStream::connect(("127.0.0.1", p.parse::<u16>().ok()?)).ok()) {
                Some(t) => {
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
                    std::thread::spawn(move || super::super::relay::splice(s, t));
                }
                None => {
                    let _ = s.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                }
            }
        }
    });
    port
}

fn say(mut s: std::net::TcpStream) -> String {
    s.write_all(b"hello").unwrap();
    let mut got = String::new();
    s.read_to_string(&mut got).unwrap();
    got
}

#[test]
fn a_dial_goes_direct_or_through_the_proxy_of_the_host_with_its_credential() {
    let server = echo();
    // A direct dial refuses the loopback of the host (below); the dial
    // under it reaches the server.
    assert_eq!(say(super::connect("127.0.0.1", server).unwrap()), "got hello");
    let at = upstream_proxy();
    let via = |auth| {
        let url = match auth {
            Some(p) => format!("http://{USER}:{p}@127.0.0.1:{at}"),
            None => format!("http://127.0.0.1:{at}"),
        };
        proxy_of("HTTPS_PROXY", &url).unwrap()
    };
    assert_eq!(say(dial(&via(Some(PASSWORD)), "way-out.test", server).unwrap()), "got hello");
    let why = dial(&via(None), "way-out.test", server).unwrap_err();
    assert_eq!(why, "the proxy of the host answered 407");
    let why = dial(&via(Some(PASSWORD)), "way-out.test", 1).unwrap_err();
    assert_eq!(why, "the proxy of the host answered 502");
}

/// A direct way out does not reach the host itself: a name that the
/// resolver of the host gives a loopback address is refused, as a literal
/// of the loopback is.
#[test]
fn a_direct_way_out_does_not_dial_the_loopback_of_the_host() {
    let l = TcpListener::bind("127.0.0.1:0").expect("a listener on the loopback");
    let port = l.local_addr().unwrap().port();
    for host in ["localhost", "127.0.0.1"] {
        let why = dial(&Upstream::Direct, host, port).expect_err("no dial of the host");
        assert!(why.contains("an address of this host"), "{host}: {why}");
    }
}

/// The certificate blocks of a PEM text, each whole; other text and a block
/// with no end are left out.
#[test]
fn the_certificate_blocks_of_a_pem_text() {
    let one = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
    let two = "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----";
    let text = format!(
        "# a bundle\n{one}\n-----BEGIN PRIVATE KEY-----\nKKKK\n-----END PRIVATE KEY-----\n{two}\n-----BEGIN CERTIFICATE-----\nCCCC"
    );
    assert_eq!(certificate_blocks(&text), format!("{one}\n{two}\n"));
    assert_eq!(super::certificate_blocks("no certificate"), "");
}

/// An `SSL_CERT_FILE` that does not read, or that holds no certificate, is
/// an error that names it; with none, the first system bundle that holds a
/// certificate gives its blocks; with no bundle, the built-in roots, each a
/// whole PEM block of a DER of `webpki-root-certs`.
#[test]
fn the_certificate_file_of_a_way_out_takes_the_file_a_bundle_or_the_built_in_roots() {
    use base64::Engine as _;
    let dir = std::env::temp_dir().join(format!("pod-lab-host-pem-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (missing, empty, bundle) = (dir.join("missing.pem"), dir.join("empty.pem"), dir.join("bundle.pem"));
    std::fs::write(&empty, "# no certificate\n").unwrap();
    let block = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    std::fs::write(&bundle, format!("# a bundle\n{block}")).unwrap();
    let e = host_pem_from(Some(&missing), &[]).unwrap_err();
    assert!(e.starts_with(&format!("SSL_CERT_FILE names {}, which does not read: ", missing.display())), "{e}");
    let e = host_pem_from(Some(&empty), std::slice::from_ref(&bundle)).unwrap_err();
    assert_eq!(e, format!("SSL_CERT_FILE names {}, which holds no certificate", empty.display()));
    assert_eq!(host_pem_from(Some(&bundle), &[]).unwrap(), block);
    let system = [missing.clone(), empty.clone(), bundle.clone()];
    assert_eq!(host_pem_from(None, &system).unwrap(), block);
    let built_in = host_pem_from(None, &[missing, empty]).unwrap();
    let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS;
    assert!(roots.len() > 100, "{}", roots.len());
    assert_eq!(built_in.matches("-----BEGIN CERTIFICATE-----").count(), roots.len());
    let first = certificate_blocks(&built_in);
    let body: String = first.lines().skip(1).take_while(|l| !l.starts_with("-----END")).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(body).unwrap();
    assert_eq!(der.as_slice(), roots[0].as_ref(), "the first block is the first root");
    let _ = std::fs::remove_dir_all(&dir);
}
