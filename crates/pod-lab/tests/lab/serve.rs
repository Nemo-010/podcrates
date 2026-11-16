//! The served ports of a network lab (`Options::serve`): the payload runs a
//! server on the loopback of the lab and reaches it only by the path of
//! its class, with the rules of the class on the bytes.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::cases::{payload, ran, settings};
use crate::serve_payload::{CA_FILE, KEY_FILE, LEAF_FILE};
use crate::way_out::{Key, pem};

/// The served port of `proxy-only`: a port of its list.
const OPEN_PORT: u16 = 8443;
/// The served port of the other classes.
const PORT: u16 = 9443;

/// Run the payload `kind` in the lab `name` with the served ports `serve`
/// and the roots `ca`; check its first line.
fn case(name: &str, kind: &str, serve: Vec<u16>, ca: Option<PathBuf>, line: &str) {
    if !crate::net::userns_here(name) {
        return;
    }
    let s = settings();
    let profile = pod_lab::find(s.profiles, name).expect("a profile");
    let (mut r, w) = std::io::pipe().expect("a pipe");
    let opts = pod_lab::Options { stdout: Some(w.into()), serve, serve_ca: ca, ..pod_lab::Options::default() };
    let out = pod_lab::run(&s, profile, &payload(kind), opts);
    let mut text = String::new();
    r.read_to_string(&mut text).expect("the output of the payload");
    if crate::filter::refused_here(name, &out) {
        return;
    }
    assert_eq!(ran(name, out, &text), 0, "{name} with a served port: {text}");
    assert_eq!(text.lines().next(), Some(line), "{name} with a served port: {text}");
    println!("{name} with a served port: ok");
}

/// The CA of the command and the leaf of `listed.test` that it signs, as
/// files of `dir`.
fn command_ca(dir: &Path) {
    let (ca_key, leaf_key) = (Key::new(), Key::new());
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name.push(rcgen::DnType::CommonName, "pod-lab test command CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&[3]));
    let ca = params.self_signed(&ca_key).expect("the CA");
    let mut leaf = rcgen::CertificateParams::new(vec![pod_lab::net::LISTED.to_string()]).expect("a leaf");
    leaf.serial_number = Some(rcgen::SerialNumber::from_slice(&[4]));
    let issuer = rcgen::Issuer::from_params(&params, &ca_key);
    let leaf = leaf.signed_by(&leaf_key, &issuer).expect("the leaf");
    std::fs::write(dir.join(CA_FILE), pem(ca.der())).expect("the CA file");
    std::fs::write(dir.join(LEAF_FILE), leaf.der()).expect("the leaf file");
    std::fs::write(dir.join(KEY_FILE), leaf_key.0.to_bytes().as_slice()).expect("the key file");
}

pub fn all() {
    case(
        "proxy-only",
        &format!("serve-open:{OPEN_PORT}"),
        vec![OPEN_PORT],
        None,
        "127.0.0.1 and listed.test reach the command, 407 with no credential, port 80 the stand-in",
    );
    case(
        "proxy-tls-reterminate",
        &format!("serve-noca:{PORT}"),
        vec![PORT],
        None,
        "listed.test 502 with no roots, other.test reaches the command",
    );
    case(
        "sni-allowlist",
        &format!("serve-sni:{PORT}"),
        vec![PORT],
        None,
        "listed.test reaches the command, other.test reset, no name reset",
    );
    let dir = std::env::temp_dir().join(format!("pod-lab-serve-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the directory of the case");
    command_ca(&dir);
    case(
        "ws-upgrade-refused",
        &format!("serve-tls:{PORT}:{}", dir.display()),
        vec![PORT],
        Some(dir.join(CA_FILE)),
        "listed.test by the proxy CA, get served by the command, upgrade 403, other.test by the CA of the command",
    );
    let _ = std::fs::remove_dir_all(&dir);
}
