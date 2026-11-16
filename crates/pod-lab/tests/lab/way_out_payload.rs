//! The payloads of the way out: this binary with `--payload KIND` inside a
//! network lab with a way out. Each reads the lab as a program does
//! (`HTTPS_PROXY`, `SSL_CERT_FILE`), reaches the servers of the test past
//! the lab, and checks that the rules of the class still hold and that no
//! credential of the host is in the lab.

use std::io::{ErrorKind, Read, Write};
use std::time::Duration;

use crate::net_payload::{connect, issuer, tls, via};

/// The name of "the real network": no name of the lab.
pub const NAME: &str = "way-out.test";
/// A name that the proxy of the host refuses.
pub const REFUSED: &str = "refused.test";
/// The user and the password of the proxy of the host: made-up values of
/// the test (`.github/secrets-allow.txt`).
pub const USER: &str = "upstream-user";
pub const SECRET: &str = "made-up-upstream-secret";
/// The body of each server past the lab.
pub const REACHED: &str = "way out reached\n";

type Out = Result<String, String>;

pub fn main(kind: &str) -> Option<Out> {
    Some(match kind {
        "out-proxy-only" => proxy_only(),
        "out-per-name" => per_name(),
        "out-reterminate" => reterminate(),
        "out-ws" => ws(),
        _ => return crate::serve_payload::main(kind),
    })
}

/// A `GET` on `s`: the status and the body.
fn get(s: &mut (impl Read + Write), extra: &str) -> Result<(u16, String), String> {
    s.write_all(format!("GET / HTTP/1.1\r\nHost: {NAME}\r\n{extra}\r\n").as_bytes()).map_err(|e| e.to_string())?;
    let mut text = Vec::new();
    match s.read_to_end(&mut text) {
        Ok(_) => {}
        // A server that ends TLS with no close_notify: the bytes are whole.
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => {}
        Err(e) => return Err(format!("the answer: {e}")),
    }
    let text = String::from_utf8_lossy(&text).into_owned();
    let code = text.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    Ok((code, body))
}

/// A `CONNECT` to `NAME:80` with the credential of the lab, and a plain
/// `GET` past it.
fn out_plain() -> Result<(), String> {
    let (c, mut s) = via(&format!("{NAME}:80"), true)?;
    let (code, body) = get(&mut s, "")?;
    if (c, code, body.as_str()) != (200, 200, REACHED) {
        return Err(format!("the way out: CONNECT {c}, GET {code} {body:?}"));
    }
    Ok(())
}

/// The processes of the lab that serve and never run the command: the
/// stand-ins and the way out, whose arguments are the ones of the lab.
fn lab_processes() -> Vec<String> {
    let mut out = Vec::new();
    for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let pid = e.file_name().to_string_lossy().into_owned();
        if !pid.bytes().all(|b| b.is_ascii_digit()) || pid == std::process::id().to_string() {
            continue;
        }
        if let Ok(cmd) = std::fs::read(format!("/proc/{pid}/cmdline"))
            && String::from_utf8_lossy(&cmd).contains("--podlab-lab")
        {
            out.push(pid);
        }
    }
    out
}

/// No credential of the host in the environment of the command, nor in the
/// arguments of a process of the lab; a process of the lab hides its
/// environment from a command that is not root.
fn no_credential() -> Result<(), String> {
    if let Some((k, _)) = std::env::vars().find(|(_, v)| v.contains(SECRET)) {
        return Err(format!("the variable {k} of the command holds the credential of the host"));
    }
    let procs = lab_processes();
    if procs.len() < 2 {
        return Err(format!("{} processes of the lab; the lab wants a stand-in and a way out", procs.len()));
    }
    let root = pod_testkit::nobody::is_root();
    for pid in procs {
        let cmd = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        if String::from_utf8_lossy(&cmd).contains(SECRET) {
            return Err(format!("the arguments of process {pid} hold the credential"));
        }
        // Root reads each process: the lab hides nothing from it.
        match std::fs::read(format!("/proc/{pid}/environ")) {
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Ok(_) if root => {}
            r => return Err(format!("the environment of process {pid}: {:?}", r.map(|b| b.len()))),
        }
    }
    Ok(())
}

fn proxy_only() -> Out {
    out_plain()?;
    let (port22, _) = via(&format!("{NAME}:22"), true)?;
    let (refused, _) = via(&format!("{REFUSED}:80"), true)?;
    if (port22, refused) != (403, 502) {
        return Err(format!("port 22 {port22}, a name that the host refuses {refused}"));
    }
    match connect("192.0.2.1:443") {
        Err(e) if e.raw_os_error() == Some(101) => {}
        r => return Err(format!("a direct connect: {r:?}; the lab wants ENETUNREACH")),
    }
    no_credential()?;
    Ok("out 200 and reached, port 22 403, refused 502, no direct route, no credential in the lab".to_string())
}

fn per_name() -> Out {
    out_plain()?;
    let (other, _) = via("other.test:443", true)?;
    let literal = match via("203.0.113.9:443", true) {
        Ok((c, _)) => format!("{c}"),
        Err(_) => "a reset".to_string(),
    };
    Ok(format!("out 200 and reached, other.test {other}, a literal gets {literal}"))
}

fn reterminate() -> Out {
    let (c, tcp) = via(&format!("{NAME}:443"), true)?;
    if c != 200 {
        return Err(format!("CONNECT {NAME}: {c}"));
    }
    let mut s = tls(tcp, NAME, true).map_err(|e| format!("TLS to {NAME}: {e}"))?;
    let by = issuer(&s);
    let (code, body) = get(&mut s, "")?;
    if (code, body.as_str()) != (200, REACHED) {
        return Err(format!("GET {code} {body:?}"));
    }
    let (c, mut s) = via(&format!("{NAME}:22"), true)?;
    s.write_all(b"SSH-2.0-payload\r\n").map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_millis(500))).map_err(|e| e.to_string())?;
    let silent =
        matches!(s.read(&mut [0u8; 8]), Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut));
    if c != 200 || !silent {
        return Err(format!("port 22: {c}, silent {silent}"));
    }
    Ok(format!("out by the {by} CA and reached, port 22 silent"))
}

fn ws() -> Out {
    let upgrade = "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: cGF5bG9hZCBvZiBwb2QtbGFi\r\n";
    let mut got = Vec::new();
    for extra in ["", upgrade] {
        let (c, tcp) = via(&format!("{NAME}:443"), true)?;
        if c != 200 {
            return Err(format!("CONNECT: {c}"));
        }
        let mut s = tls(tcp, NAME, true).map_err(|e| format!("TLS: {e}"))?;
        got.push(get(&mut s, extra)?);
    }
    if got[0] != (200, REACHED.to_string()) {
        return Err(format!("a plain GET: {:?}", got[0]));
    }
    Ok(format!("out get reached, upgrade {}", got[1].0))
}
