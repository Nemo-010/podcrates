//! The way out of a network lab (`Options::way_out`). The lab process
//! starts it before it enters the network namespace: a process of the
//! network of the host that dials the real network for the stand-in proxy,
//! directly or through the proxy of the host (`https_proxy`, `HTTPS_PROXY`,
//! `all_proxy`, `ALL_PROXY`, the order of curl), with its credential. The
//! stand-in proxy asks for each `CONNECT` that the rules of its class pass
//! ([`WayOut::ask`]) on a socket pair; the way out answers with the
//! descriptor of the connected stream (`pass`). The rules of the class stay
//! in the stand-in proxy, and the credential of the host stays in the
//! process of the way out: the command and the arguments of the lab never
//! hold it.

use std::net::{TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

use pod_hostprobe::probes::PROXY_VARIABLES;
use pod_hostprobe::sys as k;

use super::pass;
use super::wire::{read_head, status};
use crate::hold::words;

/// The time limit of a dial, and of the answer of the proxy of the host.
const DIAL: Duration = Duration::from_secs(15);
/// The time that the stand-in waits for the answer of the way out.
const ANSWER: Duration = Duration::from_secs(40);
/// The port of an HTTP proxy with no port in its URL, as curl takes it.
const PROXY_DEFAULT_PORT: u16 = 1080;

/// The way out of a running lab: the stand-in end of the socket pair, and
/// the roots of the host where the proxy of the class terminates TLS.
pub struct WayOut {
    ctl: OwnedFd,
    /// The roots of the host (its `SSL_CERT_FILE`, else its system bundle
    /// and the roots compiled in): the stand-in checks the real server with
    /// them, then shows the command a leaf of the CA of the lab.
    pub roots: Option<Arc<rustls::RootCertStore>>,
}

/// Where the way out dials.
#[derive(Debug, PartialEq, Eq)]
pub enum Upstream {
    /// A TCP connect to the target.
    Direct,
    /// A `CONNECT` through the proxy of the host at `host:port`, with the
    /// value of `Proxy-Authorization` where its URL has a credential.
    Proxy { host: String, port: u16, auth: Option<String> },
}

/// The bytes of a `%XX` text.
fn unescape(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if b[i] == b'%'
            && let (Some(h), Some(l)) = (b.get(i + 1).and_then(|c| hex(*c)), b.get(i + 2).and_then(|c| hex(*c)))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The proxy of the URL `value` of the variable `name`. A reason names the
/// variable alone: never the host or the credential.
pub fn proxy_of(name: &str, value: &str) -> Result<Upstream, String> {
    use base64::Engine as _;
    let rest = match value.split_once("://") {
        Some((s, r)) if s.eq_ignore_ascii_case("http") => r,
        Some(_) => return Err(format!("{name} names a proxy that is not http: the way out speaks HTTP to it")),
        None => value,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let (auth, at) = match authority.rsplit_once('@') {
        Some((cred, at)) => {
            let (user, password) = cred.split_once(':').unwrap_or((cred, ""));
            let pair = format!("{}:{}", unescape(user), unescape(password));
            (Some(format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(pair))), at)
        }
        None => (None, authority),
    };
    let (host, port) = match at.strip_prefix('[') {
        Some(v6) => match v6.split_once(']') {
            Some((h, tail)) => (h, tail.strip_prefix(':')),
            None => return Err(format!("{name} has an IPv6 host with no ']'")),
        },
        None => match at.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (at, None),
        },
    };
    let port = match port {
        None | Some("") => PROXY_DEFAULT_PORT,
        Some(p) => p.parse().map_err(|_| format!("{name} has a port that is not a number"))?,
    };
    if host.is_empty() {
        return Err(format!("{name} names no host"));
    }
    Ok(Upstream::Proxy { host: host.to_string(), port, auth })
}

/// The way out of this host: the first variable of a proxy that is set
/// and not empty, else a direct connect.
pub fn upstream() -> Result<Upstream, String> {
    for &name in PROXY_VARIABLES {
        if let Some(v) = std::env::var_os(name).filter(|v| !v.is_empty()) {
            return proxy_of(name, &v.to_string_lossy());
        }
    }
    Ok(Upstream::Direct)
}

fn connect(host: &str, port: u16) -> Result<TcpStream, String> {
    let addrs = (host, port).to_socket_addrs().map_err(|e| format!("the lookup of the target: {e}"))?;
    let mut last = "the lookup gave no address".to_string();
    for a in addrs {
        match TcpStream::connect_timeout(&a, DIAL) {
            Ok(s) => return Ok(s),
            Err(e) => last = format!("the connect: {e}"),
        }
    }
    Err(last)
}

/// The target of a `CONNECT`: an IPv6 literal in brackets.
pub fn authority(host: &str, port: u16) -> String {
    if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
}

/// Dial `host:port` through `up`. A reason names no host of the proxy
/// and no credential.
pub fn dial(up: &Upstream, host: &str, port: u16) -> Result<TcpStream, String> {
    use std::io::Write as _;
    match up {
        Upstream::Direct => connect(host, port),
        Upstream::Proxy { host: at, port: at_port, auth } => {
            let mut s = connect(at, *at_port).map_err(|e| format!("the proxy of the host: {e}"))?;
            let _ = s.set_read_timeout(Some(DIAL));
            let target = authority(host, port);
            let auth = auth.as_ref().map(|a| format!("Proxy-Authorization: {a}\r\n")).unwrap_or_default();
            s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}\r\n").as_bytes())
                .map_err(|e| format!("a write to the proxy of the host: {e}"))?;
            // The head alone: a server that speaks first keeps its bytes.
            let head = read_head(&mut s).map_err(|e| format!("the proxy of the host: {e}"))?;
            match status(&head) {
                Some(200) => {
                    let _ = s.set_read_timeout(None);
                    Ok(s)
                }
                Some(c) => Err(format!("the proxy of the host answered {c}")),
                None => Err("the proxy of the host gave no status".to_string()),
            }
        }
    }
}

/// The work of the process of the way out: one thread for each request,
/// until each peer of `ctl` has closed. It does not return.
fn forward(ctl: OwnedFd, up: Upstream) -> ! {
    let up = Arc::new(up);
    loop {
        let (text, reply) = match pass::recv(&ctl) {
            Ok((t, _)) if t.is_empty() => k::exit_group(0),
            Ok((t, Some(r))) => (t, r),
            Ok(_) => continue,
            Err(e) if e == k::EINTR => continue,
            Err(_) => k::exit_group(1),
        };
        let up = Arc::clone(&up);
        let _ = std::thread::Builder::new().spawn(move || {
            let answer = match text.split_once('\t').and_then(|(h, p)| Some((h, p.parse::<u16>().ok()?))) {
                Some((host, port)) => dial(&up, host, port),
                None => Err("a request with no port".to_string()),
            };
            let _ = match answer {
                Ok(s) => pass::send(&reply, "ok", Some(&OwnedFd::from(s))),
                Err(why) => pass::send(&reply, &format!("fail\t{why}"), None),
            };
        });
    }
}

/// The roots of the host, read before the lab sets its own
/// `SSL_CERT_FILE`.
fn host_roots() -> Result<Arc<rustls::RootCertStore>, String> {
    let file = std::env::var_os(super::CERT_VARIABLE)
        .filter(|v| !v.is_empty())
        .map(|p| pod_tls::CaFile::new(super::CERT_VARIABLE, p));
    let system: Vec<std::path::PathBuf> = pod_tls::SYSTEM_BUNDLES.iter().map(std::path::PathBuf::from).collect();
    let roots = pod_tls::roots::load(file.as_ref(), None, &system).map_err(|e| format!("the roots of the host: {e}"))?;
    Ok(roots.store)
}

/// Start the way out: in the lab process, with one thread, before the
/// namespaces of the lab. `reterminate`: the proxy of the class terminates
/// TLS, so the stand-in needs the roots of the host.
pub fn start(reterminate: bool) -> Result<WayOut, String> {
    let up = upstream()?;
    let roots = if reterminate { Some(host_roots()?) } else { None };
    let (ctl, theirs) = pass::pair().map_err(|e| words("socketpair(AF_UNIX, SOCK_SEQPACKET)", e))?;
    // SAFETY: the lab process has one thread; each child allocates only
    // its own memory.
    match unsafe { k::clone_fork(k::SIGCHLD) } {
        Err(e) => Err(words("fork of the way out", e)),
        Ok(0) => {
            // Two forks: the way out is no child of the command.
            // SAFETY: as above.
            match unsafe { k::clone_fork(k::SIGCHLD) } {
                Ok(0) => {
                    drop(ctl);
                    crate::net::standin::shed(&[i64::from(theirs.as_raw_fd())]);
                    forward(theirs, up)
                }
                Ok(_) => k::exit_group(0),
                Err(_) => k::exit_group(1),
            }
        }
        Ok(pid) => {
            drop(theirs);
            let mut status = 0;
            let _ = k::wait4(pid, &mut status);
            if status != 0 {
                return Err(format!("the way out did not start: status {status}"));
            }
            Ok(WayOut { ctl, roots })
        }
    }
}

impl WayOut {
    /// The descriptor of the stand-in end, which the stand-in keeps open.
    pub fn fd(&self) -> i64 {
        i64::from(self.ctl.as_raw_fd())
    }

    /// A stream to `host:port` of the real network, from the way out.
    pub fn ask(&self, host: &str, port: u16) -> Result<TcpStream, String> {
        let (mine, theirs) = pass::pair().map_err(|e| words("socketpair", e))?;
        let mine = pass::recv_limit(mine, ANSWER).map_err(|e| format!("the limit of the answer: {e}"))?;
        pass::send(&self.ctl, &format!("{host}\t{port}"), Some(&theirs)).map_err(|e| words("sendmsg", e))?;
        drop(theirs);
        match pass::recv(&mine) {
            Ok((t, Some(fd))) if t == "ok" => Ok(TcpStream::from(fd)),
            Ok((t, _)) => Err(t.strip_prefix("fail\t").unwrap_or("the way out closed").to_string()),
            Err(e) => Err(words("the answer of the way out", e)),
        }
    }
}

#[cfg(test)]
mod tests;
