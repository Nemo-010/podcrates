//! The runs of the network classes: each lab with a payload that shows its
//! parts through the stand-ins, then the check that the stand-in removed
//! the certificate file after the command.

use std::time::{Duration, Instant};

use crate::cases::{payload, ran, run, settings};
use pod_testkit::host::skip_line;

/// False, with a skip line, where a caller that is not root gets no user
/// namespace: a network lab needs one. `scripts/ci/userns-tests.sh` fails
/// on the line.
pub fn userns_here(name: &str) -> bool {
    if !pod_testkit::nobody::is_root()
        && let Err(why) = pod_testkit::host::userns()
    {
        skip_line(&format!("{name}: a network lab needs a user namespace: {why}"));
        return false;
    }
    true
}

/// Run the payload `kind` in the lab `name`; check its line, and that the
/// certificate file is gone after the run.
fn case(name: &str, kind: &str, line: &str) {
    if !userns_here(name) {
        return;
    }
    let (out, text) = run(&settings(), name, &payload(kind), false);
    if crate::filter::refused_here(name, &out) {
        return;
    }
    assert_eq!(ran(name, out, &text), 0, "{name}: {text}");
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some(line), "{name}: {text}");
    let file = lines.next().and_then(|l| l.strip_prefix("cert ")).unwrap_or_else(|| panic!("{name}: {text}"));
    assert!(file.starts_with('/') && file.ends_with(".pem"), "{name}: {file}");
    // The stand-in sees the end of the command, then removes the file.
    let start = Instant::now();
    while std::path::Path::new(file).exists() {
        assert!(start.elapsed() < Duration::from_secs(10), "{name}: the stand-in left {file}");
        std::thread::sleep(Duration::from_millis(20));
    }
    println!("{name}: ok");
}

pub fn proxy_only() {
    case(
        "proxy-only",
        "proxy-only",
        "200 with the credential, 407 with none, 403 for port 22, no direct route, no udp",
    );
}

/// The variables of a proxy of other tools than curl (T-760).
pub fn tool_variables() {
    case("proxy-only", "tool-vars", "the proxy variables of each tool name the stand-in proxy");
}

/// The name of the variable that makes the lab process of a case set
/// SIGPIPE to its default before `pod_lab::dispatch`, as a consumer can.
pub const SIGPIPE_DEFAULT: &str = "POD_LAB_TEST_SIGPIPE_DEFAULT";

/// SIGPIPE to `SIG_DFL` (the handler 0) in this process.
pub fn sigpipe_default() {
    use linux_raw_sys::general::{__NR_rt_sigaction, SIGPIPE, kernel_sigaction, kernel_sigset_t};
    // SAFETY: all zero is a valid `kernel_sigaction`: `SIG_DFL`, no flag,
    // no mask.
    let act: kernel_sigaction = unsafe { std::mem::zeroed() };
    let at = std::ptr::from_ref(&act) as usize as u64;
    let args = [u64::from(SIGPIPE), at, 0, std::mem::size_of::<kernel_sigset_t>() as u64, 0, 0];
    // SAFETY: the kernel reads `act` and writes nothing.
    unsafe { pod_hostprobe::sys::sys(i64::from(__NR_rt_sigaction), args) }.expect("rt_sigaction");
}

/// A stand-in of a lab whose process has SIGPIPE at its default lives
/// through a client that resets its connection (PodUtils/podvm#455).
pub fn sigpipe() {
    // SAFETY: this binary has one thread.
    unsafe { std::env::set_var(SIGPIPE_DEFAULT, "1") };
    case("proxy-only", "sigpipe", "a reset after the handshake, then CONNECT 200 and GET 200");
    // SAFETY: as above.
    unsafe { std::env::remove_var(SIGPIPE_DEFAULT) };
}

pub fn proxy_tls_reterminate() {
    case(
        "proxy-tls-reterminate",
        "reterminate",
        "listed.test by the proxy CA, other.test by the server CA, port 22 silent",
    );
}

pub fn proxy_per_name() {
    case("proxy-per-name", "per-name", "listed.test 200, other.test 504, a literal gets a reset");
}

pub fn sni_allowlist() {
    case(
        "sni-allowlist",
        "sni",
        "listed.test passes, other.test reset, no name reset; at 198.51.100.7: listed.test passes, no name reset",
    );
}

pub fn no_proxy_no_dns() {
    case("no-proxy-no-dns", "nodns", "no lookup, TLS to 192.0.2.1 gets 200");
}

pub fn ws_upgrade_refused() {
    case("ws-upgrade-refused", "ws", "get 200, upgrade 403");
}

/// A kernel with no IPv6 cannot hold `ipv6-only`: the lab must refuse it
/// with the reason, and the command must not run.
pub fn ipv6_only() {
    if !userns_here("ipv6-only") {
        return;
    }
    let v6 = std::net::TcpListener::bind("[::1]:0");
    if let Err(e) = &v6
        && e.raw_os_error() == Some(97)
    {
        let (out, _) = run(&settings(), "ipv6-only", &payload("v6"), false);
        match out {
            Err(pod_lab::RunError::Refused(v)) => {
                let why: Vec<&str> = v.parts.iter().flat_map(|p| &p.seen).map(|s| s.detail.as_str()).collect();
                assert!(why.iter().any(|w| w.contains("no IPv6 here")), "{why:?}");
            }
            other => panic!("ipv6-only on a kernel with no IPv6: {other:?}"),
        }
        println!("ipv6-only: no IPv6 in this kernel; the lab refuses it: ok");
        return;
    }
    drop(v6);
    case("ipv6-only", "v6", "no IPv4 route, the loopback and IPv6 reach, an IPv6 default route");
}

pub fn all() {
    proxy_only();
    proxy_tls_reterminate();
    proxy_per_name();
    sni_allowlist();
    no_proxy_no_dns();
    tool_variables();
    sigpipe();
    ws_upgrade_refused();
    ipv6_only();
    crate::way_out::all();
    crate::serve::all();
}
