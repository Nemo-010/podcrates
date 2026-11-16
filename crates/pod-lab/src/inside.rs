//! The measurements of a lab inside itself, before the command: the rows of
//! `pod-hostprobe` that the parts name, each in its own probe child (or in
//! this process, as the kind of the row says), the identity, and the facts
//! that no row measures ([`LabFact`]).

use pod_hostprobe::child::Spawner;
use pod_hostprobe::probes;
use pod_hostprobe::sys::{self as k, Errno};
use pod_hostprobe::{Findings, Settings, identity};

use crate::check::{Seen, State};
use crate::profile::{LabFact, Observe, Profile};

/// The rows that `profile` names, each once, in the order of the profile.
pub fn rows(profile: &Profile) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for o in profile.parts.iter().flat_map(|p| p.observe) {
        if let Observe::Row { row, .. } = o
            && !out.contains(row)
        {
            out.push(row);
        }
    }
    out
}

/// Run `rows`, each as `pod_hostprobe::probes::Probe::measure` runs it
/// (a probe child of `settings`), and read the identity of this process.
/// A name that no probe has is a skip.
pub fn measure(settings: &Settings, rows: &[&'static str]) -> Findings {
    let spawner = Spawner::new(settings);
    let mut f = Findings::empty();
    for &name in rows {
        let outcome = match probes::find(name) {
            Some(p) => p.measure(&spawner),
            None => pod_hostprobe::verdict::Outcome::skip(None, format!("no probe named {name:?}")),
        };
        f.rows.push((name, outcome));
    }
    f.identity = identity::read();
    f.self_exe = spawner.exe_source.clone();
    f
}

fn seen(fact: LabFact, state: State, errno: Option<Errno>, detail: impl Into<String>) -> Seen {
    Seen { what: fact.name(), state, errno: errno.map(|e| e.0), detail: detail.into() }
}

fn errno_words(e: Errno) -> String {
    format!("{} ({})", e.name(), e.0)
}

/// The answer of one call that must fail with `want`.
fn refused(fact: LabFact, call: &str, r: Result<i64, Errno>, want: Errno) -> Seen {
    match r {
        Err(e) if e == want => seen(fact, State::Holds, Some(e), format!("{call}: {}", errno_words(e))),
        Err(e) => seen(
            fact,
            State::Fails,
            Some(e),
            format!("{call}: {}; the profile wants {}", errno_words(e), errno_words(want)),
        ),
        Ok(_) => seen(fact, State::Fails, None, format!("{call} succeeded; the profile wants {}", errno_words(want))),
    }
}

/// A TCP socket of `family`, or the seen of its refusal.
fn tcp_socket(fact: LabFact, family: u64) -> Result<i64, Seen> {
    k::socket(family, k::SOCK_STREAM | k::SOCK_CLOEXEC, 0)
        .map_err(|e| seen(fact, State::Unseen, Some(e), format!("socket(2) failed: {}", errno_words(e))))
}

const EACCES: Errno = k::EACCES;
const EAFNOSUPPORT: Errno = Errno(linux_raw_sys::errno::EAFNOSUPPORT as i32);
const EOPNOTSUPP: Errno = Errno(linux_raw_sys::errno::EOPNOTSUPP as i32);

/// Measure one lab fact in this process.
pub fn lab_fact(fact: LabFact) -> Seen {
    match fact {
        LabFact::TmpdirAtMost(max) => tmpdir(fact, max),
        LabFact::FdsOpen { last } => {
            for n in 3..=i64::from(last) {
                match k::fcntl(n, k::F_GETFD, 0) {
                    Err(e) => return seen(fact, State::Fails, Some(e), format!("descriptor {n}: {}", errno_words(e))),
                    Ok(flags) if flags as u64 & k::FD_CLOEXEC != 0 => {
                        return seen(fact, State::Fails, None, format!("descriptor {n} is close-on-exec"));
                    }
                    Ok(_) => {}
                }
            }
            seen(fact, State::Holds, None, format!("3 to {last} open"))
        }
        LabFact::Inet6BindRefused => {
            // A host with no IPv6 refuses the socket itself: no bind of the
            // family can pass, so the fact holds.
            let fd = match tcp_socket(fact, k::AF_INET6) {
                Ok(fd) => fd,
                Err(s) if s.errno == Some(EAFNOSUPPORT.0) => {
                    return seen(
                        fact,
                        State::Holds,
                        Some(EAFNOSUPPORT),
                        "no IPv6 here: socket(AF_INET6) gives EAFNOSUPPORT",
                    );
                }
                Err(s) => return s,
            };
            let mut a = [0u8; 28];
            a[0..2].copy_from_slice(&(k::AF_INET6 as u16).to_ne_bytes());
            a[23] = 1; // ::1
            let r = k::bind(fd, a.as_ptr() as u64, a.len() as u64);
            let _ = k::close(fd);
            refused(fact, "bind([::1]:0)", r, EACCES)
        }
        LabFact::UnixAllowed => unix(fact),
        // The lab process measures it through its stand-ins.
        LabFact::Net(f) => crate::net::measure(f, None),
        LabFact::GetsocknameRefused => {
            let fd = match tcp_socket(fact, k::AF_INET) {
                Ok(fd) => fd,
                Err(s) => return s,
            };
            let mut a = [0u8; 16];
            let r = k::getsockname(fd, &mut a);
            let _ = k::close(fd);
            refused(fact, "getsockname", r, EOPNOTSUPP)
        }
    }
}

/// `TMPDIR` of the lab is `/tmp`: its size from `statfs(2)`.
fn tmpdir(fact: LabFact, max: u64) -> Seen {
    let path = k::CBuf::new("/tmp").expect("a literal path has no NUL");
    match k::statfs(&path) {
        Err(e) => seen(fact, State::Fails, Some(e), format!("statfs(/tmp): {}", errno_words(e))),
        Ok(s) => {
            let total = s.f_blocks.saturating_mul(s.f_bsize.max(0) as u64);
            if total <= max {
                seen(fact, State::Holds, None, format!("/tmp holds {total} bytes"))
            } else {
                seen(fact, State::Fails, None, format!("/tmp holds {total} bytes; the profile wants at most {max}"))
            }
        }
    }
}

/// `socket`, `bind` of an abstract name and `connect` to it, all AF_UNIX.
fn unix(fact: LabFact) -> Seen {
    let call = |name: &str, r: Result<i64, Errno>| {
        r.map_err(|e| {
            seen(
                fact,
                State::Fails,
                Some(e),
                format!("{name} of AF_UNIX: {}; the profile wants it allowed", errno_words(e)),
            )
        })
    };
    let mut addr = [0u8; 2 + 1 + 24];
    addr[0..2].copy_from_slice(&(k::AF_UNIX as u16).to_ne_bytes());
    let name = format!("pod-lab-{}", k::getpid());
    addr[3..3 + name.len()].copy_from_slice(name.as_bytes());
    let len = 3 + name.len();
    let out = (|| {
        let server = call("socket", k::socket(k::AF_UNIX, k::SOCK_STREAM | k::SOCK_CLOEXEC, 0))?;
        let r = call("bind", k::bind(server, addr.as_ptr() as u64, len as u64))
            .and_then(|_| call("listen", k::listen(server, 1)))
            .and_then(|_| call("socket", k::socket(k::AF_UNIX, k::SOCK_STREAM | k::SOCK_CLOEXEC, 0)))
            .and_then(|client| {
                let r = call("connect", k::connect(client, &addr[..len]));
                let _ = k::close(client);
                r
            });
        let _ = k::close(server);
        r
    })();
    match out {
        Ok(_) => seen(fact, State::Holds, None, "socket, bind and connect succeeded"),
        Err(s) => s,
    }
}
