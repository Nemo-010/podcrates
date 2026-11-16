//! The answer of a lab whose seccomp filter cannot hold on this target or
//! host: on a target with `socketcall(2)` the lab refuses a filter of a
//! socket call, and under qemu-user the kernel call of the filter gives
//! `ENOSYS`.

use pod_lab::{Hold, Ran, RunError, State, Verdict};
use pod_testkit::host::skip_line;

/// The targets whose kernel has `socketcall(2)`, as `pod-lab` names them.
const SOCKETCALL: bool = cfg!(any(target_arch = "x86", target_arch = "s390x", target_arch = "powerpc64"));

/// True where the lab `name` filters a call that `socketcall(2)` also
/// reaches.
fn filters_a_socket_call(name: &str) -> bool {
    use pod_hostprobe::sys as k;
    let socket_calls = [k::SYS_SOCKET, k::SYS_LISTEN, k::SYS_GETSOCKNAME];
    let profile = pod_lab::find(pod_lab::PROFILES, name).expect("a profile");
    profile.parts.iter().any(|p| match p.hold {
        Hold::Seccomp(calls) => calls.iter().any(|c| socket_calls.contains(&c.nr)),
        _ => false,
    })
}

/// The reason of each part that does not hold, where each one is a hold
/// that the lab could not set; `None` where a part fails for another
/// reason.
fn holds_not_set(v: &Verdict) -> Option<Vec<&str>> {
    let not = v.parts.iter().filter(|p| p.state != State::Holds);
    not.map(|p| p.seen.first().filter(|s| s.what == "the hold").map(|s| s.detail.as_str())).collect()
}

/// True where the case of the lab `name` ends with `out`: on a target with
/// `socketcall(2)`, a lab that filters a socket call must refuse, and the
/// refusal is checked; a host that takes no seccomp filter skips with a
/// line, which `scripts/ci/userns-tests.sh` fails on.
pub fn refused_here(name: &str, out: &Result<Ran, RunError>) -> bool {
    let refused = match out {
        Err(RunError::Refused(v)) => holds_not_set(v).filter(|why| !why.is_empty()),
        _ => None,
    };
    if SOCKETCALL && filters_a_socket_call(name) {
        let why = refused.unwrap_or_else(|| panic!("{name}: no refusal where the kernel has socketcall(2): {out:?}"));
        assert!(why.iter().all(|w| w.contains("socketcall(2)")), "{name}: {out:?}");
        println!("{name}: refused where the kernel has socketcall(2): ok");
        return true;
    }
    match refused {
        Some(why) if why.iter().all(|w| w.starts_with("seccomp(SET_MODE_FILTER): ENOSYS")) => {
            skip_line(&format!("{name}: the lab needs a seccomp filter; this host gives {}", why[0]));
            true
        }
        _ => false,
    }
}
