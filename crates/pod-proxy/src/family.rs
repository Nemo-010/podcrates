//! A plan of the dial by address family (T-825; report 07 of the dig study),
//! behind [`crate::Settings::families`]; off, the race keeps RFC 8305 as
//! before ([`crate::interleave`]).
//!
//! The plan: the families that this host routes ([`Local`], cached) meet the
//! families of the peer's addresses, IPv6 first; an IPv4-mapped IPv6 address
//! counts as IPv4. An empty meeting over a peer with addresses falls open:
//! each address is tried. The race of the plan holds: a success of a less
//! preferred address waits until each more preferred attempt ends, and each
//! attempt has its own timeout, so a slow IPv6 path that works is not lost
//! to a fast IPv4 one.

use std::future::Future;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Mutex;
use std::time::Duration;

use tokio::task::{Id, JoinSet};
use tokio::time::Instant;

use crate::cut::Cut;
use crate::error::DialError;
use crate::race::group_errors;

/// The timeout of each attempt of the plan.
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a probe of the local families holds.
pub const LOCAL_HOLDS: Duration = Duration::from_secs(300);

/// The plan by family, and the timeout of each attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FamilyPlan {
    pub attempt_timeout: Duration,
}

impl Default for FamilyPlan {
    fn default() -> Self {
        FamilyPlan { attempt_timeout: ATTEMPT_TIMEOUT }
    }
}

/// The families that this host routes. Only a probe that succeeds counts:
/// a host with no default route (a policy route, an overlay) reads as
/// neither, and neither reads as both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Local {
    pub v4: bool,
    pub v6: bool,
}

impl Local {
    /// A UDP socket of each family connects to a documentation address: the
    /// kernel chooses a source address when a route exists. Nothing is sent.
    pub fn probe() -> Local {
        let routes = |bind: &str, to: &str| UdpSocket::bind(bind).and_then(|s| s.connect(to)).is_ok();
        Local { v4: routes("0.0.0.0:0", "192.0.2.1:9"), v6: routes("[::]:0", "[2001:db8::1]:9") }
    }

    /// [`Local::probe`], kept for [`LOCAL_HOLDS`].
    pub fn cached() -> Local {
        static CACHE: Mutex<Option<(std::time::Instant, Local)>> = Mutex::new(None);
        let mut cache = CACHE.lock().unwrap_or_else(|p| p.into_inner());
        match *cache {
            Some((at, local)) if at.elapsed() < LOCAL_HOLDS => local,
            _ => {
                let local = Local::probe();
                *cache = Some((std::time::Instant::now(), local));
                local
            }
        }
    }
}

/// `addr` with an IPv4-mapped IPv6 address as IPv4.
pub fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(v4.into(), a.port()),
            None => addr,
        },
        v4 => v4,
    }
}

/// The attempts of the plan: each address once ([`canonical`]), the IPv6
/// ones first, each family in the peer's order, of the families of `local`
/// alone; each address when no family meets.
pub fn plan(addrs: &[SocketAddr], local: Local) -> Vec<SocketAddr> {
    let mut seen: Vec<SocketAddr> = Vec::new();
    for addr in addrs.iter().map(|a| canonical(*a)) {
        if !seen.contains(&addr) {
            seen.push(addr);
        }
    }
    let (v6, v4): (Vec<SocketAddr>, Vec<SocketAddr>) = seen.into_iter().partition(|a| a.is_ipv6());
    let both = !local.v4 && !local.v6;
    let mut out = Vec::new();
    if local.v6 || both {
        out.extend(&v6);
    }
    if local.v4 || both {
        out.extend(&v4);
    }
    if out.is_empty() {
        out = v6.into_iter().chain(v4).collect();
    }
    out
}

/// The race of the plan: the attempts of `order` start `delay` apart, or at
/// once when the one before failed, each bounded by `plan`. A success
/// returns when no more preferred attempt runs; until then it is held, and
/// no new attempt starts. Past `until` or `deadline`, a held success
/// returns; else the dial failed.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn race_held<T, F, Fut>(
    order: Vec<SocketAddr>,
    plan: FamilyPlan,
    delay: Duration,
    target: &str,
    until: Instant,
    deadline: Instant,
    budget: Duration,
    attempt: F,
) -> Result<(T, SocketAddr), DialError>
where
    T: Send + 'static,
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<T>> + Send + 'static,
{
    let mut waiting = order.into_iter().enumerate();
    let mut running = JoinSet::new();
    let mut live: Vec<(Id, usize)> = Vec::new();
    let mut held: Option<(usize, T, SocketAddr)> = None;
    let mut next_at = Instant::now();
    let mut errors: Vec<(SocketAddr, String)> = Vec::new();
    let (mut cut, mut kind) = (None, None);
    let timeout = plan.attempt_timeout;
    loop {
        if let Some((p, ..)) = &held
            && live.iter().all(|(_, i)| i > p)
        {
            let (_, value, addr) = held.take().expect("held");
            return Ok((value, addr));
        }
        if held.is_none() && (live.is_empty() || Instant::now() >= next_at) {
            if let Some((i, addr)) = waiting.next() {
                let run = attempt(addr);
                let words = format!("no answer within {} s", timeout.as_secs_f64());
                let handle = running.spawn(async move {
                    let r = tokio::time::timeout(timeout, run).await;
                    (addr, r.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, words))))
                });
                live.push((handle.id(), i));
                next_at = Instant::now() + delay;
                continue;
            }
            if live.is_empty() {
                let detail = match errors.as_slice() {
                    [] => "no address to connect to".to_string(),
                    [(addr, text)] if addr.to_string() == target => text.clone(),
                    _ => group_errors(&errors),
                };
                return Err(DialError::Connect { target: target.to_string(), detail, cut, kind });
            }
        }
        let wake = if held.is_none() && waiting.len() > 0 { next_at.min(until) } else { until };
        tokio::select! {
            joined = running.join_next_with_id() => {
                let id = match &joined {
                    Some(Ok((id, _))) => *id,
                    Some(Err(e)) => e.id(),
                    None => continue,
                };
                let index = live.iter().position(|(each, _)| *each == id).map(|at| live.remove(at).1);
                match (joined, index) {
                    (Some(Ok((_, (addr, Ok(value))))), Some(i)) => {
                        if held.as_ref().is_none_or(|(p, ..)| i < *p) {
                            held = Some((i, value, addr));
                        }
                    }
                    (Some(Ok((_, (addr, Err(e))))), _) => {
                        errors.push((addr, crate::hint::open_files(&e).unwrap_or_else(|| e.to_string())));
                        (cut, kind) = (Some(Cut::of(e.kind())), Some(e.kind()));
                        next_at = Instant::now();
                    }
                    // An attempt that panicked counts as one that failed.
                    _ => next_at = Instant::now(),
                }
            }
            _ = tokio::time::sleep_until(wake) => {
                if Instant::now() >= until.min(deadline)
                    && let Some((_, value, addr)) = held.take()
                {
                    return Ok((value, addr));
                }
                if Instant::now() >= deadline {
                    let step = format!("connecting to {target}");
                    return Err(DialError::Timeout { step, after: budget, stage: pod_core::Stage::Connect });
                }
                if Instant::now() >= until {
                    let detail = format!("no address of this source answered within {} s", pod_core::SOURCE_WAIT.as_secs());
                    return Err(DialError::Connect { target: target.to_string(), detail, cut: Some(Cut::TimedOut), kind: None });
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "family_tests.rs"]
mod tests;
