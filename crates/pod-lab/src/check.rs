//! The check of a profile against the findings of `pod-hostprobe`: for each
//! part, holds, does not hold, or cannot be observed here, with each row
//! and its errno.

use pod_hostprobe::Findings;
use pod_hostprobe::identity::Identity;
use pod_hostprobe::sys::Errno;
use pod_hostprobe::verdict::{Outcome, Verdict as Row};

use crate::profile::{Expect, IdFact, LabFact, Observe, Profile};

/// The state of a part, or of one observation of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Each observation holds.
    Holds,
    /// An observation contradicts the part.
    Fails,
    /// No observation contradicts the part, and one could not be made.
    Unseen,
}

impl State {
    pub fn word(self) -> &'static str {
        match self {
            State::Holds => "holds",
            State::Fails => "fails",
            State::Unseen => "unseen",
        }
    }

    pub fn from_word(word: &str) -> Option<State> {
        [State::Holds, State::Fails, State::Unseen].into_iter().find(|s| s.word() == word)
    }
}

/// One observation of a part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    /// The row name, or the fact in words.
    pub what: String,
    pub state: State,
    /// The errno of the row or of the measurement, where there is one.
    pub errno: Option<i32>,
    /// Why, in words.
    pub detail: String,
}

/// The verdict of one part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartVerdict {
    pub part: String,
    pub state: State,
    pub seen: Vec<Seen>,
}

impl PartVerdict {
    /// The state of a part from its observations: one that fails makes the
    /// part fail; else one that is unseen, or none at all, makes it unseen.
    pub fn new(part: impl Into<String>, seen: Vec<Seen>) -> PartVerdict {
        let state = if seen.iter().any(|s| s.state == State::Fails) {
            State::Fails
        } else if seen.is_empty() || seen.iter().any(|s| s.state == State::Unseen) {
            State::Unseen
        } else {
            State::Holds
        };
        PartVerdict { part: part.into(), state, seen }
    }
}

/// The verdict of a profile: one entry for each part, in the order of the
/// profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub profile: String,
    pub parts: Vec<PartVerdict>,
}

impl Verdict {
    /// True when each part holds.
    pub fn holds(&self) -> bool {
        self.parts.iter().all(|p| p.state == State::Holds)
    }

    /// True when a part fails.
    pub fn fails(&self) -> bool {
        self.parts.iter().any(|p| p.state == State::Fails)
    }
}

/// Check `profile` against `findings`. A fact that no row measures
/// ([`Observe::Lab`], [`Observe::Nothing`]) is [`State::Unseen`], with the
/// entry that adds its row.
pub fn check(profile: &Profile, findings: &Findings) -> Verdict {
    check_with(profile, findings, &|fact| unseen_fact(fact))
}

/// Check `profile` against the JSON report of `pod_hostprobe::report`.
#[cfg(feature = "report")]
pub fn check_report(profile: &Profile, report: &str) -> Result<Verdict, pod_hostprobe::report::ReadError> {
    let (findings, _) = pod_hostprobe::report::read(report)?;
    Ok(check(profile, &findings))
}

/// [`check`], with `lab` for each [`Observe::Lab`]: a lab measures these
/// inside itself.
pub fn check_with(profile: &Profile, findings: &Findings, lab: &dyn Fn(LabFact) -> Seen) -> Verdict {
    let parts = profile
        .parts
        .iter()
        .map(|part| {
            let seen = part
                .observe
                .iter()
                .map(|o| match *o {
                    Observe::Row { row, expect } => match findings.get(row) {
                        Some(outcome) => judge(row, expect, outcome),
                        None => Seen {
                            what: row.to_string(),
                            state: State::Unseen,
                            errno: None,
                            detail: "the findings have no such row".to_string(),
                        },
                    },
                    Observe::Identity(fact) => identity(fact, &findings.identity),
                    Observe::Lab(fact) => lab(fact),
                    Observe::Nothing { needs, .. } => Seen {
                        what: needs.to_string(),
                        state: State::Unseen,
                        errno: None,
                        detail: "nothing measures it here".to_string(),
                    },
                })
                .collect();
            PartVerdict::new(part.name, seen)
        })
        .collect();
    Verdict { profile: profile.name.to_string(), parts }
}

/// A lab fact in a check of findings: no row measures it.
pub fn unseen_fact(fact: LabFact) -> Seen {
    Seen {
        what: fact.name(),
        state: State::Unseen,
        errno: None,
        detail: "no row of pod-hostprobe measures it. A lab measures it from inside".to_string(),
    }
}

fn errno_words(e: i32) -> String {
    format!("{} ({e})", Errno(e).name())
}

fn list(errnos: &[i32]) -> String {
    errnos.iter().map(|&e| errno_words(e)).collect::<Vec<_>>().join(" or ")
}

/// One row against its expectation. A skip is never a verdict: the row did
/// not run, so the part is unseen.
pub fn judge(row: &str, expect: Expect, outcome: &Outcome) -> Seen {
    let errno = outcome.errno.map(|e| e.0);
    let seen = |state, detail: String| Seen { what: row.to_string(), state, errno, detail };
    if outcome.verdict == Row::Skip {
        return seen(State::Unseen, format!("the row did not run: {}", outcome.reason));
    }
    let refused = outcome.verdict == Row::Denied;
    match expect {
        Expect::Refused(want) => match errno {
            Some(e) if refused && want.contains(&e) => seen(State::Holds, format!("refused with {}", errno_words(e))),
            Some(e) if refused => {
                seen(State::Fails, format!("refused with {}; the profile wants {}", errno_words(e), list(want)))
            }
            _ => seen(State::Fails, format!("allowed; the profile wants {}", list(want))),
        },
        Expect::Allowed => match errno {
            _ if !refused => seen(State::Holds, "allowed".to_string()),
            Some(e) => seen(State::Fails, format!("refused with {}; the profile wants it allowed", errno_words(e))),
            None => seen(State::Fails, "refused; the profile wants it allowed".to_string()),
        },
        Expect::LandlockBelow(abi) => {
            const NO_LANDLOCK: [i32; 2] =
                [linux_raw_sys::errno::ENOSYS as i32, linux_raw_sys::errno::EOPNOTSUPP as i32];
            if refused {
                return match errno {
                    Some(e) if NO_LANDLOCK.contains(&e) => {
                        seen(State::Holds, format!("no Landlock: {}", errno_words(e)))
                    }
                    Some(e) => seen(State::Unseen, format!("the version query gave {}", errno_words(e))),
                    None => seen(State::Unseen, "the version query gave no errno".to_string()),
                };
            }
            match outcome.reason.strip_prefix("ABI ").and_then(|n| n.trim().parse::<u32>().ok()) {
                Some(n) if n < abi => seen(State::Holds, format!("ABI {n}")),
                Some(n) => seen(State::Fails, format!("ABI {n}; the profile wants an ABI below {abi}")),
                None => seen(State::Unseen, format!("the row gave no ABI: {:?}", outcome.reason)),
            }
        }
    }
}

/// The bit of `CAP_NET_ADMIN` in a capability set.
const CAP_NET_ADMIN: u32 = 12;

/// One fact of the identity.
pub fn identity(fact: IdFact, id: &Identity) -> Seen {
    let field = |value: &Option<String>, want: &str| match value {
        None => (State::Unseen, "the field is absent".to_string()),
        Some(v) if v.trim() == want => (State::Holds, v.trim().to_string()),
        Some(v) => (State::Fails, format!("{}; the profile wants {want}", v.trim())),
    };
    let (state, detail) = match fact {
        IdFact::NotRoot if id.uid != 0 => (State::Holds, format!("uid {}", id.uid)),
        IdFact::NotRoot => (State::Fails, "uid 0".to_string()),
        IdFact::NoCaps => match id.cap_eff.as_deref().map(|v| u64::from_str_radix(v.trim(), 16)) {
            None => (State::Unseen, "the field is absent".to_string()),
            Some(Err(_)) => (State::Unseen, "the field is not a hexadecimal number".to_string()),
            Some(Ok(0)) => (State::Holds, "0".to_string()),
            Some(Ok(n)) => (State::Fails, format!("{n:016x}; the profile wants 0")),
        },
        IdFact::NoNetAdmin => match id.cap_eff.as_deref().map(|v| u64::from_str_radix(v.trim(), 16)) {
            None => (State::Unseen, "the field is absent".to_string()),
            Some(Err(_)) => (State::Unseen, "the field is not a hexadecimal number".to_string()),
            Some(Ok(n)) if n & (1 << CAP_NET_ADMIN) == 0 => (State::Holds, format!("{n:016x}")),
            Some(Ok(n)) => (State::Fails, format!("{n:016x}; the profile wants no CAP_NET_ADMIN")),
        },
        IdFact::NoNewPrivs => field(&id.no_new_privs, "1"),
        IdFact::SeccompFilter => field(&id.seccomp, "2"),
    };
    Seen { what: fact.name().to_string(), state, errno: None, detail }
}

#[cfg(test)]
mod tests;
