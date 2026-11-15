//! The classes of hostile hosts as profiles, and the labs that hold them.
//!
//! A [`Profile`] is data: its parts, and for each part the rows of
//! `pod-hostprobe` that it must make refuse (with which errno) or allow
//! ([`Observe`]), and the mechanism that holds it in a lab ([`Hold`]).
//! [`PROFILES`] is the table.
//!
//! * [`check`] compares the findings of `pod-hostprobe` with a profile;
//!   [`check_report`] (feature `report`) takes its JSON report. Each part
//!   holds, fails, or cannot be observed here ([`State`]), with each row and
//!   its errno: a lab that allows what it must refuse fails its own check.
//! * [`run`] runs a command in a lab of a profile: the parts that a host
//!   with no root can hold (a seccomp filter through `pod-confine`, Landlock,
//!   a tmpfs in a user namespace, inherited descriptors). The lab measures
//!   the profile inside itself before the command, and a part that does not
//!   hold stops the run, unless the caller asks for a partial lab.
//!
//! A binary that calls [`run`] calls [`dispatch`] first in `main`: the lab
//! process and the probe children are new starts of that binary.
//!
//! The crate reads no environment variable and prints nothing. Linux only:
//! on another target the crate is empty, except [`codes`]. The module
//! `manual` (feature `cli`) is the manual of `podlab`.
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod codes;

#[cfg(target_os = "linux")]
mod check;
#[cfg(target_os = "linux")]
mod hold;
#[cfg(target_os = "linux")]
mod inside;
#[cfg(target_os = "linux")]
mod lab;
#[cfg(all(target_os = "linux", feature = "cli"))]
pub mod manual;
#[cfg(target_os = "linux")]
mod profile;
#[cfg(target_os = "linux")]
mod table;

#[cfg(all(target_os = "linux", feature = "report"))]
pub use check::check_report;
#[cfg(target_os = "linux")]
pub use check::{PartVerdict, Seen, State, Verdict, check, check_with, judge};
#[cfg(target_os = "linux")]
pub use inside::{measure, rows};
#[cfg(target_os = "linux")]
pub use lab::{Options, Ran, RunError, exit_code, lab_main, run};
#[cfg(target_os = "linux")]
pub use profile::{Call, Expect, Hold, IdFact, LabFact, Observe, Part, Profile};
#[cfg(target_os = "linux")]
pub use table::{INHERITED_LAST, PROFILES, SMALL_TMP, find};

/// The values that the caller gives to a lab.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
pub struct Settings {
    /// The settings of the probe children.
    pub hostprobe: pod_hostprobe::Settings,
    /// The private argument with which the lab process starts.
    pub lab_flag: String,
    /// The profiles that the lab process finds by name.
    pub profiles: &'static [Profile],
}

#[cfg(target_os = "linux")]
impl Default for Settings {
    fn default() -> Settings {
        Settings {
            hostprobe: pod_hostprobe::Settings {
                child_flag: "--podlab-probe-child".to_string(),
                child_name: "podlab".to_string(),
                directory_setting: None,
            },
            lab_flag: "--podlab-lab".to_string(),
            profiles: PROFILES,
        }
    }
}

/// The start of a binary that runs a lab: where the first argument is the
/// flag of a probe child or of the lab process, do that work and exit; else
/// return. Call it first in `main`, before a thread starts.
#[cfg(target_os = "linux")]
pub fn dispatch(settings: &Settings) {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let first = args.get(1).and_then(|a| a.to_str());
    if first == Some(settings.hostprobe.child_flag.as_str()) {
        let name = args.get(2).and_then(|a| a.to_str()).unwrap_or("");
        std::process::exit(pod_hostprobe::run_child(name, &mut std::io::stdout()));
    }
    if first == Some(settings.lab_flag.as_str()) {
        lab_main(settings, &args[2..]);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod text;
