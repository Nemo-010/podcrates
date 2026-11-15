//! A run of a command in a lab.
//!
//! [`run`] starts this binary again with the lab flag of the [`Settings`]:
//! a fresh process with one thread, the lab process. The lab process sets
//! each part that it can hold ([`crate::hold`]), then measures the profile
//! inside itself ([`crate::inside`]), each row in its own probe child. It
//! tells each verdict to [`run`] on a pipe. Only when each part holds (or
//! the caller asked for the parts that hold) does it replace itself with
//! the command; else it exits and the command never runs. The command
//! keeps the standard streams of the caller, and its exit status is the one
//! that [`run`] gives.

use std::ffi::OsString;
use std::io::Read;
use std::os::fd::FromRawFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, ExitStatus, Stdio};

use pod_hostprobe::sys as k;

use crate::check::{PartVerdict, Seen, State, Verdict, check_with};
use crate::profile::{Hold, Profile};
use crate::{Settings, hold, inside, mounts, table};

/// The choices of a run.
#[derive(Debug, Default)]
pub struct Options {
    /// Run the command in the parts that hold, and report the others. With
    /// `false`, a part that does not hold stops the run.
    pub partial: bool,
    /// The standard output of the command; `None`: the one of the caller.
    pub stdout: Option<Stdio>,
}

/// The run of a command in a lab.
#[derive(Debug)]
pub struct Ran {
    /// The verdict of the lab from inside, before the command.
    pub verdict: Verdict,
    /// The exit status of the command.
    pub status: ExitStatus,
}

/// Why the command did not run.
#[derive(Debug)]
pub enum RunError {
    /// A part does not hold, and the caller did not ask for a partial lab.
    Refused(Verdict),
    /// The command did not start in the lab: its errno.
    Exec { verdict: Verdict, errno: i32 },
    /// The lab process did not start, or did not speak its verdict.
    Lab(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Refused(v) => {
                let parts: Vec<&str> =
                    v.parts.iter().filter(|p| p.state != State::Holds).map(|p| p.part.as_str()).collect();
                write!(f, "the lab {} does not hold: {}", v.profile, parts.join(", "))
            }
            RunError::Exec { errno, .. } => {
                write!(f, "the command did not start: {} ({errno})", k::Errno(*errno).name())
            }
            RunError::Lab(why) => write!(f, "the lab did not start: {why}"),
        }
    }
}

impl std::error::Error for RunError {}

/// Run `cmd` in a lab of `profile`. `profile` must be in
/// [`Settings::profiles`]: the lab process finds it there by its name.
pub fn run(settings: &Settings, profile: &Profile, cmd: &[OsString], opts: Options) -> Result<Ran, RunError> {
    if cmd.is_empty() {
        return Err(RunError::Lab("no command".to_string()));
    }
    if table::find(settings.profiles, profile.name).is_none() {
        return Err(RunError::Lab(format!("the profile {} is not in the profiles of the settings", profile.name)));
    }
    let mut fds = [0i32; 2];
    k::pipe2(&mut fds, k::O_CLOEXEC).map_err(|e| RunError::Lab(format!("pipe2: {}", e.name())))?;
    let (r, w) = (fds[0], fds[1]);
    // SAFETY: `r` is a new descriptor that nothing else owns.
    let mut reader = unsafe { std::fs::File::from_raw_fd(r) };
    let exe = if std::path::Path::new("/proc/self/exe").exists() {
        std::path::PathBuf::from("/proc/self/exe")
    } else {
        std::env::current_exe().map_err(|e| RunError::Lab(format!("the path of this binary: {e}")))?
    };
    let mut c = Command::new(exe);
    c.arg0(&settings.hostprobe.child_name)
        .arg(&settings.lab_flag)
        .arg(profile.name)
        .arg(if opts.partial { "partial" } else { "whole" })
        .arg(w.to_string())
        .arg("--")
        .args(cmd);
    if let Some(out) = opts.stdout {
        c.stdout(out);
    }
    // SAFETY: one fcntl(2) in the child before the exec; no allocation.
    unsafe {
        c.pre_exec(move || {
            k::fcntl(i64::from(w), k::F_SETFD, 0).map(|_| ()).map_err(|e| std::io::Error::from_raw_os_error(e.0))
        });
    }
    let spawned = c.spawn();
    let _ = k::close(i64::from(w));
    let mut child = spawned.map_err(|e| RunError::Lab(format!("the start of the lab process: {e}")))?;
    let mut text = String::new();
    let read = reader.read_to_string(&mut text);
    drop(reader);
    let status = child.wait().map_err(|e| RunError::Lab(format!("the wait for the lab: {e}")))?;
    read.map_err(|e| RunError::Lab(format!("the verdict of the lab: {e}")))?;
    let (verdict, end) = decode(profile, &text).map_err(RunError::Lab)?;
    match end {
        End::Go => Ok(Ran { verdict, status }),
        End::Refuse => Err(RunError::Refused(verdict)),
        End::ExecFailed(errno) => Err(RunError::Exec { verdict, errno }),
    }
}

/// The last line of the lab process.
enum End {
    Go,
    Refuse,
    ExecFailed(i32),
}

fn clean(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

fn encode(v: &Verdict) -> String {
    let mut out = String::new();
    for p in &v.parts {
        out.push_str(&format!("part\t{}\t{}\n", clean(&p.part), p.state.word()));
        for s in &p.seen {
            let errno = s.errno.map_or("-".to_string(), |e| e.to_string());
            out.push_str(&format!("seen\t{}\t{}\t{errno}\t{}\n", s.state.word(), clean(&s.what), clean(&s.detail)));
        }
    }
    out
}

fn decode(profile: &Profile, text: &str) -> Result<(Verdict, End), String> {
    let mut parts: Vec<PartVerdict> = Vec::new();
    let mut end = None;
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["part", name, state] => parts.push(PartVerdict {
                part: name.to_string(),
                state: State::from_word(state).ok_or_else(|| format!("the state {state:?}"))?,
                seen: Vec::new(),
            }),
            ["seen", state, what, errno, detail] => {
                let last = parts.last_mut().ok_or("a seen line before its part")?;
                last.seen.push(Seen {
                    what: what.to_string(),
                    state: State::from_word(state).ok_or_else(|| format!("the state {state:?}"))?,
                    errno: errno.parse().ok(),
                    detail: detail.to_string(),
                });
            }
            ["go"] => end = Some(End::Go),
            ["refuse"] => end = Some(End::Refuse),
            ["exec-failed", errno] => end = Some(End::ExecFailed(errno.parse().map_err(|_| "the errno of the exec")?)),
            _ => return Err(format!("the lab said {line:?}")),
        }
    }
    let end = end.ok_or_else(|| "the lab ended with no verdict".to_string())?;
    Ok((Verdict { profile: profile.name.to_string(), parts }, end))
}

/// The work of the lab process: `args` are the arguments after the lab
/// flag (the profile, `whole` or `partial`, the descriptor of the verdict,
/// `--` and the command). It does not return.
pub fn lab_main(settings: &Settings, args: &[OsString]) -> ! {
    let text = |i: usize| args.get(i).and_then(|a| a.to_str()).unwrap_or("");
    // A lab process with no verdict descriptor cannot speak: the caller
    // reads "no verdict". The words stay here for a reader of the code.
    let fail = |_why: &str| -> ! { std::process::exit(crate::codes::EXIT_REFUSED) };
    let Some(profile) = table::find(settings.profiles, text(0)) else { fail("no such profile") };
    let partial = text(1) == "partial";
    let Ok(given) = text(2).parse::<i64>() else { fail("no descriptor of the verdict") };
    if text(3) != "--" || args.len() < 5 {
        fail("no command");
    }
    // The verdict goes on a descriptor above each one that a part opens,
    // close-on-exec, so that the command never holds it.
    let Ok(out) = k::fcntl(given, k::F_DUPFD_CLOEXEC, 100) else { fail("the descriptor of the verdict") };
    let _ = k::close(given);
    hold::close_from_3(out);
    let say = |line: &str| {
        let _ = k::write(out, line.as_bytes());
    };

    let set = setup(profile);
    let findings = inside::measure(&settings.hostprobe, &inside::rows(profile));
    let mut verdict = check_with(profile, &findings, &inside::lab_fact);
    for (part, why) in verdict.parts.iter_mut().zip(&set) {
        if let Some(why) = why {
            part.state = State::Fails;
            part.seen.insert(
                0,
                Seen { what: "the hold".to_string(), state: State::Fails, errno: None, detail: why.clone() },
            );
        }
    }
    say(&encode(&verdict));
    if !partial && !verdict.holds() {
        say("refuse\n");
        std::process::exit(crate::codes::EXIT_REFUSED);
    }
    say("go\n");
    let mut c = Command::new(&args[4]);
    c.args(&args[5..]);
    if profile.parts.iter().any(|p| matches!(p.hold, Hold::Tmpfs { .. })) {
        c.env("TMPDIR", "/tmp");
    }
    let e = c.exec();
    let errno = e.raw_os_error().unwrap_or(0);
    say(&format!("exec-failed\t{errno}\n"));
    std::process::exit(if errno == k::ENOENT.0 { crate::codes::EXIT_NOT_FOUND } else { crate::codes::EXIT_CANNOT_EXEC })
}

/// Set each part, in the order: the mount namespace, the descriptors and
/// the session, Landlock and `no_new_privs`, the drop of the
/// capabilities, then the one seccomp filter last, so that the filter does
/// not refuse a call of the setup. One entry for each part: `Some(why)`
/// where the part could not be set.
fn setup(profile: &Profile) -> Vec<Option<String>> {
    let mut why: Vec<Option<String>> = profile.parts.iter().map(|p| hold::cannot(p.hold)).collect();
    // Each mount in one namespace.
    let at: Vec<usize> =
        (0..profile.parts.len()).filter(|&i| why[i].is_none() && mounts::is_mount(profile.parts[i].hold)).collect();
    if !at.is_empty() {
        let holds: Vec<Hold> = at.iter().map(|&i| profile.parts[i].hold).collect();
        match mounts::holds(&holds) {
            Ok(each) => {
                for (&i, r) in at.iter().zip(each) {
                    why[i] = r.err();
                }
            }
            Err(e) => at.iter().for_each(|&i| why[i] = Some(e.clone())),
        }
    }
    let mut each = |rank: u8, f: &dyn Fn(Hold) -> Option<Result<(), String>>| {
        for (i, p) in profile.parts.iter().enumerate() {
            if why[i].is_some() || order(p.hold) != rank {
                continue;
            }
            if let Some(Err(e)) = f(p.hold) {
                why[i] = Some(e);
            }
        }
    };
    each(1, &|h| match h {
        Hold::Fds { last } => Some(hold::fds(last)),
        Hold::NoCtty => Some(hold::no_ctty()),
        _ => None,
    });
    each(2, &|h| match h {
        Hold::LandlockTcp => Some(hold::landlock_tcp()),
        Hold::Hide { path, rights } => Some(hold::hide(path, rights)),
        Hold::NoNewPrivs => Some(k::set_no_new_privs().map(|_| ()).map_err(|e| format!("prctl: {}", e.name()))),
        _ => None,
    });
    // After Landlock: a ruleset of a hidden path reads each directory on the
    // way, which root does with its capabilities.
    each(3, &|h| match h {
        Hold::DropCaps => Some(hold::drop_caps()),
        _ => None,
    });
    // One filter for each rule of each part that is still set.
    let rules: Vec<_> = profile
        .parts
        .iter()
        .zip(&why)
        .filter(|(_, w)| w.is_none())
        .flat_map(|(p, _)| hold::deny_rules(p.hold))
        .collect();
    if !rules.is_empty()
        && let Err(e) = hold::seccomp(&rules)
    {
        for (i, p) in profile.parts.iter().enumerate() {
            if order(p.hold) == 4 && why[i].is_none() {
                why[i] = Some(e.clone());
            }
        }
    }
    why
}

/// The rank of a hold in [`setup`].
fn order(h: Hold) -> u8 {
    match h {
        _ if mounts::is_mount(h) => 0,
        Hold::Fds { .. } | Hold::NoCtty => 1,
        Hold::LandlockTcp | Hold::Hide { .. } | Hold::NoNewPrivs => 2,
        Hold::DropCaps => 3,
        Hold::Seccomp(_) | Hold::ConfineDefaults => 4,
        _ => 5,
    }
}

/// The exit code of a status, as a shell gives it: the code, or 128 and
/// the number of the signal.
pub fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}
