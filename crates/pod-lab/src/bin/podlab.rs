//! `podlab`: the profiles of `pod-lab` on the command line.

#[cfg(target_os = "linux")]
mod cli {
    use std::ffi::OsString;
    use std::io::Write;

    /// A line on the standard output. A closed pipe (`podlab list | head`)
    /// ends the output, not the process with a panic.
    macro_rules! out {
        ($($t:tt)*) => {{
            let _ = writeln!(std::io::stdout(), $($t)*);
        }};
    }

    use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
    use pod_lab::codes::{
        EXIT_CANNOT_EXEC, EXIT_FAILS, EXIT_HOLDS, EXIT_NOT_FOUND, EXIT_REFUSED, EXIT_UNSEEN, EXIT_USAGE,
    };
    use pod_lab::{Options, Profile, RunError, Settings, State, Verdict};

    /// The classes of hostile hosts as profiles: list them, check one
    /// against this host, or run a command in a lab of one.
    #[derive(Parser)]
    #[command(name = "podlab", version)]
    pub(super) struct Cli {
        #[command(subcommand)]
        command: Cmd,
    }

    #[derive(Subcommand)]
    enum Cmd {
        /// List each profile, its parts, and what holds each part in a lab.
        List,
        /// Check a profile on this host with the probes of pod-hostprobe,
        /// or against a JSON report of pod-hostprobe.
        Check {
            /// The name of the profile.
            profile: String,
            /// A JSON report of pod-hostprobe to check, in place of the
            /// probes of this host.
            #[arg(long, value_name = "FILE")]
            report: Option<std::path::PathBuf>,
        },
        /// Run a command in a lab of a profile. The lab checks itself
        /// before the command; a part that does not hold stops the run.
        Run {
            /// Run the command in the parts that hold, and report the
            /// others.
            #[arg(long)]
            partial: bool,
            /// The name of the profile.
            profile: String,
            /// The command and its arguments.
            #[arg(last = true, required = true, value_name = "CMD")]
            cmd: Vec<OsString>,
        },
    }

    fn profile(settings: &Settings, name: &str) -> Result<&'static Profile, i32> {
        pod_lab::find(settings.profiles, name).ok_or_else(|| {
            eprintln!("podlab: no profile {name:?}; `podlab list` gives each one");
            EXIT_USAGE
        })
    }

    fn print(v: &Verdict) {
        for p in &v.parts {
            out!("{:<7} {}/{}", p.state.word(), v.profile, p.part);
            for s in &p.seen {
                let errno = s.errno.map(|e| format!(" errno={e}")).unwrap_or_default();
                out!("        {:<7} {}{errno}: {}", s.state.word(), s.what, s.detail);
            }
        }
    }

    fn code(v: &Verdict) -> i32 {
        if v.fails() {
            EXIT_FAILS
        } else if v.parts.iter().any(|p| p.state == State::Unseen) {
            EXIT_UNSEEN
        } else {
            EXIT_HOLDS
        }
    }

    pub fn main() -> i32 {
        let settings = Settings::default();
        pod_lab::dispatch(&settings);
        let command = Cli::command().after_long_help(pod_lab::codes::help());
        let cli = match command.try_get_matches().and_then(|m| Cli::from_arg_matches(&m)) {
            Ok(cli) => cli,
            Err(e) => {
                let _ = e.print();
                return if e.use_stderr() { EXIT_USAGE } else { EXIT_HOLDS };
            }
        };
        match cli.command {
            Cmd::List => {
                for p in settings.profiles {
                    out!("{:<20} {} ({})", p.name, p.about, p.source);
                    for part in p.parts {
                        out!("  {:<22} {} [{}]", part.name, part.about, part.hold.words());
                    }
                }
                EXIT_HOLDS
            }
            Cmd::Check { profile: name, report } => {
                let p = match profile(&settings, &name) {
                    Ok(p) => p,
                    Err(c) => return c,
                };
                let v = match report {
                    Some(path) => match std::fs::read_to_string(&path)
                        .map_err(|e| e.to_string())
                        .and_then(|t| pod_lab::check_report(p, &t).map_err(|e| e.to_string()))
                    {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("podlab: the report {}: {e}", path.display());
                            return EXIT_USAGE;
                        }
                    },
                    None => pod_lab::check(p, &pod_lab::measure(&settings.hostprobe, &pod_lab::rows(p))),
                };
                print(&v);
                code(&v)
            }
            Cmd::Run { partial, profile: name, cmd } => {
                let p = match profile(&settings, &name) {
                    Ok(p) => p,
                    Err(c) => return c,
                };
                match pod_lab::run(&settings, p, &cmd, Options { partial, stdout: None }) {
                    Ok(ran) => {
                        for part in ran.verdict.parts.iter().filter(|x| x.state != State::Holds) {
                            eprintln!(
                                "podlab: {}/{} does not hold here: the command runs with no such part",
                                p.name, part.part
                            );
                        }
                        pod_lab::exit_code(ran.status)
                    }
                    Err(RunError::Refused(v)) => {
                        print(&v);
                        eprintln!("podlab: the lab {} does not hold; the command did not run", p.name);
                        EXIT_REFUSED
                    }
                    Err(RunError::Exec { errno, .. }) => {
                        eprintln!("podlab: the command did not start: errno {errno}");
                        if errno == 2 { EXIT_NOT_FOUND } else { EXIT_CANNOT_EXEC }
                    }
                    Err(e) => {
                        eprintln!("podlab: {e}");
                        EXIT_REFUSED
                    }
                }
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use clap::CommandFactory;

    /// Each help text keeps the rules of a printed text.
    #[test]
    fn each_help_keeps_the_rules_of_a_printed_text() {
        let mut cmd = super::cli::Cli::command().after_long_help(pod_lab::codes::help());
        let mut texts = vec![cmd.render_long_help().to_string()];
        for sub in cmd.get_subcommands_mut() {
            texts.push(sub.render_long_help().to_string());
        }
        assert!(texts.len() >= 4, "{} texts", texts.len());
        for t in texts {
            assert_eq!(pod_lab::codes::fault(&t), None, "{t}");
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(cli::main());
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("podlab: Linux only");
    std::process::exit(pod_lab::codes::EXIT_USAGE);
}
