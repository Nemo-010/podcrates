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
    // The help and the manual come from the model of pod-manual: the parser
    // of clap gives no help of its own.
    #[derive(Parser)]
    #[command(name = "podlab", version, disable_help_flag = true, disable_help_subcommand = true)]
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
            /// Run the rows that send a packet past this host, to this
            /// name and port. The probes use the proxy of HTTPS_PROXY. With
            /// no value, these rows do not run.
            #[arg(long, value_name = "NAME:PORT", value_parser = target)]
            network: Option<(String, u16)>,
            /// A second name for the rows that send a packet out.
            #[arg(long, value_name = "NAME", requires = "network")]
            network_other: Option<String>,
            /// An IP address for the rows that send a packet out.
            #[arg(long, value_name = "ADDRESS", requires = "network")]
            network_literal: Option<std::net::IpAddr>,
            /// The port that the proxy refuses or holds with no byte.
            #[arg(long, value_name = "PORT", requires = "network", default_value_t = 22)]
            network_closed: u16,
        },
        /// Run a command in a lab of a profile. The lab checks itself
        /// before the command; a part that does not hold stops the run.
        Run {
            /// Run the command in the parts that hold, and report the
            /// others.
            #[arg(long)]
            partial: bool,
            /// Let a TCP connect reach this port where the profile refuses
            /// each TCP connect (the proxy of the host). Give it once for
            /// each port.
            #[arg(long, value_name = "PORT")]
            allow_connect: Vec<u16>,
            /// Give a network lab a way out. The stand-in proxy applies the
            /// rules of its class. Then it sends a CONNECT to a name outside
            /// the lab to the real network. It goes directly, or through the
            /// proxy of HTTPS_PROXY of this host. The command never gets that
            /// proxy or its credential.
            #[arg(long)]
            way_out: bool,
            /// The name of the profile.
            profile: String,
            /// The command and its arguments.
            #[arg(last = true, required = true, value_name = "CMD")]
            cmd: Vec<OsString>,
        },
        /// The manual: each command, profile, variable and exit code. A pager
        /// shows it on a terminal.
        Man {
            /// Write the text with no pager, also on a terminal.
            #[arg(long)]
            no_pager: bool,
            /// Write the manual as a man(7) page.
            #[arg(long, conflicts_with = "json")]
            roff: bool,
            /// Write the manual as one JSON object.
            #[arg(long)]
            json: bool,
            /// One section: a command, a topic, a table of facts.
            #[arg(value_name = "SECTION")]
            section: Vec<String>,
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

    /// The parser of this binary.
    #[cfg(test)]
    pub(super) fn command() -> clap::Command {
        Cli::command()
    }

    /// A `NAME:PORT` of `--network`: a host name and a port.
    fn target(text: &str) -> Result<(String, u16), String> {
        let (name, port) = text.rsplit_once(':').ok_or("give NAME:PORT")?;
        let port = port.parse::<u16>().map_err(|_| "the port is not a number from 0 to 65535".to_string())?;
        let ok = !name.is_empty()
            && name.len() <= 253
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b));
        if !ok {
            return Err("the name is not a host name".to_string());
        }
        Ok((name.to_string(), port))
    }

    /// The manual of this binary, as the name of `argv[0]` shows it.
    pub(super) fn manual(argv0: &str) -> pod_manual::Manual {
        pod_lab::manual::manual(Cli::command()).named(argv0)
    }

    pub fn main() -> i32 {
        let settings = Settings::default();
        pod_lab::dispatch(&settings);
        let args: Vec<String> = std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect();
        let manual = manual(args.first().map(String::as_str).unwrap_or("podlab"));
        if let Some(help) = pod_manual::help::request(&manual, args.get(1..).unwrap_or(&[])) {
            return match pod_manual::help::answer(&manual, &help) {
                Ok(text) => {
                    let _ = std::io::stdout().write_all(text.as_bytes());
                    EXIT_HOLDS
                }
                Err(e) => {
                    eprintln!("{e}");
                    EXIT_USAGE
                }
            };
        }
        let cli = match Cli::command().try_get_matches().and_then(|m| Cli::from_arg_matches(&m)) {
            Ok(cli) => cli,
            Err(e) => {
                let _ = e.print();
                return if e.use_stderr() { EXIT_USAGE } else { EXIT_HOLDS };
            }
        };
        match cli.command {
            Cmd::Man { no_pager, roff, json, section } => {
                let section = (!section.is_empty()).then(|| section.join(" "));
                let req = pod_manual::Request { section, no_pager, roff, json };
                let (mut out, mut err) = (std::io::stdout().lock(), std::io::stderr());
                let tty = pod_manual::pager::Tty::probed();
                match pod_manual::run(&manual, &req, tty, &mut std::io::stdin().lock(), &mut out, &mut err) {
                    Ok(()) => EXIT_HOLDS,
                    Err(e) => {
                        eprintln!("{e}");
                        EXIT_USAGE
                    }
                }
            }
            Cmd::List => {
                for p in settings.profiles {
                    out!("{:<20} {} ({})", p.name, p.about, p.source);
                    for part in p.parts {
                        out!("  {:<22} {} [{}]", part.name, part.about, part.hold.words());
                    }
                }
                EXIT_HOLDS
            }
            Cmd::Check { profile: name, report, network, network_other, network_literal, network_closed } => {
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
                    None => {
                        let mut probe = settings.hostprobe.clone();
                        probe.network = network.map(|(name, port)| pod_hostprobe::Network {
                            other: network_other,
                            literal: network_literal,
                            closed_port: network_closed,
                            ..pod_hostprobe::Network::new(name, port)
                        });
                        pod_lab::check(p, &pod_lab::measure(&probe, &pod_lab::rows(p)))
                    }
                };
                print(&v);
                code(&v)
            }
            Cmd::Run { partial, allow_connect, way_out, profile: name, cmd } => {
                let p = match profile(&settings, &name) {
                    Ok(p) => p,
                    Err(c) => return c,
                };
                if way_out && !pod_lab::has_proxy(p) {
                    eprintln!("podlab: --way-out needs a profile with a stand-in proxy; {name} has none");
                    return EXIT_USAGE;
                }
                if way_out {
                    // The environment of podlab holds the proxy of the host.
                    pod_lab::net::not_dumpable();
                }
                let opts = Options { partial, stdout: None, allow_connect, way_out };
                match pod_lab::run(&settings, p, &cmd, opts) {
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

// The root of a binary keeps its modules beside it: the path names the
// directory of the binary.
#[cfg(all(test, target_os = "linux"))]
#[path = "podlab/tests.rs"]
mod tests;

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(cli::main());
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("podlab: Linux only");
    std::process::exit(pod_lab::codes::EXIT_USAGE);
}
