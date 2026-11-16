//! The reader of clap (feature `clap`), with the tests of podnet's manual
//! over its sample command tree.
#![cfg(feature = "clap")]

use pod_manual::check::{assert_none, flags, model};
use pod_manual::{Request, Rule, body, help, json, roff, text};

fn sample() -> clap::Command {
    clap::Command::new("podnet")
        .version("1.0 (abc)")
        .about("about podnet")
        .subcommand(
            clap::Command::new("tunnel")
                .about("Expose a service")
                .visible_alias("expose")
                .arg(clap::Arg::new("url").long("url").help("HTTP origin").conflicts_with("socket"))
                .arg(clap::Arg::new("socket").long("socket").value_name("PATH").help("Unix origin"))
                .arg(
                    clap::Arg::new("protocol")
                        .long("protocol")
                        .default_value("auto")
                        .value_parser(["auto", "quic", "http2"]),
                )
                .arg(clap::Arg::new("quiet").short('q').long("quiet").action(clap::ArgAction::SetTrue))
                .arg(clap::Arg::new("token").long("token").env("PODNET_TOKEN").hide_env_values(true).help("The token"))
                .arg(clap::Arg::new("name").value_name("NAME").help("The name").required(true)),
        )
        .subcommand(
            clap::Command::new("stop")
                .about("Stop an instance")
                .group(clap::ArgGroup::new("target").args(["name", "all"]).required(true))
                .arg(clap::Arg::new("name").help("The instance").env("PODNET_INSTANCE"))
                .arg(clap::Arg::new("all").long("all").action(clap::ArgAction::SetTrue).conflicts_with("name"))
                .arg(clap::Arg::new("secret").long("secret").hide(true).conflicts_with("all")),
        )
        .subcommand(
            clap::Command::new("net").subcommand(
                clap::Command::new("ts-shims")
                    .about("Write shims")
                    .arg(clap::Arg::new("out").long("out").short('o').value_name("DIR")),
            ),
        )
}

fn manual() -> pod_manual::Manual {
    pod_manual::clap::read(sample())
}

#[test]
fn the_text_has_each_command_and_flag() {
    let t = text::render(&manual());
    assert!(t.starts_with("podnet 1.0 (abc) - about podnet"), "{t}");
    assert!(t.contains("podnet tunnel"), "{t}");
    assert!(t.contains("--url URL"), "{t}");
    assert!(t.contains("Default: auto."), "{t}");
    assert!(t.contains("Values: auto, quic, http2."), "{t}");
    assert!(t.contains("-o, --out DIR"), "{t}");
    assert!(t.contains("-q, --quiet\n"), "{t}");
    assert!(t.lines().all(|l| l.len() <= text::WIDTH + 2), "a line is too long");
    assert!(t.is_ascii());
}

#[test]
fn the_reader_keeps_the_aliases_the_arguments_and_the_rules() {
    let m = manual();
    let t = m.command("expose").expect("the alias finds the command");
    assert_eq!(t.path, ["tunnel"]);
    assert_eq!(t.args[0].term(), "NAME");
    assert!(t.rules.contains(&Rule::Excludes { flags: vec!["--socket".into(), "--url".into()] }), "{:?}", t.rules);
    assert_eq!(t.flag("--quiet").unwrap().value, None);
    assert_eq!(t.flag("--socket").unwrap().value.as_deref(), Some("PATH"));
}

/// The reader gives the variable of each flag and argument (clap's `env`),
/// and the text names it.
#[test]
fn the_reader_gives_the_variable_of_each_flag() {
    let m = manual();
    let t = m.command("tunnel").unwrap();
    assert_eq!(t.flag("--token").unwrap().env.as_deref(), Some("PODNET_TOKEN"));
    assert_eq!(t.flag("--url").unwrap().env, None);
    assert_eq!(m.command("stop").unwrap().arg("NAME").unwrap().env.as_deref(), Some("PODNET_INSTANCE"));
    let text = text::render(&m);
    assert!(text.contains("The token. Variable: PODNET_TOKEN."), "{text}");
    assert!(text.contains("The instance. Variable: PODNET_INSTANCE."), "{text}");
}

/// A rule of clap that names a positional argument names it as the model
/// does, so the check of the model takes it; a rule with a hidden argument
/// is left out.
#[test]
fn a_rule_with_a_positional_argument_passes_the_check_of_the_model() {
    let m = manual();
    let stop = m.command("stop").unwrap();
    assert!(stop.rules.contains(&Rule::OneOf { flags: vec!["NAME".into(), "--all".into()], required: true }));
    assert!(stop.rules.contains(&Rule::Excludes { flags: vec!["--all".into(), "NAME".into()] }), "{:?}", stop.rules);
    assert_eq!(stop.rules.len(), 2, "{:?}", stop.rules);
    assert_none(model(&m));
}

/// The model of the reader agrees with the parser of the same tree.
#[test]
fn the_model_of_the_reader_agrees_with_the_parser() {
    assert_none(flags(&manual(), pod_manual::clap::parser(sample())));
    let other = sample().mut_subcommand("tunnel", |c| c.arg(clap::Arg::new("new").long("new")));
    assert_eq!(flags(&manual(), pod_manual::clap::parser(other)).len(), 1);
}

#[test]
fn sections_are_found_by_command_path() {
    let m = manual();
    let req = |s: &str| Request { section: Some(s.into()), ..Request::default() };
    assert!(body(&m, &req("net ts-shims")).unwrap().contains("--out"));
    assert!(body(&m, &req("net/ts-shims")).unwrap().contains("--out"));
    assert!(body(&m, &req("nothing")).unwrap_err().contains("no such section"));
}

#[test]
fn the_roff_page_uses_standard_macros_and_escapes() {
    let r = roff::render(&manual());
    assert!(r.starts_with(".TH PODNET 1"));
    for line in r.lines().filter(|l| l.starts_with('.')) {
        let mac = line.split_whitespace().next().unwrap();
        assert!(roff::MACROS.contains(&mac), "non-standard macro {mac}");
    }
    assert!(r.contains("\\-\\-url"), "hyphens are escaped");
    assert_eq!(roff::escape(".x"), "\\&.x");
}

#[test]
fn the_json_is_one_object_with_the_commands() {
    let j: serde_json::Value = serde_json::from_str(&json::text(&json::document(&manual()))).unwrap();
    assert!(j["commands"].as_array().unwrap().len() >= 5);
    assert_eq!(j["name"], "podnet");
}

/// `--help`, `COMMAND --help` and `help COMMAND` give the help of the
/// command from the model; `--json` gives its JSON.
#[test]
fn the_help_of_each_command_comes_from_the_model() {
    let m = manual();
    let ask = |args: &[&str]| help::request(&m, &args.iter().map(|a| a.to_string()).collect::<Vec<_>>());
    assert_eq!(ask(&["tunnel", "--url", "x"]), None);
    let h = ask(&["tunnel", "--help"]).unwrap();
    assert_eq!(h.path, ["tunnel"]);
    assert_eq!(ask(&["help", "expose"]).unwrap().path, ["tunnel"]);
    assert_eq!(ask(&["net", "ts-shims", "-h"]).unwrap().path, ["net", "ts-shims"]);
    assert_eq!(ask(&["--", "--help"]), None);
    let text = help::answer(&m, &h).unwrap();
    assert!(text.starts_with("  Expose a service.\n"), "{text}");
    assert!(text.contains("Usage: podnet tunnel [OPTIONS] NAME"), "{text}");
    assert!(text.contains("Other names: podnet expose"), "{text}");
    assert!(text.contains("Give only one of --socket, --url."), "{text}");
    let root = help::answer(&m, &ask(&["--help"]).unwrap()).unwrap();
    assert!(root.contains("Usage: podnet COMMAND [OPTIONS]") && root.contains("tunnel  Expose a service"), "{root}");
    let j = help::answer(&m, &ask(&["tunnel", "--help", "--json"]).unwrap()).unwrap();
    let j: serde_json::Value = serde_json::from_str(&j).unwrap();
    assert_eq!(j["command"]["path"], serde_json::json!(["tunnel"]));
}

/// A tree with clap's `requires` and `requires_if`: a chain of two needs, a
/// need of one value, a need of a value that a parser of addresses takes,
/// a need of a required positional argument and of one after it, a need of
/// a group and of a hidden flag. The flag that `--password-file` needs
/// takes `PATH` as its variable, set in each test run: the probe must not
/// take a variable as given. With no argument, the command shows its help:
/// the probe must not stop there.
fn needs_sample() -> clap::Command {
    let value = |id: &'static str, name: &'static str| clap::Arg::new(id).long(id).value_name(name);
    clap::Command::new("podnet").subcommand(
        clap::Command::new("login")
            .about("Log in")
            .arg_required_else_help(true)
            .arg(clap::Arg::new("target").value_name("TARGET").required(true).requires("host").help("The host"))
            .arg(clap::Arg::new("extra").value_name("EXTRA").requires("verbose").help("More"))
            .arg(value("user", "NAME").requires("password-file"))
            .arg(value("password-file", "FILE").requires("realm"))
            .arg(value("realm", "REALM").env("PATH"))
            .arg(value("mode", "MODE").value_parser(["plain", "tls"]).requires_if("tls", "cert"))
            .arg(value("cert", "FILE"))
            .arg(value("bind", "ADDR").value_parser(clap::value_parser!(std::net::Ipv4Addr)).requires("host"))
            .arg(value("host", "HOST"))
            .arg(clap::Arg::new("verbose").long("verbose").action(clap::ArgAction::SetTrue))
            .arg(clap::Arg::new("audit").long("audit").action(clap::ArgAction::SetTrue).requires("out"))
            .arg(clap::Arg::new("json").long("json").action(clap::ArgAction::SetTrue))
            .arg(clap::Arg::new("text").long("text").action(clap::ArgAction::SetTrue))
            .group(clap::ArgGroup::new("out").args(["json", "text"]))
            .arg(clap::Arg::new("debug").long("debug").action(clap::ArgAction::SetTrue).requires("trace"))
            .arg(clap::Arg::new("trace").long("trace").hide(true).action(clap::ArgAction::SetTrue)),
    )
}

fn needs(flag: &str, value: Option<&str>, needs: &[&str]) -> Rule {
    let needs = needs.iter().map(|n| n.to_string()).collect();
    Rule::Needs { flag: flag.into(), value: value.map(str::to_string), needs }
}

/// The reader gives clap's `requires` and `requires_if` as `Needs`, each
/// need once (a need of a need is not repeated), and the text names them.
#[test]
fn the_reader_gives_each_rule_of_requires() {
    assert!(std::env::var_os("PATH").is_some(), "the test needs PATH");
    let m = pod_manual::clap::read(needs_sample());
    let login = m.command("login").unwrap();
    let want = [
        needs("--user", None, &["--password-file"]),
        needs("--password-file", None, &["--realm"]),
        needs("--mode", Some("tls"), &["--cert"]),
        needs("--bind", None, &["--host"]),
        needs("TARGET", None, &["--host"]),
        needs("EXTRA", None, &["--verbose"]),
    ];
    let got: Vec<&Rule> = login.rules.iter().filter(|r| matches!(r, Rule::Needs { .. })).collect();
    assert_eq!(got, want.iter().collect::<Vec<_>>(), "the group of --audit and the hidden --trace are left out");
    assert_none(model(&m));
    let t = text::render(&m);
    for s in ["--user needs --password-file.", "--mode tls needs --cert.", "EXTRA needs --verbose."] {
        assert!(t.contains(s), "{s}: {t}");
    }
    let j: serde_json::Value = serde_json::from_str(&json::text(&json::document(&m))).unwrap();
    let rules = j["commands"].as_array().unwrap().iter().find(|c| c["path"] == serde_json::json!(["login"])).unwrap();
    assert_eq!(rules["rules"][1], serde_json::json!({"rule": "needs", "flag": "--user", "needs": ["--password-file"]}));
    assert_eq!(rules["rules"][3]["value"], "tls");
}

/// A tree with no `requires` gives no `Needs`: the required arguments and
/// the groups of the sample are no needs of a flag.
#[test]
fn a_tree_with_no_requires_gives_no_needs() {
    let m = manual();
    let any = m.commands.iter().flat_map(|c| &c.rules).find(|r| matches!(r, Rule::Needs { .. }));
    assert_eq!(any, None);
}
