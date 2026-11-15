//! The reader of clap (feature `clap`), with the tests of podnet's manual
//! over its sample command tree.
#![cfg(feature = "clap")]

use pod_manual::check::{assert_none, flags};
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
                .arg(clap::Arg::new("name").value_name("NAME").help("The name").required(true)),
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
    assert!(j["commands"].as_array().unwrap().len() >= 4);
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
