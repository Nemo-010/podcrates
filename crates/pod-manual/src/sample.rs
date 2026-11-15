//! A manual with each part of the model, for the tests of the writers and
//! the checks.

use crate::facts::{Code, ConfigFile, ConfigKey, Exit, Facts, FileFact, Table, Var, VarGroup};
use crate::model::{Arg, Block, Command, Example, Flag, FlagKind, Manual, Parity, Rule, Span, Status, Topic};

fn s(t: &str) -> String {
    t.to_string()
}

fn command(path: &[&str], about: &str) -> Command {
    Command { path: path.iter().map(|p| s(p)).collect(), about: s(about), ..Command::default() }
}

pub fn manual() -> Manual {
    let root = Command {
        flags: vec![
            Flag { short: Some('v'), ..Flag::long("verbose", "Write more lines to stderr") },
            Flag { short: Some('V'), ..Flag::long("version", "Print the version") },
        ],
        ..command(&[], "")
    };
    let tunnel = Command {
        notes: vec![s("A tunnel stays until the program stops.")],
        args: vec![Arg { name: s("NAME"), help: s("The name of the tunnel"), ..Arg::default() }],
        flags: vec![
            Flag { value: Some(s("URL")), ..Flag::long("url", "The HTTP origin") },
            Flag { value: Some(s("PATH")), ..Flag::long("socket", "A Unix socket as the origin") },
            Flag {
                value: Some(s("PROTOCOL")),
                default: Some(s("auto")),
                values: vec![s("auto"), s("quic"), s("http2")],
                env: Some(s("SAMPLE_PROTOCOL")),
                ..Flag::long("protocol", "The protocol to the edge")
            },
            Flag {
                kind: FlagKind::Ignored { why: s("the edge picks the region") },
                ..Flag::long("region", "A region")
            },
        ],
        rules: vec![
            Rule::Excludes { flags: vec![s("--url"), s("--socket")] },
            Rule::OneOf { flags: vec![s("--url"), s("--socket")], required: true },
        ],
        ..command(&["tunnel"], "Expose a local service")
    };
    let net = command(&["net"], "Virtual networks");
    let shims = Command {
        flags: vec![Flag {
            short: Some('o'),
            value: Some(s("DIR")),
            ..Flag::long("out", "The directory of the shims")
        }],
        ..command(&["net", "ts-shims"], "Write the shims")
    };
    let chat = Command {
        aliases: vec![s("irc")],
        parity: Some(Parity { tool: s("irssi"), status: Status::Degraded, text: s("One channel only.") }),
        flags: vec![
            Flag {
                short: Some('A'),
                kind: FlagKind::Refused { instead: s("--forward") },
                parity: Some(Parity { tool: s("ssh"), status: Status::Refused, text: s("No agent here.") }),
                ..Flag::default()
            },
            Flag { value: Some(s("NODE")), ..Flag::long("forward", "Forward to a node") },
        ],
        ..command(&["chat"], "Messages with another node")
    };
    let notes = Topic {
        key: s("notes"),
        aliases: vec![s("guide")],
        heading: s("NOTES"),
        blocks: vec![
            Block::Para { text: s("The notes of the sample.") },
            Block::Sub { text: s("Setup") },
            Block::Steps { steps: vec![s("Install the binary."), s("Run sample tunnel --url http://127.0.0.1:8080.")] },
            Block::Line { spans: vec![Span::Lit(s("sample")), Span::Plain(s(" ")), Span::Var(s("COMMAND"))] },
            Block::Item { term: vec![Span::Lit(s(".dot-term"))], text: s("A term that starts with a dot.") },
            Block::Table {
                rows: vec![
                    (vec![Span::Lit(s("ab"))], s("A short term.")),
                    (vec![Span::Lit(s("a-term-that-is-too-wide"))], s("A wide term.")),
                ],
            },
            Block::Example { text: s("Start a tunnel."), command: s("sample tunnel --url http://127.0.0.1:8080") },
        ],
    };
    let facts = Facts {
        variables: vec![
            VarGroup {
                name: String::new(),
                vars: vec![Var::reads(&["HTTPS_PROXY", "https_proxy"], "The proxy for each connection")],
            },
            VarGroup {
                name: s("The tunnel"),
                vars: vec![
                    Var {
                        used_by: s("tunnel"),
                        default: Some(s("auto")),
                        ..Var::reads(&["SAMPLE_PROTOCOL"], "The value of --protocol")
                    },
                    Var::sets(&["SAMPLE_CHILD"], "The name of the tunnel, for the origin"),
                ],
            },
        ],
        exits: vec![
            Exit::new(0, "success", "The command did its work."),
            Exit::new(64, "usage", "A usage error."),
            Exit { code: Code::Range { from: 65, to: 70 }, name: s("other"), meaning: s("Other faults.") },
            Exit { code: Code::Signal, name: s("signal"), meaning: s("The payload ended on signal N.") },
            Exit { code: Code::Payload, name: s("payload"), meaning: s("The exit code of the payload.") },
        ],
        files: vec![FileFact { path: s("$HOME/.config/sample/state.json"), meaning: s("The state of the tunnels.") }],
        config: vec![ConfigFile {
            path: s("sample.toml"),
            about: s("Each key is an option."),
            keys: vec![ConfigKey {
                key: s("protocol"),
                value: s("PROTOCOL"),
                default: Some(s("auto")),
                flag: Some(s("--protocol")),
                meaning: s("The protocol to the edge."),
            }],
        }],
        tables: vec![Table {
            key: s("keywords"),
            heading: s("KEYWORDS"),
            about: s("The keywords of -o."),
            columns: vec![s("Keyword"), s("Value"), s("Meaning")],
            rows: vec![vec![s("Port"), s("PORT"), s("The port to connect to")]],
        }],
    };
    Manual {
        name: s("sample"),
        version: s("1.0"),
        date: s("2026-11-15"),
        about: s("a sample program for the tests"),
        names: vec![s("sample-alias")],
        description: vec![s("The sample has each part of the model."), s("A second paragraph.")],
        commands: vec![root, tunnel, net, shims, chat],
        topics: vec![notes],
        facts,
        examples: vec![
            Example {
                command: s("sample tunnel --url http://127.0.0.1:8080"),
                meaning: s("Expose a local web server."),
            },
            Example { command: s("sample net ts-shims -o /tmp/shims"), meaning: s("Write the shims to a directory.") },
        ],
        see_also: vec![s("sample man --roff")],
    }
}
