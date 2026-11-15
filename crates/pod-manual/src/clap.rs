//! The reader of a clap command tree (feature `clap`): one way to fill the
//! model, for a program whose parser is clap. [`read`] gives the commands,
//! their arguments, flags and rules; the program adds its facts, topics and
//! examples. [`parser`] gives the rows of the same tree for
//! `check::flags`, so that a test proves the model and the parser agree.

use crate::check::{ParserCommand, ParserFlag};
use crate::model::{Arg, Command, Flag, Manual, Rule};

fn text(s: Option<&::clap::builder::StyledStr>) -> String {
    s.map(|s| s.to_string()).unwrap_or_default()
}

fn value_name(arg: &::clap::Arg) -> String {
    arg.get_value_names()
        .and_then(|v| v.first())
        .map(|s| s.to_string())
        .unwrap_or_else(|| arg.get_id().as_str().to_ascii_uppercase())
}

fn takes_value(arg: &::clap::Arg) -> bool {
    arg.get_action().takes_values()
}

fn many(arg: &::clap::Arg) -> bool {
    matches!(arg.get_action(), ::clap::ArgAction::Append | ::clap::ArgAction::Count)
        || arg.get_num_args().is_some_and(|n| n.max_values() > 1)
}

fn defaults(arg: &::clap::Arg) -> Option<String> {
    let values: Vec<String> = arg.get_default_values().iter().map(|v| v.to_string_lossy().into_owned()).collect();
    (!values.is_empty() && takes_value(arg)).then(|| values.join(","))
}

fn values(arg: &::clap::Arg) -> Vec<String> {
    arg.get_possible_values().iter().filter(|v| !v.is_hide_set()).map(|v| v.get_name().to_string()).collect()
}

fn help(arg: &::clap::Arg) -> String {
    let long = text(arg.get_long_help());
    if long.is_empty() { text(arg.get_help()) } else { long }
}

/// The spelling of an argument in a rule: `--long`, `-x`, or the value
/// name of a positional.
fn spelling(arg: &::clap::Arg) -> String {
    match (arg.get_long(), arg.get_short()) {
        (Some(l), _) => format!("--{l}"),
        (None, Some(s)) => format!("-{s}"),
        (None, None) => value_name(arg),
    }
}

fn rules(cmd: &::clap::Command) -> Vec<Rule> {
    let mut out: Vec<Rule> = Vec::new();
    let by_id = |id: &::clap::Id| cmd.get_arguments().find(|a| a.get_id() == id).map(spelling);
    for g in cmd.get_groups().filter(|g| !(*g).clone().is_multiple()) {
        let flags: Vec<String> = g.get_args().filter_map(by_id).collect();
        if flags.len() > 1 {
            out.push(Rule::OneOf { flags, required: g.is_required_set() });
        }
    }
    for a in cmd.get_arguments().filter(|a| !a.is_hide_set()) {
        for b in cmd.get_arg_conflicts_with(a) {
            let mut pair = vec![spelling(a), spelling(b)];
            pair.sort();
            let rule = Rule::Excludes { flags: pair };
            if !out.contains(&rule) {
                out.push(rule);
            }
        }
    }
    out
}

fn walk(cmd: &::clap::Command, path: Vec<String>, out: &mut Vec<Command>) {
    let args = cmd.get_positionals().filter(|a| !a.is_hide_set());
    let args = args.map(|a| Arg {
        name: value_name(a),
        help: help(a),
        required: a.is_required_set(),
        many: many(a),
        default: defaults(a),
        values: values(a),
    });
    let flags = cmd.get_arguments().filter(|a| !a.is_positional() && !a.is_hide_set());
    let flags = flags.map(|a| Flag {
        short: a.get_short(),
        long: a.get_long().map(str::to_string),
        value: takes_value(a).then(|| value_name(a)),
        help: help(a),
        default: defaults(a),
        values: values(a),
        required: a.is_required_set(),
        repeatable: many(a),
        ..Flag::default()
    });
    let about = text(cmd.get_about());
    let long = text(cmd.get_long_about());
    let mut notes: Vec<String> = long.split("\n\n").map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect();
    // clap's `about` is the first paragraph of the long text, with no stop.
    if notes.first().is_some_and(|n| n.trim_end_matches('.') == about.trim_end_matches('.')) {
        notes.remove(0);
    }
    out.push(Command {
        path: path.clone(),
        aliases: cmd.get_visible_aliases().map(str::to_string).collect(),
        about,
        notes,
        args: args.collect(),
        flags: flags.collect(),
        rules: rules(cmd),
        ..Command::default()
    });
    for sub in cmd.get_subcommands().filter(|c| !c.is_hide_set() && c.get_name() != "help") {
        let mut p = path.clone();
        p.push(sub.get_name().to_string());
        walk(sub, p, out);
    }
}

/// The model of the command tree `cmd`: the name, the version, the about
/// line and each command. The program adds the rest.
pub fn read(mut cmd: ::clap::Command) -> Manual {
    cmd.build();
    let mut commands = Vec::new();
    walk(&cmd, Vec::new(), &mut commands);
    Manual {
        name: cmd.get_name().to_string(),
        version: cmd.get_version().unwrap_or_default().to_string(),
        about: text(cmd.get_about()),
        commands,
        ..Manual::default()
    }
}

/// The rows of the parser of `cmd`, for `check::flags`.
pub fn parser(mut cmd: ::clap::Command) -> impl Fn(&[String]) -> Option<ParserCommand> {
    cmd.build();
    let mut rows: Vec<(Vec<String>, ParserCommand)> = Vec::new();
    fn rows_of(cmd: &::clap::Command, path: Vec<String>, out: &mut Vec<(Vec<String>, ParserCommand)>) {
        let flags = cmd.get_arguments().filter(|a| !a.is_positional() && !a.is_hide_set()).map(|a| {
            let mut spellings: Vec<String> = a.get_short().map(|s| format!("-{s}")).into_iter().collect();
            spellings.extend(a.get_long().map(|l| format!("--{l}")));
            ParserFlag { spellings, takes_value: takes_value(a) }
        });
        let subs: Vec<&::clap::Command> =
            cmd.get_subcommands().filter(|c| !c.is_hide_set() && c.get_name() != "help").collect();
        let subcommands = subs.iter().map(|c| c.get_name().to_string()).collect();
        out.push((path.clone(), ParserCommand { flags: flags.collect(), subcommands }));
        for sub in subs {
            let mut p = path.clone();
            p.push(sub.get_name().to_string());
            rows_of(sub, p, out);
        }
    }
    rows_of(&cmd, Vec::new(), &mut rows);
    move |path: &[String]| rows.iter().find(|(p, _)| p == path).map(|(_, c)| c.clone())
}
