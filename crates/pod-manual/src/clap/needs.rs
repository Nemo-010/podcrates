//! The rules of clap's `requires` and `requires_if` (`Rule::Needs`),
//! found by the parser itself. clap gives no getter of the requirements of
//! an argument, so each argument is given alone to a copy of the parser,
//! and the arguments that clap's `MissingRequiredArgument` error names are
//! the arguments that it needs.
//!
//! The copy of the tree: no variable gives a value (clap's `env`), and no
//! argument, group or command is required, so that an error names only what
//! the probed argument adds. An argument whose value parser takes none of
//! [`SAMPLES`] has no probe, and a `requires_if` on a value that is no
//! possible value of clap is not found.

use std::collections::BTreeSet;

use ::clap::error::{ContextKind, ContextValue, ErrorKind};
use ::clap::{ArgAction, Command};

use crate::model::Rule;

/// The values that a probe gives to an argument with no possible values,
/// in order. A value parser refuses some (a number, an address): the
/// probe takes the first two that it accepts.
pub(super) const SAMPLES: &[&str] = &["1", "a", "1s", "a=1", "127.0.0.1", "127.0.0.1:1", "http://a/", "true", "0"];

/// The tree for the probes: no variable, nothing required.
fn probe_tree(cmd: Command) -> Command {
    let groups: Vec<String> = cmd.get_groups().map(|g| g.get_id().to_string()).collect();
    let mut c = cmd
        .mut_args(|a| a.env(None).required(false))
        .arg_required_else_help(false)
        .subcommand_required(false)
        .ignore_errors(false);
    for g in groups {
        c = c.mut_group(g, |g| g.required(false));
    }
    c.mut_subcommands(probe_tree)
}

/// A copy of a clap tree, for the parses of the probes.
pub(super) struct Probe {
    root: Command,
}

impl Probe {
    /// The probe of `cmd`, a tree that is not built.
    pub(super) fn new(cmd: &Command) -> Self {
        let mut root = probe_tree(cmd.clone());
        root.build();
        Probe { root }
    }

    /// The arguments, as clap shows them, that a parse of `tokens` after
    /// the command `path` misses; none when the parse fails for another
    /// cause (a refused value).
    fn missing(&mut self, path: &[String], tokens: &[String]) -> Option<Vec<String>> {
        let name = self.root.get_name().to_string();
        let argv = std::iter::once(&name).chain(path).chain(tokens);
        match self.root.try_get_matches_from_mut(argv) {
            Ok(_) => Some(Vec::new()),
            Err(e) if e.kind() == ErrorKind::MissingRequiredArgument => match e.get(ContextKind::InvalidArg) {
                Some(ContextValue::Strings(v)) => Some(v.clone()),
                _ => None,
            },
            Err(_) => None,
        }
    }

    /// The command at `path` in the tree of the probes.
    fn command(&self, path: &[String]) -> Option<&Command> {
        path.iter().try_fold(&self.root, |c, w| c.find_subcommand(w))
    }
}

/// The tokens that give `arg` with the value `value`.
fn tokens(arg: &::clap::Arg, value: &str) -> Vec<String> {
    let count = arg.get_num_args().map_or(1, |n| n.min_values().max(1));
    if arg.is_positional() {
        let lead = arg.is_last_set().then(|| "--".to_string());
        return lead.into_iter().chain(std::iter::repeat_n(value.to_string(), count)).collect();
    }
    let name = super::spelling(arg);
    if !super::takes_value(arg) {
        return vec![name];
    }
    if arg.is_require_equals_set() {
        return vec![format!("{name}={value}")];
    }
    std::iter::once(name).chain(std::iter::repeat_n(value.to_string(), count)).collect()
}

/// The values to probe: each shown possible value (a rule may hold for one
/// value only), else the samples; none for a flag with no value.
fn values(arg: &::clap::Arg) -> (Vec<String>, bool) {
    if !arg.is_positional() && !super::takes_value(arg) {
        return (vec![String::new()], false);
    }
    let shown = super::values(arg);
    if shown.is_empty() { (SAMPLES.iter().map(|s| s.to_string()).collect(), false) } else { (shown, true) }
}

/// What a probe found for one argument: the needs with each value, and
/// whether the values are the possible values of clap.
struct Found {
    spelling: String,
    each: Vec<(String, BTreeSet<usize>)>,
    possible: bool,
}

fn probe(p: &mut Probe, path: &[String], lead: &[String], arg: &::clap::Arg, keys: &[String]) -> Option<Found> {
    let base: BTreeSet<String> = p.missing(path, lead)?.into_iter().collect();
    let (vals, possible) = values(arg);
    let mut each = Vec::new();
    for v in vals {
        let given: Vec<String> = lead.iter().cloned().chain(tokens(arg, &v)).collect();
        let Some(miss) = p.missing(path, &given) else { continue };
        // A shown argument of the command that the parse names and the base
        // parse does not. A group or an argument of two shown forms is no
        // single need.
        let need = miss.iter().filter(|m| !base.contains(*m)).filter_map(|m| {
            let mut at = keys.iter().enumerate().filter(|(_, k)| *k == m).map(|(i, _)| i);
            at.next().filter(|_| at.next().is_none())
        });
        each.push((v, need.collect()));
        if !possible && each.len() == 2 {
            break;
        }
    }
    (!each.is_empty()).then(|| Found { spelling: super::spelling(arg), each, possible })
}

/// The `Needs` rules of the command at `path`. A rule that names a hidden
/// argument is left out, as the model has no hidden argument.
pub(super) fn rules(p: &mut Probe, path: &[String]) -> Vec<Rule> {
    let Some(cmd) = p.command(path) else { return Vec::new() };
    let args: Vec<::clap::Arg> = cmd.get_arguments().cloned().collect();
    // clap shows a missing argument as its usage with a value: the key of
    // each argument.
    let keys: Vec<String> = args.iter().map(|a| a.clone().required(true).to_string()).collect();
    let skip = |a: &::clap::Arg| {
        a.is_hide_set()
            || matches!(
                a.get_action(),
                ArgAction::Help | ArgAction::HelpShort | ArgAction::HelpLong | ArgAction::Version
            )
    };
    let mut found: Vec<(usize, Found)> = Vec::new();
    // The values of the positional arguments before the next one: clap
    // fills them in their order. A positional with no accepted value ends
    // the probes of the positionals after it.
    let mut lead: Option<Vec<String>> = Some(Vec::new());
    let mut by_index: Vec<usize> = (0..args.len()).filter(|i| args[*i].is_positional()).collect();
    by_index.sort_by_key(|i| args[*i].get_index());
    let flags = (0..args.len()).filter(|i| !args[*i].is_positional());
    for i in flags.chain(by_index) {
        let a = &args[i];
        let in_order = a.is_positional() && !a.is_last_set();
        let before = if in_order { lead.clone() } else { Some(Vec::new()) };
        let f = before.filter(|_| !skip(a)).and_then(|b| probe(p, path, &b, a, &keys));
        if in_order {
            let value = f.as_ref().and_then(|f| f.each.first()).map(|(v, _)| tokens(a, v));
            lead = lead.zip(value).map(|(l, v)| l.into_iter().chain(v).collect());
        }
        if let Some(f) = f {
            found.push((i, f));
        }
    }
    shape(&args, &found)
}

/// The rules of the probes: the needs of each value in common, then the
/// needs of one value alone; a need that another need of the same argument
/// gives is left out (clap's `requires` is followed through).
fn shape(args: &[::clap::Arg], found: &[(usize, Found)]) -> Vec<Rule> {
    let common = |f: &Found| -> BTreeSet<usize> {
        let mut sets = f.each.iter().map(|(_, s)| s.clone());
        let first = sets.next().unwrap_or_default();
        sets.fold(first, |acc, s| acc.intersection(&s).copied().collect())
    };
    let plain: Vec<(usize, BTreeSet<usize>)> = found.iter().map(|(i, f)| (*i, common(f))).collect();
    let of = |i: usize| plain.iter().find(|(j, _)| *j == i).map(|(_, s)| s.clone()).unwrap_or_default();
    let direct = |needs: &BTreeSet<usize>, all: &BTreeSet<usize>| -> Vec<String> {
        let given = |c: &usize| all.iter().any(|b| b != c && of(*b).contains(c) && !of(*c).contains(b));
        let shown = needs.iter().filter(|c| !args[**c].is_hide_set() && !given(c));
        shown.map(|c| super::spelling(&args[*c])).collect()
    };
    let mut out = Vec::new();
    for (i, f) in found {
        let all = of(*i);
        let needs = direct(&all, &all);
        if !needs.is_empty() {
            out.push(Rule::Needs { flag: f.spelling.clone(), value: None, needs });
        }
        if !f.possible {
            continue;
        }
        for (v, s) in &f.each {
            let extra: BTreeSet<usize> = s.difference(&all).copied().collect();
            let needs = direct(&extra, s);
            if !needs.is_empty() {
                out.push(Rule::Needs { flag: f.spelling.clone(), value: Some(v.clone()), needs });
            }
        }
    }
    out
}
