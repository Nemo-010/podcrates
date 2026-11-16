//! The manual as sections of blocks: each command, each topic and each
//! table of facts. The text and the man page writers render these blocks
//! only, so they show the same content.

use crate::facts::{Code, Use};
use crate::model::{Arg, Availability, Block, Command, Flag, FlagKind, Manual, Span, Topic};

/// One section of the manual.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    /// The name that `man KEY` selects it by: the path of a command, or the
    /// key of a topic.
    pub key: String,
    pub aliases: Vec<String>,
    pub heading: String,
    /// The path of the command of a command section.
    pub command: Option<Vec<String>>,
    pub blocks: Vec<Block>,
}

pub(crate) fn lit(t: impl Into<String>) -> Span {
    Span::Lit(t.into())
}

pub(crate) fn var(t: impl Into<String>) -> Span {
    Span::Var(t.into())
}

pub(crate) fn plain_span(t: impl Into<String>) -> Span {
    Span::Plain(t.into())
}

pub(crate) fn para(t: impl Into<String>) -> Block {
    Block::Para { text: t.into() }
}

fn item(term: Vec<Span>, text: impl Into<String>) -> Block {
    Block::Item { term, text: text.into() }
}

/// `text` with a stop at its end, then each of `extra`.
pub(crate) fn sentence(text: &str, extra: &[String]) -> String {
    let mut out = text.trim().to_string();
    if !out.is_empty() && !out.ends_with(['.', '!', '?', ':']) {
        out.push('.');
    }
    for e in extra {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(e);
    }
    out
}

/// The usage of a command after the name of the program.
pub fn usage(manual: &Manual, c: &Command) -> String {
    let mut words = vec![manual.name.clone()];
    words.extend(c.path.iter().cloned());
    if !c.usage.is_empty() {
        words.push(c.usage.clone());
        return words.join(" ");
    }
    if !manual.children(&c.path).is_empty() {
        words.push("COMMAND".into());
    }
    if !c.flags.is_empty() {
        words.push("[OPTIONS]".into());
    }
    words.extend(c.args.iter().map(Arg::term));
    words.join(" ")
}

fn flag_spans(f: &Flag) -> Vec<Span> {
    let mut t = Vec::new();
    for (i, s) in f.spellings().into_iter().enumerate() {
        if i > 0 {
            t.push(plain_span(", "));
        }
        t.push(lit(s));
    }
    if let Some(v) = &f.value {
        t.push(plain_span(" "));
        t.push(var(v.clone()));
    }
    t
}

/// The text of a flag: its help, then what the model adds.
pub fn flag_text(f: &Flag) -> String {
    let mut extra = Vec::new();
    match &f.kind {
        FlagKind::Wired => {}
        FlagKind::Ignored { why } if why.trim().is_empty() => extra.push("Accepted and ignored.".into()),
        FlagKind::Ignored { why } => extra.push(sentence(&format!("Accepted and ignored: {why}"), &[])),
        FlagKind::Refused { instead } if instead.trim().is_empty() => extra.push("Refused.".into()),
        FlagKind::Refused { instead } => extra.push(sentence(&format!("Refused. Use {instead}"), &[])),
        FlagKind::NotInRelease { code, why } => {
            let not = match why.trim() {
                "" => "Not in this release.".to_string(),
                why => sentence(&format!("Not in this release: {why}"), &[]),
            };
            extra.push(sentence(&not, &[format!("It exits {code}.")]));
        }
    }
    if let Some(p) = &f.parity {
        extra.push(sentence(&format!("Against {}: {}. {}", p.tool, p.status.word(), p.text), &[]));
    }
    extra.extend(f.default.as_ref().map(|d| format!("Default: {d}.")));
    if !f.values.is_empty() {
        extra.push(format!("Values: {}.", f.values.join(", ")));
    }
    extra.extend(f.env.as_ref().map(|e| format!("Variable: {e}.")));
    if f.required {
        extra.push("Required.".into());
    }
    sentence(&f.help, &extra)
}

fn arg_text(a: &Arg) -> String {
    let mut extra = Vec::new();
    extra.extend(a.default.as_ref().map(|d| format!("Default: {d}.")));
    if !a.values.is_empty() {
        extra.push(format!("Values: {}.", a.values.join(", ")));
    }
    extra.extend(a.env.as_ref().map(|e| format!("Variable: {e}.")));
    sentence(&a.help, &extra)
}

/// Whether the example line `line` is of the command `c`: its words after
/// the name are the path of `c`, and the next word is no subcommand of `c`.
fn example_of(manual: &Manual, line: &str, c: &Command) -> bool {
    let words: Vec<&str> = line.split_whitespace().skip(1).collect();
    let children: Vec<String> = manual.children(&c.path).iter().filter_map(|k| k.path.last().cloned()).collect();
    words.len() >= c.path.len()
        && words.iter().zip(&c.path).all(|(w, p)| w == p)
        && words.get(c.path.len()).is_none_or(|next| !children.iter().any(|s| s == next))
}

/// The tables of the commands under `c`: one for each group of
/// [`Command::groups`], then "Other commands" for each command in no group;
/// with no group, one table "Commands".
fn commands(manual: &Manual, c: &Command) -> Vec<Block> {
    let children = manual.children(&c.path);
    let word = |k: &Command| k.path.last().cloned().unwrap_or_default();
    let row = |k: &Command| (vec![lit(word(k))], k.about.clone());
    let mut blocks = Vec::new();
    for g in &c.groups {
        let rows: Vec<_> =
            g.commands.iter().filter_map(|w| children.iter().find(|k| word(k) == *w)).map(|k| row(k)).collect();
        blocks.push(Block::Sub { text: g.title.clone() });
        blocks.push(Block::Table { rows });
    }
    let rest: Vec<_> =
        children.iter().filter(|k| !c.groups.iter().any(|g| g.commands.contains(&word(k)))).map(|k| row(k)).collect();
    if !rest.is_empty() {
        let title = if c.groups.is_empty() { "Commands" } else { "Other commands" };
        blocks.push(Block::Sub { text: title.into() });
        blocks.push(Block::Table { rows: rest });
    }
    blocks
}

/// The blocks of a command: what `--help` and the manual show.
pub fn command_blocks(manual: &Manual, c: &Command) -> Vec<Block> {
    let mut blocks = Vec::new();
    if !c.about.is_empty() {
        blocks.push(para(sentence(&c.about, &[])));
    }
    blocks.extend(c.notes.iter().map(para));
    if !c.aliases.is_empty() {
        let mut line = vec![plain_span("Other names: ")];
        let head: Vec<&str> = c.path.iter().take(c.path.len().saturating_sub(1)).map(String::as_str).collect();
        for (i, a) in c.aliases.iter().enumerate() {
            if i > 0 {
                line.push(plain_span(", "));
            }
            let mut words = vec![manual.name.as_str()];
            words.extend(&head);
            words.push(a);
            line.push(lit(words.join(" ")));
        }
        blocks.push(Block::Line { spans: line });
    }
    if let Some(p) = &c.parity {
        blocks.push(para(sentence(&format!("Against {}: {}. {}", p.tool, p.status.word(), p.text), &[])));
    }
    if let Availability::Feature { name, why, code } = &c.availability {
        let only = format!("Only a build with the feature {name} has this command: {why}");
        blocks.push(para(sentence(&only, &[format!("Each other build exits {code}.")])));
    }
    blocks.push(Block::Line { spans: vec![plain_span("Usage: "), lit(usage(manual, c))] });
    if !c.lead.is_empty() {
        blocks.push(Block::Sub { text: "Start here".into() });
        let rows = c.lead.iter().map(|e| (vec![lit(e.command.clone())], e.meaning.clone()));
        blocks.push(Block::Table { rows: rows.collect() });
    }
    blocks.extend(commands(manual, c));
    if !c.args.is_empty() {
        blocks.push(Block::Sub { text: "Arguments".into() });
        blocks.extend(c.args.iter().map(|a| item(vec![var(a.term())], arg_text(a))));
    }
    if !c.flags.is_empty() {
        blocks.push(Block::Sub { text: "Options".into() });
        blocks.extend(c.flags.iter().map(|f| item(flag_spans(f), flag_text(f))));
    }
    if !c.rules.is_empty() {
        blocks.push(Block::Sub { text: "Rules".into() });
        blocks.extend(c.rules.iter().map(|r| para(r.sentence())));
    }
    for t in c.topics.iter().filter_map(|k| manual.topics.iter().find(|t| t.key == *k)) {
        blocks.push(Block::Sub { text: t.heading.clone() });
        blocks.extend(t.blocks.iter().cloned());
    }
    let own: Vec<_> =
        manual.examples.iter().filter(|e| !c.path.is_empty() && example_of(manual, &e.command, c)).collect();
    if !own.is_empty() {
        blocks.push(Block::Sub { text: "Examples".into() });
        blocks.extend(own.iter().map(|e| Block::Example { text: e.meaning.clone(), command: e.command.clone() }));
    }
    blocks
}

fn topic(key: &str, aliases: &[&str], heading: &str, blocks: Vec<Block>) -> Section {
    Section {
        key: key.into(),
        aliases: aliases.iter().map(|a| a.to_string()).collect(),
        heading: heading.into(),
        command: None,
        blocks,
    }
}

fn environment(manual: &Manual) -> Vec<Block> {
    let mut blocks = Vec::new();
    for g in &manual.facts.variables {
        if !g.name.is_empty() {
            blocks.push(Block::Sub { text: g.name.clone() });
        }
        for v in &g.vars {
            let mut extra = Vec::new();
            extra.extend(v.default.as_ref().map(|d| format!("Default: {d}.")));
            if !v.used_by.is_empty() {
                extra.push(format!("Used by: {}.", v.used_by));
            }
            match v.usage {
                Use::Reads => {}
                Use::Sets => extra.push(format!("{} sets it and does not read it.", manual.name)),
                Use::ReadsAndSets => extra.push(format!("{} reads it and sets it.", manual.name)),
            }
            let mut term = Vec::new();
            for (i, n) in v.names.iter().enumerate() {
                if i > 0 {
                    term.push(plain_span(", "));
                }
                term.push(lit(n.clone()));
            }
            blocks.push(item(term, sentence(&v.meaning, &extra)));
        }
    }
    blocks
}

fn exit_status(manual: &Manual) -> Vec<Block> {
    let rows = manual.facts.exits.iter().map(|e| {
        let mut term = vec![lit(e.code.words())];
        if !e.name.is_empty() {
            term.push(plain_span(format!(" ({})", e.name)));
        }
        let text = match e.code {
            Code::Payload => sentence(&e.meaning, &["Each code that no other row names.".into()]),
            _ => sentence(&e.meaning, &[]),
        };
        item(term, text)
    });
    rows.collect()
}

fn configuration(manual: &Manual) -> Vec<Block> {
    let mut blocks = Vec::new();
    for f in &manual.facts.config {
        blocks.push(Block::Sub { text: f.path.clone() });
        if !f.about.is_empty() {
            blocks.push(para(sentence(&f.about, &[])));
        }
        for k in &f.keys {
            let mut extra = Vec::new();
            extra.extend(k.default.as_ref().map(|d| format!("Default: {d}.")));
            extra.extend(k.flag.as_ref().map(|d| format!("Flag: {d}.")));
            blocks.push(item(
                vec![lit(k.key.clone()), plain_span(" = "), var(k.value.clone())],
                sentence(&k.meaning, &extra),
            ));
        }
    }
    blocks
}

/// Each section of the manual, in the order of the page: the commands, the
/// topics, then the facts, the examples and SEE ALSO. An empty table of
/// facts has no section.
pub fn sections(manual: &Manual) -> Vec<Section> {
    let mut out: Vec<Section> = manual
        .commands
        .iter()
        .filter(|c| !c.path.is_empty())
        .map(|c| Section {
            key: c.name(),
            aliases: c.aliases.clone(),
            heading: format!("{} {}", manual.name, c.name()),
            command: Some(c.path.clone()),
            blocks: command_blocks(manual, c),
        })
        .collect();
    let within = |t: &&Topic| manual.commands.iter().any(|c| c.topics.contains(&t.key));
    out.extend(manual.topics.iter().filter(|t| !within(t)).map(|t: &Topic| Section {
        key: t.key.clone(),
        aliases: t.aliases.clone(),
        heading: t.heading.clone(),
        command: None,
        blocks: t.blocks.clone(),
    }));
    let facts = &manual.facts;
    if facts.variables.iter().any(|g| !g.vars.is_empty()) {
        out.push(topic("environment", &["env"], "ENVIRONMENT", environment(manual)));
    }
    if !facts.files.is_empty() {
        let files = facts.files.iter().map(|f| item(vec![lit(f.path.clone())], sentence(&f.meaning, &[])));
        out.push(topic("files", &[], "FILES", files.collect()));
    }
    if !facts.config.is_empty() {
        out.push(topic("configuration", &["config"], "CONFIGURATION", configuration(manual)));
    }
    for t in &facts.tables {
        let mut blocks = Vec::new();
        if !t.about.is_empty() {
            blocks.push(para(sentence(&t.about, &[])));
        }
        for row in &t.rows {
            let cells: Vec<String> = t.columns.iter().zip(row).skip(1).map(|(c, v)| format!("{c}: {v}.")).collect();
            blocks.push(item(vec![lit(row.first().cloned().unwrap_or_default())], cells.join(" ")));
        }
        out.push(topic(&t.key, &[], &t.heading, blocks));
    }
    if !facts.exits.is_empty() {
        out.push(topic("exit-status", &[], "EXIT STATUS", exit_status(manual)));
    }
    if !manual.examples.is_empty() {
        let examples =
            manual.examples.iter().map(|e| Block::Example { text: e.meaning.clone(), command: e.command.clone() });
        out.push(topic("examples", &[], "EXAMPLES", examples.collect()));
    }
    if !manual.see_also.is_empty() {
        let lines = manual.see_also.iter().map(|l| Block::Line { spans: vec![plain_span(l.clone())] });
        out.push(topic("see-also", &[], "SEE ALSO", lines.collect()));
    }
    out
}

/// The section for `name`: a command path (`warp run`, `warp/run`, an
/// alias in place of the last word), a key or an alias of a topic, in any
/// case.
pub fn find<'a>(manual: &Manual, all: &'a [Section], name: &str) -> Option<&'a Section> {
    if let Some(c) = manual.command(name).filter(|c| !c.path.is_empty()) {
        return all.iter().find(|s| s.command.as_ref() == Some(&c.path));
    }
    let name = name.trim().replace(' ', "-");
    let names = |key: &str, aliases: &[String]| {
        key.eq_ignore_ascii_case(&name) || aliases.iter().any(|a| a.eq_ignore_ascii_case(&name))
    };
    let own = all.iter().find(|s| s.command.is_none() && names(&s.key, &s.aliases));
    // A topic inside the section of a command selects that command.
    own.or_else(|| {
        let t = manual.topics.iter().find(|t| names(&t.key, &t.aliases))?;
        let c = manual.commands.iter().find(|c| c.topics.contains(&t.key))?;
        all.iter().find(|s| s.command.as_ref() == Some(&c.path))
    })
}

#[cfg(test)]
mod tests;
