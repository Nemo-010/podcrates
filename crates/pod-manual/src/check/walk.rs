//! The walk of each string of a manual for the text rules.

use super::{Finding, text};
use crate::model::{Block, FlagKind, Manual, plain};
use crate::rules::Kind;

const D: Option<Kind> = Some(Kind::Description);
const P: Option<Kind> = Some(Kind::Procedure);
const TERM: Option<Kind> = None;

struct Walk {
    out: Vec<Finding>,
}

impl Walk {
    fn one(&mut self, at: &str, s: &str, kind: Option<Kind>) {
        self.out.extend(text(at, s, kind));
    }

    fn all<'a>(&mut self, at: &str, list: impl IntoIterator<Item = &'a String>, kind: Option<Kind>) {
        for s in list {
            self.one(at, s, kind);
        }
    }

    fn blocks(&mut self, at: &str, blocks: &[Block]) {
        for b in blocks {
            match b {
                Block::Para { text } => self.one(at, text, D),
                Block::Steps { steps } => self.all(at, steps, P),
                Block::Line { spans } => self.one(at, &plain(spans), D),
                Block::Sub { text } => self.one(at, text, D),
                Block::Item { term, text } => {
                    self.one(at, &plain(term), TERM);
                    self.one(at, text, D);
                }
                Block::Table { rows } => {
                    for (term, text) in rows {
                        self.one(at, &plain(term), TERM);
                        self.one(at, text, D);
                    }
                }
                Block::Example { text, command } => {
                    self.one(at, text, D);
                    self.one(at, command, TERM);
                }
            }
        }
    }
}

/// The findings of the text rules over each string of `manual`: the
/// commands, the topics, the facts, the tables and the examples; then the
/// text, the man page and the help of each command that the writers make
/// from them (the characters and the work ids: a writer joins and wraps
/// sentences).
pub fn texts(manual: &Manual) -> Vec<Finding> {
    let mut w = Walk { out: Vec::new() };
    w.one("the name", &manual.name, TERM);
    w.one("the version", &manual.version, TERM);
    w.one("the date", &manual.date, TERM);
    w.one("the about line", &manual.about, D);
    w.all("the other names", &manual.names, TERM);
    w.all("the description", &manual.description, D);
    w.all("see also", &manual.see_also, D);
    for c in &manual.commands {
        let at = format!("{} {}", manual.name, c.name());
        let at = at.trim();
        w.all(at, &c.path, TERM);
        w.all(at, &c.aliases, TERM);
        w.one(at, &c.about, D);
        w.all(at, &c.notes, D);
        w.one(at, &c.usage, TERM);
        if let crate::model::Availability::Feature { name, why, .. } = &c.availability {
            w.one(at, name, TERM);
            w.one(at, why, D);
        }
        if let Some(p) = &c.parity {
            w.one(at, &p.tool, TERM);
            w.one(at, &p.text, D);
        }
        for a in &c.args {
            w.one(at, &a.name, TERM);
            w.one(at, &a.help, D);
            w.all(at, a.default.iter().chain(&a.values).chain(&a.env), TERM);
        }
        for f in &c.flags {
            let at = format!("{at} {}", f.spelling());
            w.all(&at, f.long.iter().chain(&f.value).chain(&f.default).chain(&f.values).chain(&f.env), TERM);
            w.one(&at, &f.help, D);
            match &f.kind {
                FlagKind::Wired => {}
                FlagKind::Ignored { why } => w.one(&at, why, D),
                FlagKind::Refused { instead } => w.one(&at, instead, D),
                FlagKind::NotInRelease { why, .. } => w.one(&at, why, D),
            }
            if let Some(p) = &f.parity {
                w.one(&at, &p.tool, TERM);
                w.one(&at, &p.text, D);
            }
        }
        for r in &c.rules {
            w.one(at, &r.sentence(), D);
        }
        for g in &c.groups {
            w.one(at, &g.title, D);
            w.all(at, &g.commands, TERM);
        }
        for e in &c.lead {
            w.one(at, &e.command, TERM);
            w.one(at, &e.meaning, D);
        }
    }
    for t in &manual.topics {
        let at = format!("the topic {}", t.key);
        w.all(&at, t.aliases.iter().chain([&t.key, &t.heading]), TERM);
        w.blocks(&at, &t.blocks);
    }
    let facts = &manual.facts;
    for g in &facts.variables {
        w.one("the variables", &g.name, D);
        for v in &g.vars {
            let at = format!("the variable {}", v.names.first().map(String::as_str).unwrap_or(""));
            w.all(&at, v.names.iter().chain(&v.default), TERM);
            w.one(&at, &v.used_by, D);
            w.one(&at, &v.meaning, D);
        }
    }
    for e in &facts.exits {
        let at = format!("the exit code {}", e.code.words());
        w.one(&at, &e.name, TERM);
        w.one(&at, &e.meaning, D);
    }
    for f in &facts.files {
        w.one(&format!("the file {}", f.path), &f.path, TERM);
        w.one(&format!("the file {}", f.path), &f.meaning, D);
    }
    for c in &facts.config {
        let at = format!("the configuration file {}", c.path);
        w.one(&at, &c.path, TERM);
        w.one(&at, &c.about, D);
        for k in &c.keys {
            w.all(&at, [&k.key, &k.value].into_iter().chain(&k.default).chain(&k.flag), TERM);
            w.one(&at, &k.meaning, D);
        }
    }
    for t in &facts.tables {
        let at = format!("the table {}", t.key);
        w.all(&at, [&t.key, &t.heading].into_iter().chain(&t.columns), TERM);
        w.one(&at, &t.about, D);
        for row in &t.rows {
            w.all(&at, row, D);
        }
    }
    for e in &manual.examples {
        w.one("the examples", &e.command, TERM);
        w.one("the examples", &e.meaning, D);
    }
    w.one("the text of the manual", &crate::text::render(manual), TERM);
    w.one("the man page", &crate::roff::render(manual), TERM);
    for c in &manual.commands {
        let at = format!("the help of {} {}", manual.name, c.name());
        match crate::help::render(manual, &c.path) {
            Ok(h) => w.one(at.trim(), &h, TERM),
            Err(e) => w.one(at.trim(), &e, TERM),
        }
    }
    w.out
}
