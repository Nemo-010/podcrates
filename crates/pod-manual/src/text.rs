//! The manual as plain text: what `CLI man` writes. The lines are filled to
//! [`WIDTH`] columns, so that the page reads in an 80-column terminal. The
//! text needs nothing of the host: no man(1), no groff, no pager.

use std::fmt::Write as _;

use crate::model::{Block, Manual, Span, plain};
use crate::sections::{Section, sections, usage};

/// The widest line, except a word that is longer by itself.
pub const WIDTH: usize = 79;

/// The first line: the name, the version and what the program is.
fn title(manual: &Manual) -> String {
    let mut s = manual.name.clone();
    if !manual.version.is_empty() {
        s.push(' ');
        s.push_str(&manual.version);
    }
    if !manual.about.is_empty() {
        s.push_str(" - ");
        s.push_str(&manual.about);
    }
    s
}

/// The whole manual.
pub fn render(manual: &Manual) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}", title(manual));
    out.push_str("\nSYNOPSIS\n");
    if let Some(root) = manual.root() {
        let _ = writeln!(out, "  {}", usage(manual, root));
        let rest: Vec<Block> = crate::sections::command_blocks(manual, root)
            .into_iter()
            .skip_while(|b| !matches!(b, Block::Sub { .. }))
            .collect();
        if !rest.is_empty() {
            out.push('\n');
            blocks(&mut out, &rest);
        }
    } else {
        let _ = writeln!(out, "  {} COMMAND [OPTIONS]", manual.name);
    }
    if !manual.description.is_empty() {
        out.push_str("\nDESCRIPTION\n");
        let paras: Vec<Block> = manual.description.iter().map(crate::sections::para).collect();
        blocks(&mut out, &paras);
    }
    let all = sections(manual);
    let mut commands = false;
    for s in &all {
        if s.command.is_some() && !commands {
            out.push_str("\nCOMMANDS\n");
            commands = true;
        }
        out.push('\n');
        section(&mut out, s);
    }
    out
}

/// One section, as `CLI man SECTION` writes it.
pub fn render_section(s: &Section) -> String {
    let mut out = String::new();
    section(&mut out, s);
    out
}

fn section(out: &mut String, s: &Section) {
    out.push_str(&s.heading);
    out.push('\n');
    blocks(out, &s.blocks);
}

/// The blocks of one section. A blank line separates blocks, except after a
/// sub-heading and between the items of one list. After a sub-heading, the
/// blocks move in by two.
pub(crate) fn blocks(out: &mut String, list: &[Block]) {
    let mut indent = 2;
    let mut previous: Option<&Block> = None;
    for b in list {
        let tight =
            matches!((previous, b), (Some(Block::Sub { .. }), _) | (Some(Block::Item { .. }), Block::Item { .. }));
        if previous.is_some() && !tight {
            out.push('\n');
        }
        match b {
            Block::Para { text } => fill(out, text, indent, indent),
            Block::Steps { steps } => {
                for (i, step) in steps.iter().enumerate() {
                    let n = format!("{}. ", i + 1);
                    let first = format!("{n}{step}");
                    fill(out, &first, indent, indent + n.len());
                }
            }
            Block::Line { spans } => fill(out, &plain(spans), indent, indent + 4),
            Block::Sub { text } => {
                let _ = writeln!(out, "  {text}:");
                indent = 4;
            }
            Block::Item { term, text } => {
                // A long term, such as a list of files, wraps at its spaces.
                fill(out, &plain(term), indent, indent);
                if !text.is_empty() {
                    fill(out, text, indent + 4, indent + 4);
                }
            }
            Block::Table { rows } => table(out, rows, indent),
            Block::Example { text, command } => {
                fill(out, text, indent, indent);
                // A command stays on one line, to be copied whole.
                let _ = writeln!(out, "{:w$}$ {}", "", command, w = indent + 4);
            }
        }
        previous = Some(b);
    }
}

/// Two columns: the terms, padded to the widest (up to a limit), then the
/// text, filled with a hanging indent. A wider term puts its text below.
pub(crate) fn table(out: &mut String, rows: &[(Vec<Span>, String)], indent: usize) {
    const MAX_TERM: usize = 16;
    let width_of = |t: &[Span]| plain(t).chars().count();
    let column = rows.iter().map(|(t, _)| width_of(t)).filter(|w| *w <= MAX_TERM).max().unwrap_or(0) + 2;
    for (term, text) in rows {
        let term_text = plain(term);
        if width_of(term) + 2 > column {
            let _ = writeln!(out, "{:indent$}{term_text}", "");
            fill(out, text, indent + column, indent + column);
        } else {
            let mut first = format!("{:indent$}{term_text}", "");
            let pad = column - width_of(term);
            first.push_str(&" ".repeat(pad));
            let width = WIDTH.saturating_sub(indent + column).max(20);
            let lines = wrap(text, width);
            first.push_str(lines.first().map(String::as_str).unwrap_or(""));
            out.push_str(first.trim_end());
            out.push('\n');
            for l in lines.iter().skip(1) {
                let _ = writeln!(out, "{:w$}{l}", "", w = indent + column);
            }
        }
    }
}

/// `text`, filled to [`WIDTH`]: the first line after `first` spaces, the
/// others after `rest` spaces. A line break in `text` starts a new line.
pub fn fill(out: &mut String, text: &str, first: usize, rest: usize) {
    let width = WIDTH.saturating_sub(rest).max(20);
    let mut at_first = true;
    for line in text.split('\n') {
        for l in wrap(line, width) {
            let pad = if at_first { first } else { rest };
            let _ = writeln!(out, "{:pad$}{l}", "");
            at_first = false;
        }
    }
}

/// The words of `text` in lines of `width` or fewer characters. A word that
/// is longer by itself gets its own line, unbroken: a broken flag name is a
/// flag name that nobody can type.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

#[cfg(test)]
mod tests;
