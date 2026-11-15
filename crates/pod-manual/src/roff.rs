//! The manual as a man(7) page: `CLI man --roff`, for `man -l` or a man
//! directory. It uses only man(7) macros and requests that groff and mandoc
//! both render, and it defines no macro of its own: a macro defined in the
//! page is roff that one renderer reads differently from another.

use std::fmt::Write as _;

use crate::model::{Block, Manual, Span};
use crate::sections::{Section, sections, usage};

/// Each request the page may contain.
pub const MACROS: &[&str] = &[".TH", ".SH", ".SS", ".PP", ".TP", ".RS", ".RE", ".nf", ".fi", ".nh", ".ad"];

/// Text made safe for roff: a backslash is `\e`, a hyphen is `\-` (the
/// hyphen-minus that a user types), and a line that starts with `.` or `'`
/// starts with the zero-width `\&`, so no text can become a request.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    let mut line_start = true;
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\e"),
            '-' => out.push_str("\\-"),
            '\n' => {
                out.push('\n');
                line_start = true;
                continue;
            }
            '.' | '\'' if line_start => {
                out.push_str("\\&");
                out.push(c);
            }
            _ => out.push(c),
        }
        line_start = false;
    }
    out
}

/// The longest line of text in the page: mandoc asks for 80 bytes or
/// fewer.
const LINE: usize = 78;

/// `text` as roff text lines: each word escaped, filled to [`LINE`] bytes
/// (a longer word gets its own line), with no empty line (an empty line is
/// a break that mandoc warns about) and no space at the start of a line
/// (which starts a break too). A line break of `text` stays.
fn lines(text: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for source in text.split('\n') {
        let mut line = String::new();
        for word in source.split_whitespace() {
            let word = escape(word).trim_start_matches("\\&").to_string();
            if !line.is_empty() && line.len() + 1 + word.len() > LINE {
                out.push(std::mem::take(&mut line));
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(&word);
        }
        if !line.is_empty() {
            out.push(line);
        }
    }
    // A line that starts with `.` or `'` would be a request.
    let guard = |l: String| if l.starts_with(['.', '\'']) { format!("\\&{l}") } else { l };
    out.into_iter().map(guard).collect::<Vec<_>>().join("\n")
}

/// A term: what a user types in bold, a value to replace in italics.
fn spans(list: &[Span]) -> String {
    let mut out = String::new();
    for s in list {
        match s {
            Span::Lit(t) => {
                let _ = write!(out, "\\fB{}\\fR", escape(t));
            }
            Span::Var(t) => {
                let _ = write!(out, "\\fI{}\\fR", escape(t));
            }
            Span::Plain(t) => out.push_str(&escape(t)),
        }
    }
    // A term must not start a request.
    if out.starts_with(['.', '\'']) {
        out.insert_str(0, "\\&");
    }
    out.trim_start().to_string()
}

/// A quoted argument of a macro: a double quote in it would end it.
fn quoted(text: &str) -> String {
    format!("\"{}\"", escape(&text.replace('"', "'")))
}

/// `title` is the name or the name and a section key, in capitals.
fn header(out: &mut String, manual: &Manual, title: &str) {
    let source =
        if manual.version.is_empty() { manual.name.clone() } else { format!("{} {}", manual.name, manual.version) };
    let title: String =
        title.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '-' }).collect();
    let _ = writeln!(
        out,
        ".TH {} 1 \"{}\" {} {}",
        escape(&title),
        // A date as mandoc parses it: with no escape.
        manual.date.replace(['"', '\\'], ""),
        quoted(&source),
        quoted(&format!("{} manual", manual.name))
    );
    // No hyphenation, and a ragged right margin: a flag broken at a line
    // end, or spread with extra spaces, cannot be copied.
    out.push_str(".nh\n.ad l\n");
}

/// The whole manual.
pub fn render(manual: &Manual) -> String {
    let mut out = String::new();
    header(&mut out, manual, &manual.name);
    out.push_str(".SH NAME\n");
    let _ = writeln!(out, "{}", lines(&format!("{} - {}", manual.name, manual.about)));
    out.push_str(".SH SYNOPSIS\n");
    match manual.root() {
        Some(root) => {
            let _ = writeln!(out, "\\fB{}\\fR", escape(&usage(manual, root)));
            let rest: Vec<Block> = crate::sections::command_blocks(manual, root)
                .into_iter()
                .skip_while(|b| !matches!(b, Block::Sub { .. }))
                .collect();
            blocks(&mut out, &rest, false);
        }
        None => {
            let _ = writeln!(out, "\\fB{}\\fR \\fICOMMAND\\fR [\\fIOPTIONS\\fR]", escape(&manual.name));
        }
    }
    if !manual.description.is_empty() {
        out.push_str(".SH DESCRIPTION\n");
        let paras: Vec<Block> = manual.description.iter().map(crate::sections::para).collect();
        blocks(&mut out, &paras, true);
    }
    let mut commands = false;
    for s in &sections(manual) {
        if s.command.is_some() {
            if !commands {
                out.push_str(".SH COMMANDS\n");
                commands = true;
            }
            let _ = writeln!(out, ".SS {}", quoted(&s.heading));
        } else {
            let _ = writeln!(out, ".SH {}", quoted(&s.heading));
        }
        blocks(&mut out, &s.blocks, true);
    }
    out
}

/// One section, as `CLI man --roff SECTION` writes it.
pub fn render_section(manual: &Manual, s: &Section) -> String {
    let mut out = String::new();
    header(&mut out, manual, &format!("{}-{}", manual.name, s.key));
    let _ = writeln!(out, ".SH {}", quoted(&s.heading.to_uppercase()));
    blocks(&mut out, &s.blocks, true);
    out
}

/// The blocks after a heading. A heading starts a paragraph itself, so the
/// first block needs no `.PP` (mandoc warns about one).
fn blocks(out: &mut String, list: &[Block], first_after_heading: bool) {
    for (i, b) in list.iter().enumerate() {
        let pp = if i == 0 && first_after_heading { "" } else { ".PP\n" };
        match b {
            Block::Para { text } => {
                let _ = writeln!(out, "{pp}{}", lines(text));
            }
            Block::Steps { steps } => {
                for (n, step) in steps.iter().enumerate() {
                    let _ = writeln!(out, ".TP 4\n{}.\n{}", n + 1, lines(step));
                }
            }
            Block::Line { spans: s } => {
                let _ = writeln!(out, "{pp}{}", spans(s));
            }
            Block::Sub { text } => {
                let _ = writeln!(out, "{pp}\\fB{}:\\fR", escape(text));
            }
            Block::Item { term, text } => item(out, term, text),
            Block::Table { rows } => {
                for (term, text) in rows {
                    item(out, term, text);
                }
            }
            Block::Example { text, command } => {
                let _ = writeln!(out, "{pp}{}\n.RS 4\n.nf\n{}\n.fi\n.RE", lines(text), escape(&format!("$ {command}")));
            }
        }
    }
}

fn item(out: &mut String, term: &[Span], text: &str) {
    let _ = writeln!(out, ".TP\n{}", spans(term));
    if !text.trim().is_empty() {
        let _ = writeln!(out, "{}", lines(text));
    }
}

#[cfg(test)]
mod tests;
