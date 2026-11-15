//! `CLI man [SECTION] [--no-pager | --roff | --json]`: the form and the
//! sections that a command line asks for.

use std::io::{BufRead, Write};

use crate::model::Manual;
use crate::pager::Tty;
use crate::sections::{Section, find, sections};

/// What the command line asked for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    /// The words of the section: a command, a topic, or more than one.
    pub section: Option<String>,
    pub no_pager: bool,
    pub roff: bool,
    pub json: bool,
}

/// The words of `text` as two or more section names, the longest name
/// first; none when a word is in no name.
fn split_sections<'a>(manual: &Manual, all: &'a [Section], text: &str) -> Option<Vec<&'a Section>> {
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut parts = Vec::new();
    let mut at = 0;
    while at < words.len() {
        let (end, s) = (at + 1..=words.len().min(at + 4))
            .rev()
            .find_map(|end| find(manual, all, &words[at..end].join(" ")).map(|s| (end, s)))?;
        parts.push(s);
        at = end;
    }
    (parts.len() > 1).then_some(parts)
}

/// The refusal of a section that is not in the manual.
fn unknown(manual: &Manual, all: &[Section], name: &str) -> String {
    let keys: Vec<&str> = all.iter().map(|s| s.key.as_str()).collect();
    format!(
        "{}\nSections: {}.",
        crate::error::fault(
            name,
            "no such section",
            &format!("run {} man with one of the sections below", manual.name)
        ),
        keys.join(", ")
    )
}

/// The text for `req`, or the refusal of a request that cannot be served.
pub fn body(manual: &Manual, req: &Request) -> Result<String, String> {
    if req.json && req.roff {
        return Err(crate::error::fault("--json", "--json and --roff are two forms of the manual", "give one of them"));
    }
    let Some(name) = req.section.as_deref() else {
        return Ok(if req.json {
            crate::json::text(&crate::json::document(manual))
        } else if req.roff {
            crate::roff::render(manual)
        } else {
            crate::text::render(manual)
        });
    };
    let all = sections(manual);
    let one = |s: &Section| {
        if req.json {
            crate::json::text(&crate::json::section(manual, s))
        } else if req.roff {
            crate::roff::render_section(manual, s)
        } else {
            crate::text::render_section(s)
        }
    };
    if let Some(s) = find(manual, &all, name) {
        return Ok(one(s));
    }
    // More than one section in one call: `CLI man tunnel serve`. The words
    // split into names, the longest name first.
    match split_sections(manual, &all, name) {
        Some(_) if req.json => Err(crate::error::fault(name, "--json takes one section", "give one section")),
        Some(parts) => Ok(parts.into_iter().map(one).collect::<Vec<_>>().join("\n")),
        None => Err(unknown(manual, &all, name)),
    }
}

/// Run `CLI man`: the text of `req` to `out`, through the pager when `tty`
/// can page and the request is the text form. `keys` is where the built-in
/// pager reads its keys. `Err` holds the refusal, for the program to print
/// with its exit code of a usage error.
pub fn run(
    manual: &Manual,
    req: &Request,
    tty: Tty,
    keys: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), String> {
    let text = body(manual, req)?;
    crate::pager::show(&text, req.no_pager || req.roff || req.json, tty, keys, out, err);
    Ok(())
}

#[cfg(test)]
mod tests;
