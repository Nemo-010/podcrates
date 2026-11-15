//! The kinds of the issues of the map, and the rules that tie the state of
//! an issue to the status of its entries (the owner's ruling "Issues").
//!
//! The state of an issue is its state in `TODO/github.txt`: the record
//! sets it, and `scripts/issue-sync.py` makes GitHub agree. An issue that
//! holds work (a report, a deferred issue, a tracker) is open exactly when
//! one of its entries is not done. A message between sessions (coord) and
//! a request of a run (request) close on an answer, not on entries, and
//! need no entry.
//!
//! The kind comes from the title (the subject of the map): `COORD-NNN:`
//! is coord, `[gh action] requested` is request, `[DEFERRED]` is deferred,
//! and each other title is a report. A table of the map can add a column
//! `Kind` that names the kind of each row: a tracker, or a message that has
//! no title of a COORD issue. The column cannot change the kind that the
//! title gives to coord, request and deferred.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use crate::github::{self, Map, Number};
use crate::model::Problem;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An external report, or a request of a user or a tester.
    Report,
    /// A message between sessions.
    Coord,
    /// A request of a run of a workflow.
    Request,
    /// An issue that its author deferred.
    Deferred,
    /// An issue whose body lists the asks of another project.
    Tracker,
    /// A pull request: the sync never touches it.
    Pull,
    /// A capture or a document that a session uses: it holds no work, and
    /// its session opens and closes it by hand (PodUtils/podvm#435). The
    /// entries of its row are notes.
    Reference,
}

impl Kind {
    /// The kinds that a column `Kind` can name.
    pub const NAMES: [&'static str; 6] = ["report", "coord", "request", "deferred", "tracker", "reference"];

    pub fn name(self) -> &'static str {
        match self {
            Kind::Report => "report",
            Kind::Coord => "coord",
            Kind::Request => "request",
            Kind::Deferred => "deferred",
            Kind::Tracker => "tracker",
            Kind::Pull => "pull",
            Kind::Reference => "reference",
        }
    }

    pub fn parse(word: &str) -> Option<Kind> {
        Some(match word {
            "report" => Kind::Report,
            "coord" => Kind::Coord,
            "request" => Kind::Request,
            "deferred" => Kind::Deferred,
            "tracker" => Kind::Tracker,
            "reference" => Kind::Reference,
            _ => return None,
        })
    }

    /// The kind that a title gives.
    pub fn of_title(subject: &str) -> Kind {
        let coord = subject
            .strip_prefix("COORD-")
            .and_then(|rest| rest.split_once(':'))
            .is_some_and(|(n, _)| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
        if coord {
            Kind::Coord
        } else if subject.starts_with("[gh action] requested") {
            Kind::Request
        } else if subject.starts_with("[DEFERRED]") {
            Kind::Deferred
        } else if subject.starts_with("[Reference]") {
            Kind::Reference
        } else {
            Kind::Report
        }
    }

    /// True for a kind whose state follows its entries.
    pub fn follows_entries(self) -> bool {
        matches!(self, Kind::Report | Kind::Deferred | Kind::Tracker)
    }
}

/// One number of the record, with what the map says of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub number: u32,
    pub kind: Kind,
    /// `open`, `closed` or `deleted`, from `TODO/github.txt`.
    pub state: &'static str,
    pub subject: String,
    pub entries: Vec<String>,
    /// The line of its place in the map (0 for a pull request).
    pub line: usize,
}

/// Each id of this record in `text`: `T-NNN`, and a range `T-A to T-B` as
/// each id in it. An id of another record (`OWNER/REPO@T-NNN`) is not one.
pub fn entry_ids(text: &str) -> Vec<String> {
    let words: Vec<&str> = text.split(|c: char| c.is_whitespace() || ",;()".contains(c)).collect();
    let id = |w: &str| -> Option<(u32, usize)> {
        let digits = w.strip_prefix("T-")?.trim_end_matches(['.', ':']);
        if digits.len() < 3 || !digits.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        Some((digits.parse().ok()?, digits.len()))
    };
    let mut out: Vec<String> = Vec::new();
    let mut push = |n: u32, width: usize| {
        let s = format!("T-{n:0width$}");
        if !out.contains(&s) {
            out.push(s);
        }
    };
    let mut i = 0;
    while i < words.len() {
        if let Some((a, width)) = id(words[i]) {
            match (words.get(i + 1), words.get(i + 2).and_then(|w| id(w))) {
                (Some(&"to"), Some((b, _))) if b >= a => {
                    (a..=b).for_each(|n| push(n, width));
                    i += 3;
                    continue;
                }
                _ => push(a, width),
            }
        }
        i += 1;
    }
    out
}

/// The issues and the pull requests of the record: each number of `list`
/// with one place in `map`. A place that the check of the map refuses
/// (none, or two) gives no issue here; that check names it.
pub fn issues(list: &BTreeMap<u32, Number>, map: &Map, p: &mut Vec<Problem>) -> Vec<Issue> {
    let mut out = Vec::new();
    for (&number, n) in list {
        let state = match (n.deleted, n.open) {
            (true, _) => "deleted",
            (false, true) => "open",
            (false, false) => "closed",
        };
        if n.kind == github::Kind::Pull {
            let line = 0;
            out.push(Issue { number, kind: Kind::Pull, state, subject: String::new(), entries: Vec::new(), line });
            continue;
        }
        let Some([place]) = map.issues.get(&number).map(Vec::as_slice) else { continue };
        let by_title = Kind::of_title(&place.subject);
        let kind = match place.kind.as_deref().map(str::trim).filter(|k| !k.is_empty()) {
            None => by_title,
            Some(word) => match Kind::parse(word) {
                None => {
                    p.push(Problem::new(
                        github::MAP_AT,
                        place.line,
                        format!("issue #{number}: the kind `{word}` is not one of {}", Kind::NAMES.join(", ")),
                    ));
                    by_title
                }
                Some(k) if by_title != Kind::Report && k != by_title => {
                    p.push(Problem::new(
                        github::MAP_AT,
                        place.line,
                        format!(
                            "issue #{number}: its title gives the kind {}, and its row says {word}",
                            by_title.name()
                        ),
                    ));
                    by_title
                }
                Some(k) => k,
            },
        };
        let entries = entry_ids(&place.entries);
        out.push(Issue { number, kind, state, subject: place.subject.clone(), entries, line: place.line });
    }
    out
}

/// The rules of the state of each issue against the status of its entries
/// (`status`: each id of the index with its status).
pub fn rules(issues: &[Issue], status: &HashMap<&str, &str>, p: &mut Vec<Problem>) {
    for issue in issues.iter().filter(|i| i.kind.follows_entries() && i.state != "deleted") {
        let (n, kind) = (issue.number, issue.kind.name());
        if issue.entries.is_empty() {
            p.push(Problem::new(
                github::MAP_AT,
                issue.line,
                format!("issue #{n} ({kind}) names no entry: a {kind} holds work, so it names one entry or more"),
            ));
            continue;
        }
        let not_done: Vec<String> = issue
            .entries
            .iter()
            .filter_map(|id| status.get(id.as_str()).filter(|s| **s != "done").map(|s| format!("{id} ({s})")))
            .collect();
        match (issue.state, not_done.is_empty()) {
            ("open", true) => p.push(Problem::new(
                github::MAP_AT,
                issue.line,
                format!(
                    "issue #{n} ({kind}) is open, and each of its entries is done: set it to closed in \
                     TODO/{} and in its row",
                    github::LIST
                ),
            )),
            ("closed", false) => p.push(Problem::new(
                github::MAP_AT,
                issue.line,
                format!(
                    "issue #{n} ({kind}) is closed, and {} {} not done: set it to open in TODO/{} and in its row",
                    not_done.join(", "),
                    if not_done.len() == 1 { "is" } else { "are" },
                    github::LIST
                ),
            )),
            _ => {}
        }
    }
}

/// The map and the list of the tree at `root`, read as issues. `None` when
/// the tree has neither file; a file that is missing or cannot be read is
/// a problem of the check of the map.
pub fn read(root: &Path, p: &mut Vec<Problem>) -> Option<Vec<Issue>> {
    let dir = root.join("TODO");
    let map = std::fs::read_to_string(dir.join(github::MAP)).ok()?;
    let list = std::fs::read_to_string(dir.join(github::LIST)).ok()?;
    let mut ignored = Vec::new();
    let list = github::read_list(&list, &mut ignored);
    Some(issues(&list, &github::read_map(&map), p))
}

/// The rules on the tree at `root`.
pub fn check(root: &Path, status: &HashMap<&str, &str>, p: &mut Vec<Problem>) {
    if let Some(issues) = read(root, p) {
        rules(&issues, status, p);
    }
}

#[cfg(test)]
#[path = "issues_test.rs"]
mod tests;
