//! The status block of an issue: the text that `scripts/issue-sync.py`
//! writes into the body of each issue, between two markers, from the
//! record. It gives the kind, the state in the record, each entry with its
//! status, its title and the tag that carries its work, and the date of
//! the record. A session never edits it by hand.
//!
//! `pod-todo issues --block N` prints the block of one issue;
//! `pod-todo issues --json` prints each issue and pull request of the
//! record, with its block, for the sync. Both refuse a record whose map or
//! issues break a rule (`crate::issues`), so the sync never acts on a
//! record that disagrees with itself.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use crate::issues::{Issue, Kind};
use crate::model::{Entry, Row};

pub const START: &str = "<!-- pod-todo:state -->";
pub const END: &str = "<!-- /pod-todo:state -->";

/// Where the work of a done entry is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Carried {
    /// The first tag that holds each commit that the Done names.
    Tag(String),
    /// A commit of the Done is on the branch, and in no tag.
    Untagged,
    /// No commit of the Done is in this repository (or the entry is not
    /// done).
    Unknown,
}

/// The commits of the repository with the first tag `v*` (by version) that
/// holds each, from git. A tree with no git, or a shallow one, has fewer.
#[derive(Debug, Default)]
pub struct Tags {
    names: Vec<String>,
    /// Each full commit id, sorted, with the index of its first tag
    /// (`None`: on HEAD, in no tag).
    commits: Vec<(String, Option<usize>)>,
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git").arg("-C").arg(root).args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

impl Tags {
    pub fn of_git(root: &Path) -> Tags {
        let mut t = Tags::default();
        let names: Vec<String> = git(root, &["tag", "--list", "v*", "--sort=version:refname"])
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect();
        let mut prev: Option<&str> = None;
        for (i, name) in names.iter().enumerate() {
            let range = match prev {
                Some(p) => vec!["rev-list", name.as_str(), "--not", p],
                None => vec!["rev-list", name.as_str()],
            };
            for sha in git(root, &range).unwrap_or_default().lines() {
                t.commits.push((sha.to_string(), Some(i)));
            }
            prev = Some(name);
        }
        let untagged = match prev {
            Some(p) => git(root, &["rev-list", "HEAD", "--not", p]),
            None => git(root, &["rev-list", "HEAD"]),
        };
        for sha in untagged.unwrap_or_default().lines() {
            t.commits.push((sha.to_string(), None));
        }
        t.names = names;
        t.commits.sort();
        t.commits.dedup_by(|a, b| a.0 == b.0);
        t
    }

    /// A list given in full, for a test: each tag with its commits, then the
    /// commits in no tag.
    pub fn from(tags: &[(&str, &[&str])], untagged: &[&str]) -> Tags {
        let mut t = Tags::default();
        for (i, (name, shas)) in tags.iter().enumerate() {
            t.names.push(name.to_string());
            t.commits.extend(shas.iter().map(|s| (s.to_string(), Some(i))));
        }
        t.commits.extend(untagged.iter().map(|s| (s.to_string(), None)));
        t.commits.sort();
        t
    }

    /// The commit that `prefix` names, when it names one only.
    fn find(&self, prefix: &str) -> Option<Option<usize>> {
        let at = self.commits.partition_point(|(sha, _)| sha.as_str() < prefix);
        let hits: Vec<_> = self.commits[at..].iter().take(2).filter(|(sha, _)| sha.starts_with(prefix)).collect();
        match hits.as_slice() {
            [one] => Some(one.1),
            _ => None,
        }
    }

    /// Where the work of a Done is: each commit in a code span of `done`
    /// that this repository holds. The work is in the last of their first
    /// tags; a commit in no tag makes it untagged.
    pub fn carried(&self, done: &str) -> Carried {
        let mut last: Option<usize> = None;
        let mut any = false;
        // A commit is a word of 7 to 40 small hex digits, in a code span or
        // not; a word that this repository does not hold is no commit.
        for word in done.split(|c: char| !c.is_ascii_alphanumeric()) {
            let ok = (7..=40).contains(&word.len()) && word.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase());
            match ok.then(|| self.find(word)).flatten() {
                Some(None) => return Carried::Untagged,
                Some(Some(i)) => {
                    any = true;
                    last = last.max(Some(i));
                }
                None => {}
            }
        }
        match (any, last) {
            (true, Some(i)) => Carried::Tag(self.names[i].clone()),
            _ => Carried::Unknown,
        }
    }
}

/// For each id, the first commit that wrote its row in `TODO/INDEX.md` with
/// the status `done`: the work is in that commit or in one before it.
pub fn done_commits(root: &Path) -> HashMap<String, String> {
    let log = git(root, &["log", "--reverse", "--format=commit %H", "-p", "--unified=0", "--", "TODO/INDEX.md"]);
    let mut out = HashMap::new();
    let mut commit = "";
    for line in log.as_deref().unwrap_or("").lines() {
        if let Some(sha) = line.strip_prefix("commit ") {
            commit = sha;
        } else if let Some(row) = line.strip_prefix("+| [") {
            let cells: Vec<&str> = row.split('|').map(str::trim).collect();
            let id = cells[0].split(']').next().unwrap_or("");
            if cells.get(5) == Some(&"done") && crate::model::is_id(id) {
                out.entry(id.to_string()).or_insert_with(|| commit.to_string());
            }
        }
    }
    out
}

/// One entry of an issue, as the block shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub id: String,
    pub status: String,
    pub title: String,
    pub carried: Carried,
}

/// The entries of `issue`, with their status, title and tag. An id with
/// no row is left out: the check of the ids names it.
/// The Done of an entry names its commits; when it names none of this
/// repository, the commit that set its row to done (`closed`) stands in.
pub fn lines(
    issue: &Issue,
    rows: &HashMap<&str, &Row>,
    entries: &HashMap<&str, &Entry>,
    tags: &Tags,
    closed: &HashMap<String, String>,
) -> Vec<Line> {
    issue
        .entries
        .iter()
        .filter_map(|id| {
            let row = rows.get(id.as_str())?;
            let done = entries.get(id.as_str()).and_then(|e| e.section("Done")).map(|s| s.body.as_str());
            let carried = match (row.status.as_str(), done) {
                ("done", text) => match tags.carried(text.unwrap_or("")) {
                    Carried::Unknown => tags.carried(closed.get(id).map(String::as_str).unwrap_or("")),
                    known => known,
                },
                _ => Carried::Unknown,
            };
            Some(Line { id: id.clone(), status: row.status.clone(), title: row.title.clone(), carried })
        })
        .collect()
}

/// The words of the state of an issue for its reader.
fn state_words(issue: &Issue) -> &'static str {
    match (issue.kind, issue.state) {
        (_, "deleted") => "deleted on GitHub",
        (k, "open") if k.follows_entries() => "open: work of an entry is not done",
        (k, _) if k.follows_entries() => "closed: the work of each entry is done",
        (Kind::Coord, "open") => "open: the message waits for its answer",
        (Kind::Coord, _) => "closed: the message has its answer",
        (Kind::Request, "open") => "open: the runs are not recorded",
        (Kind::Request, _) => "closed: the record has the runs",
        (Kind::Reference, "open") => "open: a session uses it",
        (Kind::Reference, _) => "closed: no session uses it",
        (_, "open") => "open",
        _ => "closed",
    }
}

fn kind_words(kind: Kind) -> &'static str {
    match kind {
        Kind::Report => "a report or a request of a user",
        Kind::Coord => "a message between the sessions of PodUtils",
        Kind::Request => "a request of a run of a workflow",
        Kind::Deferred => "a deferred issue",
        Kind::Tracker => "a tracker of the asks of a project",
        Kind::Pull => "a pull request",
        Kind::Reference => "a reference that holds no work",
    }
}

/// The line of the date in a block. The sync does not write a block again
/// when only this line changed.
pub const DATE: &str = "Date of the record: ";

/// The block of `issue`, with its markers.
pub fn render(issue: &Issue, lines: &[Line], date: Option<&str>) -> String {
    let mut s = format!("{START}\n### The state in the record\n\n");
    s += &format!("This issue is {}. Kind: {}.\n\n", state_words(issue), kind_words(issue.kind));
    if lines.is_empty() {
        s += "No entry of the record holds work for this issue.\n\n";
    } else {
        s += "| Entry | Status | Title | Tag |\n| --- | --- | --- | --- |\n";
        for l in lines {
            let tag = match (&l.carried, l.status.as_str()) {
                (Carried::Tag(t), _) => format!("`{t}`"),
                (Carried::Untagged, _) => "the next tag".to_string(),
                (Carried::Unknown, "done") => "not known".to_string(),
                _ => "none".to_string(),
            };
            s += &format!("| {} | {} | {} | {tag} |\n", l.id, l.status, l.title.replace('|', "/"));
        }
        s += "\n";
    }
    s += "A tool writes this block from the work record of this repository (`TODO/issues.md`). \
          Do not edit it: change the record.\n";
    s += &format!("{DATE}{}.\n{END}", date.unwrap_or("not known"));
    s
}

/// A text as a JSON string.
pub fn json_string(text: &str) -> String {
    let mut s = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => s += "\\\"",
            '\\' => s += "\\\\",
            '\n' => s += "\\n",
            c if (c as u32) < 0x20 => s += &format!("\\u{:04x}", c as u32),
            c => s.push(c),
        }
    }
    s + "\""
}

/// One issue as an object of the JSON of `issues --json`.
pub fn json(issue: &Issue, lines: &[Line], block: &str) -> String {
    let entries: Vec<String> = lines
        .iter()
        .map(|l| {
            let tag = match &l.carried {
                Carried::Tag(t) => t.as_str(),
                Carried::Untagged => "next",
                Carried::Unknown => "",
            };
            format!(
                "{{\"id\": {}, \"status\": {}, \"title\": {}, \"tag\": {}}}",
                json_string(&l.id),
                json_string(&l.status),
                json_string(&l.title),
                json_string(tag)
            )
        })
        .collect();
    format!(
        "{{\"number\": {}, \"kind\": \"{}\", \"state\": \"{}\", \"entries\": [{}], \"block\": {}}}",
        issue.number,
        issue.kind.name(),
        issue.state,
        entries.join(", "),
        json_string(block)
    )
}

/// `issues --block NUMBER` or `issues --json` on the tree at `root`. Exit 0,
/// 1 when the record breaks a rule of the map or of the issues (or has no
/// such issue), 64 at a usage error.
pub fn command(root: &Path, words: &[&str], out: &mut dyn std::io::Write, err: &mut dyn std::io::Write) -> i32 {
    let tool = crate::config::current().tool.clone();
    let want = match words {
        ["--json"] => None,
        ["--block", n] => match n.trim_start_matches('#').parse::<u32>() {
            Ok(n) => Some(n),
            Err(_) => {
                let _ = writeln!(err, "{tool}: --block needs the number of an issue\n{}", crate::usage_text());
                return 64;
            }
        },
        _ => {
            let _ = writeln!(err, "{tool}: issues takes --block NUMBER or --json\n{}", crate::usage_text());
            return 64;
        }
    };
    let mut problems = Vec::new();
    let Some(record) = crate::check::load(root, &mut problems) else {
        problems.iter().for_each(|p| drop(writeln!(err, "{p}")));
        return 1;
    };
    let status: HashMap<&str, &str> = record.rows.iter().map(|r| (r.id.as_str(), r.status.as_str())).collect();
    let mut problems = Vec::new();
    crate::github::check(root, &mut problems);
    let issues = crate::issues::read(root, &mut problems).unwrap_or_default();
    crate::issues::rules(&issues, &status, &mut problems);
    if !problems.is_empty() {
        problems.iter().for_each(|p| drop(writeln!(err, "{p}")));
        let _ = writeln!(err, "{tool}: the map of the issues breaks {} rules: no block is written", problems.len());
        return 1;
    }
    let rows: HashMap<&str, &Row> = record.rows.iter().map(|r| (r.id.as_str(), r)).collect();
    let entries: HashMap<&str, &Entry> = record.entries.iter().map(|e| (e.id.as_str(), e)).collect();
    let tags = Tags::of_git(root);
    let closed = done_commits(root);
    let date = git(root, &["log", "-1", "--format=%cs", "--", "TODO"]).map(|d| d.trim().to_string());
    let date = date.as_deref().filter(|d| crate::check::has_date(d));
    let mut objects = Vec::new();
    for issue in &issues {
        if want.is_some_and(|n| n != issue.number) {
            continue;
        }
        let lines = lines(issue, &rows, &entries, &tags, &closed);
        let block = render(issue, &lines, date);
        match want {
            Some(_) if issue.kind == Kind::Pull => break,
            Some(_) => {
                let _ = writeln!(out, "{block}");
                return 0;
            }
            None => objects.push(json(issue, &lines, &block)),
        }
    }
    match want {
        Some(n) => {
            let _ = writeln!(err, "{tool}: #{n} is no issue of the map and the list");
            1
        }
        None => {
            let _ = writeln!(out, "[\n{}\n]", objects.join(",\n"));
            0
        }
    }
}

#[cfg(test)]
#[path = "block_test.rs"]
mod tests;
