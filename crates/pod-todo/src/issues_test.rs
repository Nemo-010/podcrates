//! The kinds of the issues and each rule of their state.

use super::*;

const LIST: &str = "1 issue open\n2 issue closed\n3 issue open\n4 issue closed\n5 issue open\n6 pull closed\n";

fn map(rows: &str) -> String {
    format!(
        "| Issue | Kind | Subject | State | Entries |\n| --- | --- | --- | --- | --- |\n{rows}\n#6 are pull requests.\n"
    )
}

const ROWS: &str = "| #1 |  | A defect | open | T-001, T-002 |\n\
| #2 |  | COORD-004: a message (to all) | closed | T-001 |\n\
| #3 |  | [gh action] requested: the gates | open | |\n\
| #4 | tracker | Asks of cfb | closed | T-001 |\n\
| #5 |  | [DEFERRED] Serve ECH | open | T-003 |";

fn status() -> HashMap<&'static str, &'static str> {
    HashMap::from([("T-001", "done"), ("T-002", "partial"), ("T-003", "blocked")])
}

fn found(rows: &str, status: &HashMap<&str, &str>) -> Vec<String> {
    found_with(LIST, rows, status)
}

fn named(found: &[String], says: &str) -> bool {
    found.iter().any(|p| p.contains(says))
}

#[test]
fn the_title_gives_the_kind_and_the_column_names_a_tracker() {
    assert_eq!(Kind::of_title("COORD-110: the ruling (to all)"), Kind::Coord);
    assert_eq!(Kind::of_title("COORD-: no number"), Kind::Report);
    assert_eq!(Kind::of_title("[gh action] requested: the gates"), Kind::Request);
    assert_eq!(Kind::of_title("[DEFERRED] Serve ECH"), Kind::Deferred);
    assert_eq!(Kind::of_title("`pod-proxy`: a defect"), Kind::Report);
    assert_eq!(Kind::of_title("[Reference] the tree of a project"), Kind::Reference);
    let mut p = Vec::new();
    let list = github::read_list(LIST, &mut p);
    let all = issues(&list, &github::read_map(&map(ROWS)), &mut p);
    let kinds: Vec<(u32, &str)> = all.iter().map(|i| (i.number, i.kind.name())).collect();
    assert_eq!(kinds, [(1, "report"), (2, "coord"), (3, "request"), (4, "tracker"), (5, "deferred"), (6, "pull")]);
    assert_eq!(all[0].entries, ["T-001", "T-002"]);
    assert!(p.is_empty(), "{p:?}");
}

#[test]
fn the_fixture_agrees() {
    let found = found(ROWS, &status());
    assert!(found.is_empty(), "{found:#?}");
}

fn found_with(list: &str, rows: &str, status: &HashMap<&str, &str>) -> Vec<String> {
    let mut p = Vec::new();
    let list = github::read_list(list, &mut p);
    let all = issues(&list, &github::read_map(&map(rows)), &mut p);
    rules(&all, status, &mut p);
    p.iter().map(ToString::to_string).collect()
}

#[test]
fn an_open_issue_whose_entries_are_all_done_fails() {
    let rows = ROWS.replacen("| open | T-001, T-002 |", "| open | T-001 |", 1);
    let found = found(&rows, &status());
    assert!(named(&found, "issue #1 (report) is open, and each of its entries is done"), "{found:#?}");
    assert!(!named(&found, "issue #4"), "{found:#?}");
}

#[test]
fn a_closed_issue_with_an_entry_that_is_not_done_fails() {
    let mut status = status();
    status.insert("T-001", "open");
    let found = found(ROWS, &status);
    assert!(named(&found, "issue #4 (tracker) is closed, and T-001 (open) is not done"), "{found:#?}");
    assert!(!named(&found, "issue #2"), "a coord issue does not follow its entries: {found:#?}");
    let list = LIST.replacen("1 issue open", "1 issue closed", 1);
    let rows = ROWS.replacen("| A defect | open |", "| A defect | closed |", 1);
    let found = found_with(&list, &rows, &self::status());
    assert!(named(&found, "issue #1 (report) is closed, and T-002 (partial) is not done"), "{found:#?}");
}

#[test]
fn a_report_or_a_tracker_with_no_entry_fails_and_a_request_needs_none() {
    let rows = ROWS.replacen("| Asks of cfb | closed | T-001 |", "| Asks of cfb | closed | none |", 1);
    let found = found(&rows, &status());
    assert!(named(&found, "issue #4 (tracker) names no entry"), "{found:#?}");
    assert!(!named(&found, "issue #3"), "a request needs no entry: {found:#?}");
    let rows = ROWS.replacen("| A defect | open | T-001, T-002 |", "| A defect | open | |", 1);
    assert!(named(&found_of(&rows), "issue #1 (report) names no entry"));
}

#[test]
fn a_reference_needs_no_entry_and_its_entries_are_notes() {
    let rows =
        ROWS.replacen("| #1 |  | A defect | open | T-001, T-002 |", "| #1 |  | [Reference] a capture | open | |", 1);
    assert!(!named(&found_of(&rows), "issue #1"), "a reference by its title needs no entry");
    let rows =
        ROWS.replacen("| #1 |  | A defect | open | T-001, T-002 |", "| #1 | reference | A capture | open | T-001 |", 1);
    assert!(!named(&found_of(&rows), "issue #1"), "a reference by its column: a done entry is a note");
}

fn found_of(rows: &str) -> Vec<String> {
    found(rows, &status())
}

#[test]
fn a_deferred_issue_stays_open_while_its_entry_is_blocked() {
    let mut status = status();
    status.insert("T-003", "done");
    let found = found(ROWS, &status);
    assert!(named(&found, "issue #5 (deferred) is open, and each of its entries is done"), "{found:#?}");
}

#[test]
fn a_kind_that_is_not_one_or_that_the_title_refuses_fails() {
    let rows = ROWS.replacen("| #1 |  |", "| #1 | bug |", 1).replacen("| #2 |  |", "| #2 | report |", 1);
    let found = found(&rows, &status());
    assert!(named(&found, "issue #1: the kind `bug` is not one of"), "{found:#?}");
    assert!(named(&found, "issue #2: its title gives the kind coord, and its row says report"), "{found:#?}");
}

#[test]
fn ids_and_ranges_of_this_record_are_entries_and_others_are_not() {
    assert_eq!(
        entry_ids("T-072 to T-074, T-078 (PodUtils/podvm@T-1745), T-072; T-1000."),
        ["T-072", "T-073", "T-074", "T-078", "T-1000"]
    );
    assert!(entry_ids("none, T-1, T-12").is_empty());
}
