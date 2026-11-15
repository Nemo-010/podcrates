//! The block of an issue: its markers, its state, its entries with their
//! tags, and its JSON.

use super::*;
use crate::model::Row;

fn issue(kind: Kind, state: &'static str, entries: &[&str]) -> Issue {
    Issue {
        number: 20,
        kind,
        state,
        subject: "a defect".into(),
        entries: entries.iter().map(|s| s.to_string()).collect(),
        line: 3,
    }
}

const A: &str = "aaaaaaa111111111111111111111111111111111";
const B: &str = "bbbbbbb222222222222222222222222222222222";
const C: &str = "ccccccc333333333333333333333333333333333";

fn tags() -> Tags {
    Tags::from(&[("v0.1.0", &[A]), ("v0.2.0", &[B])], &[C])
}

#[test]
fn the_tag_is_the_last_first_tag_of_the_commits_of_the_done() {
    let t = tags();
    assert_eq!(t.carried("2026-11-15: `aaaaaaa1`."), Carried::Tag("v0.1.0".into()));
    assert_eq!(t.carried("`aaaaaaa1` and `bbbbbbb2`, podvm `9999999`"), Carried::Tag("v0.2.0".into()));
    assert_eq!(t.carried("`aaaaaaa1` then `ccccccc3`"), Carried::Untagged);
    assert_eq!(t.carried("podvm `75ed306`; release 42261756998"), Carried::Unknown);
    assert_eq!(t.carried("`abc` is too short; `cargo test` is no commit"), Carried::Unknown);
    assert_eq!(t.carried("2026-11-14, commit bbbbbbb2; the plants"), Carried::Tag("v0.2.0".into()), "a bare commit");
}

/// An entry whose Done names no commit of this repository takes the
/// commit that set its row to done.
#[test]
fn the_commit_that_closed_the_row_stands_in_for_a_done_with_no_commit() {
    let row = |id: &str| Row {
        id: id.into(),
        file: "a.md".into(),
        priority: "P1".into(),
        effort: "S".into(),
        milestone: "M8".into(),
        category: "defect".into(),
        status: "done".into(),
        title: format!("the title of {id}"),
        line: 1,
    };
    let (r1, r2) = (row("T-001"), row("T-002"));
    let rows = HashMap::from([("T-001", &r1), ("T-002", &r2)]);
    let closed = HashMap::from([("T-001".to_string(), A.to_string())]);
    let got =
        lines(&issue(Kind::Report, "closed", &["T-001", "T-002", "T-999"]), &rows, &HashMap::new(), &tags(), &closed);
    let carried: Vec<(&str, &Carried)> = got.iter().map(|l| (l.id.as_str(), &l.carried)).collect();
    assert_eq!(carried, [("T-001", &Carried::Tag("v0.1.0".into())), ("T-002", &Carried::Unknown)]);
}

#[test]
fn a_prefix_that_names_two_commits_names_none() {
    let t = Tags::from(&[("v0.1.0", &["aaaaaaa1x", "aaaaaaa2y"])], &[]);
    assert_eq!(t.carried("`aaaaaaa`"), Carried::Unknown);
}

#[test]
fn the_block_has_its_markers_its_state_and_each_entry() {
    let lines = [
        Line {
            id: "T-082".into(),
            status: "done".into(),
            title: "the `Host` header".into(),
            carried: Carried::Tag("v0.7.0".into()),
        },
        Line { id: "T-083".into(), status: "done".into(), title: "the UDP path".into(), carried: Carried::Untagged },
        Line { id: "T-084".into(), status: "open".into(), title: "a | bar".into(), carried: Carried::Unknown },
    ];
    let block = render(&issue(Kind::Report, "open", &["T-082", "T-083", "T-084"]), &lines, Some("2026-11-15"));
    assert!(block.starts_with(START) && block.ends_with(END), "{block}");
    assert_eq!(block.matches(START).count() + block.matches(END).count(), 2);
    assert!(block.contains("This issue is open: work of an entry is not done. Kind: a report"), "{block}");
    assert!(block.contains("| T-082 | done | the `Host` header | `v0.7.0` |"), "{block}");
    assert!(block.contains("| T-083 | done | the UDP path | the next tag |"), "{block}");
    assert!(block.contains("| T-084 | open | a / bar | none |"), "{block}");
    assert!(block.contains(&format!("{DATE}2026-11-15.")), "{block}");
    let text: String = block.chars().filter(|c| !c.is_ascii()).collect();
    assert!(text.is_empty(), "the block is ASCII, with no emoji: {text:?}");
}

#[test]
fn a_message_with_no_entry_says_so() {
    let block = render(&issue(Kind::Coord, "closed", &[]), &[], None);
    assert!(block.contains("This issue is closed: the message has its answer."), "{block}");
    assert!(block.contains("No entry of the record holds work for this issue."), "{block}");
    assert!(block.contains(&format!("{DATE}not known.")), "{block}");
}

#[test]
fn the_json_escapes_each_text() {
    assert_eq!(json_string("a \"b\"\\\n\t"), "\"a \\\"b\\\"\\\\\\n\\u0009\"");
    let lines = [Line { id: "T-1".into(), status: "done".into(), title: "x".into(), carried: Carried::Untagged }];
    let j = json(&issue(Kind::Tracker, "closed", &["T-1"]), &lines, "B");
    assert_eq!(
        j,
        "{\"number\": 20, \"kind\": \"tracker\", \"state\": \"closed\", \"entries\": [{\"id\": \"T-1\", \
         \"status\": \"done\", \"title\": \"x\", \"tag\": \"next\"}], \"block\": \"B\"}"
    );
}
