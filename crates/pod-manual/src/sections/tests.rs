//! The four forms of PodUtils/podssh#288: an empty reason of a kind of
//! flag, a flag that is not in this release, a command that a build may not
//! have, and a topic inside the section of a command; in the blocks, the
//! text, the man page, the JSON, and the checks of the model.

use super::*;
use crate::model::{Availability, FlagKind};
use crate::sample::manual;

fn flag(kind: FlagKind) -> Flag {
    Flag { kind, ..Flag::long("x", "A flag") }
}

/// An empty reason writes the short sentence alone; a flag that is not in
/// this release names its exit code, and its reason where it has one.
#[test]
fn each_kind_of_flag_has_its_sentence() {
    let text = |kind| flag_text(&flag(kind));
    assert_eq!(text(FlagKind::Ignored { why: String::new() }), "A flag. Accepted and ignored.");
    assert_eq!(text(FlagKind::Refused { instead: " ".into() }), "A flag. Refused.");
    assert_eq!(text(FlagKind::Refused { instead: "--y".into() }), "A flag. Refused. Use --y.");
    let later = FlagKind::NotInRelease { code: 69, why: "a later release has it".into() };
    assert_eq!(text(later), "A flag. Not in this release: a later release has it. It exits 69.");
    assert_eq!(
        text(FlagKind::NotInRelease { code: 69, why: String::new() }),
        "A flag. Not in this release. It exits 69."
    );
}

/// A sample with a command of a feature, a flag that is not in this
/// release, and the topic `notes` inside the section of `tunnel`.
fn with_forms() -> Manual {
    let mut m = manual();
    let tunnel = m.commands.iter_mut().find(|c| c.name() == "tunnel").unwrap();
    tunnel.topics = vec!["notes".into()];
    tunnel.flags.push(flag(FlagKind::NotInRelease { code: 69, why: "a later release has it".into() }));
    let chat = m.commands.iter_mut().find(|c| c.name() == "chat").unwrap();
    chat.availability = Availability::Feature { name: "chat".into(), why: "it links a chat library".into(), code: 70 };
    m
}

#[test]
fn a_command_of_a_feature_says_so_in_its_blocks_and_its_json() {
    let m = with_forms();
    let chat = m.command("chat").unwrap();
    let blocks = command_blocks(&m, chat);
    let want =
        "Only a build with the feature chat has this command: it links a chat library. Each other build exits 70.";
    assert!(blocks.contains(&para(want)), "{blocks:?}");
    let doc = crate::json::document(&m);
    let commands = doc["commands"].as_array().unwrap();
    let of =
        |name: &str| commands.iter().find(|c| c["path"].as_array().map(Vec::len) == Some(1) && c["path"][0] == name);
    let chat = of("chat").unwrap();
    assert_eq!(chat["availability"]["availability"], "feature");
    assert_eq!(chat["availability"]["code"], 70);
    assert!(of("tunnel").unwrap().get("availability").is_none(), "Always is left out");
    let back = crate::json::read(&crate::json::text(&doc)).unwrap();
    assert_eq!(back, m, "the JSON reads back to the same manual");
}

/// A topic inside a command: its heading and blocks in the section of the
/// command, no section of its own, and `man KEY` selects the command.
#[test]
fn a_topic_inside_a_command_is_in_its_section_alone() {
    let m = with_forms();
    let all = sections(&m);
    assert!(all.iter().all(|s| s.key != "notes"), "the topic has no section of its own");
    let tunnel = all.iter().find(|s| s.key == "tunnel").unwrap();
    assert!(tunnel.blocks.contains(&Block::Sub { text: "NOTES".into() }), "{:?}", tunnel.blocks);
    for name in ["notes", "guide", "NOTES"] {
        assert_eq!(find(&m, &all, name).map(|s| s.key.as_str()), Some("tunnel"), "{name}");
    }
    let page = crate::text::render(&m);
    assert_eq!(page.matches("NOTES").count(), 1, "{page}");
    let roff = crate::roff::render(&m);
    assert_eq!(roff.matches("NOTES").count(), 1, "{roff}");
    let section = crate::json::section(&m, tunnel);
    assert_eq!(section["topics"][0]["key"], "notes", "{section}");
    assert!(crate::check::model(&m).is_empty(), "{:?}", crate::check::model(&m));
}

/// The checks of the model: an exit code that no row names, a topic that
/// the manual does not have, and a topic inside two commands.
#[test]
fn the_model_check_holds_the_new_forms() {
    let mut m = with_forms();
    m.facts.exits.retain(|e| e.code != crate::facts::Code::Payload);
    let chat = m.commands.iter_mut().find(|c| c.name() == "chat").unwrap();
    chat.availability = Availability::Feature { name: "chat".into(), why: "a library".into(), code: 99 };
    chat.topics = vec!["notes".into(), "none".into()];
    let later = FlagKind::NotInRelease { code: 75, why: String::new() };
    chat.flags.push(Flag { kind: later, ..Flag::long("y", "A flag") });
    let found: Vec<String> = crate::check::model(&m).iter().map(ToString::to_string).collect();
    let has = |words: &str| found.iter().any(|f| f.contains(words));
    assert!(has("the availability exits 99, which no row of EXIT STATUS names"), "{found:?}");
    assert!(has("--y exits 75, which no row of EXIT STATUS names"), "{found:?}");
    assert!(!has("--x exits 69"), "a code of a row is no finding: {found:?}");
    assert!(has("the topic none is no topic of the manual"), "{found:?}");
    assert!(has("the topic notes is inside 2 commands"), "{found:?}");
}
