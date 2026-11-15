use super::*;
use crate::model::{Block, Span};
use crate::sample::manual;

/// An example's command stays on one line, to be copied whole; each other
/// line fits the page, unless it is one long word.
#[test]
fn no_line_is_wider_than_the_page_except_one_long_word() {
    let m = manual();
    let page = render(&m);
    let commands: Vec<String> = m.examples.iter().map(|e| format!("$ {}", e.command)).collect();
    for line in page.lines() {
        if line.chars().count() > WIDTH && !commands.iter().any(|c| c == line.trim()) {
            assert_eq!(line.split_whitespace().count(), 1, "a line of {} characters: {line:?}", line.len());
        }
    }
}

#[test]
fn the_page_is_ascii_and_has_no_trailing_spaces() {
    let page = render(&manual());
    assert!(page.is_ascii(), "the page is not ASCII");
    for line in page.lines() {
        assert_eq!(line, line.trim_end(), "trailing space: {line:?}");
    }
}

#[test]
fn wrap_keeps_each_word_and_their_order() {
    let text = "a bb ccc dddd eeeee --a-very-long-flag-name-that-is-wider-than-the-width f";
    let lines = wrap(text, 10);
    assert_eq!(lines.join(" "), text);
    assert!(lines.iter().all(|l| l.len() <= 10 || !l.contains(' ')), "{lines:?}");
}

/// Each item of each section is on the page: its term, then its text.
#[test]
fn each_item_of_the_model_is_on_the_page() {
    let m = manual();
    let squeeze = |t: &str| t.split_whitespace().collect::<Vec<_>>().join(" ");
    let page = squeeze(&render(&m));
    for s in crate::sections::sections(&m) {
        for b in &s.blocks {
            if let Block::Item { term, text } = b {
                let item = squeeze(&format!("{} {text}", crate::model::plain(term)));
                assert!(page.contains(&item), "{}: {item:?} is missing", s.key);
            }
        }
    }
}

#[test]
fn the_page_has_each_command_flag_default_and_fact() {
    let t = render(&manual());
    assert!(t.starts_with("sample 1.0 - a sample program for the tests\n"), "{t}");
    let squeezed = t.split(' ').filter(|w| !w.is_empty()).collect::<Vec<_>>().join(" ");
    let flat = squeezed.replace("\n ", " ");
    for want in [
        "\nCOMMANDS\n",
        "\nsample tunnel\n",
        "--url URL",
        "Default: auto.",
        "Values: auto, quic, http2.",
        "Variable: SAMPLE_PROTOCOL.",
        "-o, --out DIR",
        "Other names: sample irc",
        "Accepted and ignored: the edge picks the region.",
        "Refused. Use --forward.",
        "Against ssh: refused. No agent here.",
        "Give only one of --url, --socket.",
        "\nENVIRONMENT\n",
        "  The tunnel:",
        "sample sets it and does not read it.",
        "\nEXIT STATUS\n",
        "64 (usage)",
        "65-70 (other)",
        "128+N (signal)",
        "N (payload)",
        "\nCONFIGURATION\n",
        "protocol = PROTOCOL",
        "\nKEYWORDS\n",
        "Value: PORT. Meaning: The port to connect to.",
        "  1. Install the binary.",
        "$ sample net ts-shims -o /tmp/shims",
    ] {
        assert!(t.contains(want) || flat.contains(want.trim()), "no {want:?} in\n{t}");
    }
}

#[test]
fn an_empty_version_is_left_out() {
    let t = render(&manual().for_repository());
    assert!(t.starts_with("sample - a sample program"), "{t}");
}

#[test]
fn a_table_puts_a_wide_term_on_its_own_line() {
    let mut out = String::new();
    let rows = vec![
        (vec![Span::Lit("ab".into())], "short".to_string()),
        (vec![Span::Lit("a-term-that-is-too-wide".into())], "below".to_string()),
    ];
    table(&mut out, &rows, 2);
    assert_eq!(out, "  ab  short\n  a-term-that-is-too-wide\n      below\n");
}

#[test]
fn fill_keeps_the_width() {
    let mut out = String::new();
    fill(&mut out, &"word ".repeat(100), 8, 8);
    for line in out.lines() {
        assert!(line.len() <= WIDTH, "{}", line.len());
        assert!(line.starts_with("        word"));
    }
}

#[test]
fn the_date_of_an_epoch_is_its_civil_date() {
    use crate::model::date_of;
    assert_eq!(date_of(0), "1970-01-01");
    assert_eq!(date_of(951_782_400), "2000-02-29");
    assert_eq!(date_of(1_794_700_800), "2026-11-15");
}
