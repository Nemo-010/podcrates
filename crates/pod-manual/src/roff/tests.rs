use super::*;
use crate::sample::manual;
use crate::sections::sections;

#[test]
fn the_first_line_is_th_and_the_name_follows() {
    let page = render(&manual());
    let first = page.lines().next().unwrap();
    assert_eq!(first, ".TH SAMPLE 1 \"2026-11-15\" \"sample 1.0\" \"sample manual\"");
    assert!(page.contains(".SH NAME\nsample \\- a sample program"), "no NAME section");
}

/// Each request line of the page is one of [`MACROS`]: no text became a
/// request, and no macro is defined.
#[test]
fn the_page_uses_only_the_listed_requests() {
    let m = manual();
    let mut pages = vec![render(&m)];
    pages.extend(sections(&m).iter().map(|s| render_section(&m, s)));
    for page in pages {
        for line in page.lines().filter(|l| l.starts_with(['.', '\''])) {
            let request = line.split_whitespace().next().unwrap();
            assert!(MACROS.contains(&request), "unlisted request {request:?} in {line:?}");
        }
        assert!(!page.lines().any(|l| l.trim().is_empty()), "an empty line");
        assert!(!page.lines().any(|l| l.starts_with(' ')), "a line that starts with a space");
    }
}

/// A planted text that tries to start a request, change a font or end a
/// macro argument stays text.
#[test]
fn text_cannot_become_a_request() {
    let planted = ".SH INJECTED\n'br\n\\fBbold\\fR -flag";
    assert_eq!(escape(planted), "\\&.SH INJECTED\n\\&'br\n\\efBbold\\efR \\-flag");
    let mut out = String::new();
    item(&mut out, &[Span::Lit(".x".into())], planted);
    let requests: Vec<&str> = out.lines().filter(|l| l.starts_with(['.', '\''])).collect();
    assert_eq!(requests, vec![".TP"], "{out}");
    assert_eq!(quoted("a \"b\""), "\"a 'b'\"");
}

/// Each flag is a `.TP` term with its spelling in bold.
#[test]
fn each_flag_is_a_tagged_paragraph_in_bold() {
    let m = manual();
    let page = render(&m);
    for c in &m.commands {
        for f in &c.flags {
            let first = format!("\\fB{}\\fR", escape(&f.spellings()[0]));
            let line = page.lines().find(|l| l.starts_with(&first)).unwrap_or("");
            assert!(page.contains(&format!(".TP\n{first}")), "{}: no .TP for {first}", c.name());
            for s in f.spellings() {
                assert!(line.contains(&format!("\\fB{}\\fR", escape(&s))), "{}: {s} is not bold in {line:?}", c.name());
            }
        }
    }
    assert!(page.contains("\\-\\-url"), "hyphens are escaped");
}

#[test]
fn a_section_has_its_own_title() {
    let m = manual();
    let all = sections(&m);
    let s = all.iter().find(|s| s.key == "net ts-shims").unwrap();
    let page = render_section(&m, s);
    assert!(page.starts_with(".TH SAMPLE\\-NET\\-TS\\-SHIMS 1 "), "{page}");
    assert!(page.contains(".SH \"SAMPLE NET TS\\-SHIMS\""), "{page}");
}
