use super::*;
use crate::sample::manual;
use std::io::Cursor;

fn req(section: &str) -> Request {
    Request { section: Some(section.into()), ..Request::default() }
}

fn run_with(m: &Manual, r: Request, tty: Tty) -> (Result<(), String>, String, String) {
    let mut keys = Cursor::new(Vec::new());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let rc = run(m, &r, tty, &mut keys, &mut out, &mut err);
    (rc, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
}

/// With no terminal there is no pager: the whole manual, nothing on stderr.
#[test]
fn with_no_terminal_the_whole_manual_is_written() {
    let m = manual();
    let (rc, out, err) = run_with(&m, Request::default(), Tty::none());
    assert_eq!(rc, Ok(()));
    assert_eq!(out, crate::text::render(&m));
    assert!(err.is_empty(), "{err}");
}

#[test]
fn no_pager_and_roff_write_at_once_even_on_a_terminal() {
    let m = manual();
    let tty = Tty { stdin: true, stdout: true };
    let (rc, out, _) = run_with(&m, Request { no_pager: true, ..Default::default() }, tty);
    assert_eq!((rc, out), (Ok(()), crate::text::render(&m)));
    let (rc, out, _) = run_with(&m, Request { roff: true, ..Default::default() }, tty);
    assert_eq!((rc, out), (Ok(()), crate::roff::render(&m)));
}

#[test]
fn sections_are_found_by_command_path_alias_and_topic() {
    let m = manual();
    assert!(body(&m, &req("net ts-shims")).unwrap().contains("--out"));
    assert!(body(&m, &req("net/ts-shims")).unwrap().contains("--out"));
    assert!(body(&m, &req("irc")).unwrap().starts_with("sample chat\n"));
    assert!(body(&m, &req("EXIT-STATUS")).unwrap().starts_with("EXIT STATUS\n"));
    assert!(body(&m, &req("exit status")).unwrap().contains("64 (usage)"));
    assert!(body(&m, &req("env")).unwrap().starts_with("ENVIRONMENT\n"));
    assert!(body(&m, &req("guide")).unwrap().starts_with("NOTES\n"));
    assert!(body(&m, &req("keywords")).unwrap().contains("Port"));
    let roff = Request { roff: true, ..req("tunnel") };
    assert!(body(&m, &roff).unwrap().starts_with(".TH SAMPLE\\-TUNNEL 1 "));
}

/// More than one section in one call, the longest name first.
#[test]
fn two_sections_in_one_call() {
    let m = manual();
    let two = body(&m, &req("net ts-shims exit-status")).unwrap();
    assert!(two.contains("--out") && two.contains("64 (usage)"), "{two}");
    assert!(body(&m, &req("net ts-shims nothing")).is_err());
    assert!(body(&m, &Request { json: true, ..req("tunnel files") }).is_err());
}

/// An unknown section is a usage error that lists the real sections.
#[test]
fn an_unknown_section_is_refused_with_the_list() {
    let m = manual();
    let (rc, out, _) = run_with(&m, req("nonsense"), Tty::none());
    let e = rc.unwrap_err();
    assert!(out.is_empty(), "{out}");
    assert!(e.starts_with("nonsense: no such section; fix: "), "{e}");
    for s in crate::sections::sections(&m) {
        assert!(e.contains(&s.key), "the refusal does not list {}: {e}", s.key);
    }
    let both = Request { roff: true, json: true, ..Request::default() };
    assert!(body(&m, &both).is_err());
}

#[test]
fn the_json_is_one_object_with_the_tables() {
    let m = manual();
    let j: serde_json::Value =
        serde_json::from_str(&body(&m, &Request { json: true, ..Request::default() }).unwrap()).unwrap();
    assert_eq!(j["schema"], crate::model::SCHEMA);
    assert!(j["commands"].as_array().unwrap().len() >= 4);
    assert_eq!(j["facts"]["exits"][1]["code"], serde_json::json!({ "form": "value", "value": 64 }));
    assert_eq!(j["commands"][4]["flags"][0]["kind"], serde_json::json!({ "kind": "refused", "instead": "--forward" }));
    let one: serde_json::Value =
        serde_json::from_str(&body(&m, &Request { json: true, ..req("environment") }).unwrap()).unwrap();
    assert_eq!(one["variables"][1]["name"], "The tunnel");
    let c: serde_json::Value = serde_json::from_str(&body(&m, &Request { json: true, ..req("irc") }).unwrap()).unwrap();
    assert_eq!(c["command"]["path"], serde_json::json!(["chat"]));
}

/// The JSON form reads back as the same model.
#[test]
fn the_json_reads_back() {
    let m = manual();
    let text = crate::json::text(&crate::json::document(&m));
    assert_eq!(crate::json::read(&text), Ok(m));
    assert!(crate::json::read("{\"schema\": 99}").unwrap_err().contains("99"));
}

#[test]
fn the_llms_files_come_from_the_json() {
    let m = manual();
    let docs =
        [crate::llms::Doc { path: "README.md".into(), meaning: "What the sample is.".into(), body: "# x\n".into() }];
    let json = crate::json::text(&crate::json::document(&m));
    let files = crate::llms::from_json(&json, &docs, "https://example.org/").unwrap();
    assert!(files.index.starts_with("# sample\n\n> a sample program for the tests. Version 1.0.\n"), "{}", files.index);
    assert!(files.index.contains("- `sample net ts-shims`: Write the shims\n"), "{}", files.index);
    assert!(files.index.contains("- [README.md](https://example.org/README.md): What the sample is.\n"));
    assert!(files.full.contains("```text\nsample 1.0 - a sample program"), "{}", files.full);
    assert!(files.full.ends_with("<!-- document: README.md -->\n\n# x\n"), "{}", files.full);
}

#[test]
fn the_name_of_argv0_is_the_name_of_the_help() {
    let m = manual().named("/usr/local/bin/sample-alias");
    assert_eq!(m.name, "sample-alias");
    assert!(crate::help::render(&m, &["tunnel".into()]).unwrap().contains("Usage: sample-alias tunnel"));
    assert_eq!(manual().named("other").name, "sample");
}
