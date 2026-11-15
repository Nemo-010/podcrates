//! The checks of pod-manual over the manual of `podlab`: the text rules,
//! the parser, the generated files, the variables and the exit codes.

use std::path::{Path, PathBuf};

use pod_manual::check::{ParserFlag, assert_none, exit_codes, flags, generated, model, texts, variables};
use pod_manual::{Manual, llms, roff, scan};

fn manual() -> Manual {
    super::cli::manual("podlab")
}

fn dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The generated files of the repository, each with its text now.
fn generated_files() -> Vec<(PathBuf, String)> {
    let m = manual().for_repository();
    vec![
        (dir().join("man/podlab.1"), roff::render(&m)),
        (dir().join("man/llms.txt"), llms::index(&m, &pod_lab::manual::docs(), pod_lab::manual::DOCS_BASE)),
    ]
}

const WRITE: &str = "run cargo test -p pod-lab --features cli -- --ignored write_the_generated_files";

#[test]
fn each_text_of_the_manual_keeps_the_rules() {
    let m = manual();
    assert_none(texts(&m));
    assert_none(model(&m));
    assert!(m.commands.len() >= 5, "{} commands", m.commands.len());
}

/// The model and the parser of clap agree. The binary answers `-h` and
/// `--help` of each command itself, from the model.
#[test]
fn the_manual_agrees_with_the_parser() {
    let parser = pod_manual::clap::parser(super::cli::command());
    assert_none(flags(&manual(), |path: &[String]| {
        let mut c = parser(path)?;
        c.flags.push(ParserFlag { spellings: vec!["-h".into(), "--help".into()], takes_value: false });
        Some(c)
    }));
}

#[test]
fn the_generated_files_equal_the_model() {
    for (path, want) in generated_files() {
        assert_none(generated(&path, &want, WRITE));
    }
}

/// Writes the generated files from the model.
#[test]
#[ignore = "it writes the files of the repository"]
fn write_the_generated_files() {
    for (path, want) in generated_files() {
        std::fs::write(&path, want).unwrap();
    }
}

/// Each variable that the code reads or sets is a fact, and each fact is
/// in the code; the pager of pod-manual reads its own.
#[test]
fn each_variable_of_the_code_is_a_fact() {
    let mut sources = scan::rust_sources(&[scan::src(env!("CARGO_MANIFEST_DIR"))]);
    sources.push((PathBuf::from("pod-manual/src/pager.rs"), scan::non_test(pod_manual::pager::SOURCE)));
    assert_none(variables(&manual(), &sources, &[]));
}

/// Each exit code that the code gives has a fact, and each fact of one code
/// is a code that it gives.
#[test]
fn each_exit_code_has_a_fact() {
    let given: Vec<i32> =
        scan::exit_constants(include_str!("../../codes.rs"), "EXIT_").into_iter().map(|(_, n)| n).collect();
    assert!(given.len() >= 7, "{given:?}");
    assert_none(exit_codes(&manual(), &given));
}

/// The help of each command, as the binary answers `-h`.
#[test]
fn the_help_of_each_command_comes_from_the_model() {
    let m = manual();
    for c in &m.commands {
        let mut args = c.path.clone();
        args.push("--help".into());
        let help = pod_manual::help::request(&m, &args).expect("a help request");
        assert_eq!(help.path, c.path);
        let text = pod_manual::help::answer(&m, &help).unwrap();
        for f in &c.flags {
            assert!(text.contains(&f.term()), "{}: no {} in\n{text}", c.name(), f.term());
        }
    }
}
