use super::*;
use crate::facts::Var;
use crate::sample::manual;

#[test]
fn the_sample_keeps_each_rule() {
    let m = manual();
    assert_none(texts(&m));
    assert_none(model(&m));
}

/// The control of [`texts`]: a fault in each kind of string is found.
#[test]
fn a_fault_in_each_part_of_the_model_is_found() {
    type Plant = Box<dyn Fn(&mut Manual)>;
    let plants: Vec<(&str, Plant)> = vec![
        ("an emoji in a flag", Box::new(|m| m.commands[1].flags[0].help.push('\u{1F680}'))),
        ("a work id in a fact", Box::new(|m| m.facts.exits[0].meaning.push_str(" See T-700."))),
        ("an escape in a topic", Box::new(|m| m.topics[0].blocks[0] = crate::sections::para("a \u{1b}[1m bold"))),
        ("a long step", Box::new(|m| m.topics[0].blocks[2] = Block::Steps { steps: vec!["do ".repeat(21)] })),
        ("a long note", Box::new(|m| m.commands[1].notes.push("word ".repeat(26)))),
        ("an issue in a table", Box::new(|m| m.facts.tables[0].rows[0][2].push_str(" (#181)"))),
        ("a control in a variable", Box::new(|m| m.facts.variables[0].vars[0].meaning.push('\u{7}'))),
        (
            "a call in a rule",
            Box::new(|m| m.commands[1].rules.push(Rule::Needs { flag: "--url".into(), needs: vec!["C681".into()] })),
        ),
    ];
    for (what, plant) in plants {
        let mut m = manual();
        plant(&mut m);
        assert!(!texts(&m).is_empty(), "{what} passed");
    }
}

use crate::model::{Block, Rule};

#[test]
fn a_rule_that_names_no_flag_and_a_name_of_two_sections_are_found() {
    let mut m = manual();
    m.commands[1].rules.push(Rule::Needs { flag: "--url".into(), needs: vec!["--nothing".into()] });
    assert_eq!(model(&m).len(), 1, "{:?}", model(&m));
    let mut m = manual();
    m.topics[0].aliases.push("keywords".into());
    assert!(model(&m).iter().any(|f| f.what.contains("names two sections")), "{:?}", model(&m));
}

#[test]
fn a_generated_file_must_equal_the_model() {
    let dir = std::env::temp_dir().join(format!("pod-manual-generated-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("sample.1");
    let want = crate::roff::render(&manual());
    let fix = "run the writer";
    assert_eq!(generated(&path, &want, fix).len(), 1, "a missing file");
    std::fs::write(&path, &want).unwrap();
    assert_none(generated(&path, &want, fix));
    std::fs::write(&path, want.replace("\\-\\-url", "\\-\\-uri")).unwrap();
    let f = generated(&path, &want, fix);
    assert!(
        f.len() == 1 && f[0].what.contains("differs from the model") && f[0].what.ends_with("fix: run the writer"),
        "{f:?}"
    );
    std::fs::write(&path, format!("{want}more\n")).unwrap();
    assert_eq!(generated(&path, &want, fix).len(), 1, "a longer file");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_variables_are_checked_both_ways() {
    let m = manual();
    let code =
        r#"std::env::var("HTTPS_PROXY"); var("https_proxy"); var("SAMPLE_PROTOCOL"); cmd.env("SAMPLE_CHILD", x);"#;
    let src = |c: &str| vec![(PathBuf::from("main.rs"), c.to_string())];
    assert_none(variables(&m, &src(code), &[]));
    let read_more = format!("{code} var(\"SAMPLE_NEW\");");
    let f = variables(&m, &src(&read_more), &[]);
    assert!(f.len() == 1 && f[0].what.contains("SAMPLE_NEW"), "{f:?}");
    assert!(variables(&m, &src(&read_more), &["SAMPLE_NEW"]).is_empty());
    let f = variables(&m, &src(&code.replace("SAMPLE_CHILD", "OTHER")), &["OTHER"]);
    assert!(f.len() == 1 && f[0].what.contains("SAMPLE_CHILD is a fact"), "{f:?}");
}

/// The pager reads its variables, and its group of facts names each.
#[test]
fn the_pager_facts_and_the_pager_agree() {
    let m = Manual {
        facts: crate::facts::Facts { variables: vec![crate::pager::variables()], ..Default::default() },
        ..Manual::default()
    };
    assert_none(variables(&m, &[(PathBuf::from("pager.rs"), crate::scan::non_test(crate::pager::SOURCE))], &[]));
    let _: Var = Var::default();
}

#[test]
fn the_exit_codes_are_checked_both_ways() {
    let m = manual();
    assert_none(exit_codes(&m, &[0, 64, 66, 130]));
    let m2 =
        Manual { facts: crate::facts::Facts { exits: m.facts.exits[..4].to_vec(), ..Default::default() }, ..m.clone() };
    let f = exit_codes(&m2, &[0, 64, 3]);
    assert!(f.len() == 1 && f[0].what.contains("gives 3"), "{f:?}");
    let f = exit_codes(&m, &[0]);
    assert!(f.len() == 1 && f[0].what.contains("64"), "{f:?}");
}

fn row(spellings: &[&str], takes_value: bool) -> ParserFlag {
    ParserFlag { spellings: spellings.iter().map(|s| s.to_string()).collect(), takes_value }
}

/// A parser that agrees with the sample, but for the change `edit`.
fn parser(edit: fn(&[String], &mut ParserCommand)) -> impl Fn(&[String]) -> Option<ParserCommand> {
    let m = manual();
    move |path: &[String]| {
        let c = m.commands.iter().find(|c| c.path == path)?;
        let mut p = ParserCommand {
            flags: c
                .flags
                .iter()
                .map(|f| ParserFlag { spellings: f.spellings(), takes_value: f.value.is_some() })
                .collect(),
            subcommands: m.children(path).iter().map(|k| k.path.last().unwrap().clone()).collect(),
        };
        edit(path, &mut p);
        Some(p)
    }
}

#[test]
fn each_flag_row_is_checked_against_the_parser() {
    let m = manual();
    assert_none(flags(&m, parser(|_, _| {})));
    type Edit = fn(&[String], &mut ParserCommand);
    let changes: [(&str, Edit); 5] = [
        ("a flag that the parser lacks", |p, c| {
            if p == ["tunnel"] {
                c.flags.remove(0);
            }
        }),
        ("a flag that the model lacks", |p, c| {
            if p == ["tunnel"] {
                c.flags.push(row(&["--new"], false));
            }
        }),
        ("a value that differs", |p, c| {
            if p == ["tunnel"] {
                c.flags[0].takes_value = false;
            }
        }),
        ("a short name that differs", |p, c| {
            if p == ["net", "ts-shims"] {
                c.flags[0] = row(&["-O", "--out"], true);
            }
        }),
        ("a command that the model lacks", |p, c| {
            if p.is_empty() {
                c.subcommands.push("new".into());
            }
        }),
    ];
    for (what, edit) in changes {
        assert_eq!(flags(&m, parser(edit)).len(), 1, "{what}");
    }
    assert_eq!(
        flags(&m, |p: &[String]| parser(|_, _| {})(p).filter(|_| p != ["chat"])).len(),
        1,
        "a command that the parser lacks"
    );
}
