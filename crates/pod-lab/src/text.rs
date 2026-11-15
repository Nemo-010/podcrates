//! The rules of a printed text (the owner's ruling "The text of a command
//! line"): no emoji, no control character but the newline and the tab, no
//! id of a work entry or of an issue, and short sentences. The tests walk
//! the text of each profile and each string literal of the code of the
//! crate; a doc comment or a comment may cite an entry. The rules are the
//! ones of `pod_manual::rules`.

use crate::profile::{Hold, IdFact, LabFact, Observe};
use crate::table::PROFILES;
use pod_manual::rules::{Kind, faults};

fn check(at: &str, text: &str) {
    if let Some(f) = faults(text, Kind::Description).first() {
        panic!("{at}: {f} in {text:?}");
    }
}

/// The rules of the characters and the work ids: a literal of the code can
/// be a part of a sentence.
fn fault(text: &str) -> Option<String> {
    let mut f = pod_manual::rules::char_faults(text).into_iter().map(|f| f.to_string());
    f.next().or_else(|| pod_manual::rules::work_ids(text).first().map(|id| format!("the work id {id}")))
}

#[test]
fn the_rules_find_each_fault() {
    for bad in ["see T-692", "call C673", "PodUtils/podvm#424", "a\u{7}bell", "ok \u{1F600}", "Q12 waits"] {
        assert!(fault(bad).is_some(), "{bad:?}");
    }
    for good in ["chroot(/tmp) gives EPERM", "TCP bind\tand\nconnect", "CapEff is 0", "AF_INET6", "Concat", "PART-2"] {
        assert_eq!(fault(good), None, "{good:?}");
    }
    assert!(!faults(&"word ".repeat(26), Kind::Description).is_empty());
}

#[test]
fn each_text_of_each_profile_keeps_the_rules() {
    for p in PROFILES {
        for (at, text) in [("name", p.name), ("about", p.about), ("source", p.source)] {
            check(&format!("{} {at}", p.name), text);
        }
        for part in p.parts {
            let at = format!("{}/{}", p.name, part.name);
            check(&at, part.name);
            check(&at, part.about);
            check(&at, &part.hold.words());
            if let Hold::Seccomp(calls) = part.hold {
                calls.iter().for_each(|c| check(&at, c.name));
            }
            for o in part.observe {
                match o {
                    Observe::Row { row, .. } => check(&at, row),
                    Observe::Identity(f) => check(&at, f.name()),
                    Observe::Lab(f) => check(&at, &f.name()),
                    Observe::Nothing { needs, .. } => check(&at, needs),
                }
            }
        }
    }
    for f in [IdFact::NotRoot, IdFact::NoCaps, IdFact::NoNewPrivs, IdFact::SeccompFilter, IdFact::NoNetAdmin] {
        check("identity", f.name());
    }
    for f in [
        LabFact::TmpdirAtMost(1),
        LabFact::FdsOpen { last: 9 },
        LabFact::Inet6BindRefused,
        LabFact::InetConnectRefused,
        LabFact::UnixAllowed,
        LabFact::GetsocknameRefused,
        LabFact::BindAllowed,
        LabFact::ListenRefused,
        LabFact::UdpRefused,
        LabFact::RawRefused,
        LabFact::NoLoopback,
        LabFact::Absent("/dev/pts"),
        LabFact::NoControllingTerminal,
        LabFact::TtyOpens,
        LabFact::NoPasswdEntry,
        LabFact::HomeNoexec,
        LabFact::ReadOnlyMount("/etc/ssl"),
    ] {
        check("lab fact", &f.name());
        check("lab fact", &crate::check::unseen_fact(f).detail);
    }
}

#[cfg(feature = "manual")]
#[test]
fn the_exit_codes_and_the_environment_keep_the_rules() {
    let m = pod_manual::Manual { name: "podlab".into(), facts: crate::codes::facts(), ..Default::default() };
    pod_manual::check::assert_none(pod_manual::check::texts(&m));
}

/// The string literals of `source`, with no comment: a crude lexer of
/// Rust that knows comments, strings, raw strings and char literals.
fn literals(source: &str) -> Vec<String> {
    let c: Vec<char> = source.chars().collect();
    let (mut out, mut i) = (Vec::new(), 0);
    while i < c.len() {
        match c[i] {
            '/' if c.get(i + 1) == Some(&'/') => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
            }
            '\'' => {
                // A char literal: 'x' or '\x'; else a lifetime.
                if c.get(i + 2) == Some(&'\'') {
                    i += 3;
                } else if c.get(i + 1) == Some(&'\\') {
                    i += 2;
                    while i < c.len() && c[i] != '\'' {
                        i += 1;
                    }
                    i += 1;
                } else {
                    i += 1;
                }
            }
            '"' => {
                let mut s = String::new();
                i += 1;
                while i < c.len() && c[i] != '"' {
                    if c[i] == '\\' {
                        i += 1;
                    }
                    s.push(c[i]);
                    i += 1;
                }
                i += 1;
                out.push(s);
            }
            _ => i += 1,
        }
    }
    out
}

/// Each fixed message of the crate: each string literal of the code that
/// a binary prints (the tests are not in the list).
#[test]
fn each_fixed_message_of_the_crate_keeps_the_rules() {
    let files = [
        ("lib.rs", include_str!("lib.rs")),
        ("codes.rs", include_str!("codes.rs")),
        ("profile.rs", include_str!("profile.rs")),
        ("table.rs", include_str!("table.rs")),
        ("check.rs", include_str!("check.rs")),
        ("hold.rs", include_str!("hold.rs")),
        ("mounts.rs", include_str!("mounts.rs")),
        ("facts.rs", include_str!("facts.rs")),
        ("table/parts.rs", include_str!("table/parts.rs")),
        ("inside.rs", include_str!("inside.rs")),
        ("lab.rs", include_str!("lab.rs")),
        ("manual.rs", include_str!("manual.rs")),
        ("bin/podlab.rs", include_str!("bin/podlab.rs")),
    ];
    let mut count = 0;
    for (name, source) in files {
        // The code before the tests of the file.
        let code = source.split("#[cfg(test)]").next().unwrap_or(source);
        for lit in literals(code) {
            if let Some(f) = fault(&lit) {
                panic!("{name}: {f} in the literal {lit:?}");
            }
            count += 1;
        }
    }
    assert!(count > 100, "the lexer found {count} literals");
    assert_eq!(
        literals(
            r#"// "T-1" a comment
let x = "two"; let c = '"'; f::<'a>("three\"q");"#
        ),
        ["two", "three\"q"]
    );
}
