//! The manual of `podlab` (feature `cli`): the command tree of its parser,
//! read by `pod_manual::clap`, with the facts of [`crate::codes`], the
//! table of the profiles and the examples. The help of each command and
//! `podlab man` come from it.

use pod_manual::{Example, Group, Manual, Table};

use crate::PROFILES;

/// The paragraphs of DESCRIPTION.
const DESCRIPTION: &[&str] = &[
    "podlab holds the classes of hostile hosts as profiles. A profile names the probe rows that each part refuses or allows.",
    "podlab check compares a profile with this host, or with a JSON report of pod-hostprobe. A part holds, fails, or cannot be observed here.",
    "podlab run runs a command in a lab of a profile. The lab holds each part with no root: a seccomp filter, Landlock, mounts in a user namespace, a network namespace and inherited descriptors.",
    "The lab measures the profile from inside before the command. A part that does not hold stops the run, unless --partial is given.",
];

fn s(t: &str) -> String {
    t.to_string()
}

/// The profiles as a table of the manual.
fn profiles() -> Table {
    let rows = PROFILES.iter().map(|p| {
        let parts: Vec<&str> = p.parts.iter().map(|x| x.name).collect();
        let holds: Vec<String> = p.parts.iter().map(|x| format!("{}: {}", x.name, x.hold.words())).collect();
        vec![s(p.name), s(p.about), parts.join(", "), holds.join("; "), s(p.source)]
    });
    Table {
        key: s("profiles"),
        heading: s("PROFILES"),
        about: s("Each profile, its parts, and what holds each part in a lab. podlab list prints the same table."),
        columns: vec![s("Profile"), s("About"), s("Parts"), s("Held by"), s("Source")],
        rows: rows.collect(),
    }
}

/// The manual of the command tree `cmd`, the parser of `podlab`.
pub fn manual(cmd: clap::Command) -> Manual {
    let mut m = pod_manual::clap::read(cmd).with_help_flags();
    m.version = env!("CARGO_PKG_VERSION").to_string();
    // The date of the page: the time of a reproducible build, else none.
    let epoch = option_env!("SOURCE_DATE_EPOCH").and_then(|s| s.trim().parse().ok());
    m.date = epoch.map(pod_manual::model::date_of).unwrap_or_default();
    m.description = DESCRIPTION.iter().map(|p| s(p)).collect();
    m.facts = crate::codes::facts();
    m.facts.tables.push(profiles());
    let example = |command: &str, meaning: &str| Example { command: s(command), meaning: s(meaning) };
    m.examples = vec![
        example("podlab list", "List each profile and its parts."),
        example("podlab check userns-off", "Check the profile userns-off on this host."),
        example("podlab check bind-denied --report report.json", "Check a profile against a report of pod-hostprobe."),
        example("podlab run small-tmp -- sh -c 'df /tmp'", "Run a command in a lab with a small /tmp."),
        example("podlab run no-ptmx -- sh -c 'ls /dev'", "Run a command in a lab with no pseudo terminal."),
        example(
            "podlab run --partial nonroot-nocaps -- id",
            "Run a command in the parts that hold, and name the others.",
        ),
        example(
            "podlab run --serve 8443 proxy-only -- ./server --listen 127.0.0.1:8443",
            "Run a server in a network lab. Its clients reach it through the stand-in proxy with the rules of the class.",
        ),
        example("podlab man --no-pager check", "Write the section of podlab check, with no pager."),
    ];
    m.see_also =
        vec![s("pod-hostprobe: the probe rows that a profile names."), s("https://github.com/PodUtils/podcrates")];
    if let Some(root) = m.commands.iter_mut().find(|c| c.path.is_empty()) {
        root.lead = vec![
            example("podlab list", "List each profile."),
            example("podlab check PROFILE", "Check a profile on this host."),
            example("podlab man", "Read the manual."),
        ];
        let group =
            |title: &str, words: &[&str]| Group { title: s(title), commands: words.iter().map(|w| s(w)).collect() };
        root.groups = vec![
            group("Read the profiles", &["list", "check"]),
            group("Run in a lab", &["run"]),
            group("Read the manual", &["man"]),
        ];
    }
    m
}

/// The documents of `llms.txt`. Their text is not in the binary.
pub fn docs() -> Vec<pod_manual::llms::Doc> {
    vec![
        pod_manual::llms::Doc {
            path: s("README.md"),
            meaning: s("The profiles, the check, the lab and the API of pod-lab."),
            body: String::new(),
        },
        pod_manual::llms::Doc {
            path: s("LANES.md"),
            meaning: s("The commands that each project runs in each profile."),
            body: String::new(),
        },
    ]
}

/// The base of the links of `llms.txt`.
pub const DOCS_BASE: &str = "https://github.com/PodUtils/podcrates/blob/main/crates/pod-lab/";
