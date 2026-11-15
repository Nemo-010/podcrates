//! `llms.txt` and `llms-full.txt` from the JSON form of the manual:
//! `llms.txt` is an index (the summary, one line for each command, one link
//! for each document); `llms-full.txt` holds the text of the manual and the
//! text of each document. A program writes both from `CLI man --json`, or
//! from its model, and a test compares the files of its repository with
//! them (`check::generated`).

use crate::model::Manual;

/// A document of the program's repository.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Doc {
    /// The path from the root of the repository: `docs/install.md`.
    pub path: String,
    /// What the document gives: one sentence.
    pub meaning: String,
    /// The text of the document, for `llms-full.txt`.
    pub body: String,
}

/// The two files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Files {
    pub index: String,
    pub full: String,
}

/// The file names of [`Files`].
pub const INDEX: &str = "llms.txt";
pub const FULL: &str = "llms-full.txt";

/// `llms.txt`. `base` is the URL before the path of a document, such as
/// `https://github.com/OWNER/REPO/blob/main/`.
pub fn index(manual: &Manual, docs: &[Doc], base: &str) -> String {
    let about = manual.about.trim_end_matches('.');
    let mut summary = format!("> {about}.");
    if !manual.version.is_empty() {
        summary.push_str(&format!(" Version {}.", manual.version));
    }
    let name = &manual.name;
    let mut lines = vec![format!("# {name}"), String::new(), summary, String::new()];
    lines.extend(manual.description.iter().cloned());
    lines.extend([
        String::new(),
        format!("Run `{name} man` for the manual, `{name} man --json` for the manual as JSON,"),
        format!("and `{name} COMMAND --help --json` for one command as JSON."),
        format!("{FULL} has the manual and the documents in one file."),
        String::new(),
        "## Commands".to_string(),
        String::new(),
    ]);
    for c in manual.commands.iter().filter(|c| !c.path.is_empty()) {
        let about = c.about.split_whitespace().collect::<Vec<_>>().join(" ");
        lines.push(format!("- `{name} {}`: {about}", c.name()));
    }
    if !docs.is_empty() {
        lines.extend([String::new(), "## Documents".to_string(), String::new()]);
        lines.extend(docs.iter().map(|d| format!("- [{}]({base}{}): {}", d.path, d.path, d.meaning)));
    }
    lines.extend([
        String::new(),
        "## Manual".to_string(),
        String::new(),
        format!("- [{FULL}]({FULL}): the manual and the documents."),
        String::new(),
    ]);
    lines.join("\n")
}

/// `llms-full.txt`: the text of the manual, then each document.
pub fn full(manual: &Manual, docs: &[Doc]) -> String {
    let text = crate::text::render(manual);
    let mut parts = vec![
        format!("# {}: manual and documents", manual.name),
        String::new(),
        format!("The manual is the output of `{} man --no-pager`.", manual.name),
        String::new(),
        "```text".to_string(),
        text.trim_end_matches('\n').to_string(),
        "```".to_string(),
    ];
    for d in docs {
        parts.extend([String::new(), format!("<!-- document: {} -->", d.path), String::new()]);
        parts.push(d.body.trim_end_matches('\n').to_string());
    }
    parts.join("\n") + "\n"
}

/// Both files from the JSON form of the manual (`CLI man --json`).
pub fn from_json(json: &str, docs: &[Doc], base: &str) -> Result<Files, String> {
    let manual = crate::json::read(json)?;
    Ok(Files { index: index(&manual, docs, base), full: full(&manual, docs) })
}
