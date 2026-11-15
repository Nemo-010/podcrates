//! The help of each command from the model: `CLI --help`, `CLI COMMAND
//! --help`, `CLI help COMMAND`, and their JSON form with `--json`. The help
//! shows the blocks of the command section of the manual, so the two do
//! not differ.

use crate::model::{Command, Manual};
use crate::sections::{command_blocks, para};

/// A request for help that a command line makes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Help {
    /// The path of the command; empty for the root.
    pub path: Vec<String>,
    /// `--json` is on the line.
    pub json: bool,
}

/// The help request of `args` (the command line without `argv[0]`), or
/// `None` when it asks for no help. The words up to `--` count: `-h` or
/// `--help` anywhere, or `help` as the first word when the program has no
/// command of that name. The path is each word that names a command under
/// the path before it (an alias gives the canonical path).
pub fn request(manual: &Manual, args: &[String]) -> Option<Help> {
    let words: Vec<&str> = args.iter().map(String::as_str).take_while(|a| *a != "--").collect();
    let help_word = words.first() == Some(&"help") && manual.command("help").is_none();
    let help_flag = words.iter().any(|a| matches!(*a, "-h" | "--help"));
    if !help_word && !help_flag {
        return None;
    }
    let json = words.contains(&"--json");
    let mut path: Vec<String> = Vec::new();
    for word in words.iter().skip(usize::from(help_word)).filter(|w| !w.starts_with('-')) {
        let mut next = path.join(" ");
        next.push(' ');
        next.push_str(word);
        match manual.command(next.trim()) {
            Some(c) => path = c.path.clone(),
            None => break,
        }
    }
    Some(Help { path, json })
}

/// The help of the command at `path`.
pub fn render(manual: &Manual, path: &[String]) -> Result<String, String> {
    let c: &Command = if path.is_empty() {
        manual.root().ok_or_else(|| format!("{}: the manual has no root command", manual.name))?
    } else {
        manual.command(&path.join(" ")).ok_or_else(|| {
            crate::error::fault(&path.join(" "), "no such command", &format!("run {} --help", manual.name))
        })?
    };
    let mut blocks = command_blocks(manual, c);
    if path.is_empty() && c.about.is_empty() && !manual.about.is_empty() {
        blocks.insert(0, para(crate::sections::sentence(&manual.about, &[])));
    }
    let mut out = String::new();
    crate::text::blocks(&mut out, &blocks);
    if manual.command("man").is_some() {
        let section = if path.is_empty() { String::new() } else { format!(" {}", path.join(" ")) };
        out.push('\n');
        crate::text::fill(&mut out, &format!("Run {} man{section} for the manual.", manual.name), 2, 2);
    }
    Ok(out)
}

/// The help request as its text: the help, or the JSON of the command.
pub fn answer(manual: &Manual, help: &Help) -> Result<String, String> {
    if help.json {
        let c = manual.command(&help.path.join(" ")).ok_or_else(|| format!("{}: no root command", manual.name))?;
        let s = crate::sections::Section {
            key: c.name(),
            aliases: c.aliases.clone(),
            heading: c.name(),
            command: Some(c.path.clone()),
            blocks: Vec::new(),
        };
        return Ok(crate::json::text(&crate::json::section(manual, &s)));
    }
    render(manual, &help.path)
}
