//! The check of each example of a manual against the parser of its program:
//! an example that the parser refuses is a promise of the help that the
//! command does not keep.

use super::{Finding, finding};
use crate::model::Manual;

/// Each example of `manual` whose program is the manual's, as the words
/// after the program, to `parse`, the program's own parser with no run. A
/// refusal is a finding with the example and the parser's words. An example
/// of another program (a pipe into `jq`, an `ssh` line) is not read.
pub fn examples(manual: &Manual, parse: impl Fn(&[String]) -> Result<(), String>) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in &manual.examples {
        let Some(words) = words(&e.command) else {
            out.push(finding(&e.command, "the example is not one command line: a quote does not end"));
            continue;
        };
        let mut words = words.into_iter().skip_while(|w| is_assignment(w));
        if words.next().as_deref() != Some(manual.name.as_str()) {
            continue;
        }
        let args: Vec<String> = words.collect();
        if let Err(why) = parse(&args) {
            out.push(finding(&e.command, format!("the parser refuses the example: {why}")));
        }
    }
    out
}

/// `NAME=value`, a variable that the shell sets for the command.
fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric()) && !name.starts_with('-')
    })
}

/// The words of the first command of `line`, as a POSIX shell splits them:
/// quotes and a backslash hold, and an unquoted `|`, `;`, `&`, `<` or `>`
/// ends the command. `None` for a quote that does not end.
fn words(line: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                started = true;
                loop {
                    match chars.next()? {
                        '\'' => break,
                        c => word.push(c),
                    }
                }
            }
            '"' => {
                started = true;
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' => word.push(chars.next()?),
                        c => word.push(c),
                    }
                }
            }
            '\\' => {
                started = true;
                if let Some(c) = chars.next() {
                    word.push(c);
                }
            }
            '|' | ';' | '&' | '<' | '>' => break,
            c if c.is_whitespace() => {
                if started {
                    out.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            c => {
                started = true;
                word.push(c);
            }
        }
    }
    if started {
        out.push(word);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Example;

    fn manual(lines: &[&str]) -> Manual {
        Manual {
            name: "prog".into(),
            examples: lines.iter().map(|l| Example { command: l.to_string(), meaning: String::new() }).collect(),
            ..Manual::default()
        }
    }

    #[test]
    fn a_line_splits_as_a_shell_splits_it() {
        assert_eq!(
            words("prog run --name 'a b' \"c \\\"d\\\"\" e\\ f").unwrap(),
            ["prog", "run", "--name", "a b", "c \"d\"", "e f"]
        );
        assert_eq!(words("prog ls | jq .").unwrap(), ["prog", "ls"]);
        assert_eq!(words("prog get > out.txt").unwrap(), ["prog", "get"]);
        assert!(words("prog 'open").is_none());
    }

    /// The flag that the help names and the parser does not know
    /// (PodUtils/podnet#612, #647) is a finding; an example of another
    /// program and a variable before the command are read right.
    #[test]
    fn an_example_that_the_parser_refuses_is_a_finding() {
        let m = manual(&[
            "prog run --known",
            "PROG_LOG=debug prog run --known",
            "prog run --gone",
            "ssh -o ProxyCommand='prog pipe %h' host",
            "prog 'open",
        ]);
        let parse = |args: &[String]| {
            if args.iter().any(|a| a == "--gone") { Err("unexpected argument '--gone'".to_string()) } else { Ok(()) }
        };
        let found: Vec<String> = examples(&m, parse).iter().map(|f| f.to_string()).collect();
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found[0].contains("prog run --gone") && found[0].contains("unexpected argument '--gone'"), "{found:?}");
        assert!(found[1].contains("a quote does not end"), "{found:?}");
    }
}
