//! The exit codes of `podlab` and the environment variables that it reads
//! or sets: one typed table each, which the help of the binary prints.

/// `podlab check`: each part holds.
pub const EXIT_HOLDS: i32 = 0;
/// `podlab check`: a part does not hold.
pub const EXIT_FAILS: i32 = 1;
/// A usage error of the command line.
pub const EXIT_USAGE: i32 = 2;
/// `podlab check`: no part fails, and a part cannot be observed here.
pub const EXIT_UNSEEN: i32 = 3;
/// `podlab run`: the lab does not hold; the command did not run.
pub const EXIT_REFUSED: i32 = 125;
/// `podlab run`: the command was found and did not start.
pub const EXIT_CANNOT_EXEC: i32 = 126;
/// `podlab run`: the command was not found.
pub const EXIT_NOT_FOUND: i32 = 127;

/// One exit code.
#[derive(Debug)]
pub struct Exit {
    pub code: &'static str,
    pub meaning: &'static str,
}

/// Each exit code of `podlab`.
pub const EXITS: &[Exit] = &[
    Exit { code: "0", meaning: "check: each part holds; run: the exit code of the command" },
    Exit { code: "1", meaning: "check: a part does not hold" },
    Exit { code: "2", meaning: "a usage error" },
    Exit { code: "3", meaning: "check: no part fails, and a part cannot be observed here" },
    Exit { code: "125", meaning: "run: a part of the lab does not hold; the command did not run" },
    Exit { code: "126", meaning: "run: the command did not start" },
    Exit { code: "127", meaning: "run: the command was not found" },
    Exit { code: "128+N", meaning: "run: the command ended on signal N" },
    Exit { code: "other", meaning: "run: the exit code of the command" },
];

/// What the binary does with a variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Use {
    Reads,
    Sets,
}

/// One environment variable.
#[derive(Debug)]
pub struct Var {
    pub name: &'static str,
    pub usage: Use,
    pub meaning: &'static str,
}

/// Each environment variable of `podlab`. It reads none.
pub const ENVIRONMENT: &[Var] = &[Var {
    name: "TMPDIR",
    usage: Use::Sets,
    meaning: "run: /tmp for the command, where a part puts a tmpfs on /tmp",
}];

/// The two tables as text, for the end of the help.
pub fn help() -> String {
    let mut s = String::from("Exit codes:\n");
    for e in EXITS {
        s.push_str(&format!("  {:<6} {}\n", e.code, e.meaning));
    }
    s.push_str("\nEnvironment:\n");
    for v in ENVIRONMENT {
        let usage = match v.usage {
            Use::Reads => "read",
            Use::Sets => "set",
        };
        s.push_str(&format!("  {:<6} ({usage}) {}\n", v.name, v.meaning));
    }
    s
}

/// The fault of a printed text, or `None`: an emoji, a control
/// character but the newline and the tab, or the id of a work entry, a
/// call, a question or an issue (the owner's ruling "The text of a command
/// line").
pub fn fault(text: &str) -> Option<String> {
    for c in text.chars() {
        if c.is_control() && c != '\n' && c != '\t' {
            return Some(format!("the control character {:?}", c));
        }
        let n = c as u32;
        if (0x1F000..=0x1FAFF).contains(&n) || (0x2600..=0x27BF).contains(&n) || n == 0xFE0F {
            return Some(format!("the emoji {c:?}"));
        }
    }
    let b = text.as_bytes();
    for i in 0..b.len() {
        let word_start = i == 0 || !b[i - 1].is_ascii_alphanumeric();
        let digit_at = |j: usize| b.get(j).is_some_and(u8::is_ascii_digit);
        if word_start && b[i] == b'T' && b.get(i + 1) == Some(&b'-') && digit_at(i + 2) {
            return Some("the id of an entry (T-NNN)".to_string());
        }
        if word_start && (b[i] == b'C' || b[i] == b'Q') && digit_at(i + 1) {
            return Some("the id of a call or a question".to_string());
        }
        if b[i] == b'#' && digit_at(i + 1) {
            return Some("the number of an issue".to_string());
        }
    }
    None
}
