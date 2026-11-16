//! The manual as data: the command tree, the topics and the facts. A
//! program fills it from its own tables, or [`crate::clap`] fills the
//! command tree from a clap program. Each writer walks the same value, so
//! the help, the text, the man page and the JSON cannot describe different
//! programs.

use serde::{Deserialize, Serialize};

use crate::facts::Facts;

/// The version of the shape of the JSON form. A change that breaks a reader
/// raises it.
pub const SCHEMA: u32 = 1;

/// The whole manual of one program.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Manual {
    /// The name of the program, as the help shows it.
    pub name: String,
    /// The version. An empty version is left out of each writer (a file that
    /// a repository keeps does not change at each release).
    pub version: String,
    /// The date of the man page header. Empty: the writer gives none.
    pub date: String,
    /// One line: what the program is.
    pub about: String,
    /// Other names of the program: a link `docker` to `podvm` shows
    /// `docker` in the help ([`Manual::named`]).
    pub names: Vec<String>,
    /// The paragraphs of DESCRIPTION.
    pub description: Vec<String>,
    /// Each command. The root has an empty path.
    pub commands: Vec<Command>,
    /// The topics that are not commands: notes, guides, examples.
    pub topics: Vec<Topic>,
    pub facts: Facts,
    pub examples: Vec<Example>,
    /// The lines of SEE ALSO.
    pub see_also: Vec<String>,
}

/// One command, for example `podnet warp run`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Command {
    /// The words after the name of the program; empty for the root.
    pub path: Vec<String>,
    /// Other names of the last word: `irc` for `chat`.
    pub aliases: Vec<String>,
    pub about: String,
    /// The paragraphs after `about`.
    pub notes: Vec<String>,
    /// The words of the usage after the name and the path. Empty: the
    /// writers make it from the flags and the arguments.
    pub usage: String,
    pub args: Vec<Arg>,
    pub flags: Vec<Flag>,
    pub rules: Vec<Rule>,
    /// The status of the command against another tool.
    pub parity: Option<Parity>,
    /// The commands under this one by purpose. Each group is a table of
    /// the help and the manual; empty: one table "Commands".
    #[serde(default)]
    pub groups: Vec<Group>,
    /// The first lines of the help, under "Start here": what to type
    /// first.
    #[serde(default)]
    pub lead: Vec<Example>,
}

/// A group of the commands under one command, by purpose.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    /// The title of the group: `Run in the background`.
    pub title: String,
    /// The last word of each command of the group, in the order of the
    /// help.
    pub commands: Vec<String>,
}

impl Command {
    /// `warp run`, or the empty string for the root.
    pub fn name(&self) -> String {
        self.path.join(" ")
    }

    /// The flag with this spelling: `-x` or `--long`.
    pub fn flag(&self, spelling: &str) -> Option<&Flag> {
        self.flags.iter().find(|f| f.spellings().iter().any(|s| s == spelling))
    }

    /// The positional argument with this name: `HOST`.
    pub fn arg(&self, name: &str) -> Option<&Arg> {
        self.args.iter().find(|a| a.name == name)
    }
}

/// One positional argument.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Arg {
    /// The value name: `HOST`.
    pub name: String,
    pub help: String,
    pub required: bool,
    /// It takes more than one word.
    pub many: bool,
    pub default: Option<String>,
    pub values: Vec<String>,
    /// The variable that gives the value when the argument is not given.
    #[serde(default)]
    pub env: Option<String>,
}

impl Arg {
    /// `HOST`, `[HOST]`, `HOST...`.
    pub fn term(&self) -> String {
        let dots = if self.many { "..." } else { "" };
        if self.required { format!("{}{dots}", self.name) } else { format!("[{}]{dots}", self.name) }
    }
}

/// One flag.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Flag {
    pub short: Option<char>,
    /// The long name without the dashes.
    pub long: Option<String>,
    /// The value name, when the flag takes a value: `PORT`.
    pub value: Option<String>,
    pub help: String,
    pub kind: FlagKind,
    pub parity: Option<Parity>,
    pub default: Option<String>,
    pub values: Vec<String>,
    /// The variable that gives the value when the flag is not given.
    pub env: Option<String>,
    pub required: bool,
    pub repeatable: bool,
}

impl Flag {
    /// A wired flag with a long name.
    pub fn long(long: &str, help: &str) -> Flag {
        Flag { long: Some(long.to_string()), help: help.to_string(), ..Flag::default() }
    }

    /// Each spelling: `-x` and `--long`.
    pub fn spellings(&self) -> Vec<String> {
        let mut out = Vec::new();
        out.extend(self.short.map(|c| format!("-{c}")));
        out.extend(self.long.as_ref().map(|l| format!("--{l}")));
        out
    }

    /// The flag as a user types it: `-p, --port PORT`.
    pub fn term(&self) -> String {
        let mut s = self.spellings().join(", ");
        if let Some(v) = &self.value {
            s.push(' ');
            s.push_str(v);
        }
        s
    }

    /// The first spelling, for a message: `--long`, else `-x`.
    pub fn spelling(&self) -> String {
        self.spellings().pop().unwrap_or_default()
    }
}

/// What the program does with a flag.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum FlagKind {
    /// It parses and it works.
    #[default]
    Wired,
    /// It parses, and the program ignores it on purpose and says so.
    Ignored { why: String },
    /// It parses, and the program refuses it and names what to use.
    Refused { instead: String },
}

/// The status of a command or a flag against another tool: podvm against
/// docker and podman, podssh against OpenSSH.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parity {
    /// The other tool: `docker`.
    pub tool: String,
    pub status: Status,
    /// What differs, or what to use.
    pub text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Implemented,
    Degraded,
    Stub,
    Refused,
}

impl Status {
    pub fn word(self) -> &'static str {
        match self {
            Status::Implemented => "implemented",
            Status::Degraded => "degraded",
            Status::Stub => "stub",
            Status::Refused => "refused",
        }
    }
}

/// A rule between the flags and the arguments of one command. Each name is
/// a spelling of a flag of the command (`--json`) or the name of one of its
/// positional arguments (`NAME`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rule", rename_all = "kebab-case")]
pub enum Rule {
    /// At most one of the flags.
    Excludes { flags: Vec<String> },
    /// `flag` only with each of `needs`; with `value`, only where `flag`
    /// has that value (clap's `requires_if`).
    Needs {
        flag: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<String>,
        needs: Vec<String>,
    },
    /// One of the flags; with `required`, exactly one.
    OneOf { flags: Vec<String>, required: bool },
}

impl Rule {
    /// The rule as a sentence.
    pub fn sentence(&self) -> String {
        match self {
            Rule::Excludes { flags } => format!("Give only one of {}.", flags.join(", ")),
            Rule::Needs { flag, value: None, needs } => format!("{flag} needs {}.", needs.join(" and ")),
            Rule::Needs { flag, value: Some(v), needs } => format!("{flag} {v} needs {}.", needs.join(" and ")),
            Rule::OneOf { flags, required: true } => format!("Give one of {}.", flags.join(", ")),
            Rule::OneOf { flags, required: false } => format!("Give one of {}, or none.", flags.join(", ")),
        }
    }

    /// Each flag that the rule names.
    pub fn names(&self) -> Vec<&str> {
        match self {
            Rule::Excludes { flags } | Rule::OneOf { flags, .. } => flags.iter().map(String::as_str).collect(),
            Rule::Needs { flag, needs, .. } => std::iter::once(flag).chain(needs).map(String::as_str).collect(),
        }
    }
}

/// A topic of the manual that is not a command.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Topic {
    /// The name that `man KEY` selects it by.
    pub key: String,
    pub aliases: Vec<String>,
    pub heading: String,
    pub blocks: Vec<Block>,
}

/// Part of a term: what a user types, a value to put in its place, or text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "span", content = "text", rename_all = "kebab-case")]
pub enum Span {
    Lit(String),
    Var(String),
    Plain(String),
}

/// The plain text of a term.
pub fn plain(spans: &[Span]) -> String {
    spans
        .iter()
        .map(|s| match s {
            Span::Lit(t) | Span::Var(t) | Span::Plain(t) => t.as_str(),
        })
        .collect()
}

/// One block of a topic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "block", rename_all = "kebab-case")]
pub enum Block {
    /// Prose, filled to the width of the page.
    Para { text: String },
    /// The steps of a procedure, in order. A step is an instruction: the
    /// limit of words is the one of a procedure.
    Steps { steps: Vec<String> },
    /// One line kept as it is, such as a synopsis.
    Line { spans: Vec<Span> },
    /// A heading inside a topic.
    Sub { text: String },
    /// A term and its description.
    Item { term: Vec<Span>, text: String },
    /// Terms and descriptions in two columns.
    Table { rows: Vec<(Vec<Span>, String)> },
    /// What a command line does, then the command line.
    Example { text: String, command: String },
}

/// The date `YYYY-MM-DD` (UTC) of `secs` seconds after 1970-01-01: for the
/// date of a man page from `SOURCE_DATE_EPOCH` of a reproducible build.
pub fn date_of(secs: u64) -> String {
    // The civil date of a count of days (the algorithm of Howard Hinnant).
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// One example: what it does, then the command line.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Example {
    pub command: String,
    pub meaning: String,
}

impl Manual {
    /// The command whose path or alias path is `name`: `warp run`,
    /// `warp/run`, or an alias in place of the last word.
    pub fn command(&self, name: &str) -> Option<&Command> {
        let words: Vec<&str> = name.split([' ', '/']).filter(|w| !w.is_empty()).collect();
        if words.is_empty() {
            return self.root();
        }
        self.commands.iter().filter(|c| c.path.len() == words.len()).find(|c| {
            let (last, head) = c.path.split_last().expect("not the root");
            head.iter().zip(&words).all(|(p, w)| p == w)
                && (words[words.len() - 1] == last || c.aliases.iter().any(|a| a == words[words.len() - 1]))
        })
    }

    /// The root command, when the manual has one.
    pub fn root(&self) -> Option<&Command> {
        self.commands.iter().find(|c| c.path.is_empty())
    }

    /// The last words of each command directly under `path`.
    pub fn children(&self, path: &[String]) -> Vec<&Command> {
        self.commands.iter().filter(|c| c.path.len() == path.len() + 1 && c.path.starts_with(path)).collect()
    }

    /// The manual as the program named `argv0` shows it: when the base name
    /// of `argv0` is one of [`Manual::names`], that name.
    pub fn named(mut self, argv0: &str) -> Manual {
        let base = argv0.rsplit(['/', '\\']).next().unwrap_or(argv0);
        let base = base.strip_suffix(".exe").unwrap_or(base);
        if self.names.iter().any(|n| n == base) {
            self.name = base.to_string();
        }
        self
    }

    /// The same manual with no version and no date: for a file that a
    /// repository keeps, which must not change at each release.
    pub fn for_repository(mut self) -> Manual {
        self.version.clear();
        self.date.clear();
        self
    }

    /// `-h, --help` on each command that has no help flag.
    pub fn with_help_flags(mut self) -> Manual {
        for c in &mut self.commands {
            if c.flag("--help").is_none() {
                let help = if c.path.is_empty() { "Print the help." } else { "Print the help of this command." };
                c.flags.push(Flag { short: Some('h'), ..Flag::long("help", help) });
            }
        }
        self
    }
}
