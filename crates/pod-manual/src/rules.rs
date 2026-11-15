//! The rules of the text of a command line (the owner's ruling "The text of
//! a command line"): no emoji or pictograph; valid UTF-8 with no control
//! character but the newline and the tab, and no escape sequence of a
//! terminal; no id of a work entry; ASD-STE100 sentence lengths.
//!
//! A sentence ends at `.`, `?` or `!` before a space or the end, and a
//! clause after `;` or `:` before a space counts as one sentence. A line
//! break also ends one, so that each line of a list counts alone. A word is
//! a run of characters between spaces that holds a letter or a digit. The
//! limit is [`PROCEDURE`] words in an instruction (a step of a procedure,
//! the fix of an error) and [`DESCRIPTION`] words in each other text. Active voice and one instruction in each sentence are not checked:
//! no rule of a machine finds them.

use std::fmt;

/// The most words in a sentence of a procedure.
pub const PROCEDURE: usize = 20;
/// The most words in a sentence of a description.
pub const DESCRIPTION: usize = 25;

/// The kind of a text, which gives its limit of words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Procedure,
    Description,
}

impl Kind {
    pub fn limit(self) -> usize {
        match self {
            Kind::Procedure => PROCEDURE,
            Kind::Description => DESCRIPTION,
        }
    }
}

/// A text that breaks a rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    /// A byte sequence that is not UTF-8, at this offset.
    NotUtf8(usize),
    /// A control character but the newline and the tab.
    Control(char),
    /// A bidirectional control, which reorders the text on a terminal.
    Bidi(char),
    Emoji(char),
    /// The id of a work entry, a call, a question or an issue.
    WorkId(String),
    /// A sentence of more words than its kind allows.
    Long {
        words: usize,
        limit: usize,
        sentence: String,
    },
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fault::NotUtf8(at) => write!(f, "a byte that is not UTF-8 at offset {at}"),
            Fault::Control(c) => write!(f, "the control character U+{:04X}", u32::from(*c)),
            Fault::Bidi(c) => write!(f, "the bidirectional control U+{:04X}", u32::from(*c)),
            Fault::Emoji(c) => write!(f, "the emoji or pictograph U+{:04X}", u32::from(*c)),
            Fault::WorkId(id) => write!(f, "the work id {id}"),
            Fault::Long { words, limit, sentence } => {
                write!(f, "a sentence of {words} words (at most {limit}): {sentence:?}")
            }
        }
    }
}

/// Whether `c` is an emoji or a pictograph: the blocks of emoji and symbols,
/// the variation selectors, the joiner and the keycap of an emoji sequence.
pub fn is_emoji(c: char) -> bool {
    let n = u32::from(c);
    matches!(n,
        0x1F000..=0x1FAFF | 0x2600..=0x27BF | 0x2B00..=0x2BFF | 0x2300..=0x23FF | 0xFE00..=0xFE0F
        | 0x200D | 0x20E3 | 0xE0020..=0xE007F | 0x3030 | 0x303D | 0x3297 | 0x3299)
}

/// Whether `c` reorders the text on a terminal (an attack on the reader).
pub fn is_bidi(c: char) -> bool {
    matches!(u32::from(c), 0x202A..=0x202E | 0x2066..=0x2069 | 0x200E | 0x200F | 0x061C)
}

/// The faults of the characters of `text`: control characters, bidi
/// controls and emoji. An escape sequence of a terminal starts with ESC, a
/// control character.
pub fn char_faults(text: &str) -> Vec<Fault> {
    let mut out = Vec::new();
    for c in text.chars() {
        let f = if c.is_control() && c != '\n' && c != '\t' {
            Fault::Control(c)
        } else if is_bidi(c) {
            Fault::Bidi(c)
        } else if is_emoji(c) {
            Fault::Emoji(c)
        } else {
            continue;
        };
        if !out.contains(&f) {
            out.push(f);
        }
    }
    out
}

/// Each work id in `text`: `T-NNN`, `C123`, `Q12`, `Q-A8`, `COORD-123`,
/// and `#123` (an issue). A letter, a digit, `-` or `_` just before an id
/// makes it a part of another word (`PKCS#1`, `AC3`, `x-T-1`).
pub fn work_ids(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let digits = |from: usize| b[from.min(b.len())..].iter().take_while(|c| c.is_ascii_digit()).count();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let start = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'-' || b[i - 1] == b'_');
        let found = if !start {
            None
        } else if b[i..].starts_with(b"T-") && digits(i + 2) > 0 {
            Some(2 + digits(i + 2))
        } else if b[i..].starts_with(b"COORD-") && digits(i + 6) > 0 {
            Some(6 + digits(i + 6))
        } else if b[i..].starts_with(b"Q-A") && digits(i + 3) > 0 {
            Some(3 + digits(i + 3))
        } else if (b[i] == b'C' || b[i] == b'Q' || b[i] == b'#') && digits(i + 1) > 0 {
            Some(1 + digits(i + 1))
        } else {
            None
        };
        // An issue of another repository: `podnet#584`.
        let issue = found.is_none() && b[i] == b'#' && i > 0 && b[i - 1].is_ascii_lowercase() && digits(i + 1) > 0;
        let len = if issue { Some(1 + digits(i + 1)) } else { found };
        match len {
            // The id ends the word: `C1x` is no id.
            Some(n) if !b.get(i + n).is_some_and(|c| c.is_ascii_alphabetic()) => {
                out.push(text[i..i + n].to_string());
                i += n;
            }
            _ => i += 1,
        }
    }
    out
}

/// The sentences of `text`, by the rule of the module.
pub fn sentences(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    for (k, &(i, c)) in chars.iter().enumerate() {
        let next = chars.get(k + 1).map(|&(_, n)| n);
        let ends = c == '\n' || (matches!(c, '.' | '?' | '!' | ';' | ':') && next.is_none_or(char::is_whitespace));
        if ends {
            out.push(text[start..i + c.len_utf8()].trim());
            start = i + c.len_utf8();
        }
    }
    out.push(text[start..].trim());
    out.retain(|s| !s.is_empty());
    out
}

/// The words of a sentence.
pub fn words(sentence: &str) -> usize {
    sentence.split_whitespace().filter(|w| w.chars().any(char::is_alphanumeric)).count()
}

/// Each fault of `text`, a text of the kind `kind`.
pub fn faults(text: &str, kind: Kind) -> Vec<Fault> {
    let mut out = char_faults(text);
    out.extend(work_ids(text).into_iter().map(Fault::WorkId));
    for s in sentences(text) {
        let n = words(s);
        if n > kind.limit() {
            out.push(Fault::Long { words: n, limit: kind.limit(), sentence: s.to_string() });
        }
    }
    out
}

/// Each fault of the bytes `bytes`: not UTF-8, or a fault of its text.
pub fn byte_faults(bytes: &[u8], kind: Kind) -> Vec<Fault> {
    match std::str::from_utf8(bytes) {
        Ok(text) => faults(text, kind),
        Err(e) => vec![Fault::NotUtf8(e.valid_up_to())],
    }
}

#[cfg(test)]
mod tests;
