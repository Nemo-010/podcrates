//! Text that came from a peer, made safe to print on a terminal.
//!
//! A relay's error body, a WebSocket close reason, a proxy's status line or an
//! SSH banner can carry ESC, BEL or a bare CR, which repaint the line, ring the
//! bell or overwrite what the user is reading. Everything a crate shows from a
//! peer goes through one of these two functions, so there is one definition of
//! "safe" (a sibling project ended up with two that disagreed). A field that
//! keeps such text takes a [`PeerText`], which is clean by its type.

/// For a one-line message: control characters (C0, DEL, C1) and bidirectional
/// formatting characters are dropped, and every run of whitespace, line breaks
/// included, becomes one space. Leading and trailing whitespace is removed.
pub fn one_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut space = false;
    for c in text.chars() {
        if c.is_whitespace() {
            space = true;
        } else if c.is_control() || is_bidi_control(c) {
            continue;
        } else {
            if space && !out.is_empty() {
                out.push(' ');
            }
            space = false;
            out.push(c);
        }
    }
    out
}

/// For text that is meant to span lines (an SSH banner, a keyboard-interactive
/// instruction): CR LF and a lone CR become LF, tabs stay, and every other
/// control or bidirectional formatting character is dropped.
pub fn multi_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            '\n' | '\t' => out.push(c),
            c if c.is_control() || is_bidi_control(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// The most characters of a [`PeerText`]: a peer that sends a page of
/// text in an error field fills no screen.
pub const PEER_TEXT_MOST: usize = 512;

/// Text of a peer, cleaned and cut when it is made: a field of this type
/// cannot hold text that is not safe to print. It has no `Deref` to `str`
/// and no `From<String>`, so raw text does not go in by a slip. It goes out
/// as a `String`:
///
/// ```
/// let text: String = pod_core::text::PeerText::one_line("bad\x1b[2J token").into();
/// assert_eq!(text, "bad[2J token");
/// ```
///
/// ```compile_fail
/// let raw = String::from("\x1b[2J");
/// let field: pod_core::text::PeerText = raw.into();
/// ```
///
/// ```compile_fail
/// let field = pod_core::text::PeerText::one_line("ok");
/// let shown: &str = &field;
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct PeerText(String);

impl PeerText {
    /// One line of a peer ([`one_line`]), cut to [`PEER_TEXT_MOST`].
    pub fn one_line(text: &str) -> PeerText {
        PeerText(cut(one_line(text)))
    }

    /// Lines of a peer ([`multi_line`]), cut to [`PEER_TEXT_MOST`].
    pub fn multi_line(text: &str) -> PeerText {
        PeerText(cut(multi_line(text)))
    }

    /// The clean text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Display for PeerText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Clean text goes where a `String` goes (the text of a `Failure`).
impl From<PeerText> for String {
    fn from(text: PeerText) -> String {
        text.0
    }
}

/// `text` cut to [`PEER_TEXT_MOST`] characters; a cut ends with "...".
fn cut(mut text: String) -> String {
    if let Some((at, _)) = text.char_indices().nth(PEER_TEXT_MOST) {
        let keep = text[..at].char_indices().nth(PEER_TEXT_MOST - 3).map_or(at, |(i, _)| i);
        text.truncate(keep);
        text.push_str("...");
    }
    text
}

/// Characters that reorder how a terminal displays the text around them
/// (the "Trojan Source" set), plus the Arabic letter mark.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_unchanged() {
        assert_eq!(one_line("403 missing or wrong token"), "403 missing or wrong token");
        assert_eq!(multi_line("Welcome.\nNo shell here.\n"), "Welcome.\nNo shell here.\n");
        assert_eq!(one_line("naïve — ok"), "naïve — ok");
    }

    #[test]
    fn terminal_controls_are_removed() {
        // ESC sequences, BEL, a bare CR that would overwrite the line, and the
        // 8-bit CSI (U+009B). The CR is whitespace, so one line shows a space.
        let hostile = "ok\x1b[2J\x1b]0;title\x07\rFAKE\u{9b}31m";
        assert_eq!(one_line(hostile), "ok[2J]0;title FAKE31m");
        assert!(!multi_line(hostile).contains('\x1b'));
        assert!(!multi_line(hostile).contains('\x07'));
        assert!(!multi_line(hostile).contains('\u{9b}'));
    }

    #[test]
    fn bidirectional_overrides_are_removed() {
        assert_eq!(one_line("abc\u{202E}fed\u{202C}"), "abcfed");
        assert_eq!(multi_line("a\u{2066}b\u{2069}c"), "abc");
    }

    #[test]
    fn one_line_folds_whitespace_and_line_breaks() {
        assert_eq!(one_line("  a \r\n\t b\n\nc  "), "a b c");
        assert_eq!(one_line("\n\n"), "");
    }

    #[test]
    fn peer_text_is_clean_and_cut() {
        let long = format!("\x1b[2J{}", "é".repeat(2 * PEER_TEXT_MOST));
        let text = PeerText::one_line(&long);
        assert_eq!(text.as_str().chars().count(), PEER_TEXT_MOST);
        assert!(text.as_str().ends_with("...") && !text.as_str().contains('\x1b'));
        let short = PeerText::multi_line("a\r\nb\x07");
        assert_eq!((short.to_string(), String::from(short)), ("a\nb".into(), "a\nb".into()));
        assert_eq!(PeerText::one_line(&"x".repeat(PEER_TEXT_MOST)).as_str().len(), PEER_TEXT_MOST);
    }

    #[test]
    fn multi_line_normalises_line_breaks() {
        assert_eq!(multi_line("a\r\nb\rc\nd\te"), "a\nb\nc\nd\te");
    }
}
