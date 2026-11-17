//! Text of a peer or of a visitor, made safe for a log line: the rule of
//! `pod_core::text`, so that each crate has one definition.

/// `text` safe for a terminal, on more than one line: each escape sequence
/// goes whole, CR LF and a lone CR become LF, tab stays, and each other
/// control and bidirectional formatting character goes
/// (`pod_core::text::multi_line`). Text from a peer (an edge error, an HTTP
/// body, a proxy reply) goes through it before it reaches a terminal.
pub fn clean(text: &str) -> String {
    pod_core::text::multi_line(text)
}
