//! Text of a peer or of a visitor, made safe for a log line.

/// Remove the control characters of `text` that a terminal acts on: each
/// escape sequence (ESC and what follows it), BEL, CR, the other C0 and C1
/// controls and DEL. Tab and line feed stay. Text from a peer (an edge
/// error, an HTTP body, a proxy reply) goes through this function before it
/// reaches a terminal.
pub fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            match chars.peek() {
                // CSI: ESC [ parameters final-byte.
                Some('[') => {
                    chars.next();
                    for c in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&c) {
                            break;
                        }
                    }
                }
                // OSC: ESC ] text, ended by BEL or ESC \.
                Some(']') => {
                    chars.next();
                    while let Some(c) = chars.next() {
                        if c == '\u{7}' {
                            break;
                        }
                        if c == '\u{1b}' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                // Another escape: ESC and one character.
                Some(_) => {
                    chars.next();
                }
                None => {}
            }
            continue;
        }
        if c == '\t' || c == '\n' || !(c.is_control()) {
            out.push(c);
        }
    }
    out
}
