//! The monitor of the emulator, in QMP, and the key names of a US layout.
//!
//! QMP, not HMP: HMP is a debug console of lines with no error report, and
//! a call that fails looks like a call that worked. In QMP each request is
//! JSON, each request gets a response, and a refusal is an `"error"`
//! member.
//!
//! No JSON dependency: the crate sends `qmp_capabilities`, `send-key`,
//! `screendump` and `quit`, with key names from a fixed table and a path
//! in a JSON string ([`json_text`]), for a warm start ([`crate::warm`])
//! `stop`, `cont`, `migrate` and the queries of the status, and the change
//! of a medium ([`crate::swap`]). The requests are formatted. A response is
//! read for an `"error"` member, for the words of a status
//! ([`json_member`]), and for the lock of a drive in an entry of
//! `query-block` ([`list_entries`], [`json_bool`]). An error object that
//! [`response_ok`] does not find reads as success; so each request that the
//! crate sends is one whose refusal the guest also shows.
//!
//! A local user who connects to the socket can type into the console. The
//! per-run directory that holds it has the mode 0700
//! ([`crate::scratch_dir`]).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use pod_core::{Class, Failure, Stage};

use crate::{Result, failure};

/// How long one press is held, in milliseconds: long enough for a full
/// keystroke in the console of the guest, short enough to type a command
/// in about one second.
pub const HOLD_MS: u32 = 30;

/// One live QMP connection.
pub struct Monitor {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
}

/// An I/O failure of the QMP connection.
fn io(what: &str, e: std::io::Error) -> Failure {
    Failure::caused(Stage::Host, Class::of_io(e.kind()), format!("qmp {what}: {e}"), e)
}

impl Monitor {
    /// Connect to `path`, wait up to `wait` for the socket, and do the
    /// handshake of the capabilities.
    ///
    /// The emulator makes the socket when it starts, so a caller that just
    /// started it polls.
    pub fn connect(path: &Path, wait: Duration) -> Result<Monitor> {
        let start = Instant::now();
        loop {
            if let Ok(s) = UnixStream::connect(path) {
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
                let reader = BufReader::new(s.try_clone().map_err(|e| io("connect", e))?);
                let mut m = Monitor { writer: s, reader };
                // The greeting comes first with no request; read it before
                // a request, or the first response read is the greeting.
                m.read_line()?;
                m.call("qmp_capabilities")?;
                return Ok(m);
            }
            if start.elapsed() >= wait {
                return Err(failure(
                    Class::Timeout,
                    format!("the QMP socket {} never appeared within {}s", path.display(), wait.as_secs()),
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn read_line(&mut self) -> Result<String> {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).map_err(|e| io("read", e))?;
        if n == 0 {
            return Err(failure(Class::Unavailable, "qmp closed the connection"));
        }
        Ok(line)
    }

    /// Send one request with no arguments, `{"execute":EXECUTE}`, and read
    /// its response.
    pub fn call(&mut self, execute: &str) -> Result<()> {
        self.send(&format!("{{\"execute\":\"{execute}\"}}"))
    }

    fn send(&mut self, body: &str) -> Result<()> {
        self.ask(body).map(drop)
    }

    /// Send one request, `body` as it is, and return the line of its
    /// response. A response with `"error"` is a [`Class::Protocol`]
    /// failure that holds the line.
    pub fn ask(&mut self, body: &str) -> Result<String> {
        self.writer
            .write_all(body.as_bytes())
            .and_then(|()| self.writer.write_all(b"\n"))
            .and_then(|()| self.writer.flush())
            .map_err(|e| io("write", e))?;
        // An event is not a response. QMP can send `RESET`, `STOP`,
        // `POWERDOWN` and others at any time; an event read as the response
        // moves each later response to the wrong request. Skip the events.
        let line = loop {
            let line = self.read_line()?;
            if !is_event(&line) {
                break line;
            }
        };
        if response_ok(&line) {
            Ok(line)
        } else {
            Err(failure(Class::Protocol, format!("qmp refused {body}: {}", line.trim())))
        }
    }

    /// Press `qcodes` together: a shifted character is the modifiers and
    /// the key in one `send-key`.
    ///
    /// `hold-time` is set: with no value, the emulator releases a key on its
    /// own timer, and the time that a key is down then depends on the time
    /// of the next request.
    pub fn keys(&mut self, qcodes: &[&str]) -> Result<()> {
        if qcodes.is_empty() {
            return Err(failure(Class::Usage, "no key to press"));
        }
        self.send(&send_key(qcodes))
    }

    /// Write the screen of the guest to `file` (`screendump`, a PPM image).
    /// A path that is not UTF-8 is a [`Class::Usage`] failure: JSON holds
    /// text.
    pub fn screendump(&mut self, file: &Path) -> Result<()> {
        let path =
            file.to_str().ok_or_else(|| failure(Class::Usage, format!("{}: not a UTF-8 path", file.display())))?;
        self.send(&format!("{{\"execute\":\"screendump\",\"arguments\":{{\"filename\":{}}}}}", json_text(path)))
    }

    /// Ask the emulator to exit. The response can be missing: the emulator
    /// can close the connection during `quit`, and that is not a failure.
    pub fn quit(&mut self) {
        let _ = self.writer.write_all(b"{\"execute\":\"quit\"}\n").and_then(|()| self.writer.flush());
        let _ = self.reader.read_line(&mut String::new());
    }
}

/// The `send-key` request for `qcodes`, pressed together.
pub fn send_key(qcodes: &[&str]) -> String {
    let keys: Vec<String> = qcodes.iter().map(|k| format!("{{\"type\":\"qcode\",\"data\":\"{k}\"}}")).collect();
    format!("{{\"execute\":\"send-key\",\"arguments\":{{\"keys\":[{}],\"hold-time\":{HOLD_MS}}}}}", keys.join(","))
}

/// `text` as a JSON string, with its quotes.
pub fn json_text(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The text of the first member `key` of a response line whose value is a
/// string, with no escape in it; `None` when there is no such member.
///
/// Enough for the words that the crate reads (`"status": "inmigrate"`):
/// the emulator writes them with no escape.
pub fn json_member(line: &str, key: &str) -> Option<String> {
    let name = format!("\"{key}\"");
    let mut rest = line;
    while let Some(at) = rest.find(&name) {
        rest = &rest[at + name.len()..];
        let Some(value) = rest.trim_start().strip_prefix(':') else { continue };
        let Some(value) = value.trim_start().strip_prefix('"') else { continue };
        let end = value.find(['"', '\\'])?;
        return (value.as_bytes()[end] == b'"').then(|| value[..end].to_string());
    }
    None
}

/// The value of the first member `key` of `line` that is `true` or
/// `false`; `None` when there is no such member.
pub fn json_bool(line: &str, key: &str) -> Option<bool> {
    let name = format!("\"{key}\"");
    let mut rest = line;
    while let Some(at) = rest.find(&name) {
        rest = &rest[at + name.len()..];
        let Some(value) = rest.trim_start().strip_prefix(':') else { continue };
        let value = value.trim_start();
        if value.starts_with("true") {
            return Some(true);
        }
        if value.starts_with("false") {
            return Some(false);
        }
    }
    None
}

/// The objects in the list of a response (`{"return": [{..}, {..}]}`),
/// each as its text.
///
/// The emulator writes the members of an object in no fixed order, so a
/// caller reads the members of one entry in the text of that entry only.
pub fn list_entries(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    let (mut text, mut escape) = (false, false);
    for (i, c) in line.char_indices() {
        if text {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                text = false;
            }
            continue;
        }
        match c {
            '"' => text = true,
            '{' | '[' => {
                if c == '{' && depth == 2 {
                    start = i;
                }
                depth += 1;
            }
            '}' | ']' => {
                depth = depth.saturating_sub(1);
                if c == '}' && depth == 2 {
                    out.push(&line[start..=i]);
                }
            }
            _ => {}
        }
    }
    out
}

/// True when a line is an event, not a response.
///
/// An event has `"event"`; a response has `"return"` or `"error"`. A line
/// with none of them is a response, as the greeting is.
pub fn is_event(line: &str) -> bool {
    line.contains("\"event\"") && !line.contains("\"return\"")
}

/// True when a QMP response line has no `"error"`.
///
/// A response that is neither is success, so each request of the crate is
/// one whose refusal the guest also shows.
pub fn response_ok(line: &str) -> bool {
    !line.contains("\"error\"")
}

/// The `send-key` name of a character, and true when it needs shift, for a
/// US layout. `None`: the character has no key.
pub fn key(c: char) -> Option<(&'static str, bool)> {
    Some(match c {
        'a'..='z' => (LETTER[usize::from(c as u8 - b'a')], false),
        'A'..='Z' => (LETTER[usize::from(c as u8 - b'A')], true),
        '0'..='9' => (DIGIT[usize::from(c as u8 - b'0')], false),
        ' ' => ("spc", false),
        '!' => ("1", true),
        '"' => ("apostrophe", true),
        '#' => ("3", true),
        '$' => ("4", true),
        '%' => ("5", true),
        '&' => ("7", true),
        '\'' => ("apostrophe", false),
        '(' => ("9", true),
        ')' => ("0", true),
        '*' => ("8", true),
        '+' => ("equal", true),
        ',' => ("comma", false),
        '-' => ("minus", false),
        '.' => ("dot", false),
        '/' => ("slash", false),
        ':' => ("semicolon", true),
        ';' => ("semicolon", false),
        '<' => ("comma", true),
        '=' => ("equal", false),
        '>' => ("dot", true),
        '?' => ("slash", true),
        '@' => ("2", true),
        '[' => ("bracket_left", false),
        '\\' => ("backslash", false),
        ']' => ("bracket_right", false),
        '^' => ("6", true),
        '_' => ("minus", true),
        '`' => ("grave_accent", false),
        '{' => ("bracket_left", true),
        '|' => ("backslash", true),
        '}' => ("bracket_right", true),
        '~' => ("grave_accent", true),
        _ => return None,
    })
}

const LETTER: [&str; 26] = [
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w",
    "x", "y", "z",
];
const DIGIT: [&str; 10] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_response_is_not_ok_and_a_return_is() {
        assert!(response_ok("{\"return\": {}}"));
        assert!(response_ok("{\"QMP\": {\"version\": {}}}"));
        assert!(!response_ok("{\"error\": {\"class\": \"GenericError\", \"desc\": \"nope\"}}"));
        assert!(!response_ok("{\"error\": null}"));
    }

    #[test]
    fn an_event_is_skipped_and_not_read_as_a_response() {
        assert!(is_event("{\"event\": \"RESET\", \"data\": {}}"));
        assert!(is_event("{\"event\": \"STOP\"}"));
        assert!(!is_event("{\"return\": {}}"));
        assert!(!is_event("{\"error\": \"nope\"}"));
        // A response that names an event in a string is a response.
        assert!(!is_event("{\"return\": \"event\"}"));
    }

    #[test]
    fn a_member_of_a_response_is_read_with_or_with_no_space() {
        let status = "{\"return\": {\"status\": \"inmigrate\", \"running\": false}}";
        assert_eq!(json_member(status, "status").as_deref(), Some("inmigrate"));
        assert_eq!(json_member("{\"return\":{\"status\":\"completed\"}}", "status").as_deref(), Some("completed"));
        // A key in a value is not a member; a value that is not a string is
        // no text.
        assert_eq!(json_member("{\"desc\": \"status\", \"status\": \"failed\"}", "status").as_deref(), Some("failed"));
        assert_eq!(json_member("{\"status\": 3}", "status"), None);
        assert_eq!(json_member("{\"status\": \"a\\\"b\"}", "status"), None, "an escape is not read");
        assert_eq!(json_member("{\"return\": {}}", "status"), None);
    }

    #[test]
    fn a_bool_member_is_read_and_a_key_in_a_value_is_not_a_member() {
        assert_eq!(json_bool("{\"locked\": true, \"x\": 1}", "locked"), Some(true));
        assert_eq!(json_bool("{\"locked\":false}", "locked"), Some(false));
        assert_eq!(json_bool("{\"desc\": \"locked\", \"locked\": true}", "locked"), Some(true));
        assert_eq!(json_bool("{\"locked\": \"true\"}", "locked"), None, "a string is not a bool");
        assert_eq!(json_bool("{\"return\": {}}", "locked"), None);
    }

    /// Each object of the list is one entry, with its nested objects and
    /// with braces in its strings.
    #[test]
    fn each_object_of_a_list_response_is_one_entry() {
        let line = "{\"return\": [{\"a\": {\"b\": [1, {\"c\": 2}]}, \"s\": \"}{\\\"[\"}, {\"d\": 3}]}";
        assert_eq!(list_entries(line), vec!["{\"a\": {\"b\": [1, {\"c\": 2}]}, \"s\": \"}{\\\"[\"}", "{\"d\": 3}"]);
        assert!(list_entries("{\"return\": []}").is_empty());
        assert!(list_entries("{\"return\": {}}").is_empty());
    }

    #[test]
    fn the_key_request_presses_a_modifier_and_a_key_together() {
        // The shape that the emulator parses, with no JSON dependency.
        assert_eq!(
            send_key(&["shift", "semicolon"]),
            "{\"execute\":\"send-key\",\"arguments\":{\"keys\":[{\"type\":\"qcode\",\"data\":\"shift\"},{\"type\":\"qcode\",\"data\":\"semicolon\"}],\"hold-time\":30}}"
        );
    }

    /// Each printable ASCII character has a key, and a character outside
    /// the table has none.
    #[test]
    fn each_printable_ascii_character_has_a_key() {
        for c in ' '..='~' {
            assert!(key(c).is_some(), "no key for {c:?}");
        }
        assert_eq!(key('a'), Some(("a", false)));
        assert_eq!(key('A'), Some(("a", true)));
        assert_eq!(key(':'), Some(("semicolon", true)));
        assert_eq!(key('\t'), None);
        assert_eq!(key('é'), None);
    }
}
