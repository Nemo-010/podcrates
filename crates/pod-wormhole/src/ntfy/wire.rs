//! The lines of an ntfy server and the messages that the ends put in them,
//! with no I/O, so that a fuzz target runs [`said`], [`Lines`] and
//! [`refusal`] on untrusted bytes.
//!
//! A subscription to `TOPIC/json` is one JSON object on each line: the
//! `open` event of a stream, a `keepalive`, or a `message` with its `id`,
//! its `time` and its text in `message`. The ends put the JSON of a message
//! of the mailbox ([`content`]) in that text. A refusal of the server is one
//! JSON object with its words in `error` ([`refusal`]).

use serde_json::{Value, json};

use super::MESSAGE_MOST;
use crate::message::{hex, words};

/// The characters of the id of a message: ntfy draws 12 letters and
/// digits (`model.ValidMessageID`).
pub const ID_CHARS: usize = 12;
/// The longest line that a reader takes: a message of [`MESSAGE_MOST`]
/// bytes with each byte escaped in JSON, and the fields around it.
pub const LINE_MOST: usize = 8 * MESSAGE_MOST;

/// What one line of a subscription says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Said {
    /// The first line of a stream: the server holds the subscription.
    Open,
    /// A line that keeps the stream alive.
    Keepalive,
    /// A message of a topic: its id, its time (seconds since the Unix
    /// epoch), its topic and its text.
    Message { id: String, time: u64, topic: String, text: String },
    /// Another event, by its name: a deletion, a poll request.
    Other(String),
}

/// What a line says; `None` for bytes that are not a JSON object with an
/// `event`, and for a `message` that misses a field or whose id is not
/// [`ID_CHARS`] letters and digits.
pub fn said(line: &[u8]) -> Option<Said> {
    let value: Value = serde_json::from_slice(line).ok().filter(Value::is_object)?;
    let event = value["event"].as_str()?;
    Some(match event {
        "open" => Said::Open,
        "keepalive" => Said::Keepalive,
        "message" => {
            let id = value["id"].as_str().filter(|id| is_id(id))?.to_string();
            let time = value["time"].as_u64()?;
            let topic = value["topic"].as_str()?.to_string();
            let text = value["message"].as_str()?.to_string();
            Said::Message { id, time, topic, text }
        }
        other => Said::Other(words(&Value::from(other))),
    })
}

/// Whether `id` is the id of a message: [`ID_CHARS`] ASCII letters and
/// digits, so that it goes in a query as it is.
pub fn is_id(id: &str) -> bool {
    id.len() == ID_CHARS && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The text of a message of the mailbox: the JSON of the side, the phase
/// and the body in hex, as the content of a Nostr event; `Err` with its
/// length when it is over [`MESSAGE_MOST`] bytes, which a server keeps as
/// an attachment or refuses.
pub fn content(side: &str, phase: &str, body: &[u8]) -> Result<String, usize> {
    let text = json!({ "side": side, "phase": phase, "body": hex(body) }).to_string();
    if text.len() > MESSAGE_MOST { Err(text.len()) } else { Ok(text) }
}

/// The words of a refusal of status `status`: ntfy's `error`, and its
/// `code` where it gives one; else the start of the body; one short line.
pub fn refusal(status: u16, body: &[u8]) -> String {
    let value: Option<Value> = serde_json::from_slice(body).ok().filter(Value::is_object);
    let said = match value.as_ref().and_then(|v| v.get("error")) {
        Some(error) => match value.as_ref().and_then(|v| v["code"].as_u64()) {
            Some(code) => format!("{} (code {code})", words(error)),
            None => words(error),
        },
        None => words(&Value::from(String::from_utf8_lossy(body).into_owned())),
    };
    if said.is_empty() { format!("HTTP {status}") } else { format!("HTTP {status}: {said}") }
}

/// The lines of a body as its parts come: each line whole, with no end of
/// line; a line longer than [`LINE_MOST`] fails.
#[derive(Debug, Default)]
pub struct Lines {
    held: Vec<u8>,
}

impl Lines {
    /// The lines that `part` ends; `Err` when a line grows past
    /// [`LINE_MOST`].
    pub fn feed(&mut self, part: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        self.held.extend_from_slice(part);
        let mut lines = Vec::new();
        while let Some(at) = self.held.iter().position(|b| *b == b'\n') {
            let mut line: Vec<u8> = self.held.drain(..=at).collect();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if !line.is_empty() {
                lines.push(line);
            }
        }
        if self.held.len() > LINE_MOST {
            return Err(format!("a line of more than {LINE_MOST} bytes"));
        }
        Ok(lines)
    }

    /// The bytes after the last end of line: the last line of a body that
    /// ends with no end of line.
    pub fn rest(&mut self) -> Option<Vec<u8>> {
        let rest = std::mem::take(&mut self.held);
        (!rest.is_empty()).then_some(rest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_line_of_ntfy_reads_as_its_event() {
        // The lines of ntfy's documents (docs/subscribe/api.md at v2.37.2).
        let open = br#"{"id":"SLiKI64DOt","time":1635528757,"event":"open","topic":"mytopic"}"#;
        assert_eq!(said(open), Some(Said::Open));
        let alive = br#"{"id":"DGUDShMCsc","time":1635528787,"event":"keepalive","topic":"mytopic"}"#;
        assert_eq!(said(alive), Some(Said::Keepalive));
        let message = br#"{"id":"hwQ2YpKdmg12","time":1635528741,"expires":1635571941,"event":"message","topic":"mytopic","message":"Disk full"}"#;
        let read = Said::Message {
            id: "hwQ2YpKdmg12".into(),
            time: 1635528741,
            topic: "mytopic".into(),
            text: "Disk full".into(),
        };
        assert_eq!(said(message), Some(read));
        let gone = br#"{"id":"hwQ2YpKdmg13","time":1,"event":"message_delete","topic":"t"}"#;
        assert_eq!(said(gone), Some(Said::Other("message_delete".into())));
        for bad in [
            &br#"{"id":"short","time":1,"event":"message","topic":"t","message":"x"}"#[..],
            br#"{"id":"hwQ2YpKdmg12","event":"message","topic":"t","message":"x"}"#,
            br#"{"id":"hwQ2YpKd/g12","time":1,"event":"message","topic":"t","message":"x"}"#,
            br#"{"time":1}"#,
            b"[]",
            b"",
        ] {
            assert_eq!(said(bad), None, "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn a_message_of_4096_bytes_or_more_is_refused_before_the_send() {
        let empty = content("0123456789", "100", b"").unwrap();
        let fits = (MESSAGE_MOST - empty.len()) / 2;
        assert_eq!(content("0123456789", "100", &vec![7; fits]).unwrap().len(), MESSAGE_MOST);
        assert_eq!(content("0123456789", "100", &vec![7; fits + 1]), Err(MESSAGE_MOST + 2));
        let read: Value = serde_json::from_str(&empty).unwrap();
        let fields = (read["side"].as_str(), read["phase"].as_str(), read["body"].as_str());
        assert_eq!(fields, (Some("0123456789"), Some("100"), Some("")));
    }

    #[test]
    fn a_refusal_says_the_words_of_the_server_on_one_line() {
        let limited = br#"{"code":42901,"http":429,"error":"limit reached: too many requests","link":"https://ntfy.sh/docs/publish/#limitations"}"#;
        assert_eq!(refusal(429, limited), "HTTP 429: limit reached: too many requests (code 42901)");
        assert_eq!(refusal(502, b"<html>bad\ngateway</html>"), "HTTP 502: <html>bad gateway</html>");
        assert_eq!(refusal(500, b""), "HTTP 500");
    }

    #[test]
    fn lines_come_whole_as_the_parts_come() {
        let mut lines = Lines::default();
        assert_eq!(lines.feed(b"{\"a\"").unwrap(), Vec::<Vec<u8>>::new());
        assert_eq!(lines.feed(b":1}\r\n\n{\"b\":2}\n{").unwrap(), vec![b"{\"a\":1}".to_vec(), b"{\"b\":2}".to_vec()]);
        assert_eq!(lines.rest(), Some(b"{".to_vec()));
        assert!(lines.feed(&vec![b'x'; LINE_MOST + 1]).is_err());
    }
}
