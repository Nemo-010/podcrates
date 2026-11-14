//! The messages of a WebTorrent tracker and the notes that the ends put in
//! them, with no I/O, so that a fuzz target runs [`said`] and [`note_of`]
//! on untrusted bytes.
//!
//! A tracker sends JSON objects in text messages: the answer to an
//! announce (its `interval`), another peer's offer, a peer's answer to an
//! offer of this end, or a `failure reason`. It passes the `sdp` of an
//! offer and of an answer from peer to peer and reads nothing in it; the
//! ends put a [`Note`] there.

use serde_json::{Value, json};

use crate::message::{Message, hex, unhex, words};

/// The characters of an `info_hash`, a `peer_id` and an `offer_id`:
/// bittorrent-tracker refuses an `info_hash` or a `peer_id` of another
/// length.
pub const ID_CHARS: usize = 20;

/// What one message of a tracker says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Said {
    /// The answer to an announce of this end: the `info_hash` and the
    /// seconds until the next announce, where the tracker states them.
    Announced { info_hash: String, interval: Option<u64> },
    /// The offer of another peer of an `info_hash`.
    Offer { info_hash: String, peer_id: String, offer_id: String, sdp: String },
    /// The answer of a peer to an offer of this end.
    Answer { info_hash: String, peer_id: String, offer_id: String, sdp: String },
    /// The tracker refused a request, in its words (one short line).
    Failure(String),
    /// A warning of the tracker, in its words (one short line).
    Warning(String),
    /// Another message: a scrape, an announce of a later version.
    Other,
}

/// What a message of a tracker says; `None` for bytes that are not a JSON
/// object, and for an offer or an answer that misses a field.
pub fn said(payload: &[u8]) -> Option<Said> {
    let value: Value = serde_json::from_slice(payload).ok().filter(Value::is_object)?;
    if let Some(reason) = value.get("failure reason") {
        return Some(Said::Failure(words(reason)));
    }
    let text = |key: &str| value[key].as_str().map(str::to_string);
    for (key, offer) in [("offer", true), ("answer", false)] {
        if value.get(key).is_none() {
            continue;
        }
        let (info_hash, peer_id, offer_id) = (text("info_hash")?, text("peer_id")?, text("offer_id")?);
        let sdp = value[key]["sdp"].as_str()?.to_string();
        return Some(match offer {
            true => Said::Offer { info_hash, peer_id, offer_id, sdp },
            false => Said::Answer { info_hash, peer_id, offer_id, sdp },
        });
    }
    if let Some(warning) = value.get("warning message") {
        return Some(Said::Warning(words(warning)));
    }
    if value["action"] == "announce"
        && let Some(info_hash) = text("info_hash")
    {
        return Some(Said::Announced { info_hash, interval: value["interval"].as_u64() });
    }
    Some(Said::Other)
}

/// What an end puts in the `sdp` of an offer or an answer: the tag of the
/// code, its side, its messages from the index `from` on, and how many
/// messages of the other end it has, so that each end sends again what the
/// other does not have and drops what it has twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// The tag of the code ([`crate::mqtt::topic`]).
    pub tag: String,
    pub side: String,
    /// The index of the first message among the sender's messages.
    pub from: u64,
    /// The count of the other end's messages that the sender has.
    pub got: u64,
    /// The phase and the body of each message.
    pub messages: Vec<(String, Vec<u8>)>,
}

impl Note {
    /// The note as the text of an `sdp`.
    pub fn to_sdp(&self) -> String {
        let messages: Vec<Value> =
            self.messages.iter().map(|(phase, body)| json!({ "phase": phase, "body": hex(body) })).collect();
        json!({ "tag": self.tag, "side": self.side, "from": self.from, "got": self.got, "m": messages }).to_string()
    }

    /// The messages as the mailbox gives them, with the index of each.
    pub fn indexed(&self) -> impl Iterator<Item = (u64, Message)> + '_ {
        let side = &self.side;
        self.messages.iter().enumerate().map(move |(n, (phase, body))| {
            let message = Message { side: side.clone(), phase: phase.clone(), body: body.clone() };
            (self.from.saturating_add(n as u64), message)
        })
    }
}

/// The note in the text of an `sdp`; `None` for the `sdp` of WebRTC or for
/// a note that misses a field.
pub fn note_of(sdp: &str) -> Option<Note> {
    let value: Value = serde_json::from_str(sdp).ok().filter(Value::is_object)?;
    let text = |key: &str| value[key].as_str().map(str::to_string);
    let number = |key: &str| value[key].as_u64();
    let mut messages = Vec::new();
    for message in value["m"].as_array()? {
        let phase = message["phase"].as_str()?.to_string();
        messages.push((phase, unhex(message["body"].as_str()?)?));
    }
    Some(Note { tag: text("tag")?, side: text("side")?, from: number("from")?, got: number("got")?, messages })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_message_of_a_tracker_is_read() {
        // As bittorrent-tracker 11.2.3 writes each (server.js).
        let announced =
            br#"{"complete":0,"incomplete":1,"action":"announce","info_hash":"0123456789abcdef0123","interval":120}"#;
        let want = Said::Announced { info_hash: "0123456789abcdef0123".into(), interval: Some(120) };
        assert_eq!(said(announced), Some(want));
        let offer =
            br#"{"action":"announce","offer":{"type":"offer","sdp":"x"},"offer_id":"o","peer_id":"p","info_hash":"h"}"#;
        let want = Said::Offer { info_hash: "h".into(), peer_id: "p".into(), offer_id: "o".into(), sdp: "x".into() };
        assert_eq!(said(offer), Some(want));
        let answer = br#"{"action":"announce","answer":{"sdp":"y","type":"answer"},"offer_id":"o","peer_id":"p","info_hash":"h"}"#;
        let want = Said::Answer { info_hash: "h".into(), peer_id: "p".into(), offer_id: "o".into(), sdp: "y".into() };
        assert_eq!(said(answer), Some(want));
        let failure = br#"{"action":"announce","failure reason":"announce: wrong offer\nitem field format"}"#;
        assert_eq!(said(failure), Some(Said::Failure("announce: wrong offer item field format".into())));
        assert_eq!(said(br#"{"warning message":"slow down"}"#), Some(Said::Warning("slow down".into())));
        assert_eq!(said(br#"{"action":"scrape","files":{}}"#), Some(Said::Other));
        for bad in [
            &b"[]"[..],
            b"not json",
            br#"{"offer":{"sdp":"x"},"peer_id":"p","info_hash":"h"}"#,
            br#"{"answer":{"type":"answer"},"offer_id":"o","peer_id":"p","info_hash":"h"}"#,
        ] {
            assert_eq!(said(bad), None, "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn a_note_goes_both_ways_and_the_sdp_of_webrtc_is_no_note() {
        let note = Note {
            tag: "pwabc".into(),
            side: "0123456789".into(),
            from: 2,
            got: 1,
            messages: vec![("pake".into(), vec![0, 0xff]), ("version".into(), Vec::new())],
        };
        let read = note_of(&note.to_sdp()).expect("a note");
        assert_eq!(read, note);
        let indexed: Vec<(u64, String)> = read.indexed().map(|(n, m)| (n, m.phase)).collect();
        assert_eq!(indexed, [(2, "pake".to_string()), (3, "version".to_string())]);
        assert_eq!(read.indexed().next().unwrap().1.side, "0123456789");
        for bad in [
            "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n",
            r#"{"tag":"t","side":"s","from":0,"got":0}"#,
            r#"{"tag":"t","side":"s","from":-1,"got":0,"m":[]}"#,
            r#"{"tag":"t","side":"s","from":0,"got":0,"m":[{"phase":"0","body":"zz"}]}"#,
        ] {
            assert_eq!(note_of(bad), None, "{bad}");
        }
    }
}
