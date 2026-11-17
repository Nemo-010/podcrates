//! A relay's offer of a pace of liveness (T-845, PodUtils/podssh#300): a
//! relay that sleeps between frames (a Durable Object with WebSocket
//! hibernation, whose runtime answers a Ping without waking it) names a
//! slower Ping in the member `liveness` of `hello` (to a node), of `ready`
//! (to an operator) and of `forward` in `/relays.json`:
//! `{"pingMs": 60000, "frame": "ws-ping"}`. It is a hint, read by one rule
//! (podssh's `docs/relay.md`, "A relay that sleeps between frames"): a pace
//! from [`LEAST`] to [`MOST`] is taken, a slower one is held to [`MOST`],
//! a faster one, a member of a wrong type and another frame are not taken,
//! and with no member (or `null`) the end keeps its own pace
//! (`pod_ws::LIVENESS_EVERY`, 10 s). `frame` is required, and only
//! `ws-ping`.

use std::time::Duration;

use serde_json::Value;

/// The name of the member.
pub const MEMBER: &str = "liveness";
/// The pace, a whole number of milliseconds.
pub const PING_MS: &str = "pingMs";
/// The only frame of the offer.
pub const FRAME: &str = "ws-ping";
/// The least pace that an end takes.
pub const LEAST: Duration = Duration::from_secs(30);
/// The most: a slower offer is held to it, as a Pong must come within the
/// forward road's idle read limit of 90 s.
pub const MOST: Duration = Duration::from_secs(60);

/// The pace of the offer `member`; `None`: keep the end's own pace.
pub fn pace(member: Option<&Value>) -> Option<Duration> {
    let offer = member?.as_object()?;
    if offer.get("frame")?.as_str()? != FRAME {
        return None;
    }
    let every = Duration::from_millis(offer.get(PING_MS)?.as_u64()?);
    if every < LEAST {
        return None;
    }
    Some(every.min(MOST))
}

/// The pace of the offer in the JSON of a control frame.
pub fn pace_in(frame: &[u8]) -> Option<Duration> {
    let value: Value = serde_json::from_slice(frame).ok()?;
    pace(value.get(MEMBER))
}

/// The vectors of podssh's `docs/relay.md` (its `liveness::VECTORS`): a
/// member as a relay writes it, and the pace in milliseconds that an end
/// takes (`None`: its own).
pub const VECTORS: &[(&str, Option<u64>)] = &[
    (r#"{"pingMs":60000,"frame":"ws-ping"}"#, Some(60_000)),
    (r#"{"pingMs":30000,"frame":"ws-ping"}"#, Some(30_000)),
    (r#"{"pingMs":45000,"frame":"ws-ping","later":1}"#, Some(45_000)),
    (r#"{"pingMs":120000,"frame":"ws-ping"}"#, Some(60_000)),
    (r#"{"pingMs":29999,"frame":"ws-ping"}"#, None),
    (r#"{"pingMs":"60000","frame":"ws-ping"}"#, None),
    (r#"{"pingMs":60000.5,"frame":"ws-ping"}"#, None),
    (r#"{"pingMs":-60000,"frame":"ws-ping"}"#, None),
    (r#"{"pingMs":60000,"frame":"text"}"#, None),
    (r#"{"pingMs":60000}"#, None),
    (r#"60000"#, None),
    (r#"null"#, None),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The vectors of podssh's document, each one.
    #[test]
    fn each_vector_of_the_document_gives_its_pace() {
        for (member, want) in VECTORS {
            let value: Value = serde_json::from_str(member).unwrap();
            let got = pace(Some(&value)).map(|d| d.as_millis() as u64);
            assert_eq!(got, *want, "{member}");
        }
        assert_eq!(pace(None), None, "no member");
    }

    #[test]
    fn the_offer_is_read_in_a_hello_and_a_ready() {
        let hello = br#"{"type":"hello","version":1,"liveness":{"pingMs":50000,"frame":"ws-ping"}}"#;
        assert_eq!(pace_in(hello), Some(Duration::from_secs(50)));
        let ready = br#"{"type":"ready","id":"abc","liveness":{"pingMs":90000,"frame":"ws-ping"}}"#;
        assert_eq!(pace_in(ready), Some(MOST));
        assert_eq!(pace_in(br#"{"type":"ready","id":"abc"}"#), None);
        assert_eq!(pace_in(b"not json"), None);
    }
}
