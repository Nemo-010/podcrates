//! A relay's offer of a pace of liveness (T-845, PodUtils/podssh#300): a
//! relay that sleeps between frames (a Durable Object with WebSocket
//! hibernation) names a slower Ping in the member `liveness` of `hello` (to
//! a node) and of `ready` (to an operator):
//! `{"frame": "ws-ping", "every_s": N}`. It is a hint, read by one rule:
//! a pace from [`LEAST`] to [`MOST`] is taken, a pace over [`MOST`] is held
//! to it, a pace under [`LEAST`] is not taken, and with no member the end
//! keeps its own pace (`pod_ws::LIVENESS_EVERY`, 10 s). `frame` is required,
//! and only `ws-ping`.

use std::time::Duration;

use serde_json::Value;

/// The name of the member.
pub const MEMBER: &str = "liveness";
/// The only frame of the offer.
pub const FRAME: &str = "ws-ping";
/// The least pace that an end takes.
pub const LEAST: Duration = Duration::from_secs(30);
/// The most: a slower offer is held to it.
pub const MOST: Duration = Duration::from_secs(60);

/// The pace of the offer `member`; `None`: keep the end's own pace.
pub fn pace(member: Option<&Value>) -> Option<Duration> {
    let offer = member?.as_object()?;
    if offer.get("frame")?.as_str()? != FRAME {
        return None;
    }
    let every = Duration::from_secs(offer.get("every_s")?.as_u64()?);
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn of(member: Value) -> Option<u64> {
        pace(Some(&member)).map(|d| d.as_secs())
    }

    #[test]
    fn a_pace_from_30_to_60_s_is_taken_and_a_slower_one_is_held_to_60() {
        assert_eq!(of(json!({"frame": "ws-ping", "every_s": 30})), Some(30));
        assert_eq!(of(json!({"frame": "ws-ping", "every_s": 45})), Some(45));
        assert_eq!(of(json!({"frame": "ws-ping", "every_s": 60})), Some(60));
        assert_eq!(of(json!({"frame": "ws-ping", "every_s": 3600})), Some(60));
    }

    #[test]
    fn a_faster_pace_another_frame_or_a_bad_member_keeps_the_end_s_pace() {
        assert_eq!(of(json!({"frame": "ws-ping", "every_s": 29})), None);
        assert_eq!(of(json!({"frame": "ws-ping", "every_s": 0})), None);
        assert_eq!(of(json!({"frame": "data", "every_s": 45})), None);
        assert_eq!(of(json!({"every_s": 45})), None, "frame is required");
        assert_eq!(of(json!({"frame": "ws-ping"})), None);
        assert_eq!(of(json!({"frame": "ws-ping", "every_s": -45})), None);
        assert_eq!(of(json!({"frame": "ws-ping", "every_s": "45"})), None);
        assert_eq!(of(json!("ws-ping")), None);
        assert_eq!(pace(None), None, "no member");
    }

    #[test]
    fn the_offer_is_read_in_a_hello_and_a_ready() {
        let hello = br#"{"type":"hello","version":1,"liveness":{"frame":"ws-ping","every_s":50}}"#;
        assert_eq!(pace_in(hello), Some(Duration::from_secs(50)));
        let ready = br#"{"type":"ready","id":"abc","liveness":{"frame":"ws-ping","every_s":90}}"#;
        assert_eq!(pace_in(ready), Some(MOST));
        assert_eq!(pace_in(br#"{"type":"ready","id":"abc"}"#), None);
        assert_eq!(pace_in(b"not json"), None);
    }
}
