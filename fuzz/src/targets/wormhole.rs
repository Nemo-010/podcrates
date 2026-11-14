//! The fuzz targets of the MQTT, the Nostr and the WebTorrent meeting
//! points of `pod-wormhole`: the bytes come from a public broker, relay or
//! tracker, which any client of it can fill.

use pod_wormhole::mqtt::packet::{decode, encode};
use pod_wormhole::mqtt::topic;
use pod_wormhole::nostr::event::{Said, checked, said};
use pod_wormhole::tracker::wire::{self, note_of};

use crate::{is_one_line, text};

/// The bound of a packet in the target: small, so that a length past it
/// is refused before its body.
const MOST: usize = 1 << 16;

/// The packets of MQTT 3.1.1 that a meeting point reads
/// (`pod_wormhole::mqtt::packet::decode`; new in `pod-wormhole`, T-261):
/// a whole packet takes no more bytes than there are, writes again to
/// bytes that read back to the same packet, and each shorter cut of it
/// waits for more; a topic of any AppID and nameplate is letters and
/// digits.
pub fn mqtt_packet(data: &[u8]) {
    if let Ok(Some((packet, used))) = decode(data, MOST) {
        assert!((2..=data.len()).contains(&used), "{used} of {} bytes", data.len());
        let bytes = encode(&packet).expect("a packet that was read is written");
        assert_eq!(decode(&bytes, MOST), Ok(Some((packet.clone(), bytes.len()))), "{packet:?}");
        assert_eq!(decode(&data[..used - 1], MOST), Ok(None), "a cut of {packet:?}");
    }
    let Some(typed) = text(data) else { return };
    let (appid, nameplate) = typed.split_once('\n').unwrap_or((typed, ""));
    let made = topic(appid, nameplate);
    assert!(made.len() == 42 && made.bytes().all(|b| b.is_ascii_alphanumeric()), "{made:?}");
}

/// The messages of a Nostr relay (`pod_wormhole::nostr::event::said` and
/// `checked`; new in `pod-wormhole`, T-550): a message reads with no panic;
/// an event that checks keeps its id, which is 64 hex digits, and a second
/// check reads the same.
pub fn nostr_message(data: &[u8]) {
    if let Some(Said::Event { event, .. }) = said(data)
        && let Some(read) = checked(&event)
    {
        assert_eq!(Some(read.id.as_str()), event["id"].as_str());
        assert!(read.id.len() == 64 && read.id.bytes().all(|b| b.is_ascii_hexdigit()), "{}", read.id);
        assert_eq!(checked(&event).as_ref(), Some(&read), "a second check reads the same");
    }
    if let Ok(event) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = checked(&event);
    }
}

/// The messages of a WebTorrent tracker and the notes in their `sdp`
/// (`pod_wormhole::tracker::wire::{said, note_of}`; new in `pod-wormhole`,
/// T-551): a message reads with no panic; the words of a refusal or a
/// warning are one line; a note that reads writes to an `sdp` that reads
/// back to the same note, and its messages count from its `from`.
pub fn tracker_message(data: &[u8]) {
    let sdp = match wire::said(data) {
        Some(wire::Said::Offer { sdp, .. } | wire::Said::Answer { sdp, .. }) => Some(sdp),
        Some(wire::Said::Failure(words) | wire::Said::Warning(words)) => {
            assert!(is_one_line(&words), "{words:?}");
            None
        }
        _ => None,
    };
    for sdp in sdp.into_iter().chain(text(data).map(str::to_string)) {
        let Some(note) = note_of(&sdp) else { continue };
        assert_eq!(note_of(&note.to_sdp()).as_ref(), Some(&note), "a note writes back to itself");
        for (n, (index, message)) in note.indexed().enumerate() {
            assert_eq!(index, note.from.saturating_add(n as u64));
            assert_eq!(message.side, note.side);
        }
    }
}
