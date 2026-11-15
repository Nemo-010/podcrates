//! The fuzz targets of `pod-egress` (feature `fuzzing`).

use pod_egress::fuzzing::{
    MAX_DATA, Message, Packet, encode, iap_ack, iap_data, iap_message as iap_read, wisp_answer, wisp_packet as read,
};

/// The newest version of Wisp that the client speaks.
const VERSION: (u8, u8) = (2, 1);

/// A message of a Wisp server (`fuzzing::wisp_packet`): a packet that is
/// read writes back to a message that reads to the same packet; the answer
/// to an INFO names a version no newer than the server's and the client's.
pub fn wisp_packet(data: &[u8]) {
    let Ok((stream, packet)) = read(data) else { return };
    assert_eq!(read(&encode(stream, &packet)), Ok((stream, packet.clone())));
    if let Packet::Info(info) = packet
        && let Ok((ours, opened)) = wisp_answer(&info)
    {
        let version = (ours.major, ours.minor);
        assert!(version <= (info.major, info.minor) && version <= VERSION, "{version:?}");
        assert_eq!(opened.version, version);
    }
}

/// A message of IAP's relay (`fuzzing::iap_message`): it reads the same
/// twice; data of 1 to 16 KiB and an acknowledgement write back to a message
/// that reads to the same; the reason of a long close is one line with no
/// control character.
pub fn iap_message(data: &[u8]) {
    let Ok(message) = iap_read(data) else { return };
    assert!(iap_read(data) == Ok(message.clone()));
    match &message {
        Message::Data(bytes) if (1..=MAX_DATA).contains(&bytes.len()) => {
            let again = iap_data(bytes).expect("data of 1 to 16 KiB writes");
            assert!(iap_read(&again) == Ok(message));
        }
        Message::Ack(n) => assert!(iap_read(&iap_ack(*n)) == Ok(message)),
        Message::LongClose { reason, .. } => assert!(!reason.contains(char::is_control), "{reason:?}"),
        _ => {}
    }
}
