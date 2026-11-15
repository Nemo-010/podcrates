//! The fuzz targets of `pod-egress` (feature `fuzzing`).

use pod_egress::fuzzing::{Packet, encode, wisp_answer, wisp_packet as read};

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
