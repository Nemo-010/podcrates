//! The clamp of the MSS of a TCP SYN to the MTU of a path (T-819, TR-3 of
//! the ingest study). A SYN or a SYN-ACK that offers a segment larger than
//! the path carries gets `mtu - 40` (IPv4) or `mtu - 60` (IPv6) in place,
//! and its TCP checksum is updated by the incremental form of RFC 1624, so
//! the packet is not built again. Each other packet stays as it is: no
//! SYN, no MSS option, an MSS at or under the limit, a fragment, an IPv6
//! packet with an extension header, or a packet that is cut short.

/// The fields of an IPv4 and a TCP header that are not options.
const IPV4_TCP: usize = 40;
/// The fields of an IPv6 and a TCP header that are not options.
const IPV6_TCP: usize = 60;
/// The protocol number of TCP.
const TCP: u8 = 6;
/// The bit SYN in the flags of TCP.
const SYN: u8 = 0x02;

/// Clamp the MSS of the SYN in `packet` (IPv4 or IPv6) for a path of
/// `mtu` bytes. The old and the new MSS when it changed.
pub fn clamp_mss(packet: &mut [u8], mtu: u16) -> Option<(u16, u16)> {
    let (tcp, limit) = match packet.first()? >> 4 {
        4 => (ipv4_tcp(packet)?, mtu.checked_sub(IPV4_TCP as u16)?),
        6 => (ipv6_tcp(packet)?, mtu.checked_sub(IPV6_TCP as u16)?),
        _ => return None,
    };
    let segment = packet.get_mut(tcp..)?;
    if segment.len() < 20 || segment[13] & SYN == 0 {
        return None;
    }
    let header = usize::from(segment[12] >> 4) * 4;
    if header < 20 || header > segment.len() {
        return None;
    }
    let at = mss_option(&segment[20..header])? + 20;
    let old = u16::from_be_bytes([segment[at + 2], segment[at + 3]]);
    if old <= limit {
        return None;
    }
    // The value can start at an odd offset: the words of the checksum that
    // it touches are the even span around it.
    let (first, last) = ((at + 2) & !1, (at + 4 + 1) & !1);
    let before: Vec<u16> = words(&segment[first..last.min(segment.len())]);
    segment[at + 2..at + 4].copy_from_slice(&limit.to_be_bytes());
    let after: Vec<u16> = words(&segment[first..last.min(segment.len())]);
    let mut sum = u16::from_be_bytes([segment[16], segment[17]]);
    for (old_word, new_word) in before.into_iter().zip(after) {
        sum = update(sum, old_word, new_word);
    }
    segment[16..18].copy_from_slice(&sum.to_be_bytes());
    Some((old, limit))
}

/// The offset of the TCP header in an IPv4 packet of TCP that is no
/// fragment.
fn ipv4_tcp(packet: &[u8]) -> Option<usize> {
    let ihl = usize::from(*packet.first()? & 0x0f) * 4;
    let flags_offset = u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]);
    // A later fragment has no TCP header; a first one may hold a part.
    if ihl < 20 || *packet.get(9)? != TCP || flags_offset & 0x3fff != 0 {
        return None;
    }
    Some(ihl)
}

/// The offset of the TCP header in an IPv6 packet whose next header is
/// TCP; an extension header is not walked.
fn ipv6_tcp(packet: &[u8]) -> Option<usize> {
    (*packet.get(6)? == TCP && packet.len() >= 40).then_some(40)
}

/// The offset of the MSS option (kind 2, length 4) in `options`.
fn mss_option(options: &[u8]) -> Option<usize> {
    let mut at = 0;
    while at < options.len() {
        match options[at] {
            0 => return None,
            1 => at += 1,
            kind => {
                let len = usize::from(*options.get(at + 1)?);
                if len < 2 || at + len > options.len() {
                    return None;
                }
                if kind == 2 && len == 4 {
                    return Some(at);
                }
                at += len;
            }
        }
    }
    None
}

/// The 16-bit words of `bytes`, a last odd byte padded with zero, as the
/// checksum reads them.
fn words(bytes: &[u8]) -> Vec<u16> {
    bytes.chunks(2).map(|w| u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)])).collect()
}

/// The checksum after one 16-bit word of the data went from `old` to
/// `new`: `HC' = ~(~HC + ~m + m')` (RFC 1624, equation 3).
fn update(sum: u16, old: u16, new: u16) -> u16 {
    let mut acc = u32::from(!sum) + u32::from(!old) + u32::from(new);
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

#[cfg(test)]
#[path = "mss_tests.rs"]
mod tests;
