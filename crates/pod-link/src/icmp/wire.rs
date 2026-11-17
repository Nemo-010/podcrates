//! The wire of one ICMP echo message: the type, the code, the Internet
//! checksum, the identifier, the sequence, and then the data. The data of
//! the carrier is `session(4) || from(1) || payload`: the session tells one
//! link from another on a shared socket, and `from` tells the dialer's
//! bytes from the listener's, so that the kernel's own reply to an echo
//! request (which echoes the data verbatim) is dropped and does not poison
//! the ARQ (call C276). The checksum is for a raw socket, which the kernel
//! does not fill; the reader does not check it, because an unprivileged ping
//! socket fills it again (call C276). By hand, a parser of untrusted bytes.

/// The ICMPv4 echo request (RFC 792).
pub const REQUEST: u8 = 8;

/// The ICMPv4 echo reply (RFC 792).
pub const REPLY: u8 = 0;

/// The mark of the dialer's bytes.
pub const CLIENT: u8 = 1;

/// The mark of the listener's bytes.
pub const SERVER: u8 = 2;

/// The bytes of the ICMP header: type, code, checksum, identifier, sequence.
pub const HEADER: usize = 8;

/// The bytes of the session and the `from` mark before the payload.
pub const SESSION: usize = 5;

/// One echo message read from the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Echo {
    pub kind: u8,
    pub id: u16,
    pub seq: u16,
    pub session: u32,
    /// Whose bytes: [`CLIENT`] or [`SERVER`].
    pub from: u8,
    pub payload: Vec<u8>,
}

/// The Internet checksum of `bytes` (RFC 1071): the ones-complement sum of
/// the 16-bit words.
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u32::from(u16::from_be_bytes([bytes[i], bytes[i + 1]]));
        i += 2;
    }
    if i < bytes.len() {
        sum += u32::from(u16::from_be_bytes([bytes[i], 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The bytes of an echo message of `kind` with `id`, `seq`, `session`,
/// `from` and `payload`, its checksum filled.
pub fn encode(kind: u8, id: u16, seq: u16, session: u32, from: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + SESSION + payload.len());
    out.extend_from_slice(&[kind, 0, 0, 0]);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&session.to_be_bytes());
    out.push(from);
    out.extend_from_slice(payload);
    let sum = checksum(&out);
    out[2..4].copy_from_slice(&sum.to_be_bytes());
    out
}

/// The fields of an echo message. A message shorter than the header and the
/// session, or of another type than echo, is `None`. The checksum is not
/// checked (call C276).
pub fn decode(bytes: &[u8]) -> Option<Echo> {
    if bytes.len() < HEADER + SESSION {
        return None;
    }
    let kind = bytes[0];
    if kind != REQUEST && kind != REPLY {
        return None;
    }
    let id = u16::from_be_bytes([bytes[4], bytes[5]]);
    let seq = u16::from_be_bytes([bytes[6], bytes[7]]);
    let session = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    Some(Echo { kind, id, seq, session, from: bytes[12], payload: bytes[HEADER + SESSION..].to_vec() })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 1071 as a fold of each word in turn: a ones-complement add, the
    /// carry back at once, then the complement. A second form of the sum.
    fn reference(bytes: &[u8]) -> u16 {
        let add = |a: u16, b: u16| {
            let (s, carry) = a.overflowing_add(b);
            s + u16::from(carry)
        };
        let words = bytes.chunks(2).map(|w| u16::from_be_bytes([w[0], w.get(1).copied().unwrap_or(0)]));
        !words.fold(0u16, add)
    }

    /// Each of the 65,536 words, alone, after a block, and with a byte
    /// after it (an odd length), against the second form (T-824, VF-4); and
    /// the message with its checksum in place sums to zero.
    #[test]
    fn the_checksum_of_each_word_is_the_reference() {
        let block: Vec<u8> = (0..61u32).map(|i| (i * 37 + 11) as u8).collect();
        let mut bytes = block.clone();
        for w in 0..=u16::MAX {
            let word = w.to_be_bytes();
            assert_eq!(checksum(&word), reference(&word), "{w:#06x}");
            bytes.truncate(block.len());
            bytes.extend_from_slice(&word);
            assert_eq!(checksum(&bytes), reference(&bytes), "{w:#06x} after the block");
            bytes.push(word[0] ^ 0x5a);
            assert_eq!(checksum(&bytes), reference(&bytes), "{w:#06x} and an odd byte");
            let mut message = [0u8, 0, word[0], word[1]];
            let sum = checksum(&message);
            message[..2].copy_from_slice(&sum.to_be_bytes());
            assert_eq!(checksum(&message), 0, "{w:#06x} with its checksum");
        }
        assert_eq!(checksum(&[]), reference(&[]));
    }

    #[test]
    fn an_echo_round_trips_and_its_checksum_is_right() {
        let payload: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let bytes = encode(REQUEST, 0x1234, 7, 0xabcd_ef01, CLIENT, &payload);
        assert_eq!(checksum(&bytes), 0, "a message with its checksum sums to zero");
        let echo = decode(&bytes).unwrap();
        assert_eq!(echo, Echo { kind: REQUEST, id: 0x1234, seq: 7, session: 0xabcd_ef01, from: CLIENT, payload });
        // A reply and an odd length.
        let odd = encode(REPLY, 1, 1, 9, SERVER, &[1, 2, 3]);
        assert_eq!(checksum(&odd), 0);
        let got = decode(&odd).unwrap();
        assert_eq!((got.kind, got.from), (REPLY, SERVER));
        // Too short, and another type.
        assert!(decode(&bytes[..HEADER + SESSION - 1]).is_none());
        let mut other = bytes.clone();
        other[0] = 3;
        assert!(decode(&other).is_none());
    }
}
