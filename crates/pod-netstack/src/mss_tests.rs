use super::*;

/// The ones-complement sum of `bytes` as 16-bit words.
fn sum(bytes: &[u8], mut acc: u32) -> u32 {
    for pair in bytes.chunks(2) {
        acc += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

/// The TCP checksum of `packet` over its pseudo-header, computed in full:
/// zero for a packet whose checksum is right (its field taken in the sum).
fn verify(packet: &[u8]) -> u16 {
    let (tcp, pseudo) = if packet[0] >> 4 == 4 {
        let ihl = usize::from(packet[0] & 0x0f) * 4;
        let len = (packet.len() - ihl) as u32;
        (ihl, sum(&packet[12..20], u32::from(TCP) + len))
    } else {
        let len = (packet.len() - 40) as u32;
        (40, sum(&packet[8..40], u32::from(TCP) + len))
    };
    !fold(sum(&packet[tcp..], pseudo))
}

/// A SYN with `options` (padded to 4 bytes), its checksum filled.
fn syn(v6: bool, flags: u8, options: &[u8]) -> Vec<u8> {
    let mut opts = options.to_vec();
    while !opts.len().is_multiple_of(4) {
        opts.push(1);
    }
    let mut tcp = vec![0x30, 0x39, 0x00, 0x16, 0, 0, 0, 1, 0, 0, 0, 0];
    tcp.push(((20 + opts.len()) / 4) as u8 * 16);
    tcp.extend_from_slice(&[flags, 0xff, 0xff, 0, 0, 0, 0]);
    tcp.extend_from_slice(&opts);
    let mut packet = if v6 {
        let mut ip = vec![0x60, 0, 0, 0];
        ip.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        ip.extend_from_slice(&[TCP, 64]);
        ip.extend_from_slice(&[0xfd, 0, 0, 0x66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        ip.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ip
    } else {
        let total = (20 + tcp.len()) as u16;
        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0, 1, 0x40, 0, 64, TCP, 0, 0, 10, 66, 0, 2, 192, 0, 2, 1]);
        ip
    };
    let tcp_at = packet.len();
    packet.extend_from_slice(&tcp);
    let check = verify(&packet);
    packet[tcp_at + 16..tcp_at + 18].copy_from_slice(&check.to_be_bytes());
    assert_eq!(verify(&packet), 0, "the built packet has a right checksum");
    packet
}

const MSS_1460: [u8; 4] = [2, 4, 0x05, 0xb4];

#[test]
fn a_syn_over_the_path_takes_mtu_less_40_with_a_right_checksum() {
    let mut packet = syn(false, SYN, &MSS_1460);
    assert_eq!(clamp_mss(&mut packet, 1280), Some((1460, 1240)));
    assert_eq!(&packet[40 + 2..40 + 4], &1240u16.to_be_bytes());
    assert_eq!(verify(&packet), 0, "the incremental checksum is the full one");
}

#[test]
fn an_ipv6_syn_ack_takes_mtu_less_60() {
    let mut packet = syn(true, SYN | 0x10, &MSS_1460);
    assert_eq!(clamp_mss(&mut packet, 1280), Some((1460, 1220)));
    assert_eq!(verify(&packet), 0);
}

#[test]
fn the_option_is_found_after_other_options() {
    // NOP, NOP, a timestamp of 10 bytes, a window scale of 3, then the MSS.
    let options = [1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 3, 3, 7, 2, 4, 0x23, 0x28];
    let mut packet = syn(false, SYN, &options);
    assert_eq!(clamp_mss(&mut packet, 1500), Some((9000, 1460)));
    assert_eq!(verify(&packet), 0);
    // The other options are as they were.
    assert_eq!(&packet[40..55], &options[..15]);
}

#[test]
fn each_other_packet_stays_as_it_is() {
    for (packet, why) in [
        (syn(false, 0x10, &MSS_1460), "no SYN"),
        (syn(false, SYN, &[2, 4, 0x04, 0x00]), "an MSS of 1024, under the limit"),
        (syn(false, SYN, &[1, 1, 3, 3, 7]), "no MSS option"),
        (syn(false, SYN, &[0, 2, 4, 0x05, 0xb4]), "an MSS after the end of the options"),
    ] {
        let mut clamped = packet.clone();
        assert_eq!(clamp_mss(&mut clamped, 1280), None, "{why}");
        assert_eq!(clamped, packet, "{why}");
    }
    let mut fragment = syn(false, SYN, &MSS_1460);
    fragment[6] = 0x20; // more fragments
    assert_eq!(clamp_mss(&mut fragment.clone(), 1280), None, "a fragment");
    let mut udp = syn(false, SYN, &MSS_1460);
    udp[9] = 17;
    assert_eq!(clamp_mss(&mut udp, 1280), None, "not TCP");
    let mut short = syn(false, SYN, &MSS_1460);
    short.truncate(42);
    assert_eq!(clamp_mss(&mut short, 1280), None, "cut short");
    assert_eq!(clamp_mss(&mut [], 1280), None, "empty");
    let mut bad_len = syn(false, SYN, &[2, 9, 0x05, 0xb4]);
    assert_eq!(clamp_mss(&mut bad_len, 1280), None, "an option past the header");
}

#[test]
fn the_incremental_form_agrees_with_a_full_sum_for_each_word() {
    let data = [0x12u8, 0x34, 0xab, 0xcd, 0xff, 0xff, 0x00, 0x01];
    let full = |d: &[u8]| !fold(sum(d, 0));
    for new in [0u16, 1, 0x05b4, 0x7fff, 0xfffe, 0xffff] {
        let mut changed = data;
        changed[2..4].copy_from_slice(&new.to_be_bytes());
        let old = u16::from_be_bytes([data[2], data[3]]);
        let got = update(full(&data), old, new);
        // Two forms of zero in ones complement are one value.
        let want = full(&changed);
        assert!(got == want || (got == 0xffff && want == 0) || (got == 0 && want == 0xffff), "{new:#x}");
    }
}
