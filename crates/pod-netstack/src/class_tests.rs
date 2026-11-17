use std::time::{Duration, Instant};

use super::*;

fn end(ip: &str, port: u16) -> End {
    End { ip: ip.parse().unwrap(), port }
}

const UDP: u8 = 17;

#[test]
fn both_directions_have_one_key_and_two_ports_of_one_host_two() {
    let (a, b) = (end("10.66.0.2", 40000), end("192.0.2.1", 443));
    assert_eq!(Key::of(UDP, a, b), Key::of(UDP, b, a));
    let v6 = (end("fd00:66::2", 40000), end("2001:db8::1", 443));
    assert_eq!(Key::of(UDP, v6.0, v6.1), Key::of(UDP, v6.1, v6.0));
    assert_ne!(Key::of(UDP, a, b), Key::of(UDP, end("10.66.0.2", 40001), b), "the same host on another port");
    assert_ne!(Key::of(UDP, a, b), Key::of(6, a, b), "another protocol");
}

#[test]
fn a_rule_wins_over_dscp_and_dscp_over_the_heuristic() {
    let now = Instant::now();
    let key = Key::of(UDP, end("10.66.0.2", 40000), end("192.0.2.1", 5004));
    let mut classes = Classes::with_rules(vec![Rule { port: 5004, class: Class::Bulk }]);
    assert_eq!(classes.class(key, 46, 100, now), Class::Bulk, "the rule over EF");
    let mut classes = Classes::default();
    assert_eq!(classes.class(key, 46, 1400, now), Class::Realtime, "EF");
    assert_eq!(classes.class(key, 8, 100, now), Class::Bulk, "CS1");
    assert_eq!(classes.class(key, 0, 19, now), Class::Default, "a 19-byte packet, cold");
}

#[test]
fn the_heuristic_warms_then_names_bulk_and_realtime() {
    let start = Instant::now();
    let mut classes = Classes::default();
    let bulk = Key::of(6, end("10.66.0.2", 40000), end("192.0.2.1", 443));
    let got: Vec<Class> =
        (0..WARM).map(|i| classes.class(bulk, 0, 1400, start + Duration::from_millis(u64::from(i)))).collect();
    assert_eq!(got[..WARM as usize - 1], [Class::Default; WARM as usize - 1], "cold");
    assert_eq!(got[WARM as usize - 1], Class::Bulk);
    let voice = Key::of(UDP, end("10.66.0.2", 40002), end("192.0.2.1", 3478));
    let mut last = Class::Default;
    for i in 0..30u64 {
        last = classes.class(voice, 0, 160, start + Duration::from_millis(i * 20));
    }
    assert_eq!(last, Class::Realtime, "160 bytes each 20 ms");
    // Small packets, slowly: no class.
    let slow = Key::of(UDP, end("10.66.0.2", 40003), end("192.0.2.1", 53));
    for i in 0..10u64 {
        last = classes.class(slow, 0, 80, start + Duration::from_secs(i));
    }
    assert_eq!(last, Class::Default);
}

#[test]
fn a_full_table_drops_its_idle_flows_and_keeps_its_live_ones() {
    let start = Instant::now();
    let mut classes = Classes::default();
    for i in 0..MOST_FLOWS {
        let key = Key::of(UDP, end("10.66.0.2", i as u16), end("192.0.2.1", 9));
        classes.class(key, 0, 100, start);
    }
    assert_eq!(classes.len(), MOST_FLOWS);
    // A new flow while each is live: no room, and no live flow goes.
    let new = Key::of(UDP, end("10.66.0.3", 1), end("192.0.2.1", 9));
    assert_eq!(classes.class(new, 46, 100, start + Duration::from_secs(1)), Class::Realtime, "DSCP still holds");
    assert_eq!(classes.len(), MOST_FLOWS);
    // Later than the idle limit: the idle flows go, and the new one comes in.
    classes.class(new, 0, 100, start + IDLE + Duration::from_secs(1));
    assert_eq!(classes.len(), 1);
}
