use std::time::{Duration, Instant};

use super::*;

/// Run the search over a path that carries `path` bytes, with an answer at
/// once to each probe that fits, for `secs` seconds. The probes, in order.
fn walk(ladder: &mut Ladder, path: u16, start: Instant, secs: u64) -> Vec<u16> {
    let mut sizes = Vec::new();
    for s in 0..secs {
        let now = start + Duration::from_secs(s);
        while let Some(p) = ladder.poll(now) {
            sizes.push(p.size);
            if p.size <= path {
                ladder.acked(p.id, now);
            }
        }
    }
    sizes
}

#[test]
fn a_wide_path_climbs_each_rung_and_rests_at_the_top() {
    let (mut ladder, start) = (Ladder::new(), Instant::now());
    assert_eq!(ladder.mtu(), 1120, "the first rung is taken to work");
    assert_eq!(walk(&mut ladder, 9000, start, 2), [1320, 1400, 1500]);
    assert_eq!(ladder.mtu(), 1500);
    assert!(ladder.settled());
    assert_eq!(walk(&mut ladder, 9000, start + RAISE_AFTER * 2, 2), [] as [u16; 0], "no rung above the top");
}

#[test]
fn a_rung_with_no_answer_ends_the_search_below_it_after_three_probes() {
    let (mut ladder, start) = (Ladder::new(), Instant::now());
    let secs = 4 * PROBE_WAIT.as_secs();
    assert_eq!(walk(&mut ladder, 1400, start, secs), [1320, 1400, 1500, 1500, 1500]);
    assert_eq!(ladder.mtu(), 1400);
    assert!(ladder.settled());
}

#[test]
fn a_settled_search_tries_the_next_rung_again_later() {
    let (mut ladder, start) = (Ladder::new(), Instant::now());
    walk(&mut ladder, 1320, start, 4 * PROBE_WAIT.as_secs());
    assert_eq!(ladder.mtu(), 1320);
    let later = start + Duration::from_secs(4 * PROBE_WAIT.as_secs()) + RAISE_AFTER;
    assert_eq!(walk(&mut ladder, 1320, later - Duration::from_secs(30), 10), [] as [u16; 0], "not before the time");
    // The path grew: the next search takes the rest.
    assert_eq!(walk(&mut ladder, 1500, later, 2), [1400, 1500]);
    assert_eq!(ladder.mtu(), 1500);
}

#[test]
fn an_old_or_unknown_answer_changes_nothing() {
    let (mut ladder, now) = (Ladder::new(), Instant::now());
    let first = ladder.poll(now).unwrap();
    let again = ladder.poll(now + PROBE_WAIT).unwrap();
    assert_eq!((first.size, again.size), (1320, 1320));
    ladder.acked(first.id, now + PROBE_WAIT);
    assert_eq!(ladder.mtu(), 1120, "the answer to the probe before");
    ladder.acked(999, now + PROBE_WAIT);
    assert_eq!(ladder.mtu(), 1120);
    ladder.acked(again.id, now + PROBE_WAIT);
    assert_eq!(ladder.mtu(), 1320);
}

#[test]
fn a_black_hole_goes_back_to_the_first_rung_and_searches_again() {
    let (mut ladder, start) = (Ladder::new(), Instant::now());
    walk(&mut ladder, 1500, start, 2);
    assert_eq!(ladder.mtu(), 1500);
    ladder.black_hole();
    assert_eq!(ladder.mtu(), 1120);
    assert!(!ladder.settled());
    let secs = 4 * PROBE_WAIT.as_secs();
    assert_eq!(walk(&mut ladder, 1320, start + Duration::from_secs(10), secs), [1320, 1400, 1400, 1400]);
    assert_eq!(ladder.mtu(), 1320);
}
