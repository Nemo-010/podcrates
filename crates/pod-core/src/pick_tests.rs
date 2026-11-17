use super::*;

/// The vectors of the paper of SipHash (Aumasson and Bernstein, appendix A):
/// the key 00 01 .. 0f, and the message 00 01 .. (len - 1).
#[test]
fn siphash24_gives_the_vectors_of_the_paper() {
    let key = (0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908);
    let message: Vec<u8> = (0..64u8).collect();
    assert_eq!(siphash24(key, &message[..0]), 0x726f_db47_dd0e_0e31);
    assert_eq!(siphash24(key, &message[..1]), 0x74f8_39c5_93dc_67fd);
    assert_eq!(siphash24(key, &message[..8]), 0x93f5_f579_9a93_2462);
    assert_eq!(siphash24(key, &message[..15]), 0xa129_ca61_49be_45e5);
    assert_eq!(siphash24(key, &message[..63]), 0x958a_324c_eb06_4572);
}

fn four() -> Vec<Candidate<'static>> {
    ["a.test", "b.test", "c.test", "d.test"].iter().map(|id| Candidate { id, weight: 1.0, tier: 0 }).collect()
}

#[test]
fn the_same_key_gives_the_same_order() {
    let candidates = four();
    assert_eq!(rank(b"pair-1", &candidates), rank(b"pair-1", &candidates));
    let firsts: std::collections::HashSet<usize> =
        (0..200u32).filter_map(|i| first(&i.to_be_bytes(), &candidates)).collect();
    assert_eq!(firsts.len(), 4, "each candidate takes keys");
}

/// A fifth candidate takes about a fifth of the keys, and each key that
/// moves goes to it: no key moves between the four.
#[test]
fn a_new_candidate_takes_about_one_in_n_plus_one_and_no_other_key_moves() {
    let four = four();
    let mut five = four.clone();
    five.push(Candidate { id: "e.test", weight: 1.0, tier: 0 });
    let keys = 10_000u32;
    let mut moved = 0;
    for i in 0..keys {
        let (before, after) = (first(&i.to_be_bytes(), &four), first(&i.to_be_bytes(), &five));
        if before != after {
            moved += 1;
            assert_eq!(after, Some(4), "a key moved between two old candidates");
        }
    }
    let share = f64::from(moved) / f64::from(keys);
    assert!((0.17..0.23).contains(&share), "{share}");
}

#[test]
fn a_weight_takes_keys_in_proportion() {
    let candidates =
        [Candidate { id: "big.test", weight: 3.0, tier: 0 }, Candidate { id: "small.test", weight: 1.0, tier: 0 }];
    let big = (0..10_000u32).filter(|i| first(&i.to_be_bytes(), &candidates) == Some(0)).count();
    let share = big as f64 / 10_000.0;
    assert!((0.72..0.78).contains(&share), "{share}");
}

#[test]
fn a_lower_tier_comes_first_and_a_bad_weight_last() {
    let candidates = [
        Candidate { id: "backup.test", weight: 100.0, tier: 1 },
        Candidate { id: "zero.test", weight: 0.0, tier: 0 },
        Candidate { id: "main.test", weight: 1.0, tier: 0 },
        Candidate { id: "nan.test", weight: f64::NAN, tier: 0 },
    ];
    for i in 0..100u32 {
        let order = rank(&i.to_be_bytes(), &candidates);
        assert_eq!(order[0], 2, "the main tier first, whatever the weight of the backup");
        assert_eq!(order[3], 0, "the backup's tier after each of tier 0");
    }
    assert!(first(b"k", &[]).is_none());
}
