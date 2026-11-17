use super::*;

#[test]
fn a_reservation_takes_first_and_a_commit_gives_back_the_rest() {
    let quota = Quota::new(100);
    let r = quota.reserve(60).expect("60 of 100");
    assert_eq!(quota.left(), 40, "taken before the write");
    assert!(quota.reserve(41).is_none(), "the bytes in flight count");
    assert_eq!(quota.left(), 40, "a refused reservation takes nothing");
    r.commit(25);
    assert_eq!(quota.left(), 75);
}

#[test]
fn a_dropped_reservation_gives_all_back_and_a_commit_keeps_at_most_what_it_held() {
    let quota = Quota::new(10);
    drop(quota.reserve(10).unwrap());
    assert_eq!(quota.left(), 10, "a failed write costs nothing");
    quota.reserve(4).unwrap().commit(1000);
    assert_eq!(quota.left(), 6, "a commit past the reservation keeps the reservation");
}

#[test]
fn up_to_takes_what_is_left_and_nothing_from_an_empty_budget() {
    let quota = Quota::new(10);
    let r = quota.reserve_up_to(64).unwrap();
    assert_eq!(r.bytes(), 10);
    assert!(quota.reserve_up_to(1).is_none());
    r.commit(10);
    assert!(quota.reserve_up_to(1).is_none());
    assert!(Quota::new(5).reserve_up_to(0).is_none(), "no reservation of nothing");
    let quota = Quota::new(0);
    assert!(quota.reserve(0).is_some_and(|r| r.bytes() == 0), "zero of zero");
}

/// Writers on many threads never take more than the budget, and the
/// committed bytes plus what is left is the budget.
#[test]
fn many_writers_never_overspend() {
    let quota = Quota::new(100_000);
    let committed = Arc::new(AtomicU64::new(0));
    std::thread::scope(|scope| {
        for t in 0..8u64 {
            let (quota, committed) = (quota.clone(), committed.clone());
            scope.spawn(move || {
                for i in 0..5_000u64 {
                    let want = 1 + (i * 7 + t) % 61;
                    if let Some(r) = quota.reserve_up_to(want) {
                        let used = r.bytes() - (i % 3).min(r.bytes());
                        committed.fetch_add(used, Ordering::Relaxed);
                        if i % 5 == 0 {
                            drop(r);
                            committed.fetch_sub(used, Ordering::Relaxed);
                        } else {
                            r.commit(used);
                        }
                    }
                }
            });
        }
    });
    let committed = committed.load(Ordering::Relaxed);
    assert!(committed <= 100_000);
    assert_eq!(committed + quota.left(), 100_000);
}
