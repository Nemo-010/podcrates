use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::time::Instant;

use super::*;

fn addrs(list: &[&str]) -> Vec<SocketAddr> {
    list.iter().map(|s| s.parse().unwrap()).collect()
}

fn shown(list: &[SocketAddr]) -> Vec<String> {
    list.iter().map(|a| a.to_string()).collect()
}

const BOTH: Local = Local { v4: true, v6: true };

#[test]
fn the_plan_puts_ipv6_first_and_keeps_the_order_of_each_family() {
    let got = plan(&addrs(&["1.1.1.1:1", "[2001:db8::1]:1", "2.2.2.2:1", "[2001:db8::2]:1"]), BOTH);
    assert_eq!(shown(&got), ["[2001:db8::1]:1", "[2001:db8::2]:1", "1.1.1.1:1", "2.2.2.2:1"]);
}

#[test]
fn a_family_that_the_host_lacks_is_not_dialled_while_another_meets() {
    let peer = addrs(&["1.1.1.1:1", "[2001:db8::1]:1"]);
    assert_eq!(shown(&plan(&peer, Local { v4: false, v6: true })), ["[2001:db8::1]:1"]);
    assert_eq!(shown(&plan(&peer, Local { v4: true, v6: false })), ["1.1.1.1:1"]);
}

#[test]
fn no_probe_that_answers_reads_as_both_and_no_meeting_falls_open() {
    let peer = addrs(&["1.1.1.1:1", "[2001:db8::1]:1"]);
    assert_eq!(plan(&peer, Local::default()).len(), 2, "neither probe: both");
    let only4 = addrs(&["1.1.1.1:1"]);
    assert_eq!(shown(&plan(&only4, Local { v4: false, v6: true })), ["1.1.1.1:1"], "falls open");
    assert!(plan(&[], BOTH).is_empty());
}

#[test]
fn a_mapped_address_is_ipv4_and_counts_once() {
    let got = plan(&addrs(&["[::ffff:1.1.1.1]:1", "1.1.1.1:1", "[2001:db8::1]:1"]), Local { v4: true, v6: false });
    assert_eq!(shown(&got), ["1.1.1.1:1"]);
}

/// An attempt that answers after `after`, or fails.
fn after(
    list: &[(&str, u64, bool)],
) -> impl Fn(SocketAddr) -> std::pin::Pin<Box<dyn Future<Output = io::Result<SocketAddr>> + Send>> {
    let list: Vec<(SocketAddr, u64, bool)> = list.iter().map(|(a, ms, ok)| (a.parse().unwrap(), *ms, *ok)).collect();
    move |addr| {
        let (_, ms, ok) = *list.iter().find(|(a, ..)| *a == addr).expect("a planned address");
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            if ok { Ok(addr) } else { Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused")) }
        })
    }
}

async fn run(order: &[&str], attempts: &[(&str, u64, bool)]) -> (Result<String, String>, Duration) {
    let start = Instant::now();
    let far = start + Duration::from_secs(60);
    let plan = FamilyPlan { attempt_timeout: Duration::from_secs(10) };
    let got = race_held(
        addrs(order),
        plan,
        Duration::from_millis(250),
        "t",
        far,
        far,
        Duration::from_secs(60),
        after(attempts),
    )
    .await;
    (got.map(|(v, _)| v.to_string()).map_err(|e| e.to_string()), start.elapsed())
}

#[tokio::test(start_paused = true)]
async fn a_fast_ipv4_success_waits_for_a_slower_ipv6_that_works() {
    let (got, took) =
        run(&["[2001:db8::1]:1", "1.1.1.1:1"], &[("[2001:db8::1]:1", 900, true), ("1.1.1.1:1", 10, true)]).await;
    assert_eq!(got.unwrap(), "[2001:db8::1]:1");
    assert_eq!(took, Duration::from_millis(900));
}

#[tokio::test(start_paused = true)]
async fn the_held_ipv4_wins_when_the_ipv6_attempt_fails_or_times_out() {
    let (got, took) =
        run(&["[2001:db8::1]:1", "1.1.1.1:1"], &[("[2001:db8::1]:1", 900, false), ("1.1.1.1:1", 10, true)]).await;
    assert_eq!((got.unwrap().as_str(), took), ("1.1.1.1:1", Duration::from_millis(900)));
    let (got, took) =
        run(&["[2001:db8::1]:1", "1.1.1.1:1"], &[("[2001:db8::1]:1", 3_600_000, true), ("1.1.1.1:1", 10, true)]).await;
    assert_eq!((got.unwrap().as_str(), took), ("1.1.1.1:1", Duration::from_secs(10)), "the timeout of the attempt");
}

#[tokio::test(start_paused = true)]
async fn the_first_success_returns_at_once_and_a_failure_starts_the_next() {
    let (got, took) =
        run(&["[2001:db8::1]:1", "1.1.1.1:1"], &[("[2001:db8::1]:1", 20, true), ("1.1.1.1:1", 10, true)]).await;
    assert_eq!((got.unwrap().as_str(), took), ("[2001:db8::1]:1", Duration::from_millis(20)));
    let (got, took) =
        run(&["[2001:db8::1]:1", "1.1.1.1:1"], &[("[2001:db8::1]:1", 5, false), ("1.1.1.1:1", 10, true)]).await;
    assert_eq!((got.unwrap().as_str(), took), ("1.1.1.1:1", Duration::from_millis(15)));
}

#[tokio::test(start_paused = true)]
async fn each_failure_is_named_when_no_attempt_connects() {
    let (got, _) =
        run(&["[2001:db8::1]:1", "1.1.1.1:1"], &[("[2001:db8::1]:1", 5, false), ("1.1.1.1:1", 5, false)]).await;
    let words = got.unwrap_err();
    assert!(words.contains("2 addresses") && words.contains("refused"), "{words}");
}

#[test]
fn the_probe_and_its_cache_run() {
    assert_eq!(Local::cached(), Local::cached());
}
