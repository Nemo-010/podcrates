//! The meeting point at ntfy servers (`pod_wormhole::ntfy`) on the stand-in
//! server of `harness/ntfy.rs`, which keeps each message as ntfy's cache
//! does, with no TLS (HTTP/1.1) and behind TLS (`harness/ntfy_tls.rs`:
//! HTTP/2, or HTTP/1.1 alone); and on ntfy's own server where
//! `POD_WORMHOLE_TEST_NTFY` names it. Two ends pair through the topic of a
//! code and move messages each way: on HTTP/1.1 the polls and the POSTs of
//! one end take turns on one connection; on HTTP/2 one connection of each
//! end holds the stream and the POSTs. No request holds a word of the code.
//! A message of 4,096 bytes or more fails before the send; a read takes what came
//! since this end's start, then since the last id; an answer `429` is
//! waited out; a server that refuses is passed over with its words.

mod harness;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use harness::ntfy::{self as stand, Ntfy, Script};
use harness::ntfy_tls::{self, Offer};
use harness::{LIMIT, config, nobody_there};
use pod_core::Event;
use pod_testkit::need_loopback;
use pod_wormhole::mailbox::Mood;
use pod_wormhole::mqtt::{self, Role};
use pod_wormhole::ntfy::{self, MESSAGE_MOST, Pace, Point, Servers, Topic, wire};
use pod_wormhole::{Code, Config, Failed, Wormhole};
use serde_json::{Value, json};

type Seen = Arc<Mutex<Vec<Event>>>;

fn versions() -> Value {
    json!({ "pod-wormhole-test": 1 })
}

/// The servers `points` with `config`, the events of a run in `seen`, and
/// short waits.
fn ends_with(points: Vec<Point>, config: Config, seen: &Seen) -> Servers {
    let kept = seen.clone();
    let events = Arc::new(move |event: Event| kept.lock().unwrap().push(event));
    Servers { pace: pace(), ..Servers::new(points, Config { events, ..config }) }
}

/// The short waits of the tests.
fn pace() -> Pace {
    let poll = Duration::from_millis(50);
    Pace { poll, waiting: poll * 2, retry: Duration::from_millis(100) }
}

fn ends(points: Vec<Point>, seen: &Seen) -> Servers {
    ends_with(points, config(), seen)
}

/// A pairing at the first server of `ends`: the versions checked and
/// messages each way.
async fn pair(ends: &Servers) -> Code {
    let (mut giver, code) = ntfy::opened(ends, versions()).await.expect("a code");
    let (taker, heard) = tokio::join!(ntfy::joined(ends, &code, versions(), LIMIT), giver.agree(LIMIT));
    let mut taker = taker.expect("the taker");
    assert!(heard.expect("the giver waits"), "the giver hears the taker's pake");
    exchange(&mut giver, &mut taker).await;
    code
}

async fn exchange(giver: &mut Wormhole, taker: &mut Wormhole) {
    let (mine, theirs) = tokio::join!(giver.confirm(LIMIT), taker.confirm(LIMIT));
    assert_eq!((mine.unwrap(), theirs.unwrap()), (versions(), versions()));
    giver.send(b"the offer").await.unwrap();
    assert_eq!(taker.receive(LIMIT).await.unwrap(), b"the offer");
    taker.send(b"the answer").await.unwrap();
    assert_eq!(giver.receive(LIMIT).await.unwrap(), b"the answer");
    giver.send(b"the last word").await.unwrap();
    assert_eq!(taker.receive(LIMIT).await.unwrap(), b"the last word");
    tokio::join!(giver.close(Mood::Happy), taker.close(Mood::Happy));
}

/// No request of `stand` holds a word of `code`; each holds the topic of
/// its nameplate with a letter of direction.
fn no_word_in(stand: &Ntfy, code: &Code) {
    let tag = mqtt::topic(harness::APPID, code.nameplate());
    let words = code.for_terminal().split_once('-').unwrap().1.to_string();
    for asked in stand.asked() {
        assert!(words.split('-').all(|w| !asked.target.contains(w)), "a request holds a word of the code: {asked:?}");
        let topic = asked.target.trim_start_matches('/').split(['/', '?']).next().unwrap().to_string();
        assert!(
            topic == format!("{tag}{}", mqtt::TO_GIVER) || topic == format!("{tag}{}", mqtt::TO_TAKER),
            "{asked:?}"
        );
        assert!(asked.body.len() <= MESSAGE_MOST, "{asked:?}");
    }
}

#[tokio::test]
async fn two_ends_pair_by_polls_that_take_turns_with_the_posts_on_http1() {
    need_loopback!();
    let stand = stand::start().await;
    let code = pair(&ends(vec![stand.url.clone()], &Seen::default())).await;
    no_word_in(&stand, &code);
    let asked = stand.asked();
    assert_eq!(stand.connections(), 2, "one connection for each end: {asked:?}");
    assert!(asked.iter().all(|a| !a.h2 && (a.method == "POST" || a.target.contains("poll=1"))), "{asked:?}");
    // The seven messages of the pairing and no more: the server keeps them.
    assert_eq!(asked.iter().filter(|a| a.method == "POST").count(), 7, "{asked:?}");
    // After the first message of the other end, a poll asks for what came
    // since its id.
    let ids: HashSet<String> = stand.kept().into_iter().map(|m| m.id).collect();
    let after_id = asked.iter().filter(|a| ids.iter().any(|id| a.target.ends_with(&format!("since={id}")))).count();
    assert!(after_id >= 2, "{asked:?}");
}

#[tokio::test]
async fn two_ends_pair_on_one_http2_connection_each_with_a_stream() {
    need_loopback!();
    let stand = ntfy_tls::start(Offer::Both, Script::Takes).await;
    let code = pair(&ends_with(vec![stand.url.clone()], ntfy_tls::config(), &Seen::default())).await;
    no_word_in(&stand, &code);
    let asked = stand.asked();
    assert_eq!(stand.connections(), 2, "one connection for each end: {asked:?}");
    assert!(asked.iter().all(|a| a.h2 && !a.target.contains("poll=1")), "no poll on HTTP/2: {asked:?}");
    let streams: HashSet<u64> = asked.iter().filter(|a| a.method == "GET").map(|a| a.conn).collect();
    let posts: HashSet<u64> = asked.iter().filter(|a| a.method == "POST").map(|a| a.conn).collect();
    assert_eq!((streams.len(), &streams), (2, &posts), "the stream and the POSTs share each connection");
}

#[tokio::test]
async fn a_server_with_http1_alone_behind_tls_is_polled() {
    need_loopback!();
    let stand = ntfy_tls::start(Offer::Http1Only, Script::Takes).await;
    pair(&ends_with(vec![stand.url.clone()], ntfy_tls::config(), &Seen::default())).await;
    let asked = stand.asked();
    assert_eq!(stand.connections(), 2, "{asked:?}");
    assert!(asked.iter().all(|a| !a.h2) && asked.iter().any(|a| a.target.contains("poll=1")), "{asked:?}");
}

#[tokio::test]
async fn a_message_of_4096_bytes_or_more_fails_before_the_send() {
    need_loopback!();
    let stand = stand::start().await;
    let servers = ends(vec![stand.url.clone()], &Seen::default());
    let mut taker = Topic::connect(&stand.url, &servers, "0123456789", "pwtest", Role::Taker).await.unwrap();
    let empty = wire::content("0123456789", "100", b"").unwrap().len();
    let most = vec![0x5a; (MESSAGE_MOST - empty) / 2];
    taker.add("100", &most).await.expect("a message of 4,095 bytes");
    let over = vec![0x5a; most.len() + 1];
    let failed = taker.add("100", &over).await.expect_err("a message of 4,097 bytes");
    assert!(failed.to_string().contains("over the 4095"), "{failed}");
    let posts: Vec<usize> = stand.asked().iter().filter(|a| a.method == "POST").map(|a| a.body.len()).collect();
    assert_eq!(posts, vec![MESSAGE_MOST], "the longer one was not sent");
    taker.end().await;
}

#[tokio::test]
async fn a_read_takes_what_came_since_its_start_then_since_the_last_id() {
    need_loopback!();
    let stand = stand::start().await;
    let servers = ends(vec![stand.url.clone()], &Seen::default());
    let (inbox, _) = Role::Giver.topics("pwtest");
    let said = |phase: &str| json!({ "side": "abcdefabcd", "phase": phase, "body": "00" }).to_string();
    // A message of an hour ago is of another code.
    stand.plant(&inbox, &said("old"), stand::now() - 3600);
    stand.plant(&inbox, &said("pake"), stand::now());
    let mut giver = Topic::connect(&stand.url, &servers, "0123456789", "pwtest", Role::Giver).await.unwrap();
    let first = giver.message(LIMIT).await.unwrap().expect("the message of now");
    assert_eq!(first.phase, "pake");
    stand.plant(&inbox, &said("version"), stand::now());
    assert_eq!(giver.message(LIMIT).await.unwrap().expect("the next").phase, "version");
    assert_eq!(giver.message(Duration::from_millis(300)).await.unwrap(), None, "nothing twice, nothing old");
    let polls: Vec<String> = stand.asked().into_iter().map(|a| a.target).collect();
    let kept = stand.kept();
    let since: u64 = polls[0].rsplit_once("since=").and_then(|(_, t)| t.parse().ok()).expect("a time");
    assert!((stand::now() - 63..=stand::now() - 59).contains(&since), "the start less 60 s: {polls:?}");
    assert!(polls.iter().any(|p| p.ends_with(&format!("since={}", kept[1].id))), "{polls:?}");
    assert!(polls.last().unwrap().ends_with(&format!("since={}", kept[2].id)), "{polls:?}");
    giver.end().await;
}

#[tokio::test]
async fn a_post_answered_429_goes_again_after_the_wait() {
    need_loopback!();
    let stand = stand::start_with(Script::LimitsPosts(2)).await;
    let seen = Seen::default();
    pair(&ends(vec![stand.url.clone()], &seen)).await;
    let limited = seen.lock().unwrap().iter().filter(|e| e.text.contains("limits this end")).count();
    assert_eq!(limited, 2, "{seen:?}");
}

#[tokio::test]
async fn a_server_that_refuses_is_passed_over_with_its_words() {
    need_loopback!();
    let forbids = stand::start_with(Script::Refuses(403, "forbidden".into())).await;
    let limits = stand::start_with(Script::Refuses(429, "limit reached: too many requests".into())).await;
    let takes = stand::start().await;
    let urls = [&forbids, &limits, &takes].map(|s| s.url.clone()).to_vec();
    let seen = Seen::default();
    let servers = ends(urls, &seen);
    let (mut giver, code) = ntfy::opened(&servers, versions()).await.expect("a code at the third server");
    let (taker, heard) = tokio::join!(ntfy::joined(&servers, &code, versions(), LIMIT), giver.agree(LIMIT));
    let mut taker = taker.expect("the taker");
    assert!(heard.unwrap());
    assert_eq!(giver.shown(), takes.url.shown());
    exchange(&mut giver, &mut taker).await;
    let lines: Vec<String> = seen.lock().unwrap().iter().map(|e| format!("{} {}", e.kind, e.text)).collect();
    for words in ["refused: HTTP 403: forbidden (code 40301)", "limits this end"] {
        let told = lines.iter().filter(|l| l.starts_with("wormhole.ntfy ") && l.contains(words)).count();
        assert!(told >= 2, "each end said {words:?}: {lines:?}");
    }
}

#[tokio::test]
async fn no_server_that_answers_is_unreachable() {
    need_loopback!();
    let nobody = Point::parse(&nobody_there().shown().replacen("ws://", "http://", 1)).unwrap();
    let servers = ends(vec![nobody], &Seen::default());
    assert!(matches!(ntfy::opened(&servers, versions()).await.map(|_| ()), Err(Failed::Unreachable(_))));
    let code = Code::make("1234", pod_wormhole::WORDS, &mut pod_core::entropy::OsEntropy).unwrap();
    let met = ntfy::joined(&servers, &code, versions(), Duration::from_secs(1)).await.map(|_| ());
    assert!(matches!(met, Err(Failed::Unreachable(_))), "{met:?}");
}

/// ntfy's own server where `POD_WORMHOLE_TEST_NTFY` names its root
/// (`scripts/ci/ntfy-tests.sh`); `POD_WORMHOLE_TEST_NTFY_SERVER=required`
/// makes a skip a failure.
#[tokio::test]
async fn two_ends_pair_at_ntfys_own_server() {
    need_loopback!();
    let Some(url) = std::env::var("POD_WORMHOLE_TEST_NTFY").ok().filter(|u| !u.is_empty()) else {
        let required = std::env::var("POD_WORMHOLE_TEST_NTFY_SERVER").is_ok_and(|v| v == "required");
        assert!(!required, "POD_WORMHOLE_TEST_NTFY_SERVER=required and no POD_WORMHOLE_TEST_NTFY");
        eprintln!("did not run: no POD_WORMHOLE_TEST_NTFY");
        return;
    };
    let servers = ends(vec![Point::parse(&url).unwrap()], &Seen::default());
    pair(&servers).await;
    println!("binwiederhier/ntfy: two ends paired");
}

/// Each public server of `pod-services` carries the largest message.
#[test]
fn each_public_server_carries_the_largest_message() {
    let servers: Vec<_> = pod_services::of_kind("ntfy-server").collect();
    assert!(!servers.is_empty(), "the catalog lists no ntfy server");
    for s in servers {
        let most = s.int("message-bytes-most").unwrap_or_else(|| panic!("{}: no message-bytes-most", s.id()));
        assert!(MESSAGE_MOST as i64 <= most, "{}: {MESSAGE_MOST} > {most}", s.id());
        let e = s.endpoint("server").unwrap_or_else(|| panic!("{}: no endpoint server", s.id()));
        Point::parse(&e.url()).unwrap_or_else(|why| panic!("{}: {why}", s.id()));
    }
}
