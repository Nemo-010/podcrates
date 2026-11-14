//! The object-storage carrier (T-494, PodUtils/podnet#521, PodUtils/podnet@T-279)
//! against the stand-in of the S3 API on the loopback (`s3::standin`,
//! feature `s3-standin`): a link carries streams
//! over objects through the caller's way out, and each end learns the key
//! of the other; a PUT whose answer was lost gives no byte twice; `prune`
//! removes each object read, and with no `prune` the objects stay; the
//! keys of a session; another key is refused on each side; a wrong secret
//! and a missing bucket end the bind and the dial; a listener takes no
//! session older than its bind; the budget ends a session whose peer
//! removes nothing; the address, the settings and the facts.

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::tcp::{Direct, id, ring};
use common::{echo, limit, pattern};
use pod_identity::KeyName;
use pod_link::s3::standin::{self, StandIn};
use pod_link::s3::{Credentials, Endpoint, S3, S3Listener};
use pod_link::tcp::Keys;
use pod_link::{Carrier, CarrierErrorKind, Cost, Link, Listener, Role, Settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const BUCKET: &str = "links";

/// A carrier of the identity `n` on the stand-in, whose listeners take the
/// identities `clients`, with small objects so that a stream spans many.
fn carrier(n: u8, standin: &StandIn, way: Arc<Direct>, clients: &[u8]) -> S3 {
    let keys = Keys::new(clients.iter().map(|c| KeyName::Key(id(*c).public())));
    let mut s3 = S3::new(ring(), id(n), way, standin.endpoint(), standin::key()).with_clients(keys);
    (s3.object, s3.poll_min, s3.poll_max) = (16 << 10, Duration::from_millis(10), Duration::from_millis(200));
    s3
}

async fn bound(s3: &S3, prefix: &str) -> S3Listener {
    timeout(limit(), s3.bind(BUCKET, prefix)).await.expect("the bind in time").expect("the bind")
}

/// The dial address of the listener of the identity 1 at `prefix`.
fn at(prefix: &str) -> String {
    format!("{}@{BUCKET}/{prefix}", id(1).public().hex())
}

/// Three streams of `size` bytes each way over a link of `dialing` to
/// `door`: each comes back whole.
async fn carries(dialing: &S3, door: &mut S3Listener, prefix: &str, size: usize) {
    let address = at(prefix);
    let both = async { tokio::join!(dialing.dial(&address), door.accept_peer()) };
    let (near, far) = timeout(limit(), both).await.expect("the dial and the accept in time");
    let (near, far) = (near.expect("the dial"), far.expect("the accept"));
    assert_eq!(far.peer, Some(id(2).public()), "the accept gives the key of the client");
    let dialer = Link::new(near, Role::Dialer, Settings::default()).unwrap();
    let _echo = echo(Link::new(far.io, Role::Listener, Settings::default()).unwrap());
    let mut moves = Vec::new();
    for seed in 0..3u32 {
        let mut stream = dialer.open().unwrap();
        moves.push(tokio::spawn(async move {
            let data = pattern(seed, size);
            let (mut reader, mut writer) = tokio::io::split(&mut stream);
            let send = async {
                writer.write_all(&data).await.unwrap();
                writer.shutdown().await.unwrap();
            };
            let mut back = Vec::new();
            let (_, read) = tokio::join!(send, reader.read_to_end(&mut back));
            read.unwrap();
            assert!(back == data, "stream {seed}: the bytes came back whole");
        }));
    }
    for each in moves {
        timeout(limit(), each).await.expect("the echo in time").unwrap();
    }
    dialer.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_over_objects_carries_streams_and_each_end_learns_the_key_of_the_other() {
    pod_testkit::need_loopback!();
    let standin = StandIn::start(&[BUCKET]).await.unwrap();
    let way = Arc::new(Direct::default());
    let mut door = bound(&carrier(1, &standin, Arc::new(Direct::default()), &[2]), "a/b").await;
    assert_eq!(door.address(), "links/a/b");
    let dialing = carrier(2, &standin, way.clone(), &[]);
    let listener_key = KeyName::Key(id(1).public());
    let both = async { tokio::join!(dialing.connect(BUCKET, "a/b", &listener_key), door.accept_key()) };
    let (near, far) = timeout(limit(), both).await.expect("in time");
    assert_eq!((near.unwrap().1, far.unwrap().1), (id(1).public(), id(2).public()), "each end proved its key");
    carries(&dialing, &mut door, "a/b", 128 << 10).await;
    assert!(way.dials.load(Ordering::SeqCst) >= 1, "the requests go through the way out of the caller");
    let keys = standin.keys(BUCKET, "a/b/");
    let session = |dir: &str| keys.iter().filter(|k| k.starts_with(dir)).count();
    assert_eq!(session("a/b/open/"), 2, "an open object for each session: {keys:?}");
    assert!(session("a/b/up/") > 2 * 8 && session("a/b/down/") > 2 * 8, "the streams span many objects: {keys:?}");
    let first = keys.iter().find(|k| k.starts_with("a/b/up/")).unwrap();
    let parts: Vec<&str> = first.split('/').collect();
    assert_eq!((parts.len(), parts[4]), (5, "0000000000000000"), "PREFIX/up/SESSION/SEQ: {first}");
    assert!(parts[3].len() == 32 && parts[3].bytes().all(|b| b.is_ascii_hexdigit()), "{first}");
    assert_eq!(standin.counts().refused, 0, "each request was signed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_put_whose_answer_was_lost_gives_no_byte_twice() {
    pod_testkit::need_loopback!();
    let standin = StandIn::start(&[BUCKET]).await.unwrap();
    let mut door = bound(&carrier(1, &standin, Arc::new(Direct::default()), &[2]), "lossy").await;
    standin.lose_puts(3);
    carries(&carrier(2, &standin, Arc::new(Direct::default()), &[]), &mut door, "lossy", 64 << 10).await;
    assert_eq!(standin.counts().lost, 3);
    assert!(standin.counts().exists >= 3, "each PUT again found its object");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prune_removes_each_object_read_and_the_open_object() {
    pod_testkit::need_loopback!();
    let standin = StandIn::start(&[BUCKET]).await.unwrap();
    let mut listening = carrier(1, &standin, Arc::new(Direct::default()), &[2]);
    let mut dialing = carrier(2, &standin, Arc::new(Direct::default()), &[]);
    (listening.prune, dialing.prune) = (true, true);
    let mut door = bound(&listening, "pruned").await;
    let address = at("pruned");
    let both = async { tokio::join!(dialing.dial(&address), door.accept()) };
    let (near, far) = timeout(limit(), both).await.expect("in time");
    let (mut near, mut far) = (near.unwrap(), far.unwrap());
    let data = pattern(5, 100 << 10);
    near.write_all(&data).await.unwrap();
    near.shutdown().await.unwrap();
    let mut got = Vec::new();
    timeout(limit(), far.read_to_end(&mut got)).await.expect("the bytes in time").unwrap();
    assert!(got == data, "the bytes came whole");
    far.shutdown().await.unwrap();
    timeout(limit(), near.read_to_end(&mut got)).await.expect("the end in time").unwrap();
    let empty = async {
        while !standin.keys(BUCKET, "pruned/").is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    timeout(limit(), empty).await.unwrap_or_else(|_| panic!("each object was removed: {:?}", standin.keys(BUCKET, "")));
    assert!(standin.counts().deletes > 8);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_key_is_refused_on_each_side_and_the_listener_stays_open() {
    pod_testkit::need_loopback!();
    let standin = StandIn::start(&[BUCKET]).await.unwrap();
    let mut door = bound(&carrier(1, &standin, Arc::new(Direct::default()), &[2]), "keys").await;
    let stranger = carrier(3, &standin, Arc::new(Direct::default()), &[]);
    let address = at("keys");
    let (dialed, accepted) =
        timeout(limit(), async { tokio::join!(stranger.dial(&address), door.accept()) }).await.expect("in time");
    assert_eq!(dialed.err().unwrap().kind, CarrierErrorKind::KeyRefused, "the listener refused the key of the dialer");
    assert_eq!(accepted.err().unwrap().kind, CarrierErrorKind::Refused, "the listener names the key it refused");
    let other = format!("{}@{BUCKET}/keys", id(4).public().hex());
    let client = carrier(2, &standin, Arc::new(Direct::default()), &[]);
    let (dialed, _) =
        timeout(limit(), async { tokio::join!(client.dial(&other), door.accept()) }).await.expect("in time");
    assert_eq!(dialed.err().unwrap().kind, CarrierErrorKind::Refused, "the dialer refused a listener of another key");
    carries(&client, &mut door, "keys", 16 << 10).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_secret_and_a_missing_bucket_end_the_bind_and_the_dial() {
    pod_testkit::need_loopback!();
    let standin = StandIn::start(&[BUCKET]).await.unwrap();
    let mut wrong = carrier(1, &standin, Arc::new(Direct::default()), &[2]);
    wrong.credentials = Credentials::new(standin::key().access_key, "another-made-up-secret");
    let Err(e) = wrong.bind(BUCKET, "x").await else { panic!("the stand-in refuses a wrong secret") };
    assert_eq!(e.kind, CarrierErrorKind::Refused, "{e}");
    assert!(e.to_string().contains("SignatureDoesNotMatch"), "{e}");
    wrong.handshake_timeout = Duration::from_secs(5);
    let e = timeout(limit(), wrong.dial(&at("x"))).await.expect("in time").err().unwrap();
    assert_eq!(e.kind, CarrierErrorKind::Refused, "{e}");
    let right = carrier(1, &standin, Arc::new(Direct::default()), &[2]);
    let e = right.bind("missing", "x").await.err().unwrap();
    assert_eq!(e.kind, CarrierErrorKind::NotFound, "{e}");
    assert!(e.to_string().contains("NoSuchBucket"), "{e}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_listener_takes_no_session_older_than_its_bind() {
    pod_testkit::need_loopback!();
    let standin = StandIn::start(&[BUCKET]).await.unwrap();
    let mut early = carrier(2, &standin, Arc::new(Direct::default()), &[]);
    early.handshake_timeout = Duration::from_secs(2);
    let old = tokio::spawn(async move { early.dial(&at("late")).await.err().map(|e| e.kind) });
    let opened = async {
        while standin.keys(BUCKET, "late/open/").is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    timeout(limit(), opened).await.expect("the old session opened");
    let mut door = bound(&carrier(1, &standin, Arc::new(Direct::default()), &[2]), "late").await;
    let kind = timeout(limit(), old).await.expect("the old dial ended").unwrap();
    assert_eq!(kind, Some(CarrierErrorKind::Io(std::io::ErrorKind::TimedOut)), "no listener took the old session");
    carries(&carrier(2, &standin, Arc::new(Direct::default()), &[]), &mut door, "late", 16 << 10).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_budget_ends_a_session_whose_peer_removes_nothing() {
    pod_testkit::need_loopback!();
    let standin = StandIn::start(&[BUCKET]).await.unwrap();
    let mut door = bound(&carrier(1, &standin, Arc::new(Direct::default()), &[2]), "full").await;
    let mut dialing = carrier(2, &standin, Arc::new(Direct::default()), &[]);
    (dialing.budget, dialing.idle) = (64 << 10, Duration::from_secs(1));
    let address = at("full");
    let both = async { tokio::join!(dialing.dial(&address), door.accept()) };
    let (near, far) = timeout(limit(), both).await.expect("in time");
    let (mut near, _far) = (near.unwrap(), far.unwrap());
    let data = pattern(1, 256 << 10);
    let wrote = timeout(limit(), async {
        near.write_all(&data).await?;
        near.flush().await?;
        let mut byte = [0u8];
        near.read(&mut byte).await
    })
    .await
    .expect("the end of the session in time");
    let e = wrote.unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::StorageFull, "{e}");
    assert!(e.to_string().contains("budget"), "{e}");
    let held: usize = {
        let buckets = standin.buckets();
        buckets[BUCKET].iter().filter(|(k, _)| k.starts_with("full/up/")).map(|(_, o)| o.body.len()).sum()
    };
    assert!(held <= 64 << 10, "the objects of the dialer keep {held} bytes, past the budget");
}

#[tokio::test]
async fn the_address_the_settings_and_the_facts() {
    let standin_endpoint = Endpoint::parse("http://127.0.0.1:9").unwrap();
    let mut s3 = S3::new(ring(), id(1), Arc::new(Direct::default()), standin_endpoint, standin::key());
    assert_eq!((s3.name(), s3.facts().cost, s3.facts().reliable), ("s3", Cost::Highest, true));
    s3.available().expect("a provider of TLS 1.3 and settings in their bounds");
    let (key, bucket, prefix) = S3::address(&at("a/b-c.d_e")).unwrap();
    assert_eq!((key, bucket.as_str(), prefix.as_str()), (KeyName::Key(id(1).public()), BUCKET, "a/b-c.d_e"));
    assert_eq!(S3::place("links").unwrap(), ("links".to_string(), String::new()));
    for bad in ["Links/a", "ab/a", "links/a//b", "links/a/", "links//a", "links/a b", "-links/a"] {
        assert_eq!(S3::place(bad).err().unwrap().kind, CarrierErrorKind::Usage, "{bad}");
    }
    assert_eq!(S3::address("links/a").err().unwrap().kind, CarrierErrorKind::Usage);
    s3.object = 512;
    assert_eq!(s3.check().err().unwrap().kind, CarrierErrorKind::Usage);
    s3.object = pod_link::s3::OBJECT;
    s3.endpoint = Endpoint::parse("https://s3.example.com").unwrap();
    assert_eq!(s3.available().err().unwrap().kind, CarrierErrorKind::Unavailable, "an endpoint of https needs TLS");
    let shown = format!("{s3:?}");
    assert!(!shown.contains(&standin::key().secret_key), "the Debug of the carrier hides the secret: {shown}");
}
