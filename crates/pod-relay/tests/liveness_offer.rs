//! A relay's offer of a pace of liveness (T-845, PodUtils/podssh#300): a
//! node told `{"frame":"ws-ping","every_s":30}` in `hello` sends its first
//! Ping at 30 s, not at its own 10 s; with no offer, or with one under
//! 30 s, it keeps 10 s. The relay is scripted over an in-memory stream, and
//! the clock is the test's.
#![cfg(feature = "pair")]

use std::sync::Arc;
use std::time::Duration;

use pod_relay::reverse::{Handler, Opening, SessionId, Settings, serve};
use pod_ws::frame::{self, Frame, Role};
use pod_ws::session::RelaySession;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::Notify;

/// A node that opens no local side.
struct Nothing;

impl Handler for Nothing {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        Box::pin(async { Err("no local side".to_string()) })
    }
}

/// The seconds from the `hello` to the node's first Ping.
async fn first_ping_after(hello: &str) -> u64 {
    let (client, mut relay) = tokio::io::duplex(64 * 1024);
    let stop = Arc::new(Notify::new());
    let stopper = stop.clone();
    let settings = Settings { ping_every: Duration::from_secs(10), pings_allowed: 3, ..Settings::default() };
    tokio::spawn(async move {
        let session = RelaySession::new(client, Vec::new(), None, Duration::from_secs(5));
        let mut stop = Box::pin(async move { stopper.notified().await });
        serve(session, Arc::new(Nothing), settings, &mut stop).await
    });
    let bytes = frame::encode(
        &Frame { fin: true, opcode: frame::OPCODE_TEXT, payload: hello.as_bytes().to_vec() },
        Role::Server,
        [0; 4],
    );
    relay.write_all(&bytes).await.unwrap();
    let start = tokio::time::Instant::now();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        while let Some((f, used)) = frame::decode(&buf, Role::Client).expect("a node frame") {
            buf.drain(..used);
            if f.opcode == frame::OPCODE_PING {
                stop.notify_one();
                return start.elapsed().as_secs();
            }
        }
        let n = tokio::time::timeout(Duration::from_secs(120), relay.read(&mut chunk))
            .await
            .expect("a Ping within 120 s")
            .unwrap();
        assert!(n > 0, "the node closed the stream");
        buf.extend_from_slice(&chunk[..n]);
    }
}

const PLAIN: &str = r#"{"type":"hello","version":1,"maxFrameBytes":65536,"maxSessions":64}"#;

#[tokio::test(start_paused = true)]
async fn a_node_takes_the_slower_ping_of_the_relay_s_offer() {
    let offered = r#"{"type":"hello","version":1,"liveness":{"frame":"ws-ping","every_s":30}}"#;
    assert_eq!(first_ping_after(offered).await, 30);
    let held = r#"{"type":"hello","version":1,"liveness":{"frame":"ws-ping","every_s":600}}"#;
    assert_eq!(first_ping_after(held).await, 60, "held to 60 s");
}

#[tokio::test(start_paused = true)]
async fn with_no_offer_or_a_faster_one_the_node_keeps_its_own_pace() {
    assert_eq!(first_ping_after(PLAIN).await, 10);
    let faster = r#"{"type":"hello","version":1,"liveness":{"frame":"ws-ping","every_s":5}}"#;
    assert_eq!(first_ping_after(faster).await, 10, "under 30 s is not taken");
}
