//! A node whose relay holds its lost socket (PodUtils/podnet#604): after a
//! loss, a relay that answers `409` for longer than `Settings::lost_hold`
//! ends the node with `Exit::LostSocketHeld` and one line, long before
//! `Settings::rejoin`. Plain `ws://` against the stand-in relay, as
//! `blocking_plain.rs`.
#![cfg(all(feature = "blocking", feature = "plain-ws"))]

// The test takes a part of the stand-in.
#[allow(dead_code)]
mod stand_in;

mod support;

use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use pod_relay::blocking::{Client, Config, Local, NodeChannel, NodeOptions, Stopper};
use pod_relay::reverse::{Exit, Settings, Wire, held_line};
use stand_in::{LIMIT, NAME, StandIn, pipe, test_pair};

fn client() -> Client {
    Client::new(Config { wire: Wire::PlainLoopback, timeout: LIMIT, ..Config::new(support::context()) })
        .expect("a client")
}

fn echo(_: &str) -> Result<Local, String> {
    let (reader, writer) = pipe();
    Ok(Local::new(reader, writer))
}

fn in_time_within<T: Send + 'static>(limit: Duration, work: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(work());
    });
    rx.recv_timeout(limit).expect("an end within the limit")
}

/// A socket that ends with no Close, then `409` for each connect: the node
/// ends at its hold of 2 s (the resume deadline stays 10 minutes), with
/// the line of a held socket.
#[test]
fn a_held_lost_socket_ends_the_node_at_its_hold() {
    let (stand_in, relay) = StandIn::new();
    let (lost_tx, lost_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (_, peer) = stand_in.accept();
        drop(peer);
        let _ = lost_tx.send(Instant::now());
        loop {
            stand_in.refuse(409, "reverse: a node is connected under this name");
        }
    });
    let lines = Arc::new(Mutex::new(Vec::new()));
    let kept = lines.clone();
    let options = NodeOptions {
        settings: Settings { lost_hold: Duration::from_secs(2), ..Settings::default() },
        channel: NodeChannel::Off,
        say: Some(Arc::new(move |line: String| kept.lock().unwrap().push(line))),
        ..NodeOptions::default()
    };
    let exit = in_time_within(Duration::from_secs(30), move || {
        client().run_node(&mut test_pair(&relay, NAME, 0), echo, &options, &Stopper::new())
    });
    assert!(matches!(exit, Ok(Exit::LostSocketHeld)), "{exit:?}");
    let since = lost_rx.recv().unwrap().elapsed();
    assert!(since >= Duration::from_secs(2), "the node tried again for its 2 s: {since:?}");
    let lines = lines.lock().unwrap();
    let last = lines.last().cloned().unwrap_or_default();
    assert!(last.starts_with("the relay still holds the node's lost socket after "), "{lines:?}");
    assert!(last.ends_with("the node stops on this route (take a new pair, or another relay)"), "{lines:?}");
    assert_eq!(lines.iter().filter(|l| l.contains("after") && l.contains("s of 409")).count(), 1, "{lines:?}");
}

/// The line names the time of the `409` in whole seconds.
#[test]
fn the_line_of_a_held_socket_names_its_time() {
    assert_eq!(
        held_line(Duration::from_millis(61_900)),
        "the relay still holds the node's lost socket after 61 s of 409: an operator's connection reaches that \
         socket and stops; the node stops on this route (take a new pair, or another relay)"
    );
}
