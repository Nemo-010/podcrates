//! magic-wormhole's own transit relay (magic-wormhole-transit-relay, in
//! Python, on Twisted and Autobahn) on the loopback, for the tests of the
//! transit road: software that this project did not write. A host with no
//! Python, or without the package, skips each test with its reason, unless
//! `POD_WORMHOLE_TEST_SERVER=required`, which a planted run and the
//! workflow set, so that a skip there is a failure.
//!
//!   python3 -m pip install --require-hashes -r scripts/ci/wormhole-servers.txt
//!
//! `POD_WORMHOLE_TEST_PYTHON` names the interpreter (a virtualenv's), as
//! for the tests of `pod-wormhole` (scripts/ci/mailbox-tests.sh).
//!
//! A start takes a relay only when its own child listens on its port
//! ([`own_listener`]): two tests that run at a time can choose one port,
//! and a test that took the other test's relay for its own lost its link
//! when the other test stopped that relay.

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pod_ws::url::WsUrl;

/// How long the server may take to listen.
const START_LIMIT: Duration = Duration::from_secs(30);
/// How many times a start takes new ports after its relay did not listen
/// on the ones that it chose.
const TRIES: u32 = 5;

/// A transit relay of magic-wormhole's, listening on the loopback.
pub struct Relay {
    child: Child,
    /// Its WebSocket.
    pub url: WsUrl,
    /// Its log, for a test that fails to show.
    pub log: PathBuf,
}

/// Each name that the interpreter may have.
fn pythons() -> Vec<String> {
    match std::env::var("POD_WORMHOLE_TEST_PYTHON") {
        Ok(named) if !named.trim().is_empty() => vec![named],
        _ => vec!["python3".into(), "python".into()],
    }
}

/// Whether `python` imports the relay and what it runs on.
fn has_relay(python: &str) -> bool {
    let probe = Command::new(python)
        .args(["-c", "import wormhole_transit_relay, autobahn, twisted"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    probe.is_ok_and(|status| status.success())
}

/// A port of the loopback that nobody holds now.
fn free_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a port of the loopback");
    listener.local_addr().expect("its address").port()
}

impl Relay {
    /// The relay, listening; `None`, with the reason on stderr, when this
    /// host cannot run it and the run does not require it.
    pub fn start(tag: &str) -> Option<Relay> {
        let required = std::env::var("POD_WORMHOLE_TEST_SERVER").is_ok_and(|v| v == "required");
        let Some(python) = pythons().into_iter().find(|p| has_relay(p)) else {
            let why = "no Python with magic-wormhole-transit-relay here (pip install magic-wormhole-transit-relay)";
            assert!(!required, "POD_WORMHOLE_TEST_SERVER=required: {why}");
            eprintln!("did not run: {why}");
            return None;
        };
        let dir = std::env::temp_dir().join(format!("pod-transit-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        crate::cleanup::at_test_end(&dir);
        let log = dir.join("relay.log");
        let mut why = String::new();
        for _ in 0..TRIES {
            // Another relay of this binary can take a port between its
            // choice here and the bind of this one: then this relay ends,
            // and its port takes the other relay's connections.
            let (tcp, ws) = (free_port(), free_port());
            // `python -m twisted` is `twist`, which runs the plugin in the
            // foreground (the package's docs/running.md); its TCP port too,
            // on the loopback, as it always listens on one.
            let mut child = Command::new(&python)
                .args(["-m", "twisted", "transitrelay"])
                .arg(format!("--port=tcp:{tcp}:interface=127.0.0.1"))
                .arg(format!("--websocket=tcp:{ws}:interface=127.0.0.1"))
                .arg(format!("--websocket-url=ws://127.0.0.1:{ws}/"))
                .current_dir(&dir)
                .stdin(Stdio::null())
                .stdout(std::fs::File::create(&log).expect("the log"))
                .stderr(std::fs::File::create(dir.join("relay.err")).expect("the log of errors"))
                .spawn()
                .expect("the transit relay starts");
            match own_listener(&mut child, SocketAddr::from((Ipv4Addr::LOCALHOST, ws)), START_LIMIT) {
                Ok(()) => {
                    let url = WsUrl::parse(&format!("ws://127.0.0.1:{ws}/")).unwrap();
                    return Some(Relay { child, url, log });
                }
                Err(not) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    why = format!("{not}: {}", said(&log));
                    eprintln!("the transit relay did not take the ports {tcp} and {ws}: {why}");
                }
            }
        }
        panic!("the transit relay did not listen on ports of its own in {TRIES} tries: {why}");
    }

    /// What the relay wrote, for a message.
    pub fn said(&self) -> String {
        said(&self.log)
    }

    /// Stop the relay at once, as a server that goes away: each of its
    /// connections ends with no Close.
    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop();
    }
}

/// What the relay of `log` wrote.
fn said(log: &Path) -> String {
    let out = std::fs::read_to_string(log).unwrap_or_default();
    let err = std::fs::read_to_string(log.with_file_name("relay.err")).unwrap_or_default();
    format!("{out}{err}")
}

/// Wait until `child` itself listens at `at`; else why not: it ended, or it
/// did not listen within `limit`. A connection to `at` is no proof: the
/// listener can be another process's, as another test's relay on a port
/// that both chose.
pub fn own_listener(child: &mut Child, at: SocketAddr, limit: Duration) -> Result<(), String> {
    let deadline = Instant::now() + limit;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("it ended ({status}) before it listened at {at}"));
        }
        if holds_listener(child.id(), at) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("it did not listen at {at} within {} s", limit.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Whether the process `pid` holds a socket that listens at `at`: the
/// inode of a listener at `at` in `/proc/net/tcp` is among the process's
/// files.
#[cfg(target_os = "linux")]
fn holds_listener(pid: u32, at: SocketAddr) -> bool {
    let SocketAddr::V4(v4) = at else { return false };
    // The kernel writes the address as the u32 of its bytes in the host's
    // order, and the port in the host's order, both in hex.
    let local = format!("{:08X}:{:04X}", u32::from_ne_bytes(v4.ip().octets()), v4.port());
    let Ok(table) = std::fs::read_to_string("/proc/net/tcp") else { return false };
    // The columns: sl, local, remote, state (0A: listen), queues, timer,
    // retransmits, uid, timeout, inode.
    let sockets: Vec<String> = table
        .lines()
        .skip(1)
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|cols| cols.len() > 9 && cols[1] == local && cols[3] == "0A")
        .map(|cols| format!("socket:[{}]", cols[9]))
        .collect();
    let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { return false };
    fds.flatten()
        .any(|fd| std::fs::read_link(fd.path()).is_ok_and(|to| sockets.iter().any(|s| to.as_os_str() == s.as_str())))
}

/// No table of the sockets on this system: a listener at `at` while the
/// child lives.
#[cfg(not(target_os = "linux"))]
fn holds_listener(_pid: u32, at: SocketAddr) -> bool {
    std::net::TcpStream::connect_timeout(&at, Duration::from_millis(200)).is_ok()
}
