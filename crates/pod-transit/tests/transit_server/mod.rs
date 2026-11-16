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
//! (`pod_testkit::listener`): two tests that run at a time can choose one
//! port, and a test that took the other test's relay for its own lost its
//! link when the other test stopped that relay.

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use pod_testkit::listener::{free_port, start};
use pod_ws::url::WsUrl;

/// How long the server may take to listen.
const START_LIMIT: Duration = Duration::from_secs(30);

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
        // The TCP port too can go to another relay of this binary: this
        // relay then ends, and the start takes new ports.
        let started = start(START_LIMIT, |ws| {
            let tcp = free_port();
            // `python -m twisted` is `twist`, which runs the plugin in the
            // foreground (the package's docs/running.md); its TCP port too,
            // on the loopback, as it always listens on one.
            Command::new(&python)
                .args(["-m", "twisted", "transitrelay"])
                .arg(format!("--port=tcp:{tcp}:interface=127.0.0.1"))
                .arg(format!("--websocket=tcp:{ws}:interface=127.0.0.1"))
                .arg(format!("--websocket-url=ws://127.0.0.1:{ws}/"))
                .current_dir(&dir)
                .stdin(Stdio::null())
                .stdout(std::fs::File::create(&log).expect("the log"))
                .stderr(std::fs::File::create(dir.join("relay.err")).expect("the log of errors"))
                .spawn()
                .expect("the transit relay starts")
        });
        let (child, ws) = started.unwrap_or_else(|why| panic!("the transit relay: {why}: {}", said(&log)));
        let url = WsUrl::parse(&format!("ws://127.0.0.1:{ws}/")).unwrap();
        Some(Relay { child, url, log })
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
