//! `listener`: a server child is taken only where it holds each listener of
//! its port itself. The children are python3 (no server of another party).
#![cfg(target_os = "linux")]

use std::io::BufRead;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use pod_testkit::listener::{TRIES, own_listener, start};

/// A child that ends with the test.
struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A python3 child that listens at `port` of 127.0.0.1 (`SO_REUSEPORT`
/// where `share`), writes its port and sleeps.
fn listen(port: u16, share: bool) -> Child {
    let code = "import socket, sys, time\ns = socket.socket()\n\
                if sys.argv[2] == '1': s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)\n\
                s.bind(('127.0.0.1', int(sys.argv[1])))\ns.listen()\nprint(s.getsockname()[1], flush=True)\n\
                time.sleep(60)";
    python(code, port, share)
}

fn python(code: &str, port: u16, share: bool) -> Child {
    Command::new("python3")
        .args(["-I", "-c", code, &port.to_string(), if share { "1" } else { "0" }])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("python3 starts")
}

/// The port that the child wrote.
fn port_of(child: &mut Child) -> u16 {
    let mut line = String::new();
    let out = child.stdout.take().expect("the child's stdout");
    std::io::BufReader::new(out).read_line(&mut line).expect("the child's port");
    line.trim().parse().expect("a port")
}

fn at(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

#[test]
fn the_harness_takes_only_its_own_child_s_listener_for_a_relay() {
    pod_testkit::need_loopback!();
    pod_testkit::need_tool!("python3");
    let other = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a port of the loopback");
    let taken = other.local_addr().expect("its address");
    let mut lost = Killed(listen(taken.port(), false));
    let why = own_listener(&mut lost.0, taken, Duration::from_secs(20));
    let why = why.expect_err("the harness took another process's listener for its child's");
    assert!(why.contains("ended"), "{why}");
    let mut late = Killed(python("import time\ntime.sleep(60)", taken.port(), false));
    let why = own_listener(&mut late.0, taken, Duration::from_secs(2));
    let why = why.expect_err("the harness took another process's listener for its child's");
    assert!(why.contains("did not listen"), "{why}");
    let mut own = Killed(listen(0, false));
    let port = port_of(&mut own.0);
    own_listener(&mut own.0, at(port), Duration::from_secs(20)).expect("the child's own listener");
    drop(other);
}

#[test]
fn a_port_that_another_process_shares_is_not_the_child_s() {
    pod_testkit::need_loopback!();
    pod_testkit::need_tool!("python3");
    let mut first = Killed(listen(0, true));
    let port = port_of(&mut first.0);
    own_listener(&mut first.0, at(port), Duration::from_secs(20)).expect("the first child's own listener");
    let mut second = Killed(listen(port, true));
    let _ = port_of(&mut second.0);
    for child in [&mut first.0, &mut second.0] {
        let why = own_listener(child, at(port), Duration::from_secs(20));
        let why = why.expect_err("the harness took a shared port for its child's");
        assert!(why.contains("another process listens"), "{why}");
    }
}

#[test]
fn a_start_takes_a_new_port_when_its_child_does_not_listen_on_its_own() {
    pod_testkit::need_loopback!();
    pod_testkit::need_tool!("python3");
    let other = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a port of the loopback");
    let taken = other.local_addr().expect("its address").port();
    let mut tries = Vec::new();
    // The first child binds the port of the test's listener, as a child
    // whose port another test took: it ends.
    let started = start(Duration::from_secs(20), |port| {
        tries.push(port);
        listen(if tries.len() == 1 { taken } else { port }, false)
    });
    let (child, port) = started.expect("the second try");
    let child = Killed(child);
    assert_eq!(tries.len(), 2, "{tries:?}");
    assert_eq!(port, tries[1]);
    drop(child);
    let mut count = 0;
    let why = start(Duration::from_secs(20), |_| {
        count += 1;
        listen(taken, false)
    });
    let why = why.expect_err("a child that never holds its port");
    assert!(why.contains("ended"), "{why}");
    assert_eq!(count, TRIES);
    drop(other);
}
