//! A route to a Unix socket (T-836, PodUtils/podssh#295), with no relay: a
//! route whose host is `unix:PATH`, or `unix:@NAME` on Linux, reaches the
//! socket both ways; a socket that is not there is refused with its path;
//! a roost's check of the SSH version line holds on it; and the stream goes
//! on as a `TcpStream` of the same descriptor, which a move takes.

#![cfg(all(feature = "pair", unix))]

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pod_e2e::Ask;
use pod_identity::{Identity, PublicKey};
use pod_relay::reverse::routes::{Grant, Route, Routes};
use pod_relay::reverse::unix_target::unix_path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

const LIMIT: Duration = Duration::from_secs(10);

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pod-relay-unix-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A service on `listener` that writes `first`, then echoes.
fn serve(listener: UnixListener, first: &'static [u8]) {
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = stream.write_all(first).await;
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
}

fn routes(fixed: Vec<Route>, sshd: bool) -> Routes {
    let grant: Arc<Grant> = Arc::new(|_: &PublicKey, _: &str| Ok(()));
    let dialer = support::dialer();
    Routes { routes: Arc::new(fixed), grant, timeout: LIMIT, sshd, exit: None, shared: None, dialer }
}

async fn open(routes: &Routes) -> Result<tokio::net::TcpStream, String> {
    let key = Identity::from_seed(&[1; 32]).public();
    routes.open(&key, &Ask::Route("sock".into())).await.map_err(|r| r.to_string())
}

/// The first bytes, then an echo of `ping`.
async fn exchange(mut stream: tokio::net::TcpStream, first: usize) -> Vec<u8> {
    let mut got = vec![0u8; first + 4];
    stream.write_all(b"ping").await.unwrap();
    tokio::time::timeout(LIMIT, stream.read_exact(&mut got)).await.expect("in time").expect("the bytes");
    got
}

#[tokio::test]
async fn a_route_reaches_a_unix_socket_by_its_path() {
    let dir = dir("path");
    let path = dir.join("s.sock");
    serve(UnixListener::bind(&path).unwrap(), b"hi:");
    let route = Route::unix(Some("sock".into()), path.to_str().unwrap());
    assert_eq!(route.unix_path(), path.to_str());
    let stream = open(&routes(vec![route], false)).await.expect("the socket");
    assert_eq!(exchange(stream, 3).await, b"hi:ping");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_route_reaches_an_abstract_name_on_linux() {
    use std::os::linux::net::SocketAddrExt;
    let name = format!("pod-relay-unix-{}", std::process::id());
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let std_listener = std::os::unix::net::UnixListener::bind_addr(&addr).unwrap();
    std_listener.set_nonblocking(true).unwrap();
    serve(UnixListener::from_std(std_listener).unwrap(), b"ab:");
    let route = Route::unix(Some("sock".into()), &format!("@{name}"));
    let stream = open(&routes(vec![route], false)).await.expect("the abstract socket");
    assert_eq!(exchange(stream, 3).await, b"ab:ping");
}

#[tokio::test]
async fn a_socket_that_is_not_there_is_refused_with_its_path() {
    let dir = dir("none");
    let path = dir.join("none.sock");
    let route = Route::unix(Some("sock".into()), path.to_str().unwrap());
    let words = open(&routes(vec![route], false)).await.expect_err("no socket");
    assert!(words.contains(&format!("the Unix socket {}", path.display())), "{words}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_roost_checks_the_version_line_of_a_unix_socket() {
    let dir = dir("sshd");
    let (good, bad) = (dir.join("good.sock"), dir.join("bad.sock"));
    serve(UnixListener::bind(&good).unwrap(), b"SSH-2.0-test\r\n");
    // Writes a line that is not a version line, then closes.
    let listener = UnixListener::bind(&bad).unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream.write_all(b"hello\r\n").await;
        }
    });
    let good = Route::unix(Some("sock".into()), good.to_str().unwrap());
    assert!(open(&routes(vec![good], true)).await.is_ok(), "a version line first");
    let bad = Route::unix(Some("sock".into()), bad.to_str().unwrap());
    let words = open(&routes(vec![bad], true)).await.expect_err("no version line");
    assert!(words.contains("the Unix socket") && words.contains("is not an SSH server"), "{words}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A move takes the stream as a std `TcpStream`: the descriptor still
/// carries the socket.
#[tokio::test]
async fn the_stream_moves_as_a_std_tcp_stream_of_the_same_descriptor() {
    let dir = dir("move");
    let path = dir.join("s.sock");
    serve(UnixListener::bind(&path).unwrap(), b"mv:");
    let route = Route::unix(Some("sock".into()), path.to_str().unwrap());
    let stream = open(&routes(vec![route], false)).await.expect("the socket");
    let moved = stream.into_std().expect("a std stream");
    let back = tokio::net::TcpStream::from_std(moved).expect("taken again");
    assert_eq!(exchange(back, 3).await, b"mv:ping");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn only_a_host_with_a_path_after_the_prefix_is_a_unix_target() {
    assert_eq!(unix_path("unix:/run/a.sock"), Some("/run/a.sock"));
    assert_eq!(unix_path("unix:@name"), Some("@name"));
    assert_eq!(unix_path("unix:"), None);
    assert_eq!(unix_path("127.0.0.1"), None);
    assert_eq!(unix_path("unixhost"), None);
}
