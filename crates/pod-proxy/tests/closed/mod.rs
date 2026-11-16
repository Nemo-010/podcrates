//! A port where nothing listens, held for the whole test: a socket bound to
//! it that does not listen. A connection to it is refused, and no other
//! test can take the port in the meantime, as it could after a listener
//! that was bound and dropped.

use std::net::SocketAddr;

/// The socket that holds the port, and the port's address. Keep the socket
/// until the test ends.
///
/// macOS drops a SYN to a port that a socket holds and does not listen on,
/// so a dial there times out and is not refused. There the port is 1: a
/// bind to port 0 never gives it, so no listener of a test can take it. A
/// freed port can go to a listener of another test, and a dial to it then
/// gets that listener's reset.
pub fn port() -> (Option<tokio::net::TcpSocket>, SocketAddr) {
    if cfg!(target_os = "macos") {
        return (None, "127.0.0.1:1".parse().expect("an address"));
    }
    let socket = tokio::net::TcpSocket::new_v4().expect("a socket");
    socket.bind("127.0.0.1:0".parse().expect("an address")).expect("bind");
    let addr = socket.local_addr().expect("its address");
    (Some(socket), addr)
}
