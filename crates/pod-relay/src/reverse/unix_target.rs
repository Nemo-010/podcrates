//! A target of a route on a Unix socket (T-836, PodUtils/podssh#295): the
//! host of a [`Route`] is `unix:PATH`, or on Linux
//! `unix:@NAME` for an abstract name, with port 0. The node's owner names
//! the target; an operator names only a route, and an exit dials its own
//! way, so no operator reaches a socket of the node.
//!
//! The connection goes on as a `TcpStream` of the same descriptor: a read,
//! a write, a shutdown and the move of a session to a new relay
//! (`pod_e2e`'s `move_out`, which takes a `TcpStream`) work on a Unix
//! stream socket as on a TCP one. Its address and the options of TCP are
//! not there.

use std::time::Duration;

use tokio::net::TcpStream;

use super::routes::Route;

/// The prefix of the host of a Unix target.
pub const UNIX: &str = "unix:";

impl Route {
    /// A route to the Unix socket `path` (`@NAME`: an abstract name, on
    /// Linux).
    pub fn unix(name: Option<String>, path: &str) -> Route {
        Route { name, host: format!("{UNIX}{path}"), port: 0 }
    }

    /// The path of a Unix target, if this route has one.
    pub fn unix_path(&self) -> Option<&str> {
        unix_path(&self.host)
    }
}

/// The path of the host `unix:PATH`, if it is one.
pub fn unix_path(host: &str) -> Option<&str> {
    host.strip_prefix(UNIX).filter(|p| !p.is_empty())
}

/// Connect to the Unix socket `path` within `timeout`.
#[cfg(unix)]
pub async fn connect(path: &str, timeout: Duration) -> Result<TcpStream, String> {
    let shown = format!("the Unix socket {path}");
    let path = path.to_string();
    let dial = tokio::task::spawn_blocking(move || connect_std(&path));
    let unix = match tokio::time::timeout(timeout, dial).await {
        Ok(Ok(Ok(unix))) => unix,
        Ok(Ok(Err(e))) => return Err(format!("{shown}: {e}")),
        Ok(Err(e)) => return Err(format!("{shown}: {e}")),
        Err(_) => return Err(format!("{shown}: no answer within {} s", timeout.as_secs_f64())),
    };
    let fd: std::os::fd::OwnedFd = unix.into();
    let tcp = std::net::TcpStream::from(fd);
    tcp.set_nonblocking(true).map_err(|e| format!("{shown}: {e}"))?;
    TcpStream::from_std(tcp).map_err(|e| format!("{shown}: {e}"))
}

#[cfg(unix)]
fn connect_std(path: &str) -> std::io::Result<std::os::unix::net::UnixStream> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(name) = path.strip_prefix('@') {
        #[cfg(target_os = "android")]
        use std::os::android::net::SocketAddrExt;
        #[cfg(target_os = "linux")]
        use std::os::linux::net::SocketAddrExt;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
        return std::os::unix::net::UnixStream::connect_addr(&addr);
    }
    std::os::unix::net::UnixStream::connect(path)
}

/// No Unix socket on this system.
#[cfg(not(unix))]
pub async fn connect(path: &str, _timeout: Duration) -> Result<TcpStream, String> {
    Err(format!("the Unix socket {path}: this system has no Unix socket for a route"))
}
