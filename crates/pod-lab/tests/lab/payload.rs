//! The payloads of the runs: this binary with `--payload KIND`, inside a
//! lab. Each one prints one line and exits 0 when the lab is what it must
//! be, else prints the fault and exits 1.

use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};

use pod_hostprobe::sys as k;

pub fn main(kind: &str) -> i32 {
    let out = match kind {
        "fds" => fds(),
        "net" => net(),
        "tmp" => tmp(),
        _ if kind.starts_with("connect:") => connect(&kind["connect:".len()..]),
        _ => crate::hosts_payload::main(kind),
    };
    match out {
        Ok(line) => {
            println!("{line}");
            0
        }
        Err(why) => {
            println!("payload {kind}: {why}");
            1
        }
    }
}

fn fds() -> Result<String, String> {
    for n in 3..=pod_lab::INHERITED_LAST {
        let flags = k::fcntl(i64::from(n), k::F_GETFD, 0).map_err(|e| format!("descriptor {n}: {}", e.name()))?;
        if flags as u64 & k::FD_CLOEXEC != 0 {
            return Err(format!("descriptor {n} is close-on-exec"));
        }
    }
    Ok(format!("fds 3-{} open", pod_lab::INHERITED_LAST))
}

/// TCP of each family gives EACCES for bind and connect; AF_UNIX works for
/// socket, bind and connect (PodUtils/podnet#585).
fn net() -> Result<String, String> {
    let refused = |what: &str, r: std::io::Result<()>| match r {
        Err(e) if e.kind() == ErrorKind::PermissionDenied => Ok(()),
        Err(e) => Err(format!("{what}: {e}; the lab wants EACCES")),
        Ok(()) => Err(format!("{what} succeeded; the lab wants EACCES")),
    };
    refused("bind(127.0.0.1:0)", TcpListener::bind("127.0.0.1:0").map(drop))?;
    // A host with no IPv6 refuses the socket itself (EAFNOSUPPORT).
    match TcpListener::bind("[::1]:0") {
        Err(e) if e.raw_os_error() == Some(97) => {}
        r => refused("bind([::1]:0)", r.map(drop))?,
    }
    refused("connect(127.0.0.1:1)", TcpStream::connect("127.0.0.1:1").map(drop))?;
    let dir = std::env::temp_dir().join(format!("pod-lab-unix-{}", std::process::id()));
    std::fs::create_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join("s");
    let unix = (|| {
        let listener = UnixListener::bind(&path).map_err(|e| format!("bind of AF_UNIX: {e}"))?;
        let mut client = UnixStream::connect(&path).map_err(|e| format!("connect of AF_UNIX: {e}"))?;
        let (mut server, _) = listener.accept().map_err(|e| format!("accept of AF_UNIX: {e}"))?;
        use std::io::{Read, Write};
        client.write_all(b"x").map_err(|e| format!("write of AF_UNIX: {e}"))?;
        let mut b = [0u8; 1];
        server.read_exact(&mut b).map_err(|e| format!("read of AF_UNIX: {e}"))?;
        Ok::<(), String>(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    unix?;
    Ok("inet refused, unix ok".to_string())
}

/// `bind-denied` with one port that a connect may reach (PodUtils/podssh#278):
/// a TCP connect to that port works, a connect to another port and each
/// TCP bind still give EACCES.
fn connect(port: &str) -> Result<String, String> {
    let refused = |what: &str, r: std::io::Result<()>| match r {
        Err(e) if e.kind() == ErrorKind::PermissionDenied => Ok(()),
        Err(e) => Err(format!("{what}: {e}; the lab wants EACCES")),
        Ok(()) => Err(format!("{what} succeeded; the lab wants EACCES")),
    };
    TcpStream::connect(format!("127.0.0.1:{port}")).map_err(|e| format!("connect(127.0.0.1:{port}): {e}"))?;
    refused("connect(127.0.0.1:1)", TcpStream::connect("127.0.0.1:1").map(drop))?;
    refused("bind(127.0.0.1:0)", TcpListener::bind("127.0.0.1:0").map(drop))?;
    Ok(format!("port {port} ok, others refused"))
}

fn tmp() -> Result<String, String> {
    let dir = std::env::var("TMPDIR").map_err(|_| "no TMPDIR".to_string())?;
    if dir != "/tmp" {
        return Err(format!("TMPDIR is {dir}"));
    }
    let s = k::statfs(&k::CBuf::new("/tmp").expect("no NUL")).map_err(|e| format!("statfs: {}", e.name()))?;
    let size = s.f_blocks * s.f_bsize as u64;
    if size > pod_lab::SMALL_TMP {
        return Err(format!("/tmp holds {size} bytes"));
    }
    let f = std::path::Path::new(&dir).join("payload");
    std::fs::write(&f, b"x").map_err(|e| format!("a write in TMPDIR: {e}"))?;
    Ok(format!("tmp ok, {size} bytes"))
}
