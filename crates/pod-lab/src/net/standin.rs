//! The stand-in process of a network lab. The lab makes the two CAs and
//! writes the certificate file of the command, then forks twice: the
//! grandchild serves the listening sockets of [`super::Ready`], one thread
//! for each connection, and is no child of the command, so a command that
//! waits for each of its children does not wait for it. It holds a pidfd
//! of the lab process, which is the command after the exec: when the
//! command ends, the stand-in removes the certificate file and exits.

use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;

use pod_hostprobe::sys as k;

use super::tls::Cas;
use super::{Ca, Net, Ready};
use crate::hold::words;

/// A network lab that runs: what the check from inside and the command
/// need.
pub struct Started {
    pub net: &'static Net,
    /// The certificates of the two CAs.
    pub cas: Arc<Cas>,
    /// The certificate file of the command (`SSL_CERT_FILE`).
    pub cert_file: PathBuf,
}

/// The certificate file: the CA of the server, and the CA of the proxy
/// where the proxy terminates TLS. A new file of the temporary directory;
/// the stand-in removes it.
fn write_cert_file(cas: &Cas, net: &Net) -> Result<PathBuf, String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut text = cas.of(Ca::Server).pem();
    if net.proxy_ca() {
        text.push_str(&cas.of(Ca::Proxy).pem());
    }
    let path = std::env::temp_dir().join(format!("podlab-ca-{}.pem", k::getpid()));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&path)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

/// Close each descriptor from 3 up but `keep`.
fn close_but(keep: &[i64]) {
    let open: Vec<i64> = match std::fs::read_dir("/proc/self/fd") {
        Ok(dir) => dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).collect(),
        Err(_) => (3..1024).collect(),
    };
    for fd in open.into_iter().filter(|fd| *fd >= 3 && !keep.contains(fd)) {
        let _ = k::close(fd);
    }
}

/// The work of the stand-in process. It does not return.
fn serve(ready: Ready, net: &'static Net, cas: Arc<Cas>, lab: i64, cert_file: PathBuf) -> ! {
    let mut keep: Vec<i64> = ready.servers.iter().map(|l| i64::from(l.as_raw_fd())).collect();
    keep.extend(ready.proxy.iter().map(|l| i64::from(l.as_raw_fd())));
    keep.push(lab);
    close_but(&keep);
    // The standard streams of the caller stay open while a stand-in holds
    // them: a reader of the output of the command would wait for it.
    if let Ok(null) =
        crate::hold::c("/dev/null").and_then(|p| k::open(&p, k::O_RDWR, 0).map_err(|e| e.name().to_string()))
    {
        for n in 0..3 {
            let _ = k::dup2(null, n);
        }
        let _ = k::close(null);
    }
    // The stand-in keeps no capability of the user namespace.
    let _ = crate::hold::drop_caps();
    let accept = |l: TcpListener, is_proxy: bool, cas: Arc<Cas>| {
        let _ = std::thread::Builder::new().spawn(move || {
            for tcp in l.incoming().flatten() {
                super::proxy::spawn(&cas, net, tcp, is_proxy);
            }
        });
    };
    for l in ready.servers {
        accept(l, false, Arc::clone(&cas));
    }
    if let Some(l) = ready.proxy {
        accept(l, true, Arc::clone(&cas));
    }
    let mut fds = [k::PollFd { fd: lab as i32, events: k::POLLIN, revents: 0 }];
    loop {
        match k::ppoll(&mut fds, -1) {
            Ok(n) if n > 0 => break,
            Err(e) if e == k::EINTR => continue,
            _ => break,
        }
    }
    let _ = std::fs::remove_file(&cert_file);
    k::exit_group(0)
}

/// Make the CAs and the certificate file, and start the stand-in process
/// on the sockets of `ready`. The lab process has one thread, so the
/// children of the fork may allocate.
pub fn start(ready: Ready, net: &'static Net) -> Result<Started, String> {
    let cas = Arc::new(Cas::new()?);
    let cert_file = write_cert_file(&cas, net)?;
    let fail = |why: String| {
        let _ = std::fs::remove_file(&cert_file);
        Err(why)
    };
    // The pidfd of the lab, which the stand-in inherits: the lab is the
    // command after the exec.
    let lab = match k::pidfd_open(k::getpid()) {
        Ok(fd) => fd,
        Err(e) => return fail(words("pidfd_open", e)),
    };
    // SAFETY: the lab process has one thread; each child allocates only
    // its own memory.
    let first = unsafe { k::clone_fork(k::SIGCHLD) };
    match first {
        Err(e) => {
            let _ = k::close(lab);
            fail(words("fork of the stand-in", e))
        }
        Ok(0) => {
            // SAFETY: as above.
            match unsafe { k::clone_fork(k::SIGCHLD) } {
                Ok(0) => serve(ready, net, Arc::clone(&cas), lab, cert_file.clone()),
                Ok(_) => k::exit_group(0),
                Err(_) => k::exit_group(1),
            }
        }
        Ok(pid) => {
            let _ = k::close(lab);
            let mut status = 0;
            let _ = k::wait4(pid, &mut status);
            drop(ready);
            if status != 0 {
                return fail(format!("the stand-in did not start: status {status}"));
            }
            Ok(Started { net, cas, cert_file })
        }
    }
}
