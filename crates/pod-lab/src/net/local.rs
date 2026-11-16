//! The servers of the command on the loopback of a network lab
//! (`Options::serve`). The stand-ins run in the network namespace of the
//! lab, so they dial `127.0.0.1:PORT` directly. After the rules of its
//! class, the stand-in proxy sends a `CONNECT` to a name of the lab at a
//! served port to that port (`relay`). The stand-in server of a class with
//! a list of names sends a ClientHello with a listed name to the first
//! served port (`proxy::server`).

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use super::{PROXY_PORT, TLS_PORT};

/// The time limit of a dial of a served port: a listener on the loopback
/// answers at once.
const DIAL: Duration = Duration::from_secs(5);

/// The served ports of a lab, and the roots that check a TLS server of the
/// command where the proxy of the class terminates TLS.
#[derive(Default)]
pub struct Local {
    /// The ports where the command listens on `127.0.0.1` of the lab.
    pub ports: Vec<u16>,
    /// The roots of `serve_ca`; `None`: no roots, so a served port whose
    /// TLS the proxy terminates gets 502.
    pub roots: Option<Arc<rustls::RootCertStore>>,
}

/// Each served port must be one that the command can listen on: not 0,
/// and not a port of the stand-ins.
pub fn check_ports(ports: &[u16]) -> Result<(), String> {
    for &p in ports {
        if p == 0 {
            return Err("the served port 0 is not a port of a listener".to_string());
        }
        if p == PROXY_PORT || p == TLS_PORT {
            return Err(format!("the served port {p} is a port of the stand-ins of the lab"));
        }
    }
    Ok(())
}

/// The roots of a PEM file of certificates: a file with no certificate is
/// an error.
pub fn roots(path: &Path) -> Result<Arc<rustls::RootCertStore>, String> {
    let certs = pod_tls::bundle::load_bundle(path)?;
    let mut store = rustls::RootCertStore::empty();
    for c in certs {
        store.add(c).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(Arc::new(store))
}

/// The check of a file of `serve_ca` before a run: it holds a certificate
/// or more, and each one is a root that rustls takes.
pub fn check_roots(path: &Path) -> Result<(), String> {
    roots(path).map(drop)
}

impl Local {
    /// The served ports and the roots of the PEM file `ca`.
    pub fn new(ports: Vec<u16>, ca: Option<&Path>) -> Result<Local, String> {
        check_ports(&ports)?;
        if ca.is_some() && ports.is_empty() {
            return Err("a CA of a served port with no served port".to_string());
        }
        let roots = ca.map(roots).transpose()?;
        Ok(Local { ports, roots })
    }

    /// True where the command serves `port`.
    pub fn serves(&self, port: u16) -> bool {
        self.ports.contains(&port)
    }
}

/// A TCP connect to `127.0.0.1:port` of the lab.
pub fn dial(port: u16) -> std::io::Result<TcpStream> {
    TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)), DIAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_served_port_is_no_port_of_the_stand_ins() {
        assert!(check_ports(&[8443, 9000]).is_ok());
        for bad in [0, PROXY_PORT, TLS_PORT] {
            assert!(check_ports(&[8443, bad]).is_err(), "{bad}");
        }
        assert!(Local::new(Vec::new(), None).is_ok());
        let why = Local::new(Vec::new(), Some(Path::new("/nonexistent/ca.pem"))).err().unwrap();
        assert!(why.contains("no served port"), "{why}");
        let why = Local::new(vec![8443], Some(Path::new("/nonexistent/ca.pem"))).err().unwrap();
        assert!(why.contains("/nonexistent/ca.pem"), "{why}");
    }

    #[test]
    fn the_roots_of_a_file_hold_its_certificates() {
        let dir = std::env::temp_dir().join(format!("pod-lab-local-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cas = crate::net::tls::Cas::new().unwrap();
        let (good, empty) = (dir.join("ca.pem"), dir.join("empty.pem"));
        std::fs::write(&good, cas.server.pem() + &cas.proxy.pem()).unwrap();
        std::fs::write(&empty, "no certificate\n").unwrap();
        assert_eq!(roots(&good).unwrap().len(), 2);
        assert!(roots(&empty).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
