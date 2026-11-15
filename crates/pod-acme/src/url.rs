//! An `https://` URL, read: its host, its port, and its path with the query.
//! A directory of ACME and each URL that a CA gives are of this form.

/// An `https://` URL, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Url {
    pub fn parse(text: &str) -> Result<Url, String> {
        let rest = text.strip_prefix("https://").ok_or("not an https:// URL")?;
        let rest = rest.split('#').next().unwrap_or_default();
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        if authority.contains('@') {
            return Err("a URL with a user in it".into());
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !port.contains(']') => {
                (host, port.parse::<u16>().map_err(|_| format!("the port {port:?} is no port"))?)
            }
            _ => (authority, 443),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() || host.contains(|c: char| c.is_whitespace() || c.is_control()) {
            return Err("a URL with no host".into());
        }
        let path = if path.is_empty() {
            "/".to_string()
        } else if path.starts_with('?') {
            format!("/{path}")
        } else {
            path.to_string()
        };
        if path.contains(|c: char| c.is_whitespace() || c.is_control()) {
            return Err("a URL with a space in its path".into());
        }
        Ok(Url { host: host.to_string(), port, path })
    }

    /// The host and the path, without the query: what a message may say.
    pub fn shown(&self) -> String {
        let path = self.path.split('?').next().unwrap_or_default();
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        match self.port {
            443 => format!("https://{host}{path}"),
            port => format!("https://{host}:{port}{path}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_gives_its_host_port_and_path() {
        let url = Url::parse("https://github.com/PodUtils/podssh/releases.atom").unwrap();
        assert_eq!(
            (url.host.as_str(), url.port, url.path.as_str()),
            ("github.com", 443, "/PodUtils/podssh/releases.atom")
        );
        let url = Url::parse("https://127.0.0.1:8443?x=1#y").unwrap();
        assert_eq!((url.host.as_str(), url.port, url.path.as_str()), ("127.0.0.1", 8443, "/?x=1"));
        let url = Url::parse("https://[::1]:8443/a").unwrap();
        assert_eq!((url.host.as_str(), url.port), ("::1", 8443));
        assert_eq!(url.shown(), "https://[::1]:8443/a");
        for wrong in ["http://github.com/", "https://", "https://user@github.com/", "https://a:b/", "https://a/b c"] {
            assert!(Url::parse(wrong).is_err(), "{wrong}");
        }
    }

    /// A signed URL's query is a credential of the moment: no message holds
    /// it.
    #[test]
    fn what_a_message_shows_holds_no_query() {
        let url = Url::parse("https://release-assets.githubusercontent.com/a/b?sig=SECRET&exp=1").unwrap();
        assert_eq!(url.shown(), "https://release-assets.githubusercontent.com/a/b");
    }
}
