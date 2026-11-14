//! The words of a 502 or a 504: what failed, and the upstream proxy that
//! the broker dialed through. A refusal of the upstream shows its status
//! only, by the RFC 9110 name: its reason phrase and its body stay out, and
//! no credential of a proxy URL is in the words.

use pod_core::{Failure, Stage};
use pod_proxy::DialError;

/// The words of the failure `f` of a dial through `via` (the label of the
/// upstream proxy, `None` with no proxy), or of a resolve.
pub(crate) fn of_failure(f: &Failure, via: Option<&str>) -> String {
    let dial = std::error::Error::source(f).and_then(|e| e.downcast_ref::<DialError>());
    let words = match dial {
        Some(DialError::ProxyRefused { proxy, target, status, .. }) => {
            let via = via.unwrap_or(proxy);
            let line = match phrase(*status) {
                Some(phrase) => format!("{status} {phrase}"),
                None => status.to_string(),
            };
            format!("the upstream proxy {via} answered \"{line}\" to CONNECT {target}")
        }
        // A failure at the proxy names the proxy already.
        Some(e) if e.stage_and_class().0 == Stage::Proxy => e.to_string(),
        _ => match via {
            Some(via) => format!("{} (through the upstream proxy {via})", f.chain()),
            None => f.chain(),
        },
    };
    without_userinfo(&words)
}

/// The RFC 9110 name of `status`, for the statuses that a proxy sends.
fn phrase(status: u16) -> Option<&'static str> {
    match status {
        401 => Some("Unauthorized"),
        500 => Some("Internal Server Error"),
        501 => Some("Not Implemented"),
        511 => Some("Network Authentication Required"),
        200..=299 => None,
        status => match pod_proxy::http::request::reason(status) {
            "Error" => None,
            phrase => Some(phrase),
        },
    }
}

/// `text` with no user information in a URL (`http://USER:PASS@host`
/// becomes `http://host`): a host's resolver or way out can name a URL with
/// its credentials.
pub(crate) fn without_userinfo(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let (head, tail) = rest.split_at(at + 3);
        out.push_str(head);
        let end = tail.find(|c: char| c.is_whitespace() || "/?#\"'<>".contains(c)).unwrap_or(tail.len());
        let authority = &tail[..end];
        out.push_str(authority.rsplit_once('@').map_or(authority, |(_, host)| host));
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use pod_core::Class;

    fn refused(status: u16, reason: &str) -> Failure {
        Failure::from(DialError::ProxyRefused {
            proxy: "proxy.example:3128".into(),
            target: "192.0.2.10:443".into(),
            status,
            reason: reason.into(),
        })
    }

    #[test]
    fn a_refusal_of_the_upstream_shows_its_status_and_the_proxy_and_no_body() {
        let f = refused(403, "Blocked: the body of the proxy, line one");
        assert_eq!(
            of_failure(&f, Some("http://proxy.example:3128")),
            "the upstream proxy http://proxy.example:3128 answered \"403 Forbidden\" to CONNECT 192.0.2.10:443"
        );
        assert_eq!(
            of_failure(&refused(511, "x"), None),
            "the upstream proxy proxy.example:3128 answered \"511 Network Authentication Required\" to CONNECT 192.0.2.10:443"
        );
        assert!(of_failure(&refused(599, "x"), None).contains("answered \"599\""));
    }

    #[test]
    fn another_failure_names_the_proxy_that_the_dial_went_through() {
        let unreachable = Failure::from(DialError::ProxyUnreachable {
            proxy: "proxy.example:3128".into(),
            detail: "Connection refused".into(),
        });
        assert_eq!(
            of_failure(&unreachable, Some("http://proxy.example:3128")),
            "could not reach the proxy proxy.example:3128: Connection refused"
        );
        let far = Failure::new(Stage::Connect, Class::Unavailable, "the far end reset the connection");
        assert_eq!(
            of_failure(&far, Some("socks5://proxy.example:1080")),
            "the far end reset the connection (through the upstream proxy socks5://proxy.example:1080)"
        );
        assert_eq!(of_failure(&far, None), "the far end reset the connection");
    }

    #[test]
    fn no_user_information_of_a_url_stays_in_the_words() {
        assert_eq!(
            without_userinfo("via http://user:made-up-pass@proxy.example:3128/x and socks5h://u@p:1 end"),
            "via http://proxy.example:3128/x and socks5h://p:1 end"
        );
        assert_eq!(without_userinfo("no url: a@b"), "no url: a@b");
        let f = Failure::new(Stage::Dns, Class::Unavailable, "https://u:made-up-pass@dns.example/dns-query failed");
        assert_eq!(of_failure(&f, None), "https://dns.example/dns-query failed");
    }
}
