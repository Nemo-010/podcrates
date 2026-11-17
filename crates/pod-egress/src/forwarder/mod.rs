//! A WebSocket forwarder that takes its target from the client: the
//! plumbing of another product, such as the Worker of Mudlet's web client or
//! the proxy of ssheasy's SSH client in a browser, which dials the host and
//! the port that a client names and carries the bytes in binary frames.
//! The target goes in the URL, by a [`Template`] with `{host}` and
//! `{port}`, or in a first text frame of JSON, which the forwarder answers
//! before the target's bytes. The dial is that of a WebSocket by its URL
//! (`pod_ws::url::dial`): TLS checked for the forwarder's name, through the
//! caller's way out, and no token: a relay token goes only to the
//! deployment that minted it, and a forwarder is another product's. The
//! headers of the caller for the forwarder's host go on the upgrade, as
//! `pod_ws::url::dial` writes them (`pod_ws::Headers`). A
//! template `wisp+wss://HOST/PATH/` names a server of the Wisp protocol,
//! which takes the target in a packet of its own ([`crate::wisp`]).
//!
//! [`Forwarder`] is a [`pod_core::Dial`]: a dial of a target is a session
//! through the forwarder.

// The public forwarders of other products that the binary names.
pub mod builtin;
mod template;

use std::time::Duration;

use pod_core::{BoxFuture, Class, Connected, Failure, Stage, Target};
use pod_tls::Trust;
use pod_ws::{ConnectError, Way};
use tokio::time::Instant;

use crate::carry::{self, First};

pub use crate::Note;
pub use crate::carry::{Carried, EARLY_WAIT, Ended, Form, Status, answer};
pub use crate::end::AtEnd;
pub use template::{HOST, PORT, Template, WISP};

/// The largest frame taken from a forwarder, which publishes no size: a
/// Worker sends what each read of its socket gave.
pub const RECEIVE_CAP: usize = 1024 * 1024;

/// What a forwarder's road needs, beside its template and its target.
#[derive(Clone)]
pub struct Dial {
    /// The way out: the dialer, the TLS context, the user agent.
    pub way: Way,
    /// The trust of the forwarder's certificate.
    pub trust: Trust,
    /// Bound on the dial, on the upgrade, and on the answer of the frame
    /// form.
    pub timeout: Duration,
    /// What the end of this side's bytes does: a Close at once (an SSH
    /// session's end), or after the forwarder's end, as the target may still
    /// answer (a pipe).
    pub at_end: AtEnd,
    /// Where the forwarder's own words go.
    pub note: Note,
}

impl std::fmt::Debug for Dial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dial").field("way", &self.way).field("timeout", &self.timeout).finish_non_exhaustive()
    }
}

/// Why a forwarder carried no session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwarderError {
    /// The target cannot go in the template; no other forwarder takes it.
    Target(String),
    /// The dial or the upgrade, as `pod_ws::url::dial` gives it.
    Connect(ConnectError),
    /// The forwarder's answer to the target, or none.
    Answer(String),
    /// The forwarder's Close before the target's first bytes: it could not
    /// reach the target, as a Worker says.
    Closed { code: Option<u16>, reason: String },
}

impl ForwarderError {
    /// The line that says it, the forwarder named as `shown`.
    pub fn line(&self, shown: &str) -> String {
        match self {
            ForwarderError::Target(why) | ForwarderError::Answer(why) => format!("the forwarder {shown}: {why}"),
            ForwarderError::Connect(ConnectError::Refused { status, body }) if body.is_empty() => {
                format!("the forwarder {shown} refused the upgrade: HTTP {status}")
            }
            ForwarderError::Connect(ConnectError::Refused { status, body }) => {
                format!("the forwarder {shown} refused the upgrade: HTTP {status}: {body}")
            }
            ForwarderError::Connect(ConnectError::Tls(why)) => format!("TLS with the forwarder {shown} failed: {why}"),
            ForwarderError::Connect(ConnectError::Upgrade(why)) => {
                format!("the WebSocket upgrade with the forwarder {shown} failed: {why}")
            }
            ForwarderError::Connect(other) => format!("the forwarder {shown}: {other}"),
            ForwarderError::Closed { code, reason } => {
                let code = code.map_or_else(|| "no code".to_string(), |c| c.to_string());
                let reason = pod_core::text::one_line(reason);
                let said = if reason.is_empty() { String::new() } else { format!(" {reason}") };
                format!("the forwarder {shown} closed the WebSocket before the target's bytes: {code}{said}")
            }
        }
    }
}

/// A session to `host:port` through the forwarder of `template`: the dial
/// and the upgrade with no token, the first frame of the frame form and its
/// answer, and the forwarder's first word in the query form, within
/// [`EARLY_WAIT`]. A Wisp server's template takes the road of
/// [`crate::wisp`].
pub async fn open(template: &Template, host: &str, port: u16, dial: &Dial) -> Result<Carried, ForwarderError> {
    if template.form() == Form::Wisp {
        return crate::wisp::forward::open(template, host, port, dial).await;
    }
    let url = template.fill(host, port).map_err(ForwarderError::Target)?;
    let idle = Some(pod_ws::DEFAULT_IDLE_TIMEOUT);
    let session = pod_ws::url::dial(&url, &dial.way, &dial.trust, dial.timeout, idle)
        .await
        .map_err(ForwarderError::Connect)?
        .naming("the forwarder");
    session.set_receive_cap(RECEIVE_CAP);
    if let Some(first) = template.first_frame(host, port) {
        session
            .send_text(&first)
            .await
            .map_err(|e| ForwarderError::Answer(format!("sending the target failed: {e}")))?;
    }
    let form = template.form();
    let (carried, first) = carry::spawn(session, form, dial.at_end, dial.note.clone(), "the forwarder");
    let wait = if form == Form::Query { EARLY_WAIT } else { dial.timeout };
    let word = match tokio::time::timeout(wait, first).await {
        Ok(Ok(word)) => word,
        Ok(Err(_)) => First::Failed("the session ended before the forwarder said a word".into()),
        Err(_) if form == Form::Query => First::Ready,
        Err(_) => First::Failed(format!("no answer to the target within {} s", wait.as_secs())),
    };
    match word {
        First::Ready => Ok(carried),
        First::Closed { code, reason } => {
            carried.abort();
            Err(ForwarderError::Closed { code, reason })
        }
        First::Failed(why) => {
            carried.abort();
            Err(ForwarderError::Answer(why))
        }
    }
}

impl ForwarderError {
    /// The stage and the class of the failure.
    pub fn stage_and_class(&self) -> (Stage, Class) {
        match self {
            ForwarderError::Target(_) => (Stage::Connect, Class::Usage),
            ForwarderError::Connect(e) => e.stage_and_class(),
            ForwarderError::Answer(_) => (Stage::WebSocket, Class::Protocol),
            ForwarderError::Closed { .. } => (Stage::Origin, Class::Unavailable),
        }
    }
}

impl std::fmt::Display for ForwarderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwarderError::Target(why) | ForwarderError::Answer(why) => f.write_str(why),
            ForwarderError::Connect(e) => write!(f, "{e}"),
            ForwarderError::Closed { .. } => {
                let line = self.line("");
                f.write_str(line.trim_start_matches("the forwarder  "))
            }
        }
    }
}

impl std::error::Error for ForwarderError {}

impl From<ForwarderError> for Failure {
    fn from(e: ForwarderError) -> Failure {
        let (stage, class) = e.stage_and_class();
        Failure::caused(stage, class, e.to_string(), e)
    }
}

/// A forwarder as a dialer: each dial is a session to its target through
/// the forwarder of the template.
#[derive(Debug, Clone)]
pub struct Forwarder {
    pub template: Template,
    pub dial: Dial,
}

impl pod_core::Dial for Forwarder {
    fn label(&self) -> String {
        format!("forwarder {}", self.template.shown())
    }

    fn proxy_label(&self, _target: &Target) -> Option<String> {
        Some(self.template.shown().to_string())
    }

    /// A session to `target`, the whole of its opening before `deadline`.
    fn dial<'a>(&'a self, target: &'a Target, deadline: Instant) -> BoxFuture<'a, Result<Connected, Failure>> {
        Box::pin(async move {
            let left = crate::road::left(deadline, target)?;
            let dial = Dial { timeout: self.dial.timeout.min(left), ..self.dial.clone() };
            let host = target.host();
            let opening = open(&self.template, &host, target.port(), &dial);
            let carried = tokio::time::timeout_at(deadline, opening)
                .await
                .map_err(|_| crate::road::late(target, self.template.shown()))?
                .map_err(|e| {
                    let (stage, class) = e.stage_and_class();
                    Failure::caused(stage, class, e.line(self.template.shown()), e)
                })?;
            Ok(Connected::new(Box::new(carried.stream)))
        })
    }

    fn names_inside(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_names_the_forwarder_and_its_close() {
        let shown = "wss://web-proxy.mudlet.org/";
        let closed =
            ForwarderError::Closed { code: Some(1011), reason: "Connections to port 25 are prohibited".into() };
        assert_eq!(
            closed.line(shown),
            "the forwarder wss://web-proxy.mudlet.org/ closed the WebSocket before the target's bytes: 1011 \
             Connections to port 25 are prohibited"
        );
        let refused = ForwarderError::Connect(ConnectError::Refused { status: 429, body: String::new() });
        assert_eq!(refused.line(shown), "the forwarder wss://web-proxy.mudlet.org/ refused the upgrade: HTTP 429");
        let tls = ForwarderError::Connect(ConnectError::Tls("unknown issuer".into()));
        assert!(tls.line(shown).starts_with("TLS with the forwarder wss://web-proxy.mudlet.org/ failed"));
    }
}
