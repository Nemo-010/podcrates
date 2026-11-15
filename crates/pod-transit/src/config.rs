//! What the caller gives each connection to the transit relay: the relay,
//! the way out, the trust, the bounds and the sink of the lines for the
//! user. Nothing is read from the environment.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use pod_core::{Event, Events, NoEvents};
use pod_ws::url::WsUrl;
use pod_ws::{Trust, Way};

/// The settings of the connections of one end to one transit relay.
#[derive(Clone)]
pub struct Config {
    /// The relay: Least Authority's ([`crate::default_url`]), or the one
    /// that the user named.
    pub url: WsUrl,
    /// The way out of each connection: the dialer, the TLS context, the
    /// user agent.
    pub way: Way,
    /// The roots that a `wss://` relay is checked against.
    pub trust: Trust,
    /// The bound of each step of a dial: TCP, TLS, the upgrade
    /// ([`pod_core::backoff::CONNECT_TIMEOUT`]).
    pub connect_timeout: Duration,
    /// The bound of each read of a connection
    /// ([`pod_ws::DEFAULT_IDLE_TIMEOUT`]); `None` for no bound.
    pub idle: Option<Duration>,
    /// Where the lines for the user go. No line holds the token or a key.
    pub events: Arc<dyn Events>,
}

impl Config {
    /// The settings for the relay of `url` through `way`, with the roots of
    /// the default trust, the bounds above and no event sink.
    pub fn new(url: WsUrl, way: Way) -> Config {
        Config {
            url,
            way,
            trust: Trust::Default,
            connect_timeout: pod_core::backoff::CONNECT_TIMEOUT,
            idle: Some(pod_ws::DEFAULT_IDLE_TIMEOUT),
            events: Arc::new(NoEvents),
        }
    }

    /// The same, with `trust` for a `wss://` relay.
    pub fn with_trust(self, trust: Trust) -> Config {
        Config { trust, ..self }
    }

    /// The same, with the lines for the user sent to `events`.
    pub fn with_events(self, events: Arc<dyn Events>) -> Config {
        Config { events, ..self }
    }

    /// Send a line of the kind `kind` to the sink.
    pub(crate) fn info(&self, kind: &'static str, text: String) {
        self.events.event(Event::info(kind, text));
    }

    /// Send a warning of the kind `kind` to the sink.
    pub(crate) fn warn(&self, kind: &'static str, text: String) {
        self.events.event(Event::warn(kind, text));
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The URL as shown: its query may hold the service's own secret.
        f.debug_struct("Config")
            .field("url", &self.url.shown())
            .field("way", &self.way)
            .field("connect_timeout", &self.connect_timeout)
            .field("idle", &self.idle)
            .finish_non_exhaustive()
    }
}
