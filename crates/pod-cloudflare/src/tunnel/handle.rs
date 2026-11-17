//! A running tunnel: its public URL, its leg, its counters, the check of
//! its URL and its shutdown.

use super::*;

/// A running tunnel.
pub struct TunnelHandle {
    /// The path of the `--forward` WebSocket endpoint (issue 203).
    pub(super) forward_path: Option<String>,
    pub(super) url: Option<String>,
    pub(super) tunnel_id: Uuid,
    pub(super) account_tag: String,
    pub(super) locations: Vec<String>,
    /// The edge leg that won the race: quic, http2, quic+warp or
    /// http2+relay (issue 95).
    pub(super) leg: String,
    pub(super) metrics: Metrics,
    pub(super) runtime: Arc<Runtime>,
    pub(super) shutdown: watch::Sender<bool>,
    pub(super) tasks: Vec<JoinHandle<()>>,
    pub(super) stopped: watch::Receiver<Option<String>>,
    pub(super) verify: bool,
    /// Kept alive for the tunnel's lifetime: dropping either tears down the
    /// WARP session and the QUIC endpoint the edge connection rides on.
    pub(super) _warp: Option<Arc<WarpLink>>,
}

impl TunnelHandle {
    /// Ready when each leg has stopped for a cause, for example a refusal of
    /// the edge with no retry. Gives the cause. It is not ready after a
    /// shutdown.
    pub async fn stopped(&self) -> String {
        let mut rx = self.stopped.clone();
        loop {
            if let Some(reason) = rx.borrow().clone() {
                return reason;
            }
            if rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }

    /// The wss:// endpoint of `--forward` for `podnet connect` (issue 203):
    /// with a public URL. A named tunnel gives the path only
    /// ([`TunnelHandle::forward_path`]).
    pub fn forward(&self) -> Option<String> {
        crate::ws::forward_url(self.url.as_deref()?, self.forward_path.as_deref()?)
    }

    /// The path of the `--forward` endpoint.
    pub fn forward_path(&self) -> Option<&str> {
        self.forward_path.as_deref()
    }

    /// Public URL for a quick tunnel; `None` for a named tunnel (the hostname
    /// is configured in the Cloudflare dashboard).
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    pub fn tunnel_id(&self) -> Uuid {
        self.tunnel_id
    }

    pub fn account_tag(&self) -> &str {
        &self.account_tag
    }

    pub fn locations(&self) -> &[String] {
        &self.locations
    }

    /// The edge leg that carries the tunnel: `quic`, `http2`, `quic+warp`
    /// or `http2+relay`.
    pub fn leg(&self) -> &str {
        &self.leg
    }

    pub fn metrics(&self) -> Metrics {
        self.metrics.clone()
    }

    /// Fetch the public URL and confirm the tunnel is reachable. For quick
    /// tunnels the expected token may be checked against the body.
    pub async fn verify(&self, expected: Option<&str>) -> Result<Option<Verified>> {
        let Some(url) = self.url.as_deref() else {
            return Ok(None);
        };
        self.verify_url(url, expected).await.map(Some)
    }

    /// Like [`verify`](Self::verify) but for a specific path on the public
    /// URL (a share session lives under `/s/<token>/`, not at the root).
    ///
    /// With no `expected` text, an answer of the origin that is not 2xx (for
    /// example 401 or 404 of an app behind a login) is a warning: the
    /// request crossed the tunnel. Only 530 (the edge has no connection of
    /// the tunnel) and transport errors are fatal after the last attempt.
    pub async fn verify_url(&self, url: &str, expected: Option<&str>) -> Result<Verified> {
        self.verify_accepting(url, expected, &[]).await
    }

    /// Like [`verify_url`](Self::verify_url). A status of `accepted` is the
    /// normal answer of the origin (issue 119: `serve` of a directory with
    /// no `index.html` answers 404 for `/`): it is logged at info, not as a
    /// warning.
    ///
    /// The retries go on for `VERIFY_BUDGET` (issue 119: a new name can
    /// need more than a minute in public DNS). A failure exits 69.
    pub async fn verify_accepting(&self, url: &str, expected: Option<&str>, accepted: &[u16]) -> Result<Verified> {
        let host = self.runtime.host();
        verify_fetch(host, url, expected, accepted, VERIFY_BUDGET, VERIFY_INTERVAL, host.settings.verify_strict).await
    }

    pub fn wants_verify(&self) -> bool {
        self.verify
    }

    /// Signal every reactor and wait for them to drain.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        let tasks = std::mem::take(&mut self.tasks);
        for task in tasks {
            let _ = tokio::time::timeout(SHUTDOWN_GRACE + Duration::from_secs(2), task).await;
        }
    }
}

impl Drop for TunnelHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}
