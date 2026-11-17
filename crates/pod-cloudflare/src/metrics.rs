//! The counters of a tunnel, and their Prometheus text. The counters of
//! the decisions of the consumer are not here: the consumer adds them.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone)]
pub struct Metrics {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    /// The start of the name of each metric: the name of the consumer.
    prefix: String,
    streams_total: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    active_streams: AtomicU64,
    reconnects: AtomicU64,
    connections: AtomicU64,
    errors: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub streams_total: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub active_streams: u64,
    pub reconnects: u64,
    pub connections: u64,
    pub errors: u64,
}

impl Metrics {
    /// Counters whose metrics start with `pod_cloudflare_`.
    pub fn new() -> Self {
        Self::with_prefix("pod-cloudflare")
    }

    /// Counters whose metrics start with `name` and `_`. A character that a
    /// Prometheus name does not take (the `-` of `pod-cloudflare`) becomes
    /// `_`.
    pub fn with_prefix(name: &str) -> Self {
        let prefix = name.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
        Self { inner: Arc::new(Inner { prefix, ..Inner::default() }) }
    }

    pub fn stream_started(&self) {
        self.inner.streams_total.fetch_add(1, Ordering::Relaxed);
        self.inner.active_streams.fetch_add(1, Ordering::Relaxed);
    }

    pub fn stream_finished(&self) {
        self.inner.active_streams.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add_in(&self, bytes: u64) {
        self.inner.bytes_in.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_out(&self, bytes: u64) {
        self.inner.bytes_out.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn reconnect(&self) {
        self.inner.reconnects.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_opened(&self) {
        self.inner.connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn error(&self) {
        self.inner.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            streams_total: self.inner.streams_total.load(Ordering::Relaxed),
            bytes_in: self.inner.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.inner.bytes_out.load(Ordering::Relaxed),
            active_streams: self.inner.active_streams.load(Ordering::Relaxed),
            reconnects: self.inner.reconnects.load(Ordering::Relaxed),
            connections: self.inner.connections.load(Ordering::Relaxed),
            errors: self.inner.errors.load(Ordering::Relaxed),
        }
    }

    /// The Prometheus text of the counters. Each name starts with the
    /// prefix of [`Metrics::with_prefix`].
    pub fn prometheus(&self) -> String {
        let m = self.snapshot();
        let rows: [(&str, &str, &str, u64); 7] = [
            ("streams_total", "counter", "Inbound streams handled.", m.streams_total),
            ("active_streams", "gauge", "Streams currently being proxied.", m.active_streams),
            ("bytes_in_total", "counter", "Bytes received from the edge.", m.bytes_in),
            ("bytes_out_total", "counter", "Bytes sent to the edge.", m.bytes_out),
            ("reconnects_total", "counter", "Edge reconnections.", m.reconnects),
            ("connections_total", "counter", "Edge connections registered.", m.connections),
            ("errors_total", "counter", "Stream or connection errors.", m.errors),
        ];
        let prefix = &self.inner.prefix;
        let mut out = String::new();
        for (name, kind, help, value) in rows {
            out.push_str(&format!(
                "# HELP {prefix}_{name} {help}\n# TYPE {prefix}_{name} {kind}\n{prefix}_{name} {value}\n"
            ));
        }
        out
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_and_renders() {
        let metrics = Metrics::with_prefix("podnet");
        metrics.stream_started();
        metrics.add_in(10);
        metrics.add_out(20);
        metrics.stream_finished();
        let snap = metrics.snapshot();
        assert_eq!(snap.streams_total, 1);
        assert_eq!(snap.active_streams, 0);
        assert_eq!(snap.bytes_in, 10);
        assert_eq!(snap.bytes_out, 20);
        let text = metrics.prometheus();
        assert!(text.contains("podnet_streams_total 1"));
        assert!(text.contains("podnet_bytes_out_total 20"));
    }
}
