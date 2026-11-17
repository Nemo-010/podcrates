//! The QUIC legs: the registration on one connection, the reactor that
//! keeps a leg registered, and the set of the legs that run.

use super::*;
use crate::fail::Context;

/// The first registered leg.
pub(super) enum First {
    Quic(Vec<edge::EdgeAddr>, noq::Endpoint, noq::Connection, rpc::ControlSession, String),
    H2(Vec<edge::EdgeAddr>, crate::edge_h2::H2Leg),
}

pub(super) async fn connect_once(
    endpoint: &noq::Endpoint,
    auth: &rpc::TunnelAuth,
    tunnel_id: Uuid,
    conn_index: u8,
    replace_existing: bool,
    edges: &[edge::EdgeAddr],
    client_version: &str,
) -> Result<(noq::Connection, rpc::ControlSession, String)> {
    if edges.is_empty() {
        bail!(Stage::Connect, Class::Config, "no edge addresses to dial");
    }
    let edges = edge::for_connection(edges, conn_index);
    let candidates = edges.len().min(5);
    let conn =
        quic_dial::dial_any(endpoint, &edges[..candidates]).await.context("QUIC handshake with the Cloudflare edge")?;

    let mut options = rpc::ConnectionOptions::default_for_quick_tunnel(client_version);
    options.replace_existing = replace_existing;

    let (details, control) =
        tokio::time::timeout(REGISTER_TIMEOUT, rpc::register_connection(&conn, auth, tunnel_id, conn_index, &options))
            .await
            .map_err(|_| crate::fail::new(Stage::EdgeRegister, Class::Timeout, "register_connection timed out"))??;
    Ok((conn, control, details.location))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn reactor(
    runtime: Arc<Runtime>,
    ingress: Arc<Ingress>,
    auth: rpc::TunnelAuth,
    tunnel_id: Uuid,
    source: EndpointSource,
    mut conn: noq::Connection,
    mut control: rpc::ControlSession,
    metrics: Metrics,
    mut shutdown: watch::Receiver<bool>,
    policy: ReconnectPolicy,
    conn_index: u8,
    edges: Arc<Vec<edge::EdgeAddr>>,
) -> Option<String> {
    use crate::config::Next;
    let mut attempt = 0u32;
    let mut started = std::time::Instant::now();
    loop {
        if *shutdown.borrow() {
            control.shutdown_graceful(SHUTDOWN_GRACE).await;
            return None;
        }
        let lost = tokio::select! {
            biased;
            _ = shutdown.changed() => {
                control.shutdown_graceful(SHUTDOWN_GRACE).await;
                return None;
            }
            // T-402: a closed WARP session stops the timers of the QUIC
            // connection in it, so the loss is seen here, not by accept_bi.
            _ = source.closed() => {
                warn!(conn_index, "the WARP session of the edge leg closed; a reconnect follows");
                true
            }
            accepted = conn.accept_bi() => {
                match accepted {
                    Ok((send, recv)) => {
                        let runtime = runtime.clone();
                        let ingress = ingress.clone();
                        tokio::spawn(async move {
                            proxy::serve_stream(runtime, ingress, send, recv).await;
                        });
                        false
                    }
                    Err(err) => {
                        // The reason (who closed it, and why) and the path
                        // state help to find an edge limit (issue 92).
                        let stats = conn.stats();
                        warn!(
                            conn_index,
                            error = %err,
                            rtt_ms = conn.rtt(noq::PathId::ZERO).unwrap_or_default().as_millis() as u64,
                            received = stats.udp_rx.bytes,
                            sent = stats.udp_tx.bytes,
                            lost_packets = stats.lost_packets,
                            "edge closed the connection; a reconnect follows"
                        );
                        true
                    }
                }
            }
        };
        if !lost {
            continue;
        }

        drop(control);
        if started.elapsed() >= policy.stable {
            attempt = 0;
        }
        // The first attempt goes at once: the edge may only have moved the
        // connection.
        let mut delay = Duration::ZERO;
        loop {
            if !delay.is_zero() {
                let mut wait = shutdown.clone();
                tokio::select! {
                    biased;
                    _ = wait.changed() => return None,
                    _ = tokio::time::sleep(delay) => {}
                }
            }
            attempt += 1;
            let result = async {
                let endpoint = source.endpoint(attempt).await?;
                let version = &runtime.host().settings.client_version;
                connect_once(&endpoint, &auth, tunnel_id, conn_index, true, &edges, version).await
            }
            .await;
            match result {
                Ok((new_conn, new_control, location)) => {
                    info!(conn_index, attempt, %location, "reconnected");
                    metrics.reconnect();
                    metrics.connection_opened();
                    conn = new_conn;
                    control = new_control;
                    started = std::time::Instant::now();
                    break;
                }
                Err(err) => {
                    metrics.error();
                    match policy.next(attempt, &err) {
                        Next::Retry(wait) => {
                            warn!(conn_index, attempt, error = %format!("{err:#}"), retry_in = ?wait, "reconnect failed");
                            delay = wait;
                        }
                        Next::Stop(reason) => {
                            tracing::error!(conn_index, %reason, "the QUIC leg stops");
                            return Some(reason);
                        }
                    }
                }
            }
        }
    }
}

/// The legs that run. When the last one stops for a cause (not a
/// shutdown), [`TunnelHandle::stopped`] gives the cause.
#[derive(Clone)]
pub(super) struct Legs(Arc<LegsInner>);

pub(super) struct LegsInner {
    live: std::sync::atomic::AtomicUsize,
    last: std::sync::Mutex<Option<String>>,
    tx: watch::Sender<Option<String>>,
}

impl Legs {
    pub(super) fn new() -> (Self, watch::Receiver<Option<String>>) {
        let (tx, rx) = watch::channel(None);
        (Self(Arc::new(LegsInner { live: Default::default(), last: Default::default(), tx })), rx)
    }
}

/// Run one leg as a task. Its result is the reason that it stopped, or
/// `None` for a shutdown.
pub(super) fn spawn_leg(
    legs: &Legs,
    leg: impl std::future::Future<Output = Option<String>> + Send + 'static,
) -> JoinHandle<()> {
    use std::sync::atomic::Ordering;
    let legs = legs.clone();
    legs.0.live.fetch_add(1, Ordering::SeqCst);
    tokio::spawn(async move {
        let reason = leg.await;
        if let Some(reason) = reason {
            *legs.0.last.lock().unwrap() = Some(reason);
        }
        if legs.0.live.fetch_sub(1, Ordering::SeqCst) == 1
            && let Some(reason) = legs.0.last.lock().unwrap().clone()
        {
            let _ = legs.0.tx.send(Some(reason));
        }
    })
}
