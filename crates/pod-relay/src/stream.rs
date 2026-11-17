//! A forward session as a byte stream (podnet's `Relay::connect`): a pipe in
//! memory whose far end a task bridges to the session (`pod_ws::bridge`),
//! each read of the stream to one binary message and each message to one
//! write. The end of the stream's writes sends a Close 1000; the relay's
//! Close, or the end of the session, ends the stream's reads.

use pod_core::BoxedIo;
use pod_ws::session::RelaySession;
use tokio::io::{AsyncRead, AsyncWrite};

/// The bytes that the pipe between the stream and the session holds.
pub const PIPE: usize = 256 * 1024;

/// The session as a byte stream. Inside a tokio runtime: a task of its own
/// carries the bytes until either end.
pub fn of<S>(session: RelaySession<S>) -> BoxedIo
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (ours, theirs) = tokio::io::duplex(PIPE);
    tokio::spawn(async move {
        if let Err(e) = pod_ws::bridge(session, theirs, &pod_ws::NoTally).await {
            tracing::debug!(error = %e, "the relay session of a stream ended");
        }
    });
    Box::new(ours)
}

/// [`of`], counting the session's bytes and busy time: at its end, its
/// rate goes into the rates of the cache for `relay` and its egress
/// (`crate::rates`, T-814). A session with too few bytes leaves no rate.
pub fn of_measured<S>(session: RelaySession<S>, ctx: &crate::Context, relay: &crate::relay::Relay) -> BoxedIo
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let ctx = ctx.clone();
    let name = crate::token::relay_name(relay);
    let egress = crate::rank_list::egress_for(&ctx, &relay.host);
    tokio::spawn(async move {
        let counted = crate::rates::Counted::default();
        if let Err(e) = pod_ws::bridge(session, theirs, &counted).await {
            tracing::debug!(error = %e, "the relay session of a stream ended");
        }
        let (bytes, secs) = counted.taken();
        if bytes >= crate::rates::MIN_BYTES {
            let mut kept = crate::rates::load(&ctx.cache);
            kept.add(&name, &egress, bytes, secs, crate::pool::now_ms());
            let _ = crate::rates::save(&ctx.cache, &kept);
        }
    });
    Box::new(ours)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pod_ws::frame::{self, Frame, Role};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    /// The relay's frames as a server writes them.
    async fn send(peer: &mut DuplexStream, opcode: u8, payload: &[u8]) {
        let bytes = frame::encode(&Frame { fin: true, opcode, payload: payload.to_vec() }, Role::Server, [0; 4]);
        peer.write_all(&bytes).await.unwrap();
    }

    /// The client's next frame.
    async fn next(peer: &mut DuplexStream, buf: &mut Vec<u8>) -> Frame {
        loop {
            if let Some((f, used)) = frame::decode(buf, Role::Client).expect("a client frame") {
                buf.drain(..used);
                return f;
            }
            let mut chunk = [0u8; 4096];
            let n = peer.read(&mut chunk).await.unwrap();
            assert!(n > 0, "the stream's session ended");
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Bytes go both ways; the end of the stream's writes is a Close 1000,
    /// and the relay's Close ends the stream's reads.
    #[tokio::test]
    async fn a_session_carries_a_byte_stream_both_ways() {
        let (client, mut relay) = tokio::io::duplex(1 << 16);
        let session = RelaySession::new(client, Vec::new(), None, Duration::from_secs(5));
        let mut io = of(session);
        let mut buf = Vec::new();
        io.write_all(b"ping").await.unwrap();
        let f = next(&mut relay, &mut buf).await;
        assert_eq!((f.opcode, f.payload.as_slice()), (frame::OPCODE_BINARY, &b"ping"[..]));
        send(&mut relay, frame::OPCODE_BINARY, b"pong").await;
        let mut got = [0u8; 4];
        io.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"pong");
        io.shutdown().await.unwrap();
        let f = next(&mut relay, &mut buf).await;
        assert_eq!(f.opcode, frame::OPCODE_CLOSE, "the end of the writes");
        assert_eq!(&f.payload[..2], &1000u16.to_be_bytes());
        send(&mut relay, frame::OPCODE_CLOSE, &1000u16.to_be_bytes()).await;
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), io.read_to_end(&mut rest)).await.expect("the end").unwrap();
        assert!(rest.is_empty());
    }

    /// A measured session that carried 2 MiB leaves its rate for its host
    /// in the cache; the bytes of the stream are the same (T-814).
    #[tokio::test]
    async fn a_measured_session_leaves_its_rate() {
        let dir = std::env::temp_dir().join(format!("pod-relay-measured-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ctx = crate::Context::new(crate::testing::way(), crate::cache::Cache::in_dirs(vec![dir.clone()]));
        let relay = crate::relay::Relay { host: "relay.test".into(), port: 443 };
        let (client, mut peer) = tokio::io::duplex(1 << 20);
        let session = RelaySession::new(client, Vec::new(), None, Duration::from_secs(5));
        let mut stream = of_measured(session, &ctx, &relay);
        let chunk = vec![9u8; 64 * 1024];
        let sender = tokio::spawn(async move {
            for _ in 0..32 {
                send(&mut peer, frame::OPCODE_BINARY, &chunk).await;
            }
            send(&mut peer, frame::OPCODE_CLOSE, &1000u16.to_be_bytes()).await;
            peer
        });
        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.unwrap();
        assert_eq!(got.len(), 2 << 20);
        let _peer = sender.await.unwrap();
        drop(stream);
        let mut kept = None;
        for _ in 0..100 {
            let rates = crate::rates::load(&ctx.cache);
            if let Some(each) = rates.hosts.get("relay.test") {
                kept = Some(each.clone());
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let kept = kept.expect("a rate for the host");
        assert_eq!(kept.len(), 1);
        assert!(kept[0].bytes >= 2 << 20 && kept[0].secs > 0.0, "{kept:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
