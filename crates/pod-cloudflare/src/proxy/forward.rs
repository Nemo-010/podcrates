//! The forward of a request to an origin: HTTP/1.1 with its body and its
//! answer, an upgrade as a byte pump, and raw TCP.

use crate::fail::{IoFail, Result};
use pod_core::BoxedIo;
use pod_core::Stage;

use super::copy::*;
use super::head::*;
use super::{EdgeReader, EdgeWriter, cqstream};
use crate::ingress::{OriginOptions, Service};
use crate::metrics::Metrics;
use crate::origin::Origins;

// ── HTTP forwarding ─────────────────────────────────────────────────────────

pub async fn forward_http(
    origins: &Origins,
    service: &Service,
    options: &OriginOptions,
    request: &cqstream::ConnectRequest,
    mut reader: EdgeReader,
    mut writer: EdgeWriter,
    metrics: &Metrics,
) -> Result<()> {
    // The QUIC leg marks a WebSocket by the connection type and may keep no
    // Upgrade header (issue 56): is_websocket checks both.
    let upgrade = is_websocket(request);
    let head = match build_request_head(request, options, upgrade) {
        Ok(head) => head,
        Err(err) => {
            write_simple_response(
                &mut writer,
                400,
                "text/plain; charset=utf-8",
                b"the request is not valid HTTP/1.1\n",
            )
            .await?;
            return Err(err);
        }
    };
    let mut io = origins.dial(service, options).await?;
    tokio::io::AsyncWriteExt::write_all(&mut io, head.as_bytes())
        .await
        .io_fail(Stage::Origin, "writing the request head")?;

    if upgrade || is_chunked(request) {
        return proxy_bidi(&mut reader, &mut writer, io, metrics).await;
    }

    if let Some(len) = content_length(request)
        && len > 0
    {
        copy_futures_to_tokio_n(&mut reader, &mut io, len, metrics).await?;
    }

    let (status, headers, leftover) = read_response_head(&mut io).await?;
    let resp_len = response_length(&headers)?;
    write_response_meta(&mut writer, status, &headers).await?;
    // A chunked body: the edge frames the body itself, so send only the
    // payload of the chunks. The last chunk ends the body, also when the
    // origin keeps the connection open.
    let chunked =
        headers_value(&headers, "transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        let mut source = tokio::io::BufReader::new(tokio::io::AsyncReadExt::chain(&leftover[..], &mut io));
        copy_chunked_to_futures(&mut source, &mut writer, metrics).await?;
        return futures_close(&mut writer).await;
    }
    if !leftover.is_empty() {
        futures_write_all(&mut writer, &leftover).await?;
        futures::io::AsyncWriteExt::flush(&mut writer).await.io_fail(Stage::EdgeStream, "writing to the edge")?;
        metrics.add_out(leftover.len() as u64);
    }
    match resp_len {
        Some(total) => {
            let remaining = total.saturating_sub(leftover.len() as u64);
            if remaining > 0 {
                copy_tokio_to_futures_n(&mut io, &mut writer, remaining, metrics).await?;
            }
        }
        None => {
            copy_tokio_to_futures_eof(&mut io, &mut writer, metrics).await?;
        }
    }
    futures_close(&mut writer).await
}

async fn proxy_bidi(reader: &mut EdgeReader, writer: &mut EdgeWriter, io: BoxedIo, metrics: &Metrics) -> Result<()> {
    let (mut io_r, mut io_w) = tokio::io::split(io);
    let in_metrics = metrics.clone();
    let out_metrics = metrics.clone();

    let request_pump = async {
        let _ = copy_futures_to_tokio_eof(reader, &mut io_w, &in_metrics).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut io_w).await;
    };
    let response_pump = async {
        let (status, headers, leftover) = read_response_head(&mut io_r).await?;
        write_response_meta(writer, status, &headers).await?;
        if !leftover.is_empty() {
            futures_write_all(writer, &leftover).await?;
            out_metrics.add_out(leftover.len() as u64);
        }
        copy_tokio_to_futures_eof(&mut io_r, writer, &out_metrics).await?;
        futures_close(writer).await?;
        Ok::<(), crate::fail::Failure>(())
    };
    let (_, response) = tokio::join!(request_pump, response_pump);
    response
}

pub async fn forward_tcp(
    origins: &Origins,
    service: &Service,
    options: &OriginOptions,
    request: &cqstream::ConnectRequest,
    mut reader: EdgeReader,
    mut writer: EdgeWriter,
    metrics: &Metrics,
) -> Result<()> {
    // A quick tunnel gets HTTP requests. A raw byte pipe gives the edge no
    // HTTP status, and the edge answers 502: the tunnel answers 501.
    if request.conn_type == cqstream::ConnectionType::Http && !is_websocket(request) {
        origins.note_http_to_tcp(service);
        let body = tcp_http_body(origins.words());
        return write_simple_response(&mut writer, 501, "text/plain; charset=utf-8", body.as_bytes()).await;
    }
    let io = origins.dial(service, options).await?;
    cqstream::write_connect_response(&mut writer, "", &[]).await?;
    let (mut io_r, mut io_w) = tokio::io::split(io);
    let in_metrics = metrics.clone();
    let out_metrics = metrics.clone();
    let to_origin = async {
        let _ = copy_futures_to_tokio_eof(&mut reader, &mut io_w, &in_metrics).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut io_w).await;
    };
    let from_origin = async {
        let _ = copy_tokio_to_futures_eof(&mut io_r, &mut writer, &out_metrics).await;
        let _ = futures_close(&mut writer).await;
    };
    tokio::join!(to_origin, from_origin);
    Ok(())
}

/// The answer of a raw TCP origin to an HTTP request, in the words of the
/// consumer.
pub fn tcp_http_body(words: &crate::Words) -> String {
    format!("{}: a raw TCP origin carries TCP or WebSocket streams, not HTTP. {}\n", words.name, words.tcp_origin)
}
