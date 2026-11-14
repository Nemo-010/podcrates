//! The live test of the reader against a real Windows ISO (T-620): the
//! Windows Server 2019 evaluation ISO of the service
//! `microsoft-windows-eval` of `pod-services`, 5 GB, read by HTTP Range
//! requests through the `ReadAt` of the test, with no download of the
//! whole image. `Udf::find` gives the extents of `/sources/boot.wim`; the
//! test checks its size, the WIM magic and the SHA-256 of its first block,
//! and the SHA-256 of its last block. A new master of the ISO changes the
//! pins: the watch `http-sha256` of the service then fails too.
//! `live.yml` runs it on Thursdays and by hand.

use std::io;
use std::sync::Arc;

use pod_proxy::blocking::{Client, Dialer};
use pod_proxy::client::Request;
use pod_proxy::{Environment, ProxyChoice, Settings};
use pod_udf::{Extent, ReadAt, Udf};
use sha2::{Digest, Sha256};

/// The file of the test, and what the ISO of the service holds.
const PATH: &str = "/sources/boot.wim";
const BOOT_WIM_BYTES: u64 = 547_572_640;
const FIRST_BLOCK_SHA256: &str = "89aa5c6eaee331a76142d977acbfece1cec7df291648fb4c7a1dc5dfdfc9e8d9";
const LAST_BLOCK_SHA256: &str = "4ec5ec582767bd547866e9bc558e43db53d8de0c1924744bd97b8bc8c4161fbb";
/// The magic of a WIM header.
const WIM_MAGIC: &[u8] = b"MSWIM\0\0\0";

/// A `ReadAt` of one URL by Range requests, which counts its requests.
struct Ranged {
    client: Client,
    url: String,
    size: u64,
    requests: usize,
    bytes: u64,
}

impl ReadAt for Ranged {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let end = offset.checked_add(buf.len() as u64).filter(|end| *end <= self.size);
        let Some(end) = end else { return Err(io::ErrorKind::UnexpectedEof.into()) };
        if buf.is_empty() {
            return Ok(());
        }
        let request = Request::new("GET", self.url.as_str())
            .header("Range", format!("bytes={offset}-{}", end - 1))
            .max_body(buf.len())
            .redirects(5);
        let answer = self.client.send(request).map_err(|f| io::Error::other(f.to_string()))?;
        self.requests += 1;
        let range = answer.header("content-range").unwrap_or_default().to_string();
        if answer.status != 206 || !range.starts_with(&format!("bytes {offset}-{}/", end - 1)) {
            let text = format!("a range from {offset} got {} with Content-Range {range:?}", answer.status);
            return Err(io::Error::new(io::ErrorKind::InvalidData, text));
        }
        if answer.body.len() != buf.len() {
            let text = format!("a range of {} bytes gave {}", buf.len(), answer.body.len());
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, text));
        }
        buf.copy_from_slice(&answer.body);
        self.bytes += buf.len() as u64;
        Ok(())
    }
}

/// The HTTP client of `pod-proxy` over the proxy settings of the process
/// (the runner of `live.yml` has none) and the default roots.
fn client() -> Client {
    let env = Environment::read(&|name| std::env::var_os(name));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let context = Arc::new(pod_tls::Context::new(provider, pod_tls::Settings::new(pod_tls::Words::new("pod-udf"))));
    let resolve = Arc::new(pod_proxy::resolve::System::new());
    let dialer = Dialer::new(Settings::new("pod-udf", ProxyChoice::FromEnvironment(env)), resolve)
        .expect("the runtime of the dialer starts");
    Client::new(context, &dialer).with_user_agent("pod-udf-live-test")
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
#[ignore = "a live download: live.yml runs it"]
fn boot_wim_of_the_windows_evaluation_iso_by_range_requests() {
    let service = pod_services::get("microsoft-windows-eval").expect("the service microsoft-windows-eval");
    let url = service.endpoint("server-2019").expect("the endpoint server-2019").url();
    let size = service.int("server-2019-bytes").expect("the fact server-2019-bytes") as u64;
    let ranged = Ranged { client: client(), url, size, requests: 0, bytes: 0 };
    let mut udf = Udf::open(ranged).expect("the UDF volume of the ISO");
    let (block, revision) = (udf.block_size(), udf.revision());
    let extents = udf.find(PATH).expect("the extents of boot.wim");
    let parts = extents.parts.len();
    eprintln!(
        "windows-eval: block {block}, UDF revision {revision:#06x}, {PATH}: {} bytes in {parts} parts",
        extents.size
    );
    assert_eq!(block, 2048, "the block of an ISO");
    let recorded = extents.parts.iter().all(|p| matches!(p, Extent::Data { offset, len } if offset + len <= size));
    assert!(recorded, "each part is recorded inside the ISO: {:?}", extents.parts);
    let range = extents.range().expect("boot.wim is one recorded part");
    let first_len = extents.size.min(u64::from(block)) as usize;
    let last_len = match extents.size % u64::from(block) {
        0 => u64::from(block),
        n => n,
    } as usize;
    let mut first = vec![0u8; first_len];
    let mut last = vec![0u8; last_len];
    let mut reader = udf.into_inner();
    reader.read_at(range.start, &mut first).expect("the first block of boot.wim");
    reader.read_at(range.end - last_len as u64, &mut last).expect("the last block of boot.wim");
    let (first_sum, last_sum) = (sha256(&first), sha256(&last));
    eprintln!("windows-eval: bytes {range:?} of the ISO; first block {first_sum}, last block {last_sum}");
    eprintln!("windows-eval: {} Range requests, {} bytes in all", reader.requests, reader.bytes);
    assert_eq!(&first[..WIM_MAGIC.len()], WIM_MAGIC, "boot.wim starts with the WIM magic");
    assert_eq!(extents.size, BOOT_WIM_BYTES, "the size of boot.wim");
    assert_eq!(first_sum, FIRST_BLOCK_SHA256, "the SHA-256 of the first block of boot.wim");
    assert_eq!(last_sum, LAST_BLOCK_SHA256, "the SHA-256 of the last block of boot.wim");
}
