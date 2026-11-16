//! The caller's name resolution for iroh: the relay's name and the proxy's
//! go through the caller's resolver (`pod_core::Resolve`: an IP literal,
//! the pinned addresses, the system resolver, then DNS over HTTPS, as
//! `pod-dns` orders them), as on the other roads, not through iroh's own
//! resolver, which knows no pins and no fallback (PodUtils/podssh@T-162).
//!
//! Through a proxy, the relay's name is not resolved here at all: the proxy
//! gets it in `CONNECT`. iroh asks for a TXT record only for address lookup,
//! which the endpoint turns off, so that answer is a refusal.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use iroh::dns::{BoxIter, DnsError, Resolver, TxtRecordData};
use n0_error::{AnyError, e};
use pod_core::Resolve;
use tokio::time::Instant;

/// The bound on one lookup: each source of the caller's resolver within it.
const LOOKUP_LIMIT: Duration = Duration::from_secs(15);

type Lookup<T> = Pin<Box<dyn Future<Output = Result<BoxIter<T>, DnsError>> + Send>>;

/// The resolver that iroh gets in place of its own: the caller's.
#[derive(Clone)]
pub struct Chain(Arc<dyn Resolve>);

impl Chain {
    /// iroh's resolver over `resolve`.
    pub fn new(resolve: Arc<dyn Resolve>) -> Chain {
        Chain(resolve)
    }
}

impl std::fmt::Debug for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Chain").field(&self.0.label()).finish()
    }
}

/// Each address of `host` that the caller's resolver finds, of each family.
async fn addresses(resolve: Arc<dyn Resolve>, host: String) -> Result<Vec<IpAddr>, DnsError> {
    let deadline = Instant::now() + LOOKUP_LIMIT;
    match resolve.resolve(&host, 0, deadline).await {
        Ok(found) => Ok(found.into_iter().map(|addr| addr.ip()).collect()),
        Err(why) => Err(e!(DnsError::Resolve, AnyError::from_string(format!("could not resolve {host}: {why}")))),
    }
}

impl Resolver for Chain {
    fn lookup_ipv4(&self, host: String) -> Lookup<Ipv4Addr> {
        let resolve = self.0.clone();
        Box::pin(async move {
            let v4: Vec<Ipv4Addr> = addresses(resolve, host)
                .await?
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(v4),
                    IpAddr::V6(_) => None,
                })
                .collect();
            Ok(Box::new(v4.into_iter()) as BoxIter<Ipv4Addr>)
        })
    }

    fn lookup_ipv6(&self, host: String) -> Lookup<Ipv6Addr> {
        let resolve = self.0.clone();
        Box::pin(async move {
            let v6: Vec<Ipv6Addr> = addresses(resolve, host)
                .await?
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V6(v6) => Some(v6),
                    IpAddr::V4(_) => None,
                })
                .collect();
            Ok(Box::new(v6.into_iter()) as BoxIter<Ipv6Addr>)
        })
    }

    fn lookup_txt(&self, _host: String) -> Lookup<TxtRecordData> {
        // Address lookup is off: no TXT record is ever needed.
        Box::pin(async { Err(e!(DnsError::NoResponse)) })
    }

    fn clear_cache(&self) {}

    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(self.clone())
    }
}
