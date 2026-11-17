//! The Cloudflare tunnel spoken directly: the edge client over QUIC and
//! HTTP/2, Cap'n Proto RPC, the legs and their race, ingress, and the quick
//! tunnels.

pub mod cloudflare;
pub mod config;
pub mod edge_discovery;
pub mod edge_h2;
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
pub mod ingress;
pub mod proxy;
pub mod quicktunnel;
pub mod race;
pub mod tunnel;
pub mod ws;
pub mod yaml;
