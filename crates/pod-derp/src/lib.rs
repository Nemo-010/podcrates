//! pod-derp: a carrier of the resumable layer through DERP servers: the
//! servers that Tailscale runs for tailcat, which need no account, its main
//! fleet, or a derper of the user's own. DERP runs over a WebSocket at
//! `wss://HOST/derp` on port 443, through the caller's way out ([`dial`]),
//! so it passes where an HTTPS proxy lets TLS pass. It is pure Rust.
//!
//! A DERP server forwards packets between Curve25519 keys ([`key`],
//! [`frame`]), keeps their order, and drops the oldest of a receiver's 32
//! when they wait. The resumable layer above ends a link at a gap, so under
//! it an adapter numbers the bytes of each link, acknowledges them, and
//! sends again what was lost ([`send`], [`recv`], [`rtt`]), with a window
//! under the server's queue. A link ([`link`]) is a byte stream between a
//! client and a node, each over one connection to the server ([`conn`]),
//! in packets of this crate's own ([`packet`]). A node serves the links that
//! clients open ([`far`]); a client opens them by the node's ticket
//! ([`ticket`], [`client`]), at the node's home or at another server of
//! the fleet ([`servers`]).
//!
//! Each session over it runs the layer and, above the layer, an end-to-end
//! channel of the caller's (`pod-e2e`), so the server is trusted for
//! availability only: it sees the keys, the sizes and the times, and a
//! change that it makes ends the session.
//!
//! The crate reads no environment variable and keeps no global state: the
//! caller gives the way to each server ([`dial::Dial`]), the sink of the
//! lines for the user (`pod_core::Events`), its [`Names`] and the choice of
//! the fleet. A failure of a connection is a `pod_core::Failure` with its
//! stage and its class.

#[cfg(test)]
mod arq_tests;
pub mod client;
pub mod conn;
pub mod dial;
pub mod far;
pub mod frame;
pub mod key;
pub mod link;
mod names;
pub mod packet;
pub mod recv;
pub mod rtt;
pub mod send;
pub mod servers;
#[cfg(feature = "standin")]
pub mod standin;
pub mod ticket;

pub use client::{Dialer, carry};
pub use conn::Conn;
pub use far::Node;
pub use key::{Key, Secret};
pub use link::Link;
pub use names::Names;
pub use servers::Server;
pub use ticket::Ticket;

/// The features of the resumable layer that each end offers over DERP: those
/// of the iroh road. The relay's limits of a session, which `move.v1`
/// keeps a session within, are not DERP's.
pub const FEATURES: &[&str] = &["replay.v1", "heartbeat.v1"];
