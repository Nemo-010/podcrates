//! The bytes of the Cloudflare edge and of the configuration of a tunnel
//! (`pod-cloudflare`, its feature `fuzzing`; podnet `src/fuzzing.rs`). Each
//! target runs the entry point of the crate of the same name, which must
//! not panic, hang or allocate much more than the input.

/// A Cap'n Proto message: the framing and a walk of each pointer.
pub fn capnp_message(data: &[u8]) {
    pod_cloudflare::fuzzing::capnp_message(data);
}

/// An RPC message of the edge: the readers of the RPC session.
pub fn rpc_message(data: &[u8]) {
    pod_cloudflare::fuzzing::rpc_message(data);
}

/// The results of `registerConnection`.
pub fn register_response(data: &[u8]) {
    pod_cloudflare::fuzzing::register_response(data);
}

/// The `ConnectRequest` and `ConnectResponse` of a stream of a visitor.
pub fn connect_request(data: &[u8]) {
    pod_cloudflare::fuzzing::connect_request(data);
}

/// The encoded response headers of the HTTP/2 leg.
pub fn h2_header_block(data: &[u8]) {
    pod_cloudflare::fuzzing::h2_header_block(data);
}

/// The `data` field of an SRV record of DNS over HTTPS.
pub fn srv_record(data: &[u8]) {
    pod_cloudflare::fuzzing::srv_record(data);
}

/// The HTTP/1.1 head to the origin from the fields of a `ConnectRequest`:
/// one empty line at its end, and no field makes a line of its own.
pub fn request_head(data: &[u8]) {
    pod_cloudflare::fuzzing::request_head(data);
}

/// A service and a forward target of an ingress rule.
pub fn ingress_rule(data: &[u8]) {
    pod_cloudflare::fuzzing::ingress_rule(data);
}

/// A YAML configuration file of cloudflared.
pub fn config_yaml(data: &[u8]) {
    pod_cloudflare::fuzzing::config_yaml(data);
}
