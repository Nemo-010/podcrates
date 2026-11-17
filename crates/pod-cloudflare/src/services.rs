//! The facts of the edge and of the quick tunnels: the data of
//! `pod-services`. `pod-services` checks its built-in set when it builds,
//! so a missing service or fact here is a defect of that set, and panics.

pub use pod_services::{Endpoint, Service};

/// The edge of Cloudflare's tunnels.
pub const EDGE: &str = "cloudflare-tunnel-edge";
/// The quick tunnels of Cloudflare.
pub const QUICK: &str = "trycloudflare";

/// The built-in service `id`.
pub fn get(id: &str) -> &'static Service {
    pod_services::get(id).unwrap_or_else(|| panic!("pod-services holds no service {id}"))
}

/// The endpoint `name` of the service `id`.
pub fn endpoint(id: &str, name: &str) -> &'static Endpoint {
    get(id).endpoint(name).unwrap_or_else(|| panic!("{id} of pod-services has no endpoint {name}"))
}

/// The endpoints of the role `role` of the service `id`, in order.
pub fn endpoints_of(id: &str, role: &str) -> Vec<&'static Endpoint> {
    get(id).endpoints().iter().filter(|e| e.role() == Some(role)).collect()
}

/// The text fact `name` of the service `id`.
pub fn text(id: &str, name: &str) -> &'static str {
    get(id).text(name).unwrap_or_else(|| panic!("{id} of pod-services holds no text {name}"))
}

/// The port of the endpoints of the edge for the role `h2` (7844).
pub fn edge_port() -> u16 {
    endpoints_of(EDGE, "h2").first().map_or(7844, |e| e.port())
}

/// The default provisioning endpoint of the quick tunnels, as cloudflared's
/// flag `quick-service`: `https://` and the host of the endpoint `api`.
pub fn default_quick_service() -> String {
    format!("https://{}", endpoint(QUICK, "api").host())
}

/// A name of the edge, for the choice of the proxy (`NO_PROXY` can name
/// it): the host of the endpoint `h2-region1`.
pub fn edge_region_name() -> &'static str {
    endpoint(EDGE, "h2-region1").host()
}
