//! The writes of the management API at the stand-in (T-378, part 2): the
//! list of the user's tunnels (the plan's tunnel and each one made since),
//! a new tunnel, its delete, and a port of a tunnel. Each takes the user's
//! token alone, as the vendor's service manages tunnels for a user: a
//! tunnel access token gets 403, no token 401.

use std::sync::atomic::Ordering;

use pod_proxy::http::request::{self, Request};
use serde_json::{Value, json};

use super::{State, problem};
use crate::service;

/// The tunnels that the stand-in made, as the API gives them.
pub(crate) type Made = Vec<Value>;

/// Whether `head` is a write, or the list: each one but the get of one
/// tunnel.
pub(super) fn is_write(head: &Request) -> bool {
    let list = service::service().text("list-query").unwrap_or_default();
    head.method != "GET" || head.target.split_once('?').is_some_and(|(_, q)| q.split('&').any(|p| p == list))
}

/// The answer to the write `head` with its body `body`.
pub(super) fn answer(state: &State, head: &Request, body: &[u8]) -> Vec<u8> {
    let plan = &state.plan;
    let (path, query) = head.target.split_once('?').unwrap_or((&head.target, ""));
    state.seen().writes.push(format!("{} {path}", head.method));
    let version = format!("api-version={}", service::api_version());
    if !query.split('&').any(|p| p == version) {
        return problem(400, "Bad Request");
    }
    match head.header("authorization") {
        Some(given) if given == plan.authorization && !state.refuse_user.load(Ordering::SeqCst) => {}
        Some(given) if given.starts_with(&format!("{} ", service::access_scheme())) => {
            return problem(403, "Forbidden: a tunnel access token manages no tunnel");
        }
        _ => return problem(401, "Unauthorized: the user token is refused"),
    }
    let Some(rest) = path.strip_prefix(service::tunnels_path()) else { return problem(404, "Not Found") };
    let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
    let ports = service::service().text("ports-path").unwrap_or_default();
    let mut made = state.made();
    let at = |made: &Made, id: &str| made.iter().position(|t| t["tunnelId"] == id);
    match (head.method.as_str(), parts.as_slice()) {
        ("GET", []) => {
            let mut all = vec![json!({ "tunnelId": plan.id, "clusterId": plan.cluster, "name": plan.name })];
            all.extend(made.iter().cloned());
            let doc = json!({ "value": [{ "regionName": "standin", "value": all }] });
            request::answer(200, "application/json", doc.to_string().as_bytes(), false)
        }
        ("PUT", [id]) => {
            let Ok(doc) = serde_json::from_slice::<Value>(body) else { return problem(400, "Bad Request") };
            if doc["tunnelId"] != *id {
                return problem(400, "Bad Request: the id of the body is not the id of the path");
            }
            if *id == plan.id || at(&made, id).is_some() {
                return problem(409, "Conflict: a tunnel has this id");
            }
            let cluster = doc["clusterId"].as_str().unwrap_or(&plan.cluster).to_string();
            let tunnel = json!({ "tunnelId": id, "clusterId": cluster, "name": doc["name"], "ports": [] });
            made.push(tunnel.clone());
            request::answer(200, "application/json", tunnel.to_string().as_bytes(), false)
        }
        ("DELETE", [id]) => match at(&made, id) {
            Some(i) => {
                made.remove(i);
                request::answer(200, "application/json", b"", false)
            }
            None => problem(404, "Not Found"),
        },
        ("PUT", [id, word, number]) if *word == ports => {
            let (Some(i), Ok(port)) = (at(&made, id), number.parse::<u16>()) else { return problem(404, "Not Found") };
            let Ok(doc) = serde_json::from_slice::<Value>(body) else { return problem(400, "Bad Request") };
            if doc["portNumber"].as_u64() != Some(u64::from(port)) {
                return problem(400, "Bad Request: the port of the body is not the port of the path");
            }
            let entry = json!({ "portNumber": port });
            if let Some(list) = made[i]["ports"].as_array_mut() {
                list.push(entry.clone());
            }
            request::answer(200, "application/json", entry.to_string().as_bytes(), false)
        }
        _ => problem(405, "Method Not Allowed"),
    }
}
