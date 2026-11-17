//! The device-code logins at the stand-in (T-378, part 2, step 2): the
//! device code and the poll of GitHub (`/login/...`) and of Entra ID
//! (`/TENANT/oauth2/v2.0/...`), and the refresh of an Entra token. The
//! token that a poll gives is the plan's user token, so the management API
//! of the stand-in takes it. GitHub answers a pending poll with 200, Entra
//! ID with 400, as the two hosts do. Its codes and tokens are made-up
//! values.

use pod_proxy::http::request::{self, Request};
use serde_json::json;

use super::State;

/// The device code of the stand-in.
pub const DEVICE_CODE: &str = "standin-device-code";
/// The code that the user gives.
pub const USER_CODE: &str = "STAN-D1N0";
/// The refresh token of the stand-in.
pub const REFRESH_TOKEN: &str = "standin-refresh-token";

/// How the stand-in answers the polls of a login.
#[derive(Clone, Debug, Default)]
pub struct Logins {
    /// The polls that wait before the token comes.
    pub pending: usize,
    /// The first poll answers `slow_down`.
    pub slow_down: bool,
    /// The user refused: each poll answers `access_denied`.
    pub deny: bool,
    /// The polls that came, and the refreshes.
    pub polls: usize,
    pub refreshes: usize,
}

/// Whether `head` is a request of a login.
pub(super) fn is_login(head: &Request) -> bool {
    head.method == "POST" && (head.target.starts_with("/login/") || head.target.contains("/oauth2/v2.0/"))
}

/// The pairs of a form body, each value decoded.
fn pairs(body: &[u8]) -> Vec<(String, String)> {
    let decode = |text: &str| -> String {
        let bytes = text.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'%' if i + 2 < bytes.len() => {
                    let hex =
                        std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
                    out.push(hex.unwrap_or(b'%'));
                    i += 3;
                }
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    };
    String::from_utf8_lossy(body)
        .split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (decode(k), decode(v)))
        .collect()
}

fn json_answer(status: u16, value: serde_json::Value) -> Vec<u8> {
    request::answer(status, "application/json", value.to_string().as_bytes(), false)
}

/// The answer to the login request `head` with its form `body`.
pub(super) fn answer(state: &State, head: &Request, body: &[u8]) -> Vec<u8> {
    let path = head.target.split_once('?').map_or(head.target.as_str(), |(p, _)| p);
    let form = pairs(body);
    let field = |name: &str| form.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    let github = path.starts_with("/login/");
    // A pending poll: GitHub says so with 200, Entra ID with 400.
    let refusal = if github { 200 } else { 400 };
    if field("client_id").is_none_or(str::is_empty) {
        return json_answer(400, json!({ "error": "invalid_client" }));
    }
    if path.ends_with("/device/code") || path.ends_with("/devicecode") {
        return json_answer(
            200,
            json!({
                "device_code": DEVICE_CODE,
                "user_code": USER_CODE,
                "verification_uri": "https://standin.invalid/device",
                "expires_in": 900,
                "interval": 1,
            }),
        );
    }
    let token = state.plan.authorization.split_once(' ').map_or("", |(_, t)| t).to_string();
    let mut logins = state.logins();
    match field("grant_type") {
        Some(crate::login::DEVICE_GRANT) => {
            if field("device_code") != Some(DEVICE_CODE) {
                return json_answer(refusal, json!({ "error": "invalid_grant" }));
            }
            logins.polls += 1;
            let error = if logins.deny {
                Some("access_denied")
            } else if logins.slow_down && logins.polls == 1 {
                Some("slow_down")
            } else if logins.polls <= logins.pending {
                Some("authorization_pending")
            } else {
                None
            };
            match error {
                Some(error) => json_answer(refusal, json!({ "error": error })),
                None if github => json_answer(200, json!({ "access_token": token, "token_type": "bearer" })),
                None => json_answer(
                    200,
                    json!({ "access_token": token, "refresh_token": REFRESH_TOKEN, "expires_in": 3600, "token_type": "Bearer" }),
                ),
            }
        }
        Some("refresh_token") if !github => {
            if field("refresh_token") != Some(REFRESH_TOKEN) {
                return json_answer(400, json!({ "error": "invalid_grant" }));
            }
            logins.refreshes += 1;
            json_answer(
                200,
                json!({ "access_token": token, "refresh_token": REFRESH_TOKEN, "expires_in": 3600, "token_type": "Bearer" }),
            )
        }
        _ => json_answer(400, json!({ "error": "unsupported_grant_type" })),
    }
}
