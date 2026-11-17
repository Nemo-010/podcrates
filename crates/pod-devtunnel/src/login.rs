//! The device-code logins of a user (T-378, part 2, step 2): the flow of
//! RFC 8628 at GitHub (the vendor's GitHub App) and at Microsoft Entra ID
//! (the caller's client id, the scope of the service), and the refresh of an
//! Entra token. The caller shows the user code and the address, the user
//! signs in in a browser, and [`poll`] gives the user's token for the
//! management API ([`UserToken`]). The hosts, the ids and the scope come from
//! the service's facts (`pod-services`); a [`Login`] holds them, so a test
//! gives the stand-in's. No token and no device code goes into a line, an
//! event or an error text.

use std::time::Duration;

use pod_core::{Class, Failure};
use pod_proxy::client::Request;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::failure::{Step, fail, wrap};
use crate::service;
use crate::token::{Scheme, UserToken};

/// The most bytes of an answer of a login host.
const ANSWER_MOST: usize = 64 * 1024;
/// The grant type of a poll (RFC 8628, section 3.4).
pub const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// The wait that a `slow_down` adds (RFC 8628, section 3.5).
pub const SLOW_DOWN: Duration = Duration::from_secs(5);
/// The wait between two polls when the host names none.
pub const INTERVAL: Duration = Duration::from_secs(5);

/// Where and as whom a user signs in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Login {
    /// GitHub: the client id of the vendor's GitHub App, at `base`
    /// (`https://github.com`).
    Github { base: String, client_id: String },
    /// Microsoft Entra ID: the caller's client id, the `tenant` of the
    /// authority (`organizations`), the `scope`, at `base`
    /// (`https://login.microsoftonline.com`).
    Aad { base: String, tenant: String, client_id: String, scope: String },
}

impl Login {
    /// GitHub with the vendor's GitHub App.
    pub fn github() -> Login {
        Login::Github { base: service::github_login(), client_id: service::github_client_id().to_string() }
    }

    /// Entra ID with the caller's `client_id`: an app of the caller's
    /// tenant that may ask for the scope of the service.
    pub fn aad(client_id: impl Into<String>) -> Login {
        Login::Aad {
            base: service::aad_login(),
            tenant: service::aad_tenant().to_string(),
            client_id: client_id.into(),
            scope: service::aad_scope(),
        }
    }

    /// The same login at another `base` (a stand-in).
    pub fn at(self, new: impl Into<String>) -> Login {
        match self {
            Login::Github { client_id, .. } => Login::Github { base: new.into(), client_id },
            Login::Aad { tenant, client_id, scope, .. } => Login::Aad { base: new.into(), tenant, client_id, scope },
        }
    }

    fn code_url(&self) -> String {
        match self {
            Login::Github { base, .. } => format!("{base}/login/device/code"),
            Login::Aad { base, tenant, .. } => format!("{base}/{tenant}/oauth2/v2.0/devicecode"),
        }
    }

    fn token_url(&self) -> String {
        match self {
            Login::Github { base, .. } => format!("{base}/login/oauth/access_token"),
            Login::Aad { base, tenant, .. } => format!("{base}/{tenant}/oauth2/v2.0/token"),
        }
    }

    fn client_id(&self) -> &str {
        match self {
            Login::Github { client_id, .. } | Login::Aad { client_id, .. } => client_id,
        }
    }

    fn scheme(&self) -> Scheme {
        match self {
            Login::Github { .. } => Scheme::Github,
            Login::Aad { .. } => Scheme::Aad,
        }
    }
}

/// What the user does: open `verification_uri` and give `user_code`,
/// within `expires_in`. The device code stays in the crate.
pub struct DeviceCode {
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: Duration,
    pub interval: Duration,
    device_code: Zeroizing<String>,
}

/// A token that a login gave: the user's token, the refresh token of
/// Entra ID, and its life when the host gives one.
pub struct Granted {
    pub token: UserToken,
    pub refresh: Option<Zeroizing<String>>,
    pub expires_in: Option<Duration>,
}

impl std::fmt::Debug for DeviceCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCode")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

/// No token in a line: the scheme, whether a refresh token came, the life.
impl std::fmt::Debug for Granted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Granted")
            .field("scheme", &self.token.scheme())
            .field("refresh", &self.refresh.is_some())
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

#[derive(Deserialize)]
struct CodeAnswer {
    device_code: String,
    user_code: String,
    #[serde(alias = "verification_url")]
    verification_uri: String,
    expires_in: u64,
    #[serde(default)]
    interval: Option<u64>,
}

#[derive(Deserialize)]
struct TokenAnswer {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    error: Option<String>,
}

/// One form body, each value encoded (RFC 3986 unreserved bytes as they
/// are).
fn form(pairs: &[(&str, &str)]) -> Zeroizing<String> {
    let encode = |text: &str| -> String {
        text.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
                _ => format!("%{b:02X}"),
            })
            .collect()
    };
    Zeroizing::new(pairs.iter().map(|(k, v)| format!("{k}={}", encode(v))).collect::<Vec<_>>().join("&"))
}

fn post(url: &str, body: &Zeroizing<String>, timeout: Duration) -> Request {
    Request::new("POST", url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.as_bytes().to_vec())
        .timeout(timeout)
        .max_body(ANSWER_MOST)
}

/// Ask `login` for a device code.
pub async fn start(client: &pod_proxy::Client, login: &Login, timeout: Duration) -> Result<DeviceCode, Failure> {
    let url = login.code_url();
    let body = match login {
        Login::Github { client_id, .. } => form(&[("client_id", client_id)]),
        Login::Aad { client_id, scope, .. } => form(&[("client_id", client_id), ("scope", scope)]),
    };
    let shown = format!("POST {url}");
    let answer = client.send(post(&url, &body, timeout)).await.map_err(|e| wrap(Step::Management, &shown, e))?;
    if answer.status != 200 {
        let class = if answer.status == 400 || answer.status == 401 { Class::Refused } else { Class::Unavailable };
        return Err(fail(Step::Management, class, format!("{shown} answered {}", answer.status)));
    }
    let code: CodeAnswer = serde_json::from_slice(&answer.body)
        .map_err(|_| fail(Step::Management, Class::Protocol, format!("{shown} gave no device code")))?;
    Ok(DeviceCode {
        user_code: pod_core::text::one_line(&code.user_code),
        verification_uri: pod_core::text::one_line(&code.verification_uri),
        expires_in: Duration::from_secs(code.expires_in),
        interval: code.interval.map(Duration::from_secs).unwrap_or(INTERVAL),
        device_code: Zeroizing::new(code.device_code),
    })
}

/// Wait for the user to sign in: a poll of `login` each interval, a longer
/// one after `slow_down`, until a token, a refusal, or the end of the
/// code's life. `wait` sleeps (a test passes a clock of its own).
pub async fn poll<W, F>(
    client: &pod_proxy::Client,
    login: &Login,
    code: &DeviceCode,
    timeout: Duration,
    wait: W,
) -> Result<Granted, Failure>
where
    W: Fn(Duration) -> F,
    F: std::future::Future<Output = ()>,
{
    let url = login.token_url();
    let body =
        form(&[("client_id", login.client_id()), ("grant_type", DEVICE_GRANT), ("device_code", &code.device_code)]);
    let shown = format!("POST {url}");
    let (mut interval, mut waited) = (code.interval, Duration::ZERO);
    loop {
        if waited >= code.expires_in {
            return Err(fail(Step::Management, Class::Timeout, "the device code expired before the user signed in"));
        }
        wait(interval).await;
        waited += interval;
        let answer = client.send(post(&url, &body, timeout)).await.map_err(|e| wrap(Step::Management, &shown, e))?;
        let token: TokenAnswer = serde_json::from_slice(&answer.body).map_err(|_| {
            fail(Step::Management, Class::Protocol, format!("{shown} answered {} with no JSON", answer.status))
        })?;
        match (token.access_token, token.error.as_deref()) {
            (Some(access), _) => return granted(login.scheme(), access, token.refresh_token, token.expires_in),
            (None, Some("authorization_pending")) => {}
            (None, Some("slow_down")) => interval += SLOW_DOWN,
            (None, Some("expired_token")) => {
                return Err(fail(
                    Step::Management,
                    Class::Timeout,
                    "the device code expired before the user signed in",
                ));
            }
            (None, Some("access_denied")) => {
                return Err(fail(Step::Management, Class::Refused, "the user refused the sign-in"));
            }
            (None, Some(other)) => {
                let words = pod_core::text::one_line(other);
                return Err(fail(Step::Management, Class::Refused, format!("{shown} refused the sign-in: {words}")));
            }
            (None, None) => {
                return Err(fail(Step::Management, Class::Protocol, format!("{shown} gave no token and no error")));
            }
        }
    }
}

/// A new Entra token from a refresh token (RFC 6749, section 6).
pub async fn refresh(
    client: &pod_proxy::Client,
    login: &Login,
    refresh: &str,
    timeout: Duration,
) -> Result<Granted, Failure> {
    let Login::Aad { client_id, scope, .. } = login else {
        return Err(fail(Step::Management, Class::Usage, "a token of GitHub has no refresh"));
    };
    let url = login.token_url();
    let body = form(&[
        ("client_id", client_id),
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh),
        ("scope", scope),
    ]);
    let shown = format!("POST {url}");
    let answer = client.send(post(&url, &body, timeout)).await.map_err(|e| wrap(Step::Management, &shown, e))?;
    let token: TokenAnswer = serde_json::from_slice(&answer.body).map_err(|_| {
        fail(Step::Management, Class::Protocol, format!("{shown} answered {} with no JSON", answer.status))
    })?;
    match token.access_token {
        Some(access) => granted(Scheme::Aad, access, token.refresh_token, token.expires_in),
        None => Err(fail(Step::Management, Class::Refused, "the refresh token is refused: sign in again")),
    }
}

fn granted(
    scheme: Scheme,
    access: String,
    refresh: Option<String>,
    expires_in: Option<u64>,
) -> Result<Granted, Failure> {
    Ok(Granted {
        token: UserToken::new(scheme, access)?,
        refresh: refresh.map(Zeroizing::new),
        expires_in: expires_in.map(Duration::from_secs),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_form_encodes_each_byte_out_of_the_unreserved_set() {
        assert_eq!(form(&[("a", "x y"), ("scope", "id/.default")]).as_str(), "a=x%20y&scope=id%2F.default");
        assert_eq!(
            form(&[("grant_type", DEVICE_GRANT)]).as_str(),
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
        );
    }

    #[test]
    fn the_urls_of_each_host() {
        let g = Login::Github { base: "https://g.test".into(), client_id: "c".into() };
        assert_eq!(
            (g.code_url(), g.token_url()),
            ("https://g.test/login/device/code".into(), "https://g.test/login/oauth/access_token".into())
        );
        let a = Login::Aad {
            base: "https://a.test".into(),
            tenant: "organizations".into(),
            client_id: "c".into(),
            scope: "s".into(),
        };
        assert_eq!(a.code_url(), "https://a.test/organizations/oauth2/v2.0/devicecode");
        assert_eq!(a.token_url(), "https://a.test/organizations/oauth2/v2.0/token");
    }
}
