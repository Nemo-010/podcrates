//! The facts of Dev Tunnels: the service `microsoft-devtunnel` of
//! `pod-services` (its management endpoint and the values of the vendor's
//! client, each with its source). The crate holds no host and no value of
//! the protocol in its code; [`crate::Settings`] gives a caller other
//! values where a test or a deployment needs them.

use pod_services::Service;

/// The id of the service in `pod-services`.
pub const ID: &str = "microsoft-devtunnel";

/// The service `microsoft-devtunnel`.
pub fn service() -> &'static Service {
    pod_services::get(ID).expect("pod-services holds the service microsoft-devtunnel")
}

fn text(name: &str) -> &'static str {
    service().text(name).unwrap_or_else(|| panic!("microsoft-devtunnel of pod-services holds the fact {name}"))
}

/// The base of the management API: the endpoint `management`
/// (`https://HOST`).
pub fn management() -> String {
    service().endpoint("management").expect("microsoft-devtunnel has the endpoint management").url()
}

/// The version of the management API in the query `api-version`.
pub fn api_version() -> &'static str {
    text("api-version")
}

/// The path of the tunnels: `/tunnels/NAME` or `/tunnels/ID`.
pub fn tunnels_path() -> &'static str {
    text("tunnels-path")
}

/// The scope of the token that the query `tokenScopes` asks for.
pub fn token_scope() -> &'static str {
    text("token-scope")
}

/// The start of the global host that the id of a cluster takes the place
/// of, for a tunnel by its id.
pub fn cluster_host_rule() -> &'static str {
    text("cluster-host-rule")
}

/// The scheme of a tunnel access token in `Authorization` to the
/// management API.
pub fn access_scheme() -> &'static str {
    text("access-scheme")
}

/// The scheme of `Authorization` in the relay's upgrade.
pub fn relay_scheme() -> &'static str {
    text("relay-scheme")
}

/// The WebSocket subprotocol of a client of the relay.
pub fn subprotocol() -> &'static str {
    text("subprotocol")
}

/// The SSH user of a client of the relay.
pub fn ssh_user() -> &'static str {
    text("ssh-user")
}

/// The host to connect and the originator of each `direct-tcpip` channel.
pub fn connect_host() -> &'static str {
    text("connect-host")
}

/// The host of GitHub's device flow (`https://github.com`).
pub fn github_login() -> String {
    text("github-login").to_string()
}

/// The client id of the vendor's GitHub App.
pub fn github_client_id() -> &'static str {
    text("github-client-id")
}

/// The host of Microsoft Entra ID (`https://login.microsoftonline.com`).
pub fn aad_login() -> String {
    text("aad-login").to_string()
}

/// The tenant of the authority of a login of Entra ID.
pub fn aad_tenant() -> &'static str {
    text("aad-tenant")
}

/// The scope that a token of Entra ID asks for: the service's first-party
/// app, `ID/.default`.
pub fn aad_scope() -> String {
    format!("{}/.default", text("aad-app-id"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_facts_of_the_vendor_client() {
        assert_eq!(management(), "https://global.rel.tunnels.api.visualstudio.com");
        assert_eq!(api_version(), "2023-09-27-preview");
        assert_eq!((tunnels_path(), token_scope(), cluster_host_rule()), ("/tunnels", "connect", "global."));
        assert_eq!((relay_scheme(), subprotocol()), ("tunnel", "tunnel-relay-client"));
        assert_eq!(access_scheme(), "tunnel");
        assert_eq!((ssh_user(), text("ssh-auth"), text("channel-type")), ("tunnel", "none", "direct-tcpip"));
        assert_eq!(connect_host(), "127.0.0.1");
        assert_eq!(service().kind(), "devtunnel");
        assert_eq!((github_login(), github_client_id()), ("https://github.com".to_string(), "Iv1.e7b89e013f801f03"));
        assert_eq!((aad_login(), aad_tenant()), ("https://login.microsoftonline.com".to_string(), "organizations"));
        assert_eq!(aad_scope(), "46da2f7e-b5ef-422a-88d4-2a7f9de6a0b2/.default");
    }
}
