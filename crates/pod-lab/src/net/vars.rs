//! The variables of a proxy that tools other than curl read. A network lab
//! removes each one from the environment of the command, and sets the URL
//! forms to its stand-in proxy where the class has one, as it does for the
//! variables of curl ([`super::PROXY_VARIABLES`]). Else a tool that reads
//! one of them dials past the proxy of the lab, or fails on the port of the
//! host.

use super::{PROXY_PASSWORD, PROXY_PORT, PROXY_USER, Proxy, proxy_url};

/// The variables that take the URL of a proxy: global-agent of Node.js,
/// npm, Yarn, a build of Docker.
pub const URL_VARIABLES: &[&str] = &[
    "GLOBAL_AGENT_HTTP_PROXY",
    "GLOBAL_AGENT_HTTPS_PROXY",
    "npm_config_proxy",
    "npm_config_https_proxy",
    "NPM_CONFIG_PROXY",
    "NPM_CONFIG_HTTPS_PROXY",
    "YARN_HTTP_PROXY",
    "YARN_HTTPS_PROXY",
    "DOCKER_HTTP_PROXY",
    "DOCKER_HTTPS_PROXY",
];

/// The variables that the lab removes and does not set: the lists of names
/// that skip a proxy, of the same tools.
pub const SKIP_VARIABLES: &[&str] =
    &["GLOBAL_AGENT_NO_PROXY", "npm_config_noproxy", "NPM_CONFIG_NOPROXY", "DOCKER_NO_PROXY"];

/// The proxy of the Google Cloud CLI, in parts.
pub const CLOUDSDK_VARIABLES: &[&str] = &[
    "CLOUDSDK_PROXY_TYPE",
    "CLOUDSDK_PROXY_ADDRESS",
    "CLOUDSDK_PROXY_PORT",
    "CLOUDSDK_PROXY_USERNAME",
    "CLOUDSDK_PROXY_PASSWORD",
    "CLOUDSDK_PROXY_RDNS",
];

/// The options of a Java virtual machine. The lab removes the options of a
/// proxy from them, and keeps each other option.
pub const JAVA_VARIABLES: &[&str] = &["JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"];

/// The options of a Java virtual machine that name a proxy.
const JAVA_PROXY_OPTIONS: &[&str] = &[
    "-Dhttp.proxyHost=",
    "-Dhttp.proxyPort=",
    "-Dhttp.proxyUser=",
    "-Dhttp.proxyPassword=",
    "-Dhttp.nonProxyHosts=",
    "-Dhttps.proxyHost=",
    "-Dhttps.proxyPort=",
    "-Dhttps.proxyUser=",
    "-Dhttps.proxyPassword=",
    "-DsocksProxyHost=",
    "-DsocksProxyPort=",
    "-Djava.net.useSystemProxies=",
];

/// A change of the environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Remove(String),
    Set(String, String),
}

/// The changes that make `current` (the environment of the lab process)
/// hold no proxy of the host for the tools of this module: each variable
/// removed, then the URL forms and the parts of the Google Cloud CLI set to
/// `proxy` where the class has one. The options of a Java virtual machine
/// lose the options of a proxy alone.
pub fn changes<'a>(current: impl IntoIterator<Item = (&'a str, &'a str)>, proxy: Option<&Proxy>) -> Vec<Change> {
    let mut out = Vec::new();
    let removed = URL_VARIABLES.iter().chain(SKIP_VARIABLES).chain(CLOUDSDK_VARIABLES).copied();
    out.extend(removed.map(|v| Change::Remove(v.to_string())));
    for (name, value) in current {
        if JAVA_VARIABLES.contains(&name) {
            let kept: Vec<&str> =
                value.split_whitespace().filter(|o| !JAVA_PROXY_OPTIONS.iter().any(|p| o.starts_with(p))).collect();
            out.push(if kept.is_empty() {
                Change::Remove(name.to_string())
            } else {
                Change::Set(name.to_string(), kept.join(" "))
            });
        }
    }
    if let Some(p) = proxy {
        let url = proxy_url(p);
        out.extend(URL_VARIABLES.iter().map(|v| Change::Set(v.to_string(), url.clone())));
        let mut set = |k: &str, v: &str| out.push(Change::Set(k.to_string(), v.to_string()));
        set("CLOUDSDK_PROXY_TYPE", "http");
        set("CLOUDSDK_PROXY_ADDRESS", "127.0.0.1");
        set("CLOUDSDK_PROXY_PORT", &PROXY_PORT.to_string());
        if p.auth {
            set("CLOUDSDK_PROXY_USERNAME", PROXY_USER);
            set("CLOUDSDK_PROXY_PASSWORD", PROXY_PASSWORD);
        }
    }
    out
}

#[cfg(test)]
mod tests;
