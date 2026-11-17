//! The configuration file in the format of cloudflared: its keys, the types
//! of its values, its ingress rules and its credentials.

use super::*;

// ── the config file of cloudflared ───────────────────────────────────────────

#[derive(Deserialize)]
pub(super) struct RawConfig {
    #[serde(default)]
    tunnel: Option<String>,
    #[serde(default, rename = "credentials-file")]
    credentials_file: Option<PathBuf>,
    #[serde(default)]
    ingress: Vec<crate::ingress::RawIngress>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default, rename = "ha-connections")]
    ha_connections: Option<u8>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default, rename = "hello-world")]
    hello_world: Option<bool>,
}

/// The top-level keys of a cloudflared config.yml. The client reads `tunnel`,
/// `credentials-file`, `token`, `ingress`, `url`, `hello-world`, `protocol`
/// and `ha-connections`, and ignores the others. A key outside this list is
/// a typo, and thus an error.
pub const CLOUDFLARED_KEYS: &[&str] = &[
    "tunnel",
    "credentials-file",
    "ingress",
    "protocol",
    "ha-connections",
    "originRequest",
    "warp-routing",
    "loglevel",
    "transport-loglevel",
    "logfile",
    "log-directory",
    "metrics",
    "no-autoupdate",
    "autoupdate-freq",
    "edge-ip-version",
    "edge-bind-address",
    "region",
    "retries",
    "grace-period",
    "pidfile",
    "post-quantum",
    "management-diagnostics",
    "tag",
    "url",
    "hello-world",
    "origincert",
    "token",
];

pub use crate::ingress::RULE_KEYS;

/// The keys of `originRequest` that cloudflared knows. The client reads
/// `noTLSVerify`, `httpHostHeader`, `connectTimeout`, `tlsTimeout`,
/// `keepAliveTimeout`, `disableChunkedEncoding` and its own
/// `stripAcceptEncoding`, and ignores the others.
pub const ORIGIN_REQUEST_KEYS: &[&str] = &[
    "connectTimeout",
    "tlsTimeout",
    "tcpKeepAlive",
    "noHappyEyeballs",
    "keepAliveConnections",
    "keepAliveTimeout",
    "httpHostHeader",
    "originServerName",
    "matchSNItoHost",
    "caPool",
    "noTLSVerify",
    "disableChunkedEncoding",
    "bastionMode",
    "proxyAddress",
    "proxyPort",
    "proxyType",
    "ipRules",
    "http2Origin",
    "access",
    "stripAcceptEncoding",
];

/// An error for each key of `map` that is not in `known`. `place` names
/// the map: "a cloudflared config", "ingress rule 2".
pub(super) fn check_keys(
    file: &std::path::Path,
    map: &serde_json::Map<String, serde_json::Value>,
    known: &[&'static str],
    place: &str,
) -> Result<()> {
    for key in map.keys() {
        if !known.contains(&key.as_str()) {
            let hint = nearest_key(key, known).map(|k| format!("; did you mean {k}?")).unwrap_or_default();
            bail!(Stage::Host, Class::Config, "{}: the key {key:?} is not a key of {place}{hint}", file.display());
        }
    }
    Ok(())
}

/// Check the keys of each ingress rule and of each `originRequest`: a
/// misspelt key (`hostnam:`) is an error, not a catch-all rule. The top-level
/// `originRequest` is the default of each rule; the key of a rule wins.
pub(super) fn check_and_merge_rules(file: &Path, value: &mut serde_json::Value, at: &[usize]) -> Result<()> {
    let Some(map) = value.as_object_mut() else {
        return Ok(());
    };
    let defaults = match map.get("originRequest") {
        None | Some(serde_json::Value::Null) => serde_json::Map::new(),
        Some(serde_json::Value::Object(o)) => {
            check_keys(file, o, ORIGIN_REQUEST_KEYS, "originRequest")?;
            check_origin_values(file, o, "originRequest")?;
            o.clone()
        }
        Some(_) => bail!(Stage::Host, Class::Config, "{}: originRequest: give a map of keys", file.display()),
    };
    let Some(ingress) = map.get_mut("ingress") else {
        return Ok(());
    };
    let Some(rules) = ingress.as_array_mut() else {
        if ingress.is_null() {
            return Ok(());
        }
        bail!(
            Stage::Host,
            Class::Config,
            "{}: ingress: give a list of rules, for example `- service: http://127.0.0.1:8080`",
            file.display()
        );
    };
    for (i, rule) in rules.iter_mut().enumerate() {
        let place = crate::yaml::numbered("ingress rule", i, at);
        let Some(rule) = rule.as_object_mut() else {
            bail!(Stage::Host, Class::Config, "{}: {place}: give a map of keys", file.display());
        };
        check_keys(file, rule, RULE_KEYS, &place)?;
        match rule.get("service") {
            None | Some(serde_json::Value::Null) => {
                bail!(
                    Stage::Host,
                    Class::Config,
                    "{}: {place}: service: is missing, for example `service: http://127.0.0.1:8080`",
                    file.display()
                )
            }
            Some(serde_json::Value::String(_)) => {}
            Some(_) => bail!(Stage::Host, Class::Config, "{}: {place}: service: give a string", file.display()),
        }
        for key in ["hostname", "path"] {
            if let Some(value) = rule.get(key)
                && !value.is_string()
                && !value.is_null()
            {
                bail!(Stage::Host, Class::Config, "{}: {place}: {key}: give a string", file.display());
            }
        }
        // The key path: is a regular expression, as in cloudflared. A
        // path that does not compile is an error at load.
        if let Some(path) = rule.get("path").and_then(|v| v.as_str()) {
            crate::ingress::PathPattern::regex(path).with_context(|| format!("{}: {place}", file.display()))?;
        }
        let mut origin = match rule.remove("originRequest") {
            None | Some(serde_json::Value::Null) => serde_json::Map::new(),
            Some(serde_json::Value::Object(o)) => {
                check_keys(file, &o, ORIGIN_REQUEST_KEYS, &format!("{place}, originRequest"))?;
                check_origin_values(file, &o, &format!("{place}, originRequest"))?;
                o
            }
            Some(_) => {
                bail!(Stage::Host, Class::Config, "{}: {place}: originRequest: give a map of keys", file.display())
            }
        };
        for (key, default) in &defaults {
            origin.entry(key.clone()).or_insert_with(|| default.clone());
        }
        if !origin.is_empty() {
            rule.insert("originRequest".into(), serde_json::Value::Object(origin));
        }
    }
    Ok(())
}

/// The types of the values of `originRequest` that the client reads:
/// a time needs a unit, a flag is true or false.
pub(super) fn check_origin_values(
    file: &std::path::Path,
    map: &serde_json::Map<String, serde_json::Value>,
    place: &str,
) -> Result<()> {
    for (key, value) in map {
        match key.as_str() {
            "connectTimeout" | "tlsTimeout" | "keepAliveTimeout" | "tcpKeepAlive" => {
                if value.is_number() {
                    bail!(
                        Stage::Host,
                        Class::Config,
                        "{}: {place}: {key}: {value} needs a unit, for example {value}s",
                        file.display()
                    );
                }
                if !value.is_string() {
                    bail!(
                        Stage::Host,
                        Class::Config,
                        "{}: {place}: {key}: give a time, for example 30s",
                        file.display()
                    );
                }
            }
            "noTLSVerify" | "disableChunkedEncoding" | "stripAcceptEncoding" => {
                if !value.is_boolean() {
                    bail!(Stage::Host, Class::Config, "{}: {place}: {key}: give true or false", file.display());
                }
            }
            "httpHostHeader" if !value.is_string() => {
                bail!(Stage::Host, Class::Config, "{}: {place}: {key}: give a string", file.display());
            }
            _ => {}
        }
    }
    Ok(())
}

/// The types of the top-level values that the client reads.
pub(super) fn check_top_values(file: &std::path::Path, value: &serde_json::Value) -> Result<()> {
    let map = match value {
        serde_json::Value::Null => bail!(
            Stage::Host,
            Class::Config,
            "{}: the file has no keys (it needs ingress:, for example `ingress:` and `  - service: http://127.0.0.1:8080`)",
            file.display()
        ),
        serde_json::Value::Object(map) => map,
        _ => bail!(
            Stage::Host,
            Class::Config,
            "{}: the config must be a mapping of keys (for example ingress:), not a list or a value",
            file.display()
        ),
    };
    for key in ["tunnel", "credentials-file", "protocol", "token", "url"] {
        if let Some(v) = map.get(key)
            && !v.is_string()
            && !v.is_null()
        {
            bail!(Stage::Host, Class::Config, "{}: {key}: give a string", file.display());
        }
    }
    if let Some(v) = map.get("hello-world")
        && !v.is_boolean()
        && !v.is_null()
    {
        bail!(Stage::Host, Class::Config, "{}: hello-world: give true or false", file.display());
    }
    if let Some(v) = map.get("ha-connections")
        && !v.is_u64()
    {
        bail!(Stage::Host, Class::Config, "{}: ha-connections: give a number from 1 to 8", file.display());
    }
    Ok(())
}

/// Load a YAML config in the format of cloudflared.
///
/// * With `credentials-file:`, the file gives the credentials, and
///   `tunnel:` is the name or the UUID of the tunnel, as in cloudflared. A
///   UUID must be the TunnelID of the file.
/// * With `tunnel:` only, it is a named-tunnel token.
/// * With `token:`, the value is the named-tunnel token. `credentials-file:`
///   is then an error. A `tunnel:` must then be the tunnel id of the token.
/// * With none of the three, the client starts a quick tunnel, and says so.
/// * A key that cloudflared does not know is an error: at the top level,
///   in an ingress rule and in `originRequest`.
/// * The top-level `originRequest` is the default of each rule.
/// * The last ingress rule must match each request (no hostname, no path).
pub fn load_file(path: &std::path::Path) -> Result<Config> {
    load_file_with(path, &pod_core::Report::default())
}

/// [`load_file`], with the lines for the user (a file that starts a quick
/// tunnel) as events for `report`.
pub fn load_file_with(path: &std::path::Path, report: &pod_core::Report) -> Result<Config> {
    let text = std::fs::read_to_string(path).io_fail(Stage::Host, format!("reading config {}", path.display()))?;
    let mut value = crate::yaml::parse(&text).with_context(|| format!("parsing {}", path.display()))?;
    check_top_values(path, &value)?;
    if let Some(map) = value.as_object() {
        check_keys(path, map, CLOUDFLARED_KEYS, "a cloudflared config")?;
    }
    check_and_merge_rules(path, &mut value, &crate::yaml::item_lines(&text, "ingress"))?;
    let raw: RawConfig =
        serde_json::from_value(value).or_fail(Stage::Host, Class::Config, format!("parsing {}", path.display()))?;

    let mut config = Config::default();
    if !raw.ingress.is_empty() {
        if let Some(last) = raw.ingress.last()
            && (last.hostname.is_some() || last.path.is_some())
        {
            bail!(
                Stage::Host,
                Class::Config,
                "{}: the last ingress rule must match each request (no hostname and no path), for example `- service: http_status:404`",
                path.display()
            );
        }
        config.ingress = crate::ingress::ingress_from_raw(raw.ingress)?;
    }
    // The keys url: and hello-world: of cloudflared give one catch-all
    // rule when the file has no ingress rules.
    let hello = raw.hello_world == Some(true);
    match (&raw.url, hello) {
        (Some(_), true) => bail!(
            Stage::Host,
            Class::Config,
            "{}: url: and hello-world: both give the origin; give one",
            path.display()
        ),
        (Some(_), false) | (None, true) if !config.ingress.is_empty() => bail!(
            Stage::Host,
            Class::Config,
            "{}: {} and ingress: both give the origin; give one",
            path.display(),
            if hello { "hello-world:" } else { "url:" }
        ),
        (Some(url), false) => {
            let service =
                crate::ingress::Service::parse(url).with_context(|| format!("{}: url: {url}", path.display()))?;
            config.ingress = crate::ingress::Ingress::default().catch_all(service);
        }
        (None, true) => {
            config.ingress = crate::ingress::Ingress::default().catch_all(crate::ingress::Service::HelloWorld);
        }
        (None, false) => {}
    }
    if let Some(token) = &raw.token {
        // A token of the file is the named tunnel, not a quick
        // tunnel.
        config.secrets.push(token.clone());
        if raw.credentials_file.is_some() {
            bail!(
                Stage::Host,
                Class::Config,
                "{}: token: and credentials-file: both give the credentials; give one",
                path.display()
            );
        }
        let credentials =
            parse_token(token).with_context(|| format!("{}: token: is not a tunnel token", path.display()))?;
        if let (Some(tunnel), Credentials::Explicit { tunnel_id, .. }) = (&raw.tunnel, &credentials)
            && Uuid::parse_str(tunnel.trim()).ok() != Some(*tunnel_id)
        {
            bail!(
                Stage::Host,
                Class::Config,
                "{}: tunnel: {tunnel} is not the tunnel id of token: ({tunnel_id}); remove tunnel: or correct it",
                path.display()
            );
        }
        config.credentials = credentials;
    } else {
        credentials_of_file(path, raw.tunnel, raw.credentials_file, &mut config, report)?;
    }
    if let Some(protocol) = raw.protocol {
        config.protocol = Protocol::parse(&protocol)?;
    }
    if let Some(ha) = raw.ha_connections {
        if !(1..=8).contains(&ha) {
            bail!(Stage::Host, Class::Config, "{}: ha-connections: {ha} is not from 1 to 8", path.display());
        }
        config.ha_connections = ha;
    }
    Ok(config)
}

/// The credentials of `tunnel:` and `credentials-file:` of a config file.
pub(super) fn credentials_of_file(
    path: &std::path::Path,
    tunnel: Option<String>,
    credentials_file: Option<PathBuf>,
    config: &mut Config,
    report: &pod_core::Report,
) -> Result<()> {
    match (tunnel, credentials_file) {
        (tunnel, Some(file)) => {
            let credentials = parse_credentials_file(&file)?;
            if let (Some(tunnel), Credentials::Explicit { tunnel_id, .. }) = (&tunnel, &credentials)
                && let Ok(uuid) = Uuid::parse_str(tunnel.trim())
                && uuid != *tunnel_id
            {
                bail!(
                    Stage::Host,
                    Class::Config,
                    "{}: tunnel: {uuid} is not the TunnelID of {} ({tunnel_id})",
                    path.display(),
                    file.display()
                );
            }
            config.credentials = credentials;
        }
        (Some(tunnel), None) => {
            if Uuid::parse_str(tunnel.trim()).is_ok() || !tunnel.trim().starts_with("ey") {
                bail!(
                    Stage::Host,
                    Class::Config,
                    "{}: tunnel: names a tunnel ({tunnel}); give its credentials-file:, or a tunnel token",
                    path.display()
                );
            }
            config.credentials = parse_token(&tunnel)?;
        }
        (None, None) => {
            let text =
                format!("{} has no tunnel:, no credentials-file: and no token:; a quick tunnel starts", path.display());
            report.event(pod_core::Event::info("config.quick", text));
        }
    }
    Ok(())
}
